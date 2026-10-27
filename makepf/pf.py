"""Native PF validation and explicit, privileged ruleset reloads."""

from contextlib import contextmanager
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile

from .config import FILES, load_config
from .model import ConfigError
from .render import render


PF_CONF = Path("/etc/pf.conf")
MANAGED = b"# Managed by MakePF. Edit the source configuration instead.\n"


def require_openbsd():
    if not sys.platform.startswith("openbsd"):
        raise ConfigError("native PF operations require OpenBSD")


def pfctl(path, *, load=False):
    result = subprocess.run(
        ["/sbin/pfctl", "-f" if load else "-nf", str(path)],
        capture_output=True, text=True, check=False,
    )
    if result.returncode:
        detail = result.stderr.strip() or result.stdout.strip() or "no diagnostic returned"
        operation = "load" if load else "syntax check"
        raise ConfigError(f"pfctl {operation} failed: {detail}")


def check(content):
    require_openbsd()
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", suffix=".pf") as stream:
        stream.write(content)
        stream.flush()
        pfctl(stream.name)


def trusted(path, *, directory=False):
    """Require root ownership and protected parent directories for root input."""
    path = Path(path)
    info = path.lstat()
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected(info.st_mode):
        raise ConfigError(f"{path}: expected a regular {'directory' if directory else 'file'}, not a symbolic link")
    for entry in (path, *path.parents):
        info = entry.lstat()
        if entry != path and not stat.S_ISDIR(info.st_mode):
            raise ConfigError(f"{entry}: reload requires real parent directories, not symbolic links")
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise ConfigError(f"{entry}: reload requires root ownership and no group or other write permission")


def configuration(directory):
    directory = Path(directory).absolute()
    trusted(directory, directory=True)
    directory = directory.resolve()
    for name in FILES:
        path = directory / name
        if path.exists() or path.is_symlink():
            info = path.lstat()
            if info.st_uid != 0:
                raise ConfigError(f"{path}: reload requires root-owned configuration")
            target = path
            if stat.S_ISLNK(info.st_mode):
                target = path.readlink()
                if not target.is_absolute():
                    target = path.parent / target
            # Check the original target path, not its resolution: intermediate
            # links could otherwise hide a directory controlled by another user.
            trusted(target)
    return directory


def stage(path, content, mode=0o600, group=None):
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".makepf-", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(content)
            if group is not None:
                os.fchown(stream.fileno(), -1, group)
            os.fchmod(stream.fileno(), mode)
            stream.flush()
            os.fsync(stream.fileno())
        return temporary
    except BaseException:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        raise


def replace(path, content, mode=0o600, group=None):
    temporary = stage(path, content, mode, group)
    try:
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


@contextmanager
def locked(target):
    import fcntl

    path = target.with_name(".makepf.lock")
    descriptor = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ConfigError(f"{path}: expected a root-owned, protected regular lock file")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ConfigError("another MakePF reload is in progress") from error
        yield
    finally:
        os.close(descriptor)


def reload(directory, *, adopt=False):
    require_openbsd()
    if os.geteuid() != 0:
        raise ConfigError("reload requires root; use doas makepf reload")
    target = PF_CONF
    backup = target.with_name(target.name + ".makepf.bak")
    trusted(target.parent, directory=True)
    with locked(target):
        directory = configuration(directory)
        for output in (target, backup):
            resolved = output.resolve()
            if resolved.is_relative_to(directory) or any(resolved == (directory / name).resolve() for name in FILES):
                raise ConfigError(f"{output}: reload cannot replace a configuration input")
        previous, previous_info = None, None
        if target.exists() or target.is_symlink():
            trusted(target)
            previous_info = target.stat()
            previous = target.read_bytes()
            if not previous.startswith(MANAGED) and not adopt:
                raise ConfigError(f"{target}: not managed by MakePF; use reload --adopt once to replace it with a backup")
        if backup.exists() or backup.is_symlink():
            trusted(backup)
        content = MANAGED + render(load_config(directory)).encode("utf-8")
        candidate = stage(target, content)
        try:
            pfctl(candidate)
            if previous is not None and previous != content:
                replace(backup, previous)
            os.replace(candidate, target)
            try:
                pfctl(target, load=True)
            except (ConfigError, OSError) as error:
                try:
                    if previous is None:
                        target.unlink()
                    else:
                        replace(target, previous, stat.S_IMODE(previous_info.st_mode), previous_info.st_gid)
                except OSError as recovery_error:
                    recovery = f"previous file is at {backup}" if previous is not None else "new saved configuration may remain"
                    raise ConfigError(f"{error}; could not restore {target}: {recovery_error}; {recovery}") from error
                recovery = "saved configuration restored" if previous is not None else "new saved configuration removed"
                raise ConfigError(f"{error}; {recovery}") from error
        finally:
            candidate.unlink(missing_ok=True)
