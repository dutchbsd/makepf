"""Command-line compilation, checking and explicit PF reloads."""

import argparse
import os
from pathlib import Path
import stat
import sys
import tempfile

from . import __version__
from .config import FILES, load_config
from .model import ConfigError
from . import pf
from .render import render


DEFAULT_DIRECTORY = Path("/etc/makepf")


def write_output(path, content):
    """Replace a selected file only after the complete output is available."""
    if path.is_symlink():
        raise ConfigError(f"{path}: refusing to replace a symbolic link")
    try:
        current = path.stat()
    except FileNotFoundError:
        mode = 0o600
    else:
        if not stat.S_ISREG(current.st_mode):
            raise ConfigError(f"{path}: output must be a regular file")
        mode = stat.S_IMODE(current.st_mode) & 0o777
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", newline="\n", dir=path.parent,
            prefix=f".{path.name}.", delete=False,
        ) as stream:
            temporary = Path(stream.name)
            stream.write(content)
            stream.flush()
            os.fchmod(stream.fileno(), mode)
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def run(argv=None):
    parser = argparse.ArgumentParser(
        prog="makepf", description="Compile zone policies to OpenBSD PF rules."
    )
    parser.add_argument("--version", action="version", version=f"MakePF {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("check", help="validate configuration without loading PF rules")
    check.add_argument("directory", nargs="?", type=Path, default=DEFAULT_DIRECTORY, help="configuration directory (default: /etc/makepf)")
    check.add_argument("--pf", action="store_true", help="require native PF checking (automatic on OpenBSD)")
    compile_command = commands.add_parser("compile", help="write a complete PF configuration")
    compile_command.add_argument("directory", nargs="?", type=Path, default=DEFAULT_DIRECTORY, help="configuration directory (default: /etc/makepf)")
    compile_command.add_argument("-o", "--output", type=Path, help="replace this file instead of writing stdout")
    reload_command = commands.add_parser("reload", help="check, save and load the PF configuration; requires root on OpenBSD")
    reload_command.add_argument("directory", nargs="?", type=Path, default=DEFAULT_DIRECTORY, help="configuration directory (default: /etc/makepf)")
    reload_command.add_argument("--adopt", action="store_true", help="take over an existing PF configuration with a backup")
    args = parser.parse_args(argv)
    try:
        if args.command == "reload":
            pf.reload(args.directory, adopt=args.adopt)
            print("PF configuration reloaded; existing states retained", file=sys.stderr)
            return 0
        content = render(load_config(args.directory))
        if args.command == "check":
            native = args.pf or sys.platform.startswith("openbsd")
            if native:
                pf.check(content)
            print("Configuration valid" + ("; PF syntax valid" if native else ""), file=sys.stderr)
        elif args.output:
            destination = args.output.resolve()
            if destination.is_relative_to(args.directory.resolve()):
                raise ConfigError("output must be outside the configuration directory")
            if any(destination == (args.directory / name).resolve() for name in FILES):
                raise ConfigError("output cannot replace a configuration input")
            write_output(args.output, content)
        else:
            sys.stdout.write(content)
        return 0
    except BrokenPipeError:
        return 1
    except KeyboardInterrupt:
        print("makepf: interrupted; if reloading, inspect the saved and active PF configuration", file=sys.stderr)
        return 130
    except (ConfigError, OSError, UnicodeError) as error:
        print(f"makepf: {error}", file=sys.stderr)
        return 1


def main():
    raise SystemExit(run())
