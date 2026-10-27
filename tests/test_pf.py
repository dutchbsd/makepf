"""PF reload contracts using private files and mocked native commands."""

from contextlib import nullcontext
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from makepf import pf
from makepf.model import ConfigError


PROJECT = Path(__file__).resolve().parents[1]


class ReloadTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.config = self.directory / "configuration"
        shutil.copytree(PROJECT / "examples" / "dual-stack", self.config)
        self.target = self.directory / "pf.conf"
        self.backup = self.directory / "pf.conf.makepf.bak"
        self.original_trusted = pf.trusted
        self.previous = pf.MANAGED + b"block all\n# previous policy\n"
        self.target.write_bytes(self.previous)
        self.target.chmod(0o640)
        for name, value in (
            ("PF_CONF", self.target),
            ("sys.platform", "openbsd7"),
        ):
            replacement = patch(f"makepf.pf.{name}", value)
            replacement.start()
            self.addCleanup(replacement.stop)
        for name, value in (
            ("os.geteuid", 0),
            ("trusted", None),
            ("configuration", self.config),
        ):
            replacement = patch(f"makepf.pf.{name}", return_value=value)
            replacement.start()
            self.addCleanup(replacement.stop)
        lock = patch("makepf.pf.locked", side_effect=lambda target: nullcontext())
        lock.start()
        self.addCleanup(lock.stop)

    def assert_no_temporary_files(self):
        self.assertEqual(list(self.directory.glob(".makepf-*")), [])

    def test_reload_checks_then_loads_identical_private_bytes_and_keeps_backup(self):
        checked, loaded = [], []

        def native(arguments, **kwargs):
            self.assertEqual(arguments[0], "/sbin/pfctl")
            self.assertEqual(len(arguments), 3)
            self.assertFalse(kwargs.get("shell", False))
            path = Path(arguments[2])
            if arguments[1] == "-nf":
                self.assertNotEqual(path, self.target)
                self.assertEqual(path.parent, self.target.parent)
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                self.assertEqual(self.target.read_bytes(), self.previous)
                checked.append(path.read_bytes())
            else:
                self.assertEqual(arguments[1], "-f")
                self.assertEqual(path, self.target)
                loaded.append(path.read_bytes())
            return subprocess.CompletedProcess(arguments, 0, "", "")

        with patch("makepf.pf.subprocess.run", side_effect=native):
            pf.reload(self.config)
        self.assertEqual(checked, loaded)
        self.assertEqual(len(loaded), 1)
        self.assertTrue(loaded[0].startswith(pf.MANAGED))
        self.assertIn(b"block all\n", loaded[0])
        self.assertEqual(self.target.read_bytes(), loaded[0])
        self.assertEqual(self.backup.read_bytes(), self.previous)
        self.assertEqual(stat.S_IMODE(self.target.stat().st_mode), 0o600)
        self.assert_no_temporary_files()

    def test_unchanged_reload_still_loads_and_preserves_previous_different_backup(self):
        with patch("makepf.pf.pfctl") as native:
            pf.reload(self.config)
            accepted = self.target.read_bytes()
            pf.reload(self.config)
        self.assertEqual(native.call_count, 4)
        self.assertEqual(sum(call.kwargs.get("load", False) for call in native.call_args_list), 2)
        self.assertEqual(self.target.read_bytes(), accepted)
        self.assertEqual(self.backup.read_bytes(), self.previous)

    def test_unmanaged_file_requires_explicit_adoption_and_is_backed_up(self):
        previous = b"# existing administrator policy\nblock all\n"
        self.target.write_bytes(previous)
        with patch("makepf.pf.pfctl") as native:
            with self.assertRaisesRegex(ConfigError, "reload --adopt"):
                pf.reload(self.config)
            native.assert_not_called()
            self.assertEqual(self.target.read_bytes(), previous)
            self.assertFalse(self.backup.exists())
            pf.reload(self.config, adopt=True)
        self.assertEqual(self.backup.read_bytes(), previous)
        self.assertTrue(self.target.read_bytes().startswith(pf.MANAGED))

    def test_non_openbsd_and_non_root_fail_before_native_or_filesystem_changes(self):
        with patch("makepf.pf.pfctl") as native:
            with patch("makepf.pf.sys.platform", "linux"):
                with self.assertRaisesRegex(ConfigError, "require OpenBSD"):
                    pf.reload(self.config)
            with patch("makepf.pf.os.geteuid", return_value=1000):
                with self.assertRaisesRegex(ConfigError, "doas makepf reload"):
                    pf.reload(self.config)
            native.assert_not_called()
        self.assertEqual(self.target.read_bytes(), self.previous)
        self.assertFalse(self.backup.exists())
        self.assert_no_temporary_files()

    def test_untrusted_configuration_fails_without_touching_saved_rules(self):
        with patch("makepf.pf.configuration", side_effect=ConfigError("configuration is writable by another user")), patch("makepf.pf.pfctl") as native:
            with self.assertRaisesRegex(ConfigError, "writable"):
                pf.reload(self.config)
            native.assert_not_called()
        self.assertEqual(self.target.read_bytes(), self.previous)
        self.assertFalse(self.backup.exists())

    def test_reload_refuses_symbolic_link_target_or_backup_before_validation(self):
        unrelated = self.directory / "unrelated"
        unrelated.write_bytes(b"unchanged\n")
        for output in (self.target, self.backup):
            with self.subTest(output=output):
                if output.exists():
                    output.unlink()
                output.symlink_to(unrelated)

                def trust(path, **kwargs):
                    if path == output:
                        self.original_trusted(path, **kwargs)

                with patch("makepf.pf.trusted", side_effect=trust), patch("makepf.pf.pfctl") as native:
                    with self.assertRaisesRegex(ConfigError, "symbolic link"):
                        pf.reload(self.config, adopt=True)
                    native.assert_not_called()
                self.assertTrue(output.is_symlink())
                self.assertEqual(unrelated.read_bytes(), b"unchanged\n")
                output.unlink()
                if output == self.target:
                    self.target.write_bytes(self.previous)

    def test_configuration_inputs_cannot_be_replaced_by_saved_rules(self):
        with patch("makepf.pf.PF_CONF", self.config / "policy"), patch("makepf.pf.pfctl") as native:
            original = (self.config / "policy").read_bytes()
            with self.assertRaisesRegex(ConfigError, "configuration input"):
                pf.reload(self.config)
            native.assert_not_called()
        self.assertEqual((self.config / "policy").read_bytes(), original)

    def test_invalid_configuration_never_reaches_native_pf(self):
        (self.config / "rules").write_text("ACCEPT loc fw both tcp 65536\n", encoding="utf-8")
        with patch("makepf.pf.pfctl") as native:
            with self.assertRaisesRegex(ConfigError, "invalid port"):
                pf.reload(self.config)
            native.assert_not_called()
        self.assertEqual(self.target.read_bytes(), self.previous)
        self.assertFalse(self.backup.exists())
        self.assert_no_temporary_files()

    def test_syntax_rejection_does_not_replace_target_or_previous_backup(self):
        self.backup.write_bytes(b"older accepted rules\n")
        with patch("makepf.pf.pfctl", side_effect=ConfigError("native syntax failure")) as native:
            with self.assertRaisesRegex(ConfigError, "native syntax failure"):
                pf.reload(self.config)
            native.assert_called_once()
        self.assertEqual(self.target.read_bytes(), self.previous)
        self.assertEqual(self.backup.read_bytes(), b"older accepted rules\n")
        self.assert_no_temporary_files()

    def test_backup_failure_prevents_installation_and_loading(self):
        with patch("makepf.pf.pfctl") as native, patch("makepf.pf.replace", side_effect=OSError("backup unavailable")):
            with self.assertRaisesRegex(OSError, "backup unavailable"):
                pf.reload(self.config)
        native.assert_called_once()
        self.assertEqual(self.target.read_bytes(), self.previous)
        self.assertFalse(self.backup.exists())
        self.assert_no_temporary_files()

    def test_failed_load_restores_previous_contents_permissions_and_group(self):
        group = self.target.stat().st_gid
        with patch("makepf.pf.pfctl", side_effect=[None, ConfigError("load rejected")]):
            with self.assertRaisesRegex(ConfigError, "load rejected; saved configuration restored"):
                pf.reload(self.config)
        self.assertEqual(self.target.read_bytes(), self.previous)
        self.assertEqual(stat.S_IMODE(self.target.stat().st_mode), 0o640)
        self.assertEqual(self.target.stat().st_gid, group)
        self.assertEqual(self.backup.read_bytes(), self.previous)
        self.assert_no_temporary_files()

    def test_failed_first_load_leaves_no_saved_candidate(self):
        self.target.unlink()
        with patch("makepf.pf.pfctl", side_effect=[None, ConfigError("load rejected")]):
            with self.assertRaisesRegex(ConfigError, "load rejected"):
                pf.reload(self.config)
        self.assertFalse(self.target.exists())
        self.assertFalse(self.backup.exists())
        self.assert_no_temporary_files()

    def test_failed_restore_identifies_preserved_backup(self):
        original_replace = pf.replace

        def replacement(path, *arguments):
            if path == self.target:
                raise OSError("cannot restore target")
            return original_replace(path, *arguments)

        with patch("makepf.pf.pfctl", side_effect=[None, ConfigError("load rejected")]), patch("makepf.pf.replace", side_effect=replacement):
            with self.assertRaises(ConfigError) as failure:
                pf.reload(self.config)
        self.assertIn("could not restore", str(failure.exception))
        self.assertIn(str(self.backup), str(failure.exception))
        self.assertEqual(self.backup.read_bytes(), self.previous)
        self.assert_no_temporary_files()


class TrustAndLockTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.file = self.directory / "rules"
        self.file.write_text("block all\n", encoding="utf-8")

    def protected_metadata(self, *, writable=()):
        """Model protected root-owned fixtures without needing privileged chown."""
        original_lstat = Path.lstat

        def metadata(path):
            actual = original_lstat(path)
            mode = actual.st_mode
            if stat.S_ISLNK(mode):
                # OpenBSD links can have protected permission bits too.
                mode = stat.S_IFLNK | 0o755
            else:
                mode &= ~0o022
            if path.resolve() in writable:
                mode |= 0o022
            return SimpleNamespace(st_uid=0, st_mode=mode)

        return patch.object(Path, "lstat", metadata)

    def test_symbolic_link_output_is_rejected_without_following_it(self):
        link = self.directory / "pf.conf"
        link.symlink_to(self.file)
        with self.assertRaisesRegex(ConfigError, "symbolic link"):
            pf.trusted(link)
        self.assertEqual(self.file.read_text(encoding="utf-8"), "block all\n")

    def test_untrusted_file_or_parent_is_rejected(self):
        for rejected, owner, mode in (
            (self.file, 1000, stat.S_IFREG | 0o600),
            (self.file, 0, stat.S_IFREG | 0o662),
            (self.directory, 1000, stat.S_IFDIR | 0o700),
            (self.directory, 0, stat.S_IFDIR | 0o777),
        ):
            def metadata(path):
                if path == rejected:
                    return SimpleNamespace(st_uid=owner, st_mode=mode)
                return SimpleNamespace(st_uid=0, st_mode=(stat.S_IFREG | 0o600) if path == self.file else (stat.S_IFDIR | 0o755))

            with self.subTest(path=rejected, owner=owner, mode=mode), patch.object(Path, "lstat", metadata):
                with self.assertRaisesRegex(ConfigError, "root ownership and no group or other write"):
                    pf.trusted(self.file)

    def test_configuration_rejects_a_non_root_owned_link(self):
        directory = self.directory / "configuration"
        directory.mkdir()
        link = directory / "rules"
        link.symlink_to(self.file)
        original_lstat = Path.lstat

        def metadata(path):
            actual = original_lstat(path)
            if path == link:
                return SimpleNamespace(st_uid=1000, st_mode=actual.st_mode)
            return actual

        with patch("makepf.pf.trusted"), patch.object(Path, "lstat", metadata):
            with self.assertRaisesRegex(ConfigError, "root-owned configuration"):
                pf.configuration(directory)

    def test_configuration_accepts_protected_direct_absolute_and_relative_links(self):
        directory = self.directory / "configuration"
        directory.mkdir()
        link = directory / "rules"
        for target in (self.file, Path("..") / "rules"):
            with self.subTest(target=target):
                link.symlink_to(target)
                with self.protected_metadata():
                    self.assertEqual(pf.configuration(directory), directory.resolve())
                link.unlink()

    def test_configuration_rejects_a_link_chain_even_when_the_final_file_is_protected(self):
        directory = self.directory / "configuration"
        directory.mkdir()
        intermediate = self.directory / "intermediate"
        intermediate.symlink_to(self.file)
        (directory / "rules").symlink_to(intermediate)
        self.assertEqual((directory / "rules").resolve(), self.file)
        with self.protected_metadata():
            with self.assertRaisesRegex(ConfigError, "symbolic link"):
                pf.configuration(directory)

    def test_configuration_rejects_a_direct_link_through_a_symbolic_link_parent(self):
        directory = self.directory / "configuration"
        directory.mkdir()
        parent = self.directory / "alias"
        parent.symlink_to(self.directory, target_is_directory=True)
        (directory / "rules").symlink_to(parent / "rules")
        self.assertEqual((directory / "rules").resolve(), self.file)
        with self.protected_metadata():
            with self.assertRaisesRegex(ConfigError, "symbolic link"):
                pf.configuration(directory)

    def test_configuration_rejects_a_direct_link_target_in_a_writable_parent(self):
        directory = self.directory / "configuration"
        directory.mkdir()
        parent = self.directory / "writable"
        parent.mkdir()
        target = parent / "rules"
        target.write_text("block all\n", encoding="utf-8")
        (directory / "rules").symlink_to(target)
        with self.protected_metadata(writable=(parent,)):
            with self.assertRaisesRegex(ConfigError, "no group or other write"):
                pf.configuration(directory)

    def test_configuration_rejects_a_symbolic_link_directory(self):
        directory = self.directory / "configuration"
        directory.mkdir()
        alias = self.directory / "configuration-alias"
        alias.symlink_to(directory, target_is_directory=True)
        with self.protected_metadata():
            with self.assertRaisesRegex(ConfigError, "symbolic link"):
                pf.configuration(alias)

    def test_configuration_rejects_a_directory_reached_through_a_symbolic_link_parent(self):
        parent = self.directory / "protected"
        parent.mkdir()
        directory = parent / "configuration"
        directory.mkdir()
        alias = self.directory / "alias"
        alias.symlink_to(parent, target_is_directory=True)
        with self.protected_metadata():
            with self.assertRaisesRegex(ConfigError, "symbolic link"):
                pf.configuration(alias / "configuration")

    def test_configuration_rejects_a_writable_lexical_directory_parent(self):
        parent = self.directory / "writable"
        parent.mkdir()
        directory = parent / "configuration"
        directory.mkdir()
        with self.protected_metadata(writable=(parent,)):
            with self.assertRaisesRegex(ConfigError, "no group or other write"):
                pf.configuration(directory)

    def test_lock_contention_fails_without_entering_reload(self):
        import fcntl

        original_fstat = os.fstat

        def protected_metadata(descriptor):
            actual = original_fstat(descriptor)
            return SimpleNamespace(st_uid=0, st_mode=actual.st_mode)

        with patch("makepf.pf.os.fstat", side_effect=protected_metadata), patch.object(fcntl, "flock", side_effect=BlockingIOError):
            with self.assertRaisesRegex(ConfigError, "another MakePF reload"):
                with pf.locked(self.directory / "pf.conf"):
                    self.fail("reload entered while another process held the lock")

    def test_lock_refuses_symlinks_without_changing_the_target(self):
        (self.directory / ".makepf.lock").symlink_to(self.file)
        with self.assertRaises(OSError):
            with pf.locked(self.directory / "pf.conf"):
                self.fail("symbolic link lock accepted")
        self.assertEqual(self.file.read_text(encoding="utf-8"), "block all\n")


if __name__ == "__main__":
    unittest.main()
