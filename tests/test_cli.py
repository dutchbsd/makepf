"""End-to-end command and archive contracts, without changing the running PF."""

from contextlib import redirect_stderr, redirect_stdout
import io
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from makepf.cli import run


PROJECT = Path(__file__).resolve().parents[1]


class CommandLineTests(unittest.TestCase):
    def setUp(self):
        platform = patch("makepf.cli.sys.platform", "linux")
        platform.start()
        self.addCleanup(platform.stop)
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.config = self.directory / "configuration"
        shutil.copytree(PROJECT / "examples" / "dual-stack", self.config)

    def invoke(self, *arguments):
        output, diagnostics = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(diagnostics):
            status = run([str(argument) for argument in arguments])
        return status, output.getvalue(), diagnostics.getvalue()

    def test_check_reports_success_without_emitting_a_ruleset(self):
        status, output, diagnostics = self.invoke("check", self.config)
        self.assertEqual(status, 0)
        self.assertEqual(output, "")
        self.assertIn("Configuration valid", diagnostics)
        self.assertNotIn("PF syntax valid", diagnostics)

    def test_check_and_compile_use_the_default_directory_when_omitted(self):
        with patch("makepf.cli.DEFAULT_DIRECTORY", self.config):
            self.assertEqual(self.invoke("check"), self.invoke("check", self.config))
            self.assertEqual(self.invoke("compile"), self.invoke("compile", self.config))

    def test_openbsd_check_automatically_checks_native_syntax_without_root(self):
        def syntax_success(arguments, **kwargs):
            self.assertEqual(arguments[:2], ["/sbin/pfctl", "-nf"])
            self.assertIn("block all", Path(arguments[2]).read_text(encoding="utf-8"))
            self.assertFalse(kwargs.get("shell", False))
            return subprocess.CompletedProcess(arguments, 0, "", "")

        with patch("makepf.cli.sys.platform", "openbsd7"), patch("makepf.pf.os.geteuid", return_value=1000), patch("makepf.pf.subprocess.run", side_effect=syntax_success) as native:
            status, output, diagnostics = self.invoke("check", self.config)
        self.assertEqual((status, output), (0, ""))
        self.assertIn("PF syntax valid", diagnostics)
        native.assert_called_once()

    def test_reload_uses_the_default_directory_and_reports_success(self):
        with patch("makepf.cli.DEFAULT_DIRECTORY", self.config), patch("makepf.pf.reload") as reload:
            status, output, diagnostics = self.invoke("reload")
        self.assertEqual((status, output), (0, ""))
        reload.assert_called_once_with(self.config, adopt=False)
        self.assertIn("existing states retained", diagnostics)

    def test_reload_reports_root_requirement_without_a_traceback(self):
        with patch("makepf.cli.sys.platform", "openbsd7"), patch("makepf.pf.os.geteuid", return_value=1000), patch("makepf.pf.subprocess.run") as native:
            status, output, diagnostics = self.invoke("reload")
        self.assertEqual((status, output), (1, ""))
        self.assertIn("doas makepf reload", diagnostics)
        self.assertNotIn("Traceback", diagnostics)
        native.assert_not_called()

    def test_output_cannot_replace_a_symlinked_input_outside_the_directory(self):
        shared = self.directory / "shared-rules"
        shared.write_text((self.config / "rules").read_text(), encoding="utf-8")
        (self.config / "rules").unlink()
        (self.config / "rules").symlink_to(shared)
        original = shared.read_bytes()
        status, output, diagnostic = self.invoke("compile", self.config, "-o", shared)
        self.assertEqual((status, output), (1, ""))
        self.assertIn("configuration input", diagnostic)
        self.assertEqual(shared.read_bytes(), original)

    def test_compile_stdout_is_deterministic_and_does_not_change_inputs(self):
        original = {path.name: path.read_bytes() for path in self.config.iterdir()}
        first = self.invoke("compile", self.config)
        second = self.invoke("compile", self.config)
        self.assertEqual(first, second)
        self.assertEqual(first[0], 0)
        self.assertIn("block all\n", first[1])
        self.assertEqual(first[2], "")
        self.assertEqual(original, {path.name: path.read_bytes() for path in self.config.iterdir()})

    def test_output_file_is_private_and_retains_existing_permissions(self):
        candidate = self.directory / "candidate.pf"
        status, output, diagnostics = self.invoke("compile", self.config, "-o", candidate)
        self.assertEqual((status, output, diagnostics), (0, "", ""))
        self.assertEqual(stat.S_IMODE(candidate.stat().st_mode), 0o600)
        self.assertEqual(candidate.read_text(encoding="utf-8"), self.invoke("compile", self.config)[1])
        candidate.chmod(0o640)
        candidate.write_text("old rules\n", encoding="utf-8")
        self.assertEqual(self.invoke("compile", self.config, "-o", candidate)[0], 0)
        self.assertEqual(stat.S_IMODE(candidate.stat().st_mode), 0o640)
        self.assertNotEqual(candidate.read_text(encoding="utf-8"), "old rules\n")

    def test_invalid_configuration_preserves_existing_output_and_emits_no_pf(self):
        candidate = self.directory / "candidate.pf"
        candidate.write_text("known good rules\n", encoding="utf-8")
        (self.config / "rules").write_text("ACCEPT loc fw both tcp 65536\n", encoding="utf-8")
        for arguments in (("compile", self.config), ("compile", self.config, "-o", candidate), ("check", self.config)):
            with self.subTest(arguments=arguments):
                status, output, diagnostics = self.invoke(*arguments)
                self.assertNotEqual(status, 0)
                self.assertEqual(output, "")
                self.assertIn("rules:1:", diagnostics)
                self.assertNotIn("Traceback", diagnostics)
        self.assertEqual(candidate.read_text(encoding="utf-8"), "known good rules\n")

    def test_output_cannot_replace_or_pollute_the_configuration_directory(self):
        original = (self.config / "rules").read_bytes()
        for output_path in (self.config / "rules", self.config / "generated.pf"):
            with self.subTest(output_path=output_path):
                status, output, diagnostics = self.invoke("compile", self.config, "-o", output_path)
                self.assertNotEqual(status, 0)
                self.assertEqual(output, "")
                self.assertIn("configuration", diagnostics)
        self.assertEqual((self.config / "rules").read_bytes(), original)
        self.assertFalse((self.config / "generated.pf").exists())

    def test_symbolic_links_are_refused_without_following_them(self):
        target = self.directory / "important"
        target.write_text("unchanged", encoding="utf-8")
        link = self.directory / "candidate.pf"
        link.symlink_to(target)
        status, output, diagnostics = self.invoke("compile", self.config, "-o", link)
        self.assertNotEqual(status, 0)
        self.assertEqual(output, "")
        self.assertIn("symbolic link", diagnostics)
        self.assertEqual(target.read_text(encoding="utf-8"), "unchanged")
        link.unlink()
        link.symlink_to(self.directory / "missing")
        self.assertNotEqual(self.invoke("compile", self.config, "-o", link)[0], 0)
        self.assertFalse((self.directory / "missing").exists())

    def test_write_errors_leave_no_partial_candidate(self):
        nonexistent_parent = self.directory / "missing" / "candidate.pf"
        status, output, diagnostics = self.invoke("compile", self.config, "-o", nonexistent_parent)
        self.assertNotEqual(status, 0)
        self.assertEqual(output, "")
        self.assertTrue(diagnostics)
        self.assertFalse(nonexistent_parent.exists())
        status, output, diagnostics = self.invoke("compile", self.config, "-o", self.directory)
        self.assertNotEqual(status, 0)
        self.assertEqual(output, "")
        self.assertIn("regular file", diagnostics)

    def test_pf_option_rejects_non_openbsd_without_running_a_command(self):
        with patch("makepf.cli.sys.platform", "linux"), patch("makepf.pf.subprocess.run") as native:
            status, output, diagnostics = self.invoke("check", self.config, "--pf")
        self.assertNotEqual(status, 0)
        self.assertEqual(output, "")
        self.assertIn("require OpenBSD", diagnostics)
        native.assert_not_called()

    def test_pf_option_only_checks_syntax_and_propagates_native_failure(self):
        def syntax_failure(arguments, **kwargs):
            self.assertEqual(arguments[:2], ["/sbin/pfctl", "-nf"])
            self.assertEqual(len(arguments), 3)
            self.assertIn("block all", Path(arguments[2]).read_text(encoding="utf-8"))
            self.assertFalse(kwargs.get("shell", False))
            return subprocess.CompletedProcess(arguments, 1, "", "native syntax failure")

        with patch("makepf.cli.sys.platform", "openbsd7"), patch("makepf.pf.subprocess.run", side_effect=syntax_failure):
            status, output, diagnostics = self.invoke("check", self.config, "--pf")
        self.assertNotEqual(status, 0)
        self.assertEqual(output, "")
        self.assertIn("native syntax failure", diagnostics)
        self.assertNotIn("PF syntax valid", diagnostics)

    def test_module_help_version_and_invalid_command(self):
        for argument in ("--help", "--version", "load"):
            result = subprocess.run(
                [sys.executable, "-m", "makepf", argument], cwd=PROJECT,
                capture_output=True, text=True, check=False,
            )
            with self.subTest(argument=argument):
                if argument == "load":
                    self.assertEqual(result.returncode, 2)
                    self.assertEqual(result.stdout, "")
                    self.assertIn("invalid choice", result.stderr)
                else:
                    self.assertEqual(result.returncode, 0)
                    self.assertTrue(result.stdout)
                    self.assertEqual(result.stderr, "")

    def test_archive_build_runs_without_checkout_or_pythonpath(self):
        source = self.directory / "source"
        (source / "tools").mkdir(parents=True)
        shutil.copyfile(PROJECT / "tools" / "build.py", source / "tools" / "build.py")
        shutil.copyfile(PROJECT / "LICENSE", source / "LICENSE")
        shutil.copytree(PROJECT / "makepf", source / "makepf", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        (source / "private-notes.txt").write_text("must not ship", encoding="utf-8")
        cache = source / "makepf" / "__pycache__"
        cache.mkdir()
        (cache / "private.pyc").write_bytes(b"must not ship")
        built = subprocess.run(
            [sys.executable, str(source / "tools" / "build.py")],
            cwd=self.directory, capture_output=True, text=True, check=False,
        )
        self.assertEqual(built.returncode, 0, built.stderr)
        archive = source / "dist" / "makepf"
        self.assertTrue(archive.stat().st_mode & stat.S_IXUSR)
        self.assertEqual(archive.read_bytes().splitlines()[0], f"#!{sys.executable}".encode())
        with zipfile.ZipFile(archive) as package:
            names = package.namelist()
            self.assertIn("LICENSE", names)
            self.assertIn("makepf/config.py", names)
            self.assertFalse(any("private" in name or "__pycache__" in name or name.startswith("/") for name in names))
        standalone = self.directory / "makepf"
        shutil.copy2(archive, standalone)
        shutil.rmtree(source)
        environment = os.environ.copy()
        environment.pop("PYTHONPATH", None)
        result = subprocess.run(
            [sys.executable, "-I", str(standalone), "compile", str(self.config)],
            cwd=self.directory, env=environment, capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, self.invoke("compile", self.config)[1])
        self.assertEqual(result.stderr, "")
        direct = subprocess.run(
            [str(standalone), "--version"], cwd=self.directory,
            env=environment, capture_output=True, text=True, check=False,
        )
        self.assertEqual(direct.returncode, 0, direct.stderr)
        self.assertIn("MakePF", direct.stdout)


if __name__ == "__main__":
    unittest.main()
