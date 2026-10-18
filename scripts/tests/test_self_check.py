"""Exercise selection with real Git history and Cargo workspace metadata."""

import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "self_check.py"
SPEC = importlib.util.spec_from_file_location("self_check", SCRIPT)
self_check = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(self_check)


class SelectionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.git("init", "--quiet", "--initial-branch=main")
        self.git("config", "user.email", "test@example.invalid")
        self.git("config", "user.name", "Test")
        self.write("Cargo.toml", '[workspace]\nmembers = ["crates/*", "examples/*"]\nresolver = "3"\n')
        self.crate("crates/core", "contract-core")
        self.crate("crates/api", "contract-api", "contract-core", "../core")
        self.crate("examples/client", "contract-client", "contract-api", "../../crates/api")
        self.crate("crates/other", "contract-other")
        self.write("docs/readme.md", "Documentation\n")
        self.write("crates/core/vectors/sample.json", "{}\n")
        subprocess.run(["cargo", "generate-lockfile", "--offline"], cwd=self.root, check=True)
        self.metadata = self_check.workspace_metadata(self.root)
        self.commit()

    def git(self, *args):
        return subprocess.check_output(["git", *args], cwd=self.root, text=True).strip()

    def write(self, path, contents):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(contents)

    def crate(self, directory, name, dependency=None, path=None):
        manifest = f'[package]\nname = "{name}"\nversion = "0.1.0"\nedition = "2024"\n'
        if dependency:
            manifest += f'\n[dependencies]\n{dependency} = {{ path = "{path}" }}\n'
        self.write(f"{directory}/Cargo.toml", manifest)
        self.write(f"{directory}/src/lib.rs", "pub fn value() -> u8 { 1 }\n")
        self.write(f"{directory}/tests/value.rs", f"#[test]\nfn value_is_in_range() {{ assert!({name.replace('-', '_')}::value() <= 3); }}\n")

    def commit(self):
        self.git("add", ".")
        self.git("commit", "--quiet", "-m", "test: fixture")

    def selection(self):
        paths = self_check.changed_paths(self.root, "main")
        return self_check.select(self.root, paths, self.metadata)

    def test_one_crate_selects_transitive_reverse_dependencies(self):
        self.write("crates/core/src/lib.rs", "pub fn value() -> u8 { 2 }\n")
        selection = self.selection()
        self.assertFalse(selection["full"])
        self.assertEqual(selection["changed"], ["contract-core"])
        self.assertEqual(selection["affected"], ["contract-api", "contract-client", "contract-core"])
        commands = self_check.commands(selection)
        self.assertEqual(commands[0], ["just", "fmt-check", "lint", "deny", "shear", "typos", "vectors-check", "semver"])
        self.assertEqual(commands[2], ["cargo", "nextest", "run", "--workspace", "--locked", "-E", "rdeps(contract-core)"])
        for command in commands[3:]:
            packages = [command[i + 1] for i, arg in enumerate(command) if arg == "--package"]
            self.assertEqual(packages, selection["affected"])

    def test_scoped_commands_run_real_tests_and_documentation(self):
        self.write("crates/core/src/lib.rs", "pub fn value() -> u8 { 2 }\n")
        commands = self_check.commands(self.selection())
        result = subprocess.run(commands[2], cwd=self.root, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=True)
        self.assertIn("3 tests run: 3 passed", result.stdout)
        self.assertIn("contract-api", result.stdout)
        self.assertIn("contract-client", result.stdout)
        self.assertIn("contract-core", result.stdout)
        for command in commands[3:]:
            subprocess.run(command, cwd=self.root, check=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def test_multiple_crates_use_union_filter(self):
        self.write("crates/core/new.rs", "")
        self.write("crates/other/new.rs", "")
        selection = self.selection()
        self.assertEqual(selection["changed"], ["contract-core", "contract-other"])
        self.assertEqual(self_check.commands(selection)[2][-1], "rdeps(contract-core) | rdeps(contract-other)")

    def test_global_paths_select_complete_check(self):
        for path in ["Cargo.lock", "crates/core/vectors/sample.json", "tools/vectors/generate.py",
                     "docs/readme.md", "justfile", "Cargo.toml", "crates/core/Cargo.toml",
                     "rust-toolchain.toml", "deny.toml", "typos.toml", ".config/nextest.toml",
                     "scripts/check.py", ".gitea/workflows/qa.yml", "crates/core/clippy.toml",
                     "examples/client/src/lib.rs", "crates/unknown/src/lib.rs"]:
            with self.subTest(path=path):
                selection = self_check.select(self.root, [path], self.metadata)
                self.assertTrue(selection["full"])
                self.assertIn(path, selection["reason"])
                self.assertEqual(self_check.commands(selection), [["just", "qa"]])

    def test_empty_diff_selects_complete_check(self):
        selection = self.selection()
        self.assertTrue(selection["full"])
        self.assertIn("empty diff", selection["reason"])

    def test_mixed_global_and_crate_paths_print_package_set(self):
        selection = self_check.select(self.root, ["docs/readme.md", "crates/core/src/lib.rs"], self.metadata)
        self.assertTrue(selection["full"])
        self.assertEqual(selection["changed"], ["contract-core"])

    def test_committed_staged_unstaged_untracked_and_renamed_paths(self):
        self.git("switch", "--quiet", "-c", "feature")
        self.write("crates/core/src/committed.rs", "")
        self.commit()
        self.write("crates/api/src/staged.rs", "")
        self.git("add", "crates/api/src/staged.rs")
        self.write("crates/other/src/lib.rs", "pub fn value() -> u8 { 3 }\n")
        self.write("crates/core/src/space and\nnewline.rs", "")
        self.git("mv", "docs/readme.md", "crates/core/readme.md")
        paths = self_check.changed_paths(self.root, "main")
        for path in ["crates/core/src/committed.rs", "crates/api/src/staged.rs",
                     "crates/other/src/lib.rs", "crates/core/src/space and\nnewline.rs",
                     "docs/readme.md", "crates/core/readme.md"]:
            self.assertIn(path, paths)
        self.assertTrue(self.selection()["full"])

    def test_merge_base_includes_changes_on_feature_only(self):
        self.git("switch", "--quiet", "-c", "feature")
        self.write("crates/core/src/lib.rs", "pub fn value() -> u8 { 2 }\n")
        self.commit()
        self.git("switch", "--quiet", "main")
        self.write("docs/readme.md", "New documentation\n")
        self.commit()
        self.git("switch", "--quiet", "feature")
        self.assertEqual(self_check.changed_paths(self.root, "main"), ["crates/core/src/lib.rs"])

    def test_invalid_comparison_ref_fails(self):
        with self.assertRaises(subprocess.CalledProcessError):
            self_check.changed_paths(self.root, "missing-ref")

    def test_first_failure_preserves_exit_and_stops(self):
        marker = self.root / "should-not-exist"
        with self.assertRaises(subprocess.CalledProcessError) as failure:
            self_check.run_commands([
                [sys.executable, "-c", "raise SystemExit(23)"],
                [sys.executable, "-c", f"from pathlib import Path; Path({str(marker)!r}).touch()"],
            ], self.root)
        self.assertEqual(failure.exception.returncode, 23)
        self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
