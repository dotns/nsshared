"""Exercise selection with real Git history and Cargo workspace metadata."""

import importlib.util
import json
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
        self.write("crates/api/src/doc.rs", 'const DOC: &str = include_str!("../../../docs/readme.md");\n')
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

    def test_added_leaf_dependency_scopes_consumers(self):
        manifest = self.root / "crates/core/Cargo.toml"
        manifest.write_text(manifest.read_text() +
                            '\n[dependencies]\ncontract-other = { path = "../other" }\n')
        subprocess.run(["cargo", "generate-lockfile", "--offline"], cwd=self.root, check=True)
        selection = self_check.select_changes(self.root, "main")
        self.assertFalse(selection["full"])
        self.assertEqual(selection["changed"], ["contract-api", "contract-client", "contract-core"])
        self.assertEqual(selection["affected"], ["contract-api", "contract-client", "contract-core"])
        for name in selection["changed"]:
            self.assertIn(name + ":", selection["reason"])
        self.assertIn("added contract-other", selection["reason"])

    def test_shared_dependency_version_scopes_all_users(self):
        manifest = self.root / "crates/core/Cargo.toml"
        manifest.write_text(manifest.read_text().replace('version = "0.1.0"', 'version = "0.2.0"'))
        subprocess.run(["cargo", "generate-lockfile", "--offline"], cwd=self.root, check=True)
        selection = self_check.select_changes(self.root, "main")
        self.assertFalse(selection["full"])
        self.assertEqual(selection["affected"], ["contract-api", "contract-client", "contract-core"])
        self.assertIn("removed contract-core 0.1.0", selection["reason"])
        self.assertIn("added contract-core 0.2.0", selection["reason"])

    def test_root_dependency_and_patch_edits_are_global(self):
        for section in ('[workspace.dependencies]\nunused = "1"\n',
                        '[patch.crates-io]\ncontract-core = { path = "crates/core" }\n'):
            with self.subTest(section=section):
                self.write("Cargo.toml", '[workspace]\nmembers = ["crates/*", "examples/*"]\n'
                           'resolver = "3"\n' + section)
                selection = self_check.select_changes(self.root, "main")
                self.assertTrue(selection["full"])
                self.assertIn("Cargo.toml", selection["reason"])

    def test_failed_current_metadata_selects_full(self):
        self.write("crates/core/Cargo.toml", "invalid manifest")
        selection = self_check.select_changes(self.root, "main")
        self.assertTrue(selection["full"])
        self.assertIn("metadata comparison failed", selection["reason"])
        self.assertEqual(self_check.commands(selection), [["just", "qa"]])

    def test_failed_base_metadata_selects_full(self):
        self.write("Cargo.lock", "invalid lockfile")
        self.commit()
        subprocess.run(["cargo", "generate-lockfile", "--offline"], cwd=self.root, check=True)
        selection = self_check.select_changes(self.root, "main")
        self.assertTrue(selection["full"])
        self.assertIn("metadata comparison failed", selection["reason"])

    def test_dependency_policies_are_global(self):
        for path in ("deps/allow.toml", "deps/layers.toml", "deps/custom-policy.txt"):
            selection = self_check.select(self.root, [path], self.metadata)
            self.assertTrue(selection["full"])
            self.assertIn("dependency policy", selection["reason"])

    def test_lockfile_only_checksum_change_selects_users(self):
        # Real directory-source metadata supplies two independently valid snapshots.
        checksum = "1" * 64
        self.write("vendor/resolved-fixture/Cargo.toml",
                   '[package]\nname = "resolved-fixture"\nversion = "0.1.0"\nedition = "2024"\n')
        self.write("vendor/resolved-fixture/src/lib.rs", "pub fn fixture() {}\n")
        self.write("vendor/resolved-fixture/.cargo-checksum.json",
                   json.dumps({"files": {}, "package": checksum}))
        self.write(".cargo/config.toml",
                   '[source.crates-io]\nreplace-with = "vendored"\n'
                   '[source.vendored]\ndirectory = "vendor"\n')
        manifest = self.root / "crates/core/Cargo.toml"
        manifest.write_text(manifest.read_text() +
                            '\n[dependencies]\nresolved-fixture = "=0.1.0"\n')
        subprocess.run(["cargo", "generate-lockfile", "--offline"], cwd=self.root, check=True)
        self.commit()
        before = self_check.dependency_snapshot(self.root)
        lock = self.root / "Cargo.lock"
        lock.write_text(lock.read_text().replace(checksum, "2" * 64))
        self.write("vendor/resolved-fixture/.cargo-checksum.json",
                   json.dumps({"files": {}, "package": "2" * 64}))
        after = self_check.dependency_snapshot(self.root)
        paths = ["Cargo.lock"]
        selection = self_check.select(self.root, paths, after,
                                      self_check.dependency_changes(before, after, paths))
        self.assertFalse(selection["full"], selection["reason"])
        self.assertEqual(selection["changed"], ["contract-api", "contract-client", "contract-core"])
        self.assertEqual(selection["affected"], selection["changed"])
        self.assertIn("checksum=" + checksum, selection["reason"])
        self.assertIn("checksum=" + "2" * 64, selection["reason"])

    def test_manifest_only_change_selects_its_owner(self):
        manifest = self.root / "crates/other/Cargo.toml"
        manifest.write_text(manifest.read_text() + '\ndescription = "Independent contract"\n')
        before = self.git("status", "--porcelain")
        selection = self_check.select_changes(self.root, "main")
        self.assertFalse(selection["full"])
        self.assertEqual(selection["changed"], ["contract-other"])
        self.assertEqual(selection["affected"], ["contract-other"])
        self.assertIn("own manifest changed", selection["reason"])
        self.assertEqual(self.git("status", "--porcelain"), before)
        self.assertEqual(self.git("worktree", "list", "--porcelain").count("worktree "), 1)

    def test_lockfile_format_only_change_selects_static_checks(self):
        lock = self.root / "Cargo.lock"
        lock.write_text(lock.read_text() + "\n")
        selection = self_check.select_changes(self.root, "main")
        self.assertFalse(selection["full"])
        self.assertEqual(selection["changed"], [])
        self.assertEqual(self_check.commands(selection), [["just", *self_check.STATIC_CHECKS]])

    def test_enabled_feature_change_selects_consumers(self):
        manifest = self.root / "crates/core/Cargo.toml"
        manifest.write_text(manifest.read_text() + "\n[features]\nextra = []\n")
        selection = self_check.select_changes(self.root, "main")
        self.assertFalse(selection["full"])
        self.assertEqual(selection["affected"], ["contract-api", "contract-client", "contract-core"])
        self.assertIn("features=extra", selection["reason"])

    def test_dependency_comparison_uses_merge_base(self):
        self.git("switch", "--quiet", "-c", "feature")
        manifest = self.root / "crates/other/Cargo.toml"
        manifest.write_text(manifest.read_text() + '\ndescription = "Independent contract"\n')
        self.commit()
        self.git("switch", "--quiet", "main")
        core = self.root / "crates/core/Cargo.toml"
        core.write_text(core.read_text().replace('version = "0.1.0"', 'version = "0.2.0"'))
        subprocess.run(["cargo", "generate-lockfile", "--offline"], cwd=self.root, check=True)
        self.commit()
        self.git("switch", "--quiet", "feature")
        selection = self_check.select_changes(self.root, "main")
        self.assertFalse(selection["full"])
        self.assertEqual(selection["changed"], ["contract-other"])
        self.assertEqual(selection["affected"], ["contract-other"])

    def test_removed_dependency_selects_former_consumers(self):
        manifest = self.root / "crates/api/Cargo.toml"
        manifest.write_text(manifest.read_text().split("[dependencies]")[0])
        subprocess.run(["cargo", "generate-lockfile", "--offline"], cwd=self.root, check=True)
        selection = self_check.select_changes(self.root, "main")
        self.assertFalse(selection["full"])
        self.assertEqual(selection["changed"], ["contract-api", "contract-client"])
        self.assertEqual(selection["affected"], ["contract-api", "contract-client"])
        self.assertIn("removed contract-core", selection["reason"])

    def test_incomparable_membership_selects_full(self):
        self.crate("crates/new", "contract-new")
        subprocess.run(["cargo", "generate-lockfile", "--offline"], cwd=self.root, check=True)
        selection = self_check.select_changes(self.root, "main")
        self.assertTrue(selection["full"])
        self.assertIn("workspace membership changed", selection["reason"])

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

    def test_gated_feature_sets_are_tested_when_their_package_is_affected(self):
        selection = {"full": False, "reason": "", "changed": ["nsshared-control"],
                     "affected": ["nsshared-control", "nsshared-proto"]}
        commands = self_check.commands(selection)
        flags = ["--features", "nsshared-control/unstable-account"]
        gated = [command for command in commands if "nsshared-control/unstable-account" in command]
        self.assertEqual(len(gated), 3)
        self.assertEqual(gated[0], ["cargo", "nextest", "run", "--workspace", "--locked", *flags,
                                    "-E", "rdeps(nsshared-control)"])
        selection = dict(selection, changed=["nsshared-relay"], affected=["nsshared-proto", "nsshared-relay"])
        self.assertFalse(any("nsshared-control/unstable-account" in c for c in self_check.commands(selection)))

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

    def test_record_only_diff_runs_static_checks_without_tests(self):
        path = "docs/task/new-record.md"
        self.write(path, "Completed documentation\n")
        selection = self.selection()
        self.assertFalse(selection["full"])
        self.assertEqual(selection["changed"], [])
        self.assertEqual(selection["affected"], [])
        self.assertEqual(self_check.commands(selection), [["just", *self_check.STATIC_CHECKS]])
        self.assertIn(f"non-input: {path}", selection["reason"])

    def test_included_fixture_is_input(self):
        self.write("crates/core/src/lib.rs", 'const DATA: &str = include_str!("../fixtures/data.txt");\n')
        self.write("crates/core/fixtures/data.txt", "old\n")
        self.commit()
        self.write("crates/core/fixtures/data.txt", "new\n")
        selection = self.selection()
        self.assertTrue(selection["full"])
        self.assertEqual(selection["changed"], ["contract-core"])
        self.assertIn("input: crates/core/fixtures/data.txt", selection["reason"])
        self.assertIn("crates/core/src/lib.rs", selection["reason"])

    def test_directory_walk_is_input(self):
        self.write("crates/core/tests/walk.rs", 'fn files() { for entry in std::fs::read_dir("fixtures").unwrap() {} }\n')
        self.write("fixtures/nested/data.txt", "old\n")
        self.commit()
        self.write("fixtures/nested/data.txt", "new\n")
        selection = self.selection()
        self.assertTrue(selection["full"])
        self.assertIn("crates/core/tests/walk.rs", selection["reason"])
        self.assertIn("directory", selection["reason"])

    def test_included_and_unincluded_crate_documents(self):
        self.write("crates/core/src/lib.rs", '#![doc = include_str!("../README.md")]\n')
        self.write("crates/core/README.md", "Included\n")
        self.write("crates/core/PROVENANCE.md", "Unincluded\n")
        self.commit()
        for path, full in [("crates/core/README.md", True), ("crates/core/PROVENANCE.md", False)]:
            with self.subTest(path=path):
                selection = self_check.select(self.root, [path], self.metadata)
                self.assertEqual(selection["full"], full)
                self.assertIn(("input: " if full else "non-input: ") + path, selection["reason"])
                if full:
                    self.assertIn("crates/core/src/lib.rs", selection["reason"])
                else:
                    self.assertEqual(selection["affected"], [])

    def test_manifest_joined_include_is_input(self):
        self.write("crates/core/src/lib.rs", 'const DATA: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/data.bin"));\n')
        self.write("crates/core/fixtures/data.bin", "old\n")
        self.commit()
        selection = self_check.select(self.root, ["crates/core/fixtures/data.bin"], self.metadata)
        self.assertTrue(selection["full"])
        self.assertIn("crates/core/src/lib.rs", selection["reason"])

    def test_computed_and_glob_reads_are_uncertain_inputs(self):
        for source in ['std::fs::read_to_string(compute_path())', 'glob::glob("fixtures/**/*.txt")', 'glob::glob("fixtures/[d]ata.txt")']:
            with self.subTest(source=source):
                self.write("crates/core/src/lib.rs", f"fn read() {{ {source}; }}\n")
                self.commit()
                selection = self_check.select(self.root, ["fixtures/item.txt"], self.metadata)
                self.assertTrue(selection["full"])
                self.assertIn("crates/core/src/lib.rs", selection["reason"])
                self.assertIn("uncertain computed path or glob", selection["reason"])

    def test_literal_concat_include_is_input(self):
        self.write("crates/core/src/lib.rs", 'const DATA: &str = include_str!(concat!("../fixtures/", "item.txt"));\n')
        self.write("crates/core/fixtures/item.txt", "data\n")
        self.commit()
        selection = self_check.select(self.root, ["crates/core/fixtures/item.txt"], self.metadata)
        self.assertTrue(selection["full"])
        self.assertIn("crates/core/src/lib.rs", selection["reason"])

    def test_checked_head_reader_is_retained_after_local_removal(self):
        self.write("crates/core/src/lib.rs", 'const DATA: &str = include_str!("../fixtures/item.txt");\n')
        self.write("crates/core/fixtures/item.txt", "data\n")
        self.commit()
        self.write("crates/core/src/lib.rs", "")
        selection = self_check.select(self.root, ["crates/core/fixtures/item.txt"], self.metadata)
        self.assertTrue(selection["full"])
        self.assertIn("crates/core/src/lib.rs", selection["reason"])

    def test_untracked_reader_does_not_become_tracked_input(self):
        self.write("scripts/unused.py", 'open("docs/task/new-record.md")\n')
        self.write("docs/task/new-record.md", "Record\n")
        selection = self_check.select(self.root, ["docs/task/new-record.md"], self.metadata)
        self.assertFalse(selection["full"])

    def test_every_non_rust_path_has_diagnostic_even_in_full_mode(self):
        selection = self_check.select(self.root, ["Cargo.lock", "docs/plan/new.md"], self.metadata)
        self.assertTrue(selection["full"])
        self.assertIn("input: Cargo.lock", selection["reason"])
        self.assertIn("non-input: docs/plan/new.md", selection["reason"])

    def test_rust_lifetimes_do_not_hide_included_paths(self):
        self.write("crates/core/src/lib.rs", "const DATA: &'static str = include_str!(\"../fixtures/data.txt\");\nconst NEXT: &'static str = \"next\";\n")
        self.write("crates/core/fixtures/data.txt", "data\n")
        self.commit()
        selection = self_check.select(self.root, ["crates/core/fixtures/data.txt"], self.metadata)
        self.assertTrue(selection["full"])
        self.assertIn("crates/core/src/lib.rs", selection["reason"])

    def test_parent_directory_walk_is_input(self):
        self.write("crates/core/tests/walk.rs", 'fn files() { std::fs::read_dir("..").unwrap(); }\n')
        self.commit()
        selection = self_check.select(self.root, ["docs/task/new-record.md"], self.metadata)
        self.assertTrue(selection["full"])
        self.assertIn("directory read by crates/core/tests/walk.rs", selection["reason"])

    def test_lock_read_is_not_a_file_input(self):
        self.write("crates/core/src/lib.rs", 'fn value() { let lock = std::sync::RwLock::new(1); let guard = lock.read().unwrap(); }\n')
        self.commit()
        selection = self_check.select(self.root, ["docs/task/new-record.md"], self.metadata)
        self.assertFalse(selection["full"])
        self.assertIn("non-input: docs/task/new-record.md", selection["reason"])

    def test_unresolved_shell_file_read_selects_complete_check(self):
        self.write("scripts/check.sh", 'cat "$INPUT_FILE"\n')
        self.write("fixtures/data.txt", "old\n")
        self.commit()
        self.write("fixtures/data.txt", "new\n")
        self.assertEqual(self_check.changed_paths(self.root, "main"), ["fixtures/data.txt"])
        selection = self.selection()
        self.assertTrue(selection["full"])
        self.assertIn("input: fixtures/data.txt", selection["reason"])
        self.assertIn("scripts/check.sh", selection["reason"])
        self.assertIn("uncertain", selection["reason"])
        self.assertEqual(self_check.commands(selection), [["just", "qa"]])

    def test_unresolved_rust_include_selects_complete_check(self):
        self.write("crates/core/src/lib.rs", 'include!(concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/", env!("INPUT_NAME")));\n')
        self.write("fixtures/data.txt", "old\n")
        self.commit()
        self.write("fixtures/data.txt", "new\n")
        self.assertEqual(self_check.changed_paths(self.root, "main"), ["fixtures/data.txt"])
        selection = self.selection()
        self.assertTrue(selection["full"])
        self.assertIn("input: fixtures/data.txt", selection["reason"])
        self.assertIn("crates/core/src/lib.rs", selection["reason"])
        self.assertIn("uncertain", selection["reason"])
        self.assertEqual(self_check.commands(selection), [["just", "qa"]])

    def test_shell_reader_forms_are_conservative(self):
        commands = ['head "$INPUT_FILE"', 'tail "$INPUT_FILE"', 'sed -n 1p "$INPUT_FILE"',
                    'awk 1 "$INPUT_FILE"', 'grep pattern "$INPUT_FILE"', 'sort "$INPUT_FILE"',
                    'wc "$INPUT_FILE"', 'source "$INPUT_FILE"', '. "$INPUT_FILE"',
                    'while read line; do :; done < "$INPUT_FILE"', 'find "$INPUT_DIRECTORY" -type f',
                    'cat fixtures/*.txt', 'cat fixtures/[d]ata.txt', 'cat "$(fixture_path)"']
        for command in commands:
            with self.subTest(command=command):
                self.write("scripts/check.sh", command + "\n")
                self.commit()
                selection = self_check.select(self.root, ["fixtures/data.txt"], self.metadata)
                self.assertTrue(selection["full"])
                self.assertIn("scripts/check.sh", selection["reason"])

    def test_known_shell_paths_and_directories(self):
        for command, full in [('cat fixtures/other.txt', False), ('cat fixtures/data.txt', True),
                              ('find fixtures -type f', True)]:
            with self.subTest(command=command):
                self.write("scripts/check.sh", command + "\n")
                self.commit()
                selection = self_check.select(self.root, ["fixtures/data.txt"], self.metadata)
                self.assertEqual(selection["full"], full)
                if full:
                    self.assertIn("scripts/check.sh", selection["reason"])

    def test_rust_inclusion_macro_delimiters(self):
        for macro in ("include", "include_str", "include_bytes", "include ", "include_str ", "include_bytes "):
            for opening, closing in (("(", ")"), ("{", "}"), ("[", "]")):
                with self.subTest(macro=macro, opening=opening):
                    self.write("crates/core/src/lib.rs", f'{macro}!{opening}env!("INPUT_FILE"){closing};\n')
                    self.commit()
                    selection = self_check.select(self.root, ["fixtures/data.txt"], self.metadata)
                    self.assertTrue(selection["full"])
                    self.assertIn("crates/core/src/lib.rs", selection["reason"])

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
