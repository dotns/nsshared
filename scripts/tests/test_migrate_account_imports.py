"""Rewrite tests for scripts/migrate-account-imports.py on a synthetic map."""

import importlib.util
import pathlib
import subprocess
import sys
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "migrate-account-imports.py"
SPEC = importlib.util.spec_from_file_location("migrate_account_imports", SCRIPT)
migrate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(migrate)

OLD = "nsshared_proto::account"
NEW = "nsshared_control::account"
DOCUMENT = {
    "items": [
        {"old": OLD, "kind": "module", "status": "moved", "new": NEW},
        {"old": f"{OLD}::control_exchange", "kind": "module", "status": "renamed", "new": f"{NEW}::control"},
        {"old": f"{OLD}::source_binding", "kind": "module", "status": "split",
         "new": [f"{NEW}::domains", f"{NEW}::publication"]},
        {"old": f"{OLD}::Roster", "kind": "type", "status": "moved", "new": f"{NEW}::relay::Roster"},
        {"old": f"{OLD}::Lifecycle", "kind": "type", "status": "moved", "new": f"{NEW}::node::Lifecycle"},
        {"old": f"{OLD}::validate_snapshot", "kind": "fn", "status": "renamed",
         "new": f"{NEW}::relay::validate_admission_snapshot"},
        {"old": f"{OLD}::control_exchange::CONFIG_STREAM", "kind": "const", "status": "moved",
         "new": f"{NEW}::control::CONFIG_STREAM"},
        {"old": f"{OLD}::source_binding::SourceBinding", "kind": "type", "status": "moved",
         "new": f"{NEW}::publication::SourceBinding"},
        {"old": f"{OLD}::source_binding::SourceSnapshot", "kind": "type", "status": "moved",
         "new": f"{NEW}::publication::SourceSnapshot"},
        {"old": f"{OLD}::source_binding::SOURCE_DOMAIN", "kind": "const", "status": "moved",
         "new": f"{NEW}::domains::SOURCE_DOMAIN"},
        {"old": f"{OLD}::source_binding::SOURCE_FRAME", "kind": "const", "status": "changed",
         "new": f"{NEW}::publication::FrameKind::Source", "manual": True, "note": "frame kind"},
        {"old": f"{OLD}::USAGE_PART_DOMAIN", "kind": "const", "status": "changed",
         "new": f"{NEW}::domains::USAGE_PART_DIGEST_DOMAIN", "manual": True, "note": "text domain"},
        {"old": f"{OLD}::AccountError", "kind": "enum", "status": "changed", "new": f"{NEW}::AccountError"},
    ],
    "errors": [
        {"old": f"{OLD}::AccountError", "new": f"{NEW}::AccountError", "variants": [
            {"old": "AccountError::InvalidField", "new": "AccountError::Field", "status": "renamed"},
            {"old": "AccountError::Bounds", "new": "AccountError::Bounds", "status": "moved"},
        ]},
    ],
}


def run(text, document=DOCUMENT):
    mapping = migrate.Map(document)
    report = migrate.Report()
    updated, _ = migrate.rewrite(text, mapping, report, "lib.rs")
    return updated, report


class Rewrites(unittest.TestCase):
    def test_nested_groups_keep_other_paths(self):
        updated, report = run(
            "use nsshared_proto::{\n    IdentityKey,\n    account::{Roster, control_exchange::{CONFIG_STREAM}},\n};\n")
        self.assertIn("use nsshared_proto::IdentityKey;", updated)
        self.assertIn("use nsshared_control::account::{control::CONFIG_STREAM, relay::Roster};", updated)
        self.assertEqual(report.paths, 2)

    def test_renamed_item_is_aliased(self):
        updated, report = run("use nsshared_proto::account::validate_snapshot;\n")
        self.assertEqual(updated, "use nsshared_control::account::relay::validate_admission_snapshot as validate_snapshot;\n")
        self.assertEqual(len(report.aliased), 1)

    def test_manual_items_leave_the_statement_untouched(self):
        source = "pub use nsshared_proto::account::{Roster, USAGE_PART_DOMAIN};\n"
        updated, report = run(source)
        self.assertEqual(updated, source)
        self.assertEqual(report.unmapped[0][1], f"{OLD}::USAGE_PART_DOMAIN")

    def test_inline_and_module_relative_paths(self):
        updated, report = run(
            "use nsshared_proto::account;\nfn f(l: account::Lifecycle) -> nsshared_proto::account::Roster { todo!() }\n")
        self.assertIn("use nsshared_control::account;", updated)
        self.assertIn("l: account::node::Lifecycle", updated)
        self.assertIn("-> nsshared_control::account::relay::Roster", updated)
        self.assertEqual(report.unmapped, [])

    def test_renamed_module_import(self):
        updated, _ = run("use nsshared_proto::account::control_exchange;\nconst S: &str = control_exchange::CONFIG_STREAM;\n")
        self.assertIn("use nsshared_control::account::control as control_exchange;", updated)

    def test_globs_become_explicit_imports_of_used_items(self):
        updated, report = run("use nsshared_proto::account::{*, source_binding::*};\n"
                              "fn f(r: Roster, b: SourceBinding) -> &'static str { SOURCE_DOMAIN }\n")
        self.assertIn("use nsshared_control::account::{domains::SOURCE_DOMAIN, publication::SourceBinding, "
                      "relay::Roster};", updated)
        self.assertNotIn("*", updated)
        self.assertNotIn("Lifecycle", updated)
        self.assertEqual(report.unmapped, [])
        updated, _ = run("use nsshared_proto::account::*;\nuse other::Roster;\n"
                         "fn f(e: E, r: Roster) -> bool { matches!(e, E::Lifecycle) || r.source_binding || Roster::ok() }\n")
        self.assertNotIn("nsshared_control", updated)
        source = "use nsshared_proto::account::*;\nconst D: &str = USAGE_PART_DOMAIN;\n"
        updated, report = run(source)
        self.assertEqual(updated, source)
        self.assertEqual(report.unmapped[0][1], f"{OLD}::USAGE_PART_DOMAIN")

    def test_split_module_import_uses_its_primary_area(self):
        updated, report = run("use nsshared_proto::account::source_binding;\n"
                              "fn f(b: source_binding::SourceBinding) -> &'static str { source_binding::SOURCE_DOMAIN }\n")
        self.assertIn("use nsshared_control::account::publication as source_binding;", updated)
        self.assertIn("b: source_binding::SourceBinding", updated)
        self.assertIn("nsshared_control::account::domains::SOURCE_DOMAIN", updated)
        self.assertIn("split", report.notes[0][2])

    def test_split_module_without_a_primary_area_is_reported(self):
        document = dict(DOCUMENT, items=[i for i in DOCUMENT["items"] if not i["old"].endswith("SourceSnapshot")])
        source = "use nsshared_proto::account::source_binding;\n"
        updated, report = run(source, document)
        self.assertEqual(updated, source)
        self.assertIn("split", report.unmapped[0][2])

    def test_changed_error_variants_are_listed(self):
        _, report = run("use nsshared_proto::account::AccountError;\nfn f(e: AccountError) -> bool { matches!(e, AccountError::InvalidField) }\n")
        self.assertEqual(report.variants[0][1:], ("AccountError::InvalidField", "AccountError::Field"))


class Attributes(unittest.TestCase):
    def test_attributes_are_kept_on_every_emitted_statement(self):
        updated, _ = run("#[cfg(test)]\nuse nsshared_proto::{IdentityKey, account::Roster};\n")
        self.assertEqual(updated, "#[cfg(test)]\nuse nsshared_proto::IdentityKey;\n"
                                  "#[cfg(test)]\nuse nsshared_control::account::relay::Roster;\n")

    def test_indented_stacked_and_same_line_attributes(self):
        updated, _ = run("mod t {\n    #[cfg(test)]\n    #[allow(unused_imports)]\n"
                         "    pub(crate) use nsshared_proto::{IdentityKey, account::Roster};\n}\n")
        self.assertEqual(updated.count("    #[cfg(test)]\n    #[allow(unused_imports)]\n    pub(crate) use "), 2)
        updated, _ = run("#[cfg(feature = \"x\")] use nsshared_proto::{IdentityKey, account::Roster};\n")
        self.assertEqual(updated, "#[cfg(feature = \"x\")] use nsshared_proto::IdentityKey;\n"
                                  "#[cfg(feature = \"x\")] use nsshared_control::account::relay::Roster;\n")

    def test_doc_comments_are_repeated(self):
        updated, _ = run("/// Shared types.\npub use nsshared_proto::{IdentityKey, account::Roster};\n")
        self.assertEqual(updated.count("/// Shared types.\npub use "), 2)

    def test_prose_in_doc_comments_is_not_a_statement(self):
        source = "/// Holds the lock through use of the result {\nfn f() {}\n/// use nsshared_proto::account::Roster;\nfn g() {}\n"
        updated, report = run(source)
        self.assertEqual(updated, source.replace("nsshared_proto::account::Roster", "nsshared_control::account::relay::Roster"))
        self.assertEqual(report.unmapped, [])

    def test_untouched_statement_keeps_its_attribute_and_paths(self):
        source = "#[cfg(test)] use nsshared_proto::account::{Roster, USAGE_PART_DOMAIN};\n"
        updated, report = run(source)
        self.assertEqual(updated, source)
        self.assertEqual(len(report.unmapped), 1)

    def test_removed_statement_takes_its_attribute(self):
        updated, _ = run("#[cfg(test)]\nuse nsshared_proto::account::*;\nfn f() {}\n")
        self.assertNotIn("cfg(test)", updated)


class GlobModules(unittest.TestCase):
    def test_proto_glob_brings_account_into_scope(self):
        updated, report = run("use nsshared_proto::*;\nfn f(r: account::Roster) {}\n")
        self.assertIn("use nsshared_proto::*;", updated)
        self.assertIn("use nsshared_control::account;", updated)
        self.assertIn("r: account::relay::Roster", updated)
        self.assertEqual(report.unmapped, [])
        updated, _ = run("use nsshared_proto::*;\nmod account;\nfn f(r: account::Roster) {}\n")
        self.assertNotIn("nsshared_control", updated)

    def test_relative_use_through_a_glob_imported_module(self):
        updated, report = run("use nsshared_proto::account::*;\nuse control_exchange::CONFIG_STREAM;\n"
                              "use source_binding::{SOURCE_DOMAIN, SourceBinding};\nfn f(b: SourceBinding) {}\n")
        self.assertIn("use nsshared_control::account::control::CONFIG_STREAM;", updated)
        self.assertIn("use nsshared_control::account::{domains::SOURCE_DOMAIN, publication::SourceBinding};", updated)
        self.assertNotIn("as control_exchange", updated)
        self.assertNotIn("nsshared_proto", updated)
        updated, report = run("use nsshared_proto::account::*;\nuse source_binding::SOURCE_FRAME;\n")
        self.assertIn("use source_binding::SOURCE_FRAME;", updated)
        self.assertEqual(report.unmapped[0][1], f"{OLD}::source_binding::SOURCE_FRAME")

    def test_glob_of_an_unknown_module_is_listed(self):
        source = "use nsshared_proto::account::retired::*;\n"
        updated, report = run(source)
        self.assertEqual(updated, source)
        self.assertEqual(report.unmapped[0][1], f"{OLD}::retired::*")


class Macros(unittest.TestCase):
    def test_paths_inside_macro_token_trees_are_rewritten(self):
        updated, report = run("fn f() -> Value { json!({\"op\":nsshared_proto::account::control_exchange::CONFIG_STREAM,"
                              " \"r\": ::nsshared_proto::account::Roster::NAME,"
                              " \"s\": format!(\"{}\", nsshared_proto :: account :: Lifecycle::Active)}) }\n")
        self.assertIn("\"op\":nsshared_control::account::control::CONFIG_STREAM,", updated)
        self.assertIn("::nsshared_control::account::relay::Roster::NAME", updated)
        self.assertIn("nsshared_control::account::node::Lifecycle::Active", updated)
        self.assertEqual(report.unmapped, [])
        self.assertEqual(report.paths, 3)

    def test_module_relative_paths_inside_macros(self):
        updated, _ = run("use nsshared_proto::account;\nconst V: Value = json!({\"r\":account::Roster::NAME});\n")
        self.assertIn("\"r\":account::relay::Roster::NAME", updated)

    def test_ambiguous_or_unmappable_macro_paths_are_listed(self):
        source = ("m!(other::nsshared_proto::account::Roster);\n"
                  "m!(nsshared_proto::account::{Roster, Lifecycle});\n"
                  "json!({\"d\":nsshared_proto::account::USAGE_PART_DOMAIN});\n")
        updated, report = run(source)
        self.assertEqual(updated, source)
        self.assertEqual([row[0] for row in report.unmapped], ["lib.rs:1", "lib.rs:2", "lib.rs:3"])


def tree(files):
    directory = tempfile.TemporaryDirectory()
    root = pathlib.Path(directory.name)
    for name, text in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text)
    mapping = root / "map.json"
    mapping.write_text(__import__("json").dumps(DOCUMENT))
    output = subprocess.run([sys.executable, "-B", str(SCRIPT), str(root), "--map", str(mapping), "--apply"],
                            capture_output=True, text=True, check=True).stdout
    return directory, root, output


class CommandLine(unittest.TestCase):
    def test_child_modules_follow_the_parent_glob(self):
        directory, root, output = tree({
            "src/parent.rs": "use nsshared_proto::account::*;\nmod child;\n",
            "src/parent/child.rs": "use super::*;\nuse control_exchange::CONFIG_STREAM;\n"
                                   "fn f(b: source_binding::SourceBinding) -> &'static str { source_binding::SOURCE_DOMAIN }\n"
                                   "const K: u8 = source_binding::SOURCE_FRAME;\n",
        })
        with directory:
            self.assertEqual((root / "src" / "parent.rs").read_text(),
                             "use nsshared_control::account::publication as source_binding;\nmod child;\n")
            child = (root / "src" / "parent" / "child.rs").read_text()
            self.assertIn("use nsshared_control::account::control::CONFIG_STREAM;", child)
            self.assertIn("b: source_binding::SourceBinding", child)
            self.assertIn("{ nsshared_control::account::domains::SOURCE_DOMAIN }", child)
            self.assertIn("const K: u8 = source_binding::SOURCE_FRAME;", child)
            self.assertIn("src/parent/child.rs:4 | source_binding::SOURCE_FRAME", output)

    def test_globs_keep_items_used_by_child_modules(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "src" / "parent").mkdir(parents=True)
            (root / "src" / "parent.rs").write_text("use nsshared_proto::account::*;\nmod child;\n")
            (root / "src" / "parent" / "child.rs").write_text("use super::*;\nfn f(r: Roster) {}\n")
            mapping = root / "map.json"
            mapping.write_text(__import__("json").dumps(DOCUMENT))
            subprocess.run([sys.executable, "-B", str(SCRIPT), str(root), "--map", str(mapping), "--apply"],
                           capture_output=True, text=True, check=True)
            self.assertEqual((root / "src" / "parent.rs").read_text(),
                             "use nsshared_control::account::relay::Roster;\nmod child;\n")

    def test_dry_run_changes_nothing_and_manifests_are_untouched(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "Cargo.toml").write_text('[workspace.dependencies]\nnsshared-proto = { git = "x", rev = "r" }\n')
            (root / "src").mkdir()
            source = root / "src" / "lib.rs"
            source.write_text("use nsshared_proto::account::Roster;\n")
            mapping = root / "map.json"
            mapping.write_text(__import__("json").dumps(DOCUMENT))
            output = subprocess.run([sys.executable, "-B", str(SCRIPT), str(root), "--map", str(mapping)],
                                    capture_output=True, text=True, check=True).stdout
            self.assertIn("+use nsshared_control::account::relay::Roster;", output)
            self.assertIn("nsshared-control = { git = \"x\", rev = \"r\", features = [\"unstable-account\"] }", output)
            self.assertEqual(source.read_text(), "use nsshared_proto::account::Roster;\n")
            subprocess.run([sys.executable, "-B", str(SCRIPT), str(root), "--map", str(mapping), "--apply"],
                           capture_output=True, text=True, check=True)
            self.assertEqual(source.read_text(), "use nsshared_control::account::relay::Roster;\n")
            self.assertIn('nsshared-proto = { git = "x", rev = "r" }', (root / "Cargo.toml").read_text())


if __name__ == "__main__":
    unittest.main()
