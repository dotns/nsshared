#!/usr/bin/env python3
"""List or compare the public API of a workspace crate, following re-exports into
other workspace crates.

    api_surface.py list PACKAGE [--root DIR]
    api_surface.py check PACKAGE --baseline REV [--exclude PATH ...]

`list` prints one line per public item, field, variant, method and trait impl at
every public path of PACKAGE. `check` builds the same listing for PACKAGE at git
revision REV and fails when any baseline line is missing from the working tree,
that is when an item, a path or a signature was removed or changed. Types are
compared by name, so an item moved to another workspace crate and re-exported at
its old path is unchanged. Additions are allowed.

Rustdoc JSON is unstable; the tool sets RUSTC_BOOTSTRAP for the documented
crates only, as cargo-semver-checks does.
"""

import argparse
import json
import os
import pathlib
import re
import subprocess
import sys
import tarfile
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]


def workspace_packages(root):
    metadata = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--format-version", "1", "--no-deps", "--locked"], cwd=root))
    return {p["name"] for p in metadata["packages"]}


def build_docs(root, package, target, features=()):
    """Builds rustdoc JSON for PACKAGE and its workspace dependencies (default features plus FEATURES)."""
    env = dict(os.environ, RUSTC_BOOTSTRAP="1", CARGO_TARGET_DIR=str(target),
               RUSTDOCFLAGS="-Z unstable-options --output-format json")
    env.pop("RUSTC_WRAPPER", None)
    metadata = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--format-version", "1", "--locked"], cwd=root))
    members = {p["id"]: p for p in metadata["packages"] if p["id"] in metadata["workspace_members"]}
    nodes = {n["id"]: n for n in metadata["resolve"]["nodes"]}
    start = next(i for i, p in members.items() if p["name"] == package)
    wanted, queue = set(), [start]
    while queue:
        current = queue.pop()
        if current in wanted:
            continue
        wanted.add(current)
        queue.extend(d["pkg"] for d in nodes[current]["deps"]
                     if d["pkg"] in members and any(k["kind"] is None for k in d["dep_kinds"]))
    docs = {}
    for package_id in sorted(wanted):
        name = members[package_id]["name"]
        own = [f"--features={feature}" for feature in features if feature.startswith(name + "/")]
        subprocess.run(["cargo", "doc", "--no-deps", "--locked", "-q", "-p", name, *own],
                       cwd=root, env=env, check=True)
        crate = name.replace("-", "_")
        docs[crate] = json.loads((target / "doc" / f"{crate}.json").read_text())
    return docs


class Surface:
    def __init__(self, docs):
        self.docs = docs
        self.lines = set()
        self.aliases = {}
        self.by_path = {}
        for crate, doc in docs.items():
            self.by_path[crate] = {
                tuple(entry["path"]): item_id
                for item_id, entry in doc["paths"].items() if entry["crate_id"] == 0
            }

    def resolve(self, crate, item_id):
        """Returns (crate, item) for an id of CRATE's JSON, following external ids
        into other documented workspace crates; None for other crates."""
        doc = self.docs[crate]
        key = str(item_id)
        if key in doc["index"] and doc["index"][key]["crate_id"] == 0:
            return crate, doc["index"][key]
        entry = doc["paths"].get(key)
        if entry is None:
            return None
        owner = doc["external_crates"].get(str(entry["crate_id"]), {}).get("name")
        if owner not in self.docs:
            return None
        target = self.by_path[owner].get(tuple(entry["path"]))
        if target is None or str(target) not in self.docs[owner]["index"]:
            return None
        return owner, self.docs[owner]["index"][str(target)]

    def emit(self, line):
        self.lines.add(line)

    def module(self, crate, item, path, seen):
        if (crate, item["id"]) in seen:
            return
        seen = seen | {(crate, item["id"])}
        for child in item["inner"]["module"]["items"]:
            resolved = self.resolve(crate, child)
            if resolved is None:
                continue
            owner, child_item = resolved
            if child_item["visibility"] != "public" and "use" not in child_item["inner"]:
                continue
            self.item(owner, child_item, path, seen)

    def item(self, crate, item, path, seen, name=None):
        kind, inner = next(iter(item["inner"].items()))
        if kind == "use":
            if item["visibility"] != "public":
                return
            target = self.resolve(crate, inner["id"]) if inner["id"] is not None else None
            if target is None:
                self.emit(f"{'::'.join(path)}::{inner['name']} = use {inner['source']}")
                return
            owner, target_item = target
            if not inner["is_glob"] and target_item["name"] != inner["name"]:
                self.aliases[target_item["name"]] = inner["name"]
            if inner["is_glob"]:
                if "module" in target_item["inner"]:
                    self.module(owner, target_item, path, seen)
                elif "enum" in target_item["inner"]:
                    for variant in target_item["inner"]["enum"]["variants"]:
                        self.item(owner, self.docs[owner]["index"][str(variant)], path, seen)
                return
            self.item(owner, target_item, path, seen, inner["name"])
            return
        name = name or item["name"]
        here = path + [name]
        full = "::".join(here)
        attrs = attributes(item)
        if kind == "module":
            self.emit(f"mod {full}")
            self.module(crate, item, here, seen)
        elif kind == "struct":
            self.emit(f"struct {full}{generics(inner['generics'])}{attrs}")
            shape = inner["kind"]
            if shape == "unit":
                self.emit(f"struct {full} unit")
            elif "tuple" in shape:
                for index, field in enumerate(shape["tuple"]):
                    if field is not None:
                        self.emit(f"field {full}.{index}: {ty(self.field_type(crate, field))}")
                self.emit(f"struct {full} tuple {len(shape['tuple'])}")
            else:
                self.fields(crate, full, shape["plain"])
            self.impls(crate, full, item["id"], inner["impls"])
        elif kind == "enum":
            self.emit(f"enum {full}{generics(inner['generics'])}{attrs}")
            for variant_id in inner["variants"]:
                variant = self.docs[crate]["index"][str(variant_id)]
                self.variant(crate, f"{full}::{variant['name']}", variant)
            self.impls(crate, full, item["id"], inner["impls"])
        elif kind == "variant":
            self.variant(crate, full, item)
        elif kind == "union":
            self.emit(f"union {full}{attrs}")
        elif kind == "function":
            self.emit(f"fn {full}{function(inner)}")
        elif kind == "constant":
            constant = inner["const"]
            self.emit(f"const {full}: {ty(inner['type'])} = {constant.get('value') or constant['expr']}")
        elif kind == "static":
            self.emit(f"static {full}: {ty(inner['type'])}")
        elif kind == "type_alias":
            self.emit(f"type {full}{generics(inner['generics'])} = {ty(inner['type'])}")
        elif kind == "trait":
            self.emit(f"trait {full}{generics(inner['generics'])}")
            for member in inner["items"]:
                self.assoc(crate, full, self.docs[crate]["index"][str(member)])
        elif kind in ("macro", "proc_macro"):
            self.emit(f"macro {full}")

    def field_type(self, crate, field_id):
        return self.docs[crate]["index"][str(field_id)]["inner"]["struct_field"]

    def fields(self, crate, full, plain):
        for field_id in plain["fields"]:
            field = self.docs[crate]["index"][str(field_id)]
            self.emit(f"field {full}.{field['name']}: {ty(field['inner']['struct_field'])}")
        self.emit(f"struct {full} fields{' (private fields)' if plain['has_stripped_fields'] else ''}")

    def variant(self, crate, full, item):
        inner = item["inner"]["variant"]
        shape = inner["kind"]
        line = f"variant {full}{attributes(item)}"
        if inner.get("discriminant"):
            line += f" = {inner['discriminant']['value']}"
        if shape == "plain":
            self.emit(line)
        elif "tuple" in shape:
            parts = [ty(self.field_type(crate, f)) if f is not None else "_" for f in shape["tuple"]]
            self.emit(f"{line}({', '.join(parts)})")
        else:
            self.emit(line + " {}")
            self.fields(crate, full, shape["struct"])

    def impls(self, crate, full, item_id, impl_ids):
        for impl_id in impl_ids:
            impl = self.docs[crate]["index"][str(impl_id)]["inner"]["impl"]
            if impl["blanket_impl"] is not None:
                continue
            target = impl["for"].get("resolved_path", {}).get("id")
            if target != item_id:
                # Impls for another workspace type are listed with that type; impls for
                # foreign types (arrays, std types) are listed here.
                if target is not None and self.resolve(crate, target) is not None:
                    continue
                if impl["trait"] is not None:
                    self.emit(f"impl {path_type(impl['trait'])} for {ty(impl['for'])}")
                continue
            if impl["trait"] is not None:
                negative = "!" if impl["is_negative"] else ""
                self.emit(f"impl {negative}{path_type(impl['trait'])} for {full}")
                for member in impl["items"]:
                    member_item = self.docs[crate]["index"][str(member)]
                    if "assoc_type" in member_item["inner"]:
                        value = member_item["inner"]["assoc_type"].get("type")
                        self.emit(f"type {full}::<{path_type(impl['trait'])}>::{member_item['name']} = {ty(value)}")
                continue
            for member in impl["items"]:
                member_item = self.docs[crate]["index"][str(member)]
                if member_item["visibility"] == "public":
                    self.assoc(crate, full, member_item)

    def assoc(self, crate, full, item):
        kind, inner = next(iter(item["inner"].items()))
        name = f"{full}::{item['name']}"
        if kind == "function":
            self.emit(f"fn {name}{function(inner)}")
        elif kind == "assoc_const":
            self.emit(f"const {name}: {ty(inner['type'])} = {inner.get('value')}")
        elif kind == "assoc_type":
            self.emit(f"type {name}")


def attributes(item):
    marks = []
    for attr in item["attrs"]:
        if attr == "non_exhaustive":
            marks.append("non_exhaustive")
        elif isinstance(attr, dict) and "repr" in attr:
            marks.append(f"repr({attr['repr'].get('int') or attr['repr'].get('kind')})")
        elif isinstance(attr, dict) and "must_use" in attr:
            marks.append("must_use")
    return f" #[{', '.join(marks)}]" if marks else ""


def function(inner):
    sig = inner["sig"]
    header = inner["header"]
    prefix = "".join(word for flag, word in (("is_const", "const "), ("is_async", "async "),
                                             ("is_unsafe", "unsafe ")) if header[flag])
    inputs = ", ".join(ty(t) if n == "self" else f"{ty(t)}" for n, t in sig["inputs"])
    output = f" -> {ty(sig['output'])}" if sig["output"] is not None else ""
    where = where_clause(inner["generics"])
    qualifiers = f" [{prefix.strip()}]" if prefix else ""
    return f"{generics(inner['generics'])}({inputs}){output}{where}{qualifiers}"


def generics(value):
    params = []
    for param in value["params"]:
        kind = param["kind"]
        if "lifetime" in kind:
            params.append(param["name"])
        elif "type" in kind:
            if kind["type"].get("is_synthetic"):
                continue
            bounds = " + ".join(bound(b) for b in kind["type"]["bounds"])
            params.append(param["name"] + (f": {bounds}" if bounds else ""))
        elif "const" in kind:
            params.append(f"const {param['name']}: {ty(kind['const']['type'])}")
    return f"<{', '.join(params)}>" if params else ""


def where_clause(value):
    predicates = []
    for predicate in value["where_predicates"]:
        if "bound_predicate" in predicate:
            p = predicate["bound_predicate"]
            predicates.append(f"{ty(p['type'])}: {' + '.join(bound(b) for b in p['bounds'])}")
    return f" where {', '.join(predicates)}" if predicates else ""


def bound(value):
    if "trait_bound" in value:
        return path_type(value["trait_bound"]["trait"])
    if "outlives" in value:
        return value["outlives"]
    return json.dumps(value, sort_keys=True)


def path_type(value):
    name = value["path"].split("::")[-1]
    return name + args(value.get("args"))


def args(value):
    if not value:
        return ""
    if "angle_bracketed" in value:
        parts = []
        for arg in value["angle_bracketed"]["args"]:
            if "type" in arg:
                parts.append(ty(arg["type"]))
            elif "lifetime" in arg:
                parts.append(arg["lifetime"])
            elif "const" in arg:
                parts.append(str(arg["const"].get("expr")))
        for constraint in value["angle_bracketed"]["constraints"]:
            binding = constraint["binding"]
            if "equality" in binding:
                parts.append(f"{constraint['name']} = {ty(binding['equality']['type'])}")
        return f"<{', '.join(parts)}>" if parts else ""
    if "parenthesized" in value:
        p = value["parenthesized"]
        output = f" -> {ty(p['output'])}" if p["output"] else ""
        return f"({', '.join(ty(t) for t in p['inputs'])}){output}"
    return ""


def ty(value):
    if value is None:
        return "()"
    if isinstance(value, str):
        return value
    kind, inner = next(iter(value.items()))
    if kind == "resolved_path":
        return path_type(inner)
    if kind in ("generic", "primitive"):
        return inner
    if kind == "borrowed_ref":
        lifetime = f"{inner['lifetime']} " if inner["lifetime"] else ""
        return f"&{lifetime}{'mut ' if inner['is_mutable'] else ''}{ty(inner['type'])}"
    if kind == "slice":
        return f"[{ty(inner)}]"
    if kind == "array":
        return f"[{ty(inner['type'])}; {inner['len']}]"
    if kind == "tuple":
        return f"({', '.join(ty(t) for t in inner)})"
    if kind == "raw_pointer":
        return f"*{'mut' if inner['is_mutable'] else 'const'} {ty(inner['type'])}"
    if kind == "qualified_path":
        trait = f" as {path_type(inner['trait'])}" if inner.get("trait") else ""
        return f"<{ty(inner['self_type'])}{trait}>::{inner['name']}"
    if kind == "impl_trait":
        return "impl " + " + ".join(bound(b) for b in inner)
    if kind == "dyn_trait":
        return "dyn " + " + ".join(path_type(t["trait"]) for t in inner["traits"])
    return json.dumps(value, sort_keys=True)


def listing(root, package, target, features=()):
    docs = build_docs(root, package, target, features)
    crate = package.replace("-", "_")
    doc = docs[crate]
    surface = Surface(docs)
    surface.module(crate, doc["index"][str(doc["root"])], [crate], frozenset())
    # A type re-exported under another name is spelled by that name in signatures.
    lines = surface.lines
    for original, alias in surface.aliases.items():
        pattern = re.compile(rf"\b{re.escape(original)}\b")
        lines = {pattern.sub(alias, line) for line in lines}
    return lines


def export(revision, directory):
    archive = subprocess.check_output(["git", "archive", revision], cwd=ROOT)
    with tarfile.open(fileobj=__import__("io").BytesIO(archive)) as tar:
        tar.extractall(directory, filter="data")


def excluded(line, prefixes):
    """True when the line describes an item, member or impl under one of PREFIXES."""
    words = line.split(" ")
    subjects = words[1:2] + (words[-1:] if words[0] == "impl" else [])
    return any(word == prefix or word.startswith(prefix + "::") or word.startswith(prefix + ".")
               for word in subjects for prefix in prefixes)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=["list", "check"])
    parser.add_argument("package")
    parser.add_argument("--root", type=pathlib.Path, default=ROOT)
    parser.add_argument("--baseline")
    parser.add_argument("--exclude", action="append", default=[],
                        help="ignore baseline items whose path starts with this prefix")
    options = parser.parse_args()
    target = ROOT / "target" / "api-surface"
    if options.command == "list":
        for line in sorted(listing(options.root, options.package, target / "current")):
            print(line)
        return 0
    if not options.baseline:
        parser.error("check requires --baseline")
    revision = subprocess.check_output(["git", "rev-parse", options.baseline], cwd=ROOT, text=True).strip()
    with tempfile.TemporaryDirectory() as directory:
        export(revision, directory)
        if options.package not in workspace_packages(directory):
            print(f"api-surface: {options.package} does not exist at {options.baseline}; skipped")
            return 0
        before = listing(pathlib.Path(directory), options.package, target / revision[:12])
    after = listing(ROOT, options.package, target / "current")
    missing = sorted(line for line in before - after if not excluded(line, options.exclude))
    for line in missing:
        print(f"missing: {line}")
    print(f"api-surface {options.package} against {options.baseline}: {len(before)} baseline lines, "
          f"{len(missing)} missing, {len(after - before)} added")
    return 1 if missing else 0


if __name__ == "__main__":
    sys.exit(main())
