#!/usr/bin/env python3
"""Rewrites `nsshared_proto::account` imports and paths of a consumer to nsshared-control.

    migrate-account-imports.py REPOSITORY [--map MAP] [--apply] [--quiet]

Without --apply it prints a unified diff of every change (dry run). With --apply it
writes the Rust sources. It reads only `*.rs` files outside `target/`, never changes
Cargo manifests, and prints the dependency change each affected manifest needs
(`nsshared-control` with its `unstable-account` feature, which gates `account`).

Mapping comes from docs/review/account-migration.json. Moved and renamed items get
their new path; a renamed item imported by `use` is aliased to its old name so the code
using it keeps compiling (listed for cleanup). A glob import becomes explicit imports
of the old items the file and its child modules name; old modules a glob brings into
scope are followed in paths, in `use` statements relative to them and in child modules
that `use super::*`, and `nsshared_proto::*` brings `account` along. A module split
across areas is imported as the area holding most of its items, and its other items are
rewritten to full paths. Attributes and doc comments of a `use` statement are repeated
on every statement it is split into. Paths in macro invocations are rewritten like any
other path. Items marked manual (participant frame kind constants, the usage digest
domain), split modules without a majority area, path groups inside macros, old paths
behind another path, and anything not in the map are left untouched and listed,
together with each `use` statement that contains one of them; any old account path
still present afterwards is listed too. Error variants that changed are listed with
their successors.
"""

import argparse
import collections
import difflib
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
FEATURE = "unstable-account"
OLD = "nsshared_proto::account"
NEW = "nsshared_control::account"
ATTRS = r"(?:(?:#\[(?:[^\[\]]|\[[^\[\]]*\])*\][ \t]*\n?|///[^\n]*\n)[ \t]*)*"
STATEMENT = re.compile(rf"^(?P<indent>[ \t]*)(?P<attrs>{ATTRS})(?P<vis>pub(?:\([^)]*\))?\s+)?use\s+(?P<tree>[^;]*);",
                       re.M | re.S)
IDENT = r"[A-Za-z_][A-Za-z0-9_]*"
INLINE = re.compile(rf"(?<![\w$])(?P<lead>::\s*)?nsshared_proto\s*::\s*account(?!\w)(?P<rest>(?:\s*::\s*{IDENT})*)"
                    r"(?P<group>\s*::\s*[{*])?")
LEFTOVER = re.compile(r"(?<![\w$])nsshared_proto\s*::\s*account(?!\w)")


class Map:
    def __init__(self, document):
        self.items = {}
        self.modules = {}
        for entry in document["items"]:
            if entry["kind"] == "module":
                self.modules[entry["old"]] = entry
            else:
                self.items[entry["old"]] = entry
        self.variants = {}
        for error in document["errors"]:
            if not error["old"]:
                continue
            name = error["old"].rsplit("::", 1)[1]
            for row in error["variants"]:
                if row["status"] != "moved":
                    variant = re.match(r"\w+::(\w+)", row["old"]).group(1)
                    self.variants[(name, variant)] = row["new"]

    def children(self, module):
        """Old item and module paths directly below an old module."""
        return sorted(p for p in [*self.items, *self.modules] if p.rsplit("::", 1)[0] == module)

    def primary(self, module):
        """The area module holding most items of an old module, or None if unclear."""
        counts = collections.Counter()
        for old, entry in self.items.items():
            if old.rsplit("::", 1)[0] == module:
                target = entry["new"][0] if isinstance(entry["new"], list) else entry["new"]
                counts[target.rsplit("::", 1)[0]] += 1
        ranked = counts.most_common(2)
        if not ranked or (len(ranked) == 2 and ranked[0][1] == ranked[1][1]):
            return None
        return ranked[0][0]

    def item(self, path):
        """Returns (new path, entry) for an item path or a path below an item."""
        segments = path.split("::")
        for end in range(len(segments), 2, -1):
            prefix = "::".join(segments[:end])
            entry = self.items.get(prefix)
            if entry:
                target = entry["new"][0] if isinstance(entry["new"], list) else entry["new"]
                return "::".join([target] + segments[end:]), entry
        return None, None


def split(path):
    return [s for s in re.sub(r"\s+", "", path).split("::") if s]


def flatten(tree):
    """Flattens a use tree into (segments, alias) pairs."""
    tree = tree.strip()
    depth = 0
    for index, char in enumerate(tree):
        if char == "{" and depth == 0:
            if "}" not in tree:
                return []
            prefix = split(tree[:index].strip().rstrip(":"))
            body = tree[index + 1: tree.rindex("}")]
            parts, current, level = [], "", 0
            for c in body:
                if c == "," and level == 0:
                    parts.append(current)
                    current = ""
                    continue
                level += c == "{"
                level -= c == "}"
                current += c
            parts.append(current)
            out = []
            for part in parts:
                if part.strip():
                    for segments, alias in flatten(part):
                        out.append((prefix if segments == ["self"] else prefix + segments, alias))
            return out
        depth += char == "{"
        depth -= char == "}"
    match = re.match(r"^(.*?)\s+as\s+([A-Za-z_][A-Za-z0-9_]*)$", tree, re.S)
    if match:
        return [(split(match.group(1)), match.group(2))]
    return [(split(tree), None)]


def nest(members):
    """Renders (segments, alias) pairs below a common prefix as one use tree."""
    parts, groups = set(), collections.OrderedDict()
    for segments, alias in members:
        if len(segments) > 1:
            groups.setdefault(segments[0], []).append((segments[1:], alias))
        else:
            parts.add((segments[0] if segments else "self") + (f" as {alias}" if alias else ""))
    for name, below in groups.items():
        parts.add(f"{name}::{nest(below)}")
    ordered = sorted(parts)
    return ordered[0] if len(ordered) == 1 else "{" + ", ".join(ordered) + "}"


def render(pairs, indent, vis, attrs=""):
    """One `use` statement per root, each carrying the original attributes."""
    groups = collections.OrderedDict()
    for segments, alias in pairs:
        groups.setdefault(segments[0], []).append((segments[1:], alias))
    return "\n".join(f"{indent}{attrs}{vis}use {root}::{nest(members)};" for root, members in groups.items())


class Report:
    def __init__(self):
        self.files = 0
        self.paths = 0
        self.unmapped = []
        self.aliased = []
        self.notes = []
        self.variants = []
        self.manifests = collections.defaultdict(set)


def map_use(mapping, segments, alias, report, location, used=frozenset(), globbed=None):
    """Maps one flattened `nsshared_proto::account...` path; None when unmappable.

    Old modules a glob brings into scope are recorded in `globbed` by name."""
    path = "::".join(segments)
    rest = segments[2:]
    if path == OLD:
        return [(split(NEW), alias)], {alias or "account": ("account", OLD)}
    if rest and rest[-1] == "*":
        module = "::".join(segments[:-1])
        if module != OLD and module not in mapping.modules:
            report.unmapped.append((location, path, "glob of a module not in the migration map"))
            return None
        pairs, aliases = [], {}
        for child in mapping.children(module):
            name = child.rsplit("::", 1)[1]
            if child in mapping.modules and globbed is not None:
                globbed[name] = child
            if f"{name}::" not in used and (child in mapping.modules or name not in used):
                continue
            mapped = map_use(mapping, split(child), None, report, location, used)
            if mapped is None:
                return None
            pairs.extend(mapped[0])
            aliases.update(mapped[1])
        return pairs, aliases
    if path in mapping.modules:
        target = mapping.primary(path)
        if target is None:
            report.unmapped.append((location, path, "module split across " + ", ".join(mapping.modules[path]["new"])))
            return None
        name = alias or segments[-1]
        if mapping.modules[path]["status"] == "split":
            report.notes.append((location, path, f"split module imported as {target}; "
                                 "its other items are rewritten to full paths"))
        return [(split(target), name if name != target.rsplit("::", 1)[1] else None)], {name: (target, path)}
    target, entry = mapping.item(path)
    if not entry:
        report.unmapped.append((location, path, "not in the migration map"))
        return None
    if entry.get("manual"):
        report.unmapped.append((location, path, entry.get("note", "manual migration")))
        return None
    if entry["status"] in ("split", "changed") and entry.get("note"):
        report.notes.append((location, path, entry["note"]))
    new_name = target.rsplit("::", 1)[1]
    if alias is None and new_name != segments[-1]:
        alias = segments[-1]
        report.aliased.append((location, path, target))
    return [(split(target), alias)], {}


ANY_USE = STATEMENT


def outside_uses(text, transform):
    """Applies `transform` to the text between `use` statements only."""
    out, last = [], 0
    for match in ANY_USE.finditer(text):
        out.append(transform(text[last:match.start()], last))
        out.append(match.group(0))
        last = match.end()
    out.append(transform(text[last:], last))
    return "".join(out)


def identifiers(text):
    """Unqualified names outside `use` statements and line comments; `name::` marks a path root."""
    code = re.sub(r"//[^\n]*", "", STATEMENT.sub(" ", text))
    names = set()
    for match in re.finditer(rf"(?<![\w.$])(?<!::)({IDENT})(\s*::)?", code):
        names.add(match.group(1) + ("::" if match.group(2) else ""))
    return names


def imported(text):
    """Names bound by `use` statements that do not import from nsshared_proto, and local modules."""
    names = set(re.findall(rf"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+({IDENT})\b", text, re.M))
    for match in STATEMENT.finditer(text):
        for segments, alias in flatten(match.group("tree")):
            if segments[:1] != ["nsshared_proto"] and segments and segments[-1] != "*":
                names.add(alias or segments[-1])
    return names


def child_modules(path):
    """Files of the out-of-line modules a source file declares, recursively."""
    for child in direct_children(path):
        yield child
        yield from child_modules(child)


def direct_children(path):
    """Files of the out-of-line modules a source file declares."""
    text = path.read_text(errors="surrogateescape")
    root = (path.name in ("lib.rs", "main.rs", "mod.rs", "build.rs")
            or path.parent.name in ("tests", "examples", "benches")
            or path.parent.parts[-2:] == ("src", "bin"))
    directory = path.parent if root else path.with_suffix("")
    for name in re.findall(r"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;", text, re.M):
        for candidate in (directory / f"{name}.rs", directory / name / "mod.rs"):
            if candidate.exists():
                yield candidate
                break


def rewrite(text, mapping, report, file, descendants=(), inherited=None, scope=None):
    """Rewrites one source file.

    `inherited` holds the module scope of the parent module when this file does
    `use super::*`; `scope`, when given, receives this file's module scope."""
    modules, globbed = {}, {}
    changed = False
    used = identifiers(text)
    for other in descendants:
        used |= identifiers(other)
    shadowed = imported(text)
    used -= shadowed | {f"{name}::" for name in shadowed}
    inherited = inherited or {"modules": {}, "globbed": {}}
    outer = {name: value for name, value in inherited["modules"].items() if name not in shadowed}
    outer_globbed = {name: value for name, value in inherited["globbed"].items() if name not in shadowed}

    def location(match):
        return f"{file}:{text.count(chr(10), 0, base + match.start('tree')) + 1}"

    def replace_use(match):
        nonlocal changed
        tree = match.group("tree")
        pairs = flatten(tree)
        if not pairs or not pairs[0][0] or pairs[0][0][0] != "nsshared_proto":
            return match.group(0)
        proto_glob = "account::" in used and any(s == ["nsshared_proto", "*"] for s, _ in pairs)
        if not proto_glob and not any(s[:2] == ["nsshared_proto", "account"] for s, _ in pairs):
            return match.group(0)
        out, local, found, count = [], {}, {}, 0
        for segments, alias in pairs:
            if segments[:2] != ["nsshared_proto", "account"]:
                out.append((segments, alias))
                continue
            mapped = map_use(mapping, segments, alias, report, location(match), used, found)
            if mapped is None:
                return match.group(0)
            new_pairs, aliases = mapped
            out.extend(new_pairs)
            local.update(aliases)
            count += 1
        if proto_glob and "account" not in local:
            out.append((split(NEW), None))
            local["account"] = ("account", OLD)
            count += 1
        report.paths += count
        modules.update(local)
        globbed.update(found)
        changed = True
        if not out:
            return ""
        return render(out, match.group("indent"), match.group("vis") or "", match.group("attrs"))

    base = 0
    text = STATEMENT.sub(replace_use, text)
    relative_roots = {name: old for name, (_, old) in {**outer, **modules}.items() if old}
    relative_roots = {**outer_globbed, **globbed, **relative_roots}

    def replace_relative_use(match):
        nonlocal changed
        pairs = flatten(match.group("tree"))
        if not any(len(s) > 1 and s[0] in relative_roots for s, _ in pairs):
            return match.group(0)
        out, count = [], 0
        for segments, alias in pairs:
            if len(segments) < 2 or segments[0] not in relative_roots:
                out.append((segments, alias))
                continue
            old = split(relative_roots[segments[0]]) + segments[1:]
            mapped = map_use(mapping, old, alias, report, location(match), used)
            if mapped is None:
                return match.group(0)
            out.extend(mapped[0])
            modules.update(mapped[1])
            count += 1
        report.paths += count
        changed = True
        return render(out, match.group("indent"), match.group("vis") or "", match.group("attrs"))

    text = STATEMENT.sub(replace_relative_use, text)

    def replace_inline(match):
        nonlocal changed
        line = text.count("\n", 0, base + match.start()) + 1
        where = f"{file}:{line}"
        lead = "::" if match.group("lead") else ""
        path = "nsshared_proto::account" + re.sub(r"\s+", "", match.group("rest"))
        before = match.string[:match.start()]
        if not lead and re.search(r"::\s*$", before):
            report.unmapped.append((where, path, "old path behind another path; migrate by hand"))
            return match.group(0)
        if match.group("group"):
            report.unmapped.append((where, path + "::" + match.group("group").strip()[-1],
                                    "path group or glob outside a use statement; migrate by hand"))
            return match.group(0)
        if path == OLD:
            target, entry = NEW, {}
        else:
            target, entry = mapping.item(path)
            if not entry or entry.get("manual"):
                report.unmapped.append((where, path, entry.get("note") if entry else "not in the migration map"))
                return match.group(0)
        report.paths += 1
        changed = True
        return lead + target

    def inline(part, offset):
        nonlocal base
        base = offset
        return INLINE.sub(replace_inline, part)

    text = outside_uses(text, inline)
    for name, (target, old_module) in {**outer, **modules}.items():
        pattern = re.compile(rf"(?<![\w$.])(?<!::){re.escape(name)}::({IDENT}(?:::{IDENT})*)")

        def replace_relative(match, old_module=old_module, name=name, target=target):
            nonlocal changed
            if old_module is None:
                return match.group(0)
            new_path, entry = mapping.item(f"{old_module}::{match.group(1)}")
            line = text.count("\n", 0, base + match.start()) + 1
            if not entry or entry.get("manual"):
                if (f"{old_module}::{match.group(1)}" not in mapping.modules
                        and not match.group(1)[:1].islower()):
                    report.unmapped.append((f"{file}:{line}", f"{name}::{match.group(1)}",
                                            entry.get("note") if entry else "not in the migration map"))
                return match.group(0)
            base_path = NEW if target == "account" else target
            if new_path.startswith(base_path + "::"):
                replacement = name + new_path[len(base_path):]
            else:
                replacement = new_path
            if replacement == f"{name}::{match.group(1)}":
                return match.group(0)
            report.paths += 1
            changed = True
            return replacement

        def relative(part, offset, pattern=pattern, replace=replace_relative):
            nonlocal base
            base = offset
            return pattern.sub(replace, part)

        text = outside_uses(text, relative)

    listed = {row[0] for row in report.unmapped}

    def leftover(part, offset):
        for found in LEFTOVER.finditer(part):
            where = f"{file}:{text.count(chr(10), 0, offset + found.start()) + 1}"
            if where not in listed:
                listed.add(where)
                report.unmapped.append((where, found.group(0), "old account path left in place; migrate by hand"))
        return part

    outside_uses(text, leftover)
    for (enum, variant), successor in mapping.variants.items():
        for found in re.finditer(rf"\b{enum}::{variant}\b", text):
            line = text.count("\n", 0, found.start()) + 1
            report.variants.append((f"{file}:{line}", f"{enum}::{variant}", successor))
    if scope is not None:
        scope["modules"] = {**outer, **modules}
        scope["globbed"] = {**outer_globbed, **globbed}
    return text, changed


def manifest_for(path, repository):
    for parent in path.parents:
        candidate = parent / "Cargo.toml"
        if candidate.exists():
            return candidate
        if parent == repository:
            break
    return repository / "Cargo.toml"


def declared(text, crate):
    return re.search(rf"^{crate}\s*=", text, re.M) is not None


def dependency_advice(repository, manifests):
    root = repository / "Cargo.toml"
    root_text = root.read_text() if root.exists() else ""
    pin = None
    match = re.search(r"^nsshared-proto\s*=\s*(\{[^}\n]*\})", root_text, re.M)
    if match:
        pin = re.sub(r",?\s*(?:default-features\s*=\s*false|features\s*=\s*\[[^\]]*\])", "", match.group(1)).strip()
    lines = ["Dependency changes (not applied):"]
    wanted = sorted(set().union(*manifests.values())) if manifests else []
    for crate in wanted:
        if pin and not declared(root_text, crate):
            source = re.sub(r"(path\s*=\s*\"[^\"]*/)nsshared-proto\"", rf'\g<1>{crate}"', pin)
            if crate == "nsshared-control":
                source = source[:-1].rstrip() + f', features = ["{FEATURE}"] }}'
            lines.append(f"- {root.relative_to(repository)} [workspace.dependencies]: {crate} = {source} "
                         "(the same source; pin a revision that contains it)")
        elif crate == "nsshared-control" and declared(root_text, crate) and FEATURE not in root_text:
            lines.append(f"- {root.relative_to(repository)} [workspace.dependencies]: enable "
                         f'features = ["{FEATURE}"] on nsshared-control')
    for manifest, needs in sorted(manifests.items()):
        text = manifest.read_text() if manifest.exists() else ""
        missing = sorted(c for c in needs if not declared(text, c))
        if not missing:
            continue
        uses_workspace = "workspace = true" in text
        form = " ".join(f"{c}.workspace = true" for c in missing) if uses_workspace else ", ".join(missing)
        lines.append(f"- {manifest.relative_to(repository)} [dependencies]: add {form}")
    if len(lines) == 1:
        lines.append("- none: every affected manifest already declares the crates it needs")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("repository", type=pathlib.Path)
    parser.add_argument("--map", type=pathlib.Path, default=ROOT / "docs" / "review" / "account-migration.json")
    parser.add_argument("--apply", action="store_true", help="write the changes instead of printing a diff")
    parser.add_argument("--quiet", action="store_true", help="print only the summary")
    options = parser.parse_args()
    mapping = Map(json.loads(options.map.read_text()))
    repository = options.repository.resolve()
    report = Report()
    sources = [path for path in sorted(repository.rglob("*.rs"))
               if "target" not in path.relative_to(repository).parts]
    parents = {child: path for path in sources for child in direct_children(path)}
    scopes = {}

    def inherited(path):
        parent = parents.get(path)
        text = path.read_text(errors="surrogateescape")
        if parent is None or not re.search(r"\buse\s+super::\*\s*;", text):
            return None
        return scope_of(parent)

    def scope_of(path):
        if path not in scopes:
            scopes[path] = {"modules": {}, "globbed": {}}
            outer = inherited(path)
            text = path.read_text(errors="surrogateescape")
            if "nsshared_proto" in text:
                scope = {}
                descendants = [child.read_text(errors="surrogateescape") for child in child_modules(path)]
                rewrite(text, mapping, Report(), path.relative_to(repository), descendants, outer, scope)
                scopes[path] = scope
            elif outer:
                scopes[path] = outer
        return scopes[path]

    for path in sources:
        original = path.read_text(errors="surrogateescape")
        outer = inherited(path)
        if "nsshared_proto" not in original and "account::" not in original and not outer:
            continue
        relative = path.relative_to(repository)
        descendants = [child.read_text(errors="surrogateescape") for child in child_modules(path)]
        updated, changed = rewrite(original, mapping, report, relative, descendants, outer)
        if not changed or updated == original:
            continue
        report.files += 1
        needs = {"nsshared-control"}
        if "nsshared_identity::" in updated and "nsshared_identity::" not in original:
            needs.add("nsshared-identity")
        if "nsshared_codec::" in updated and "nsshared_codec::" not in original:
            needs.add("nsshared-codec")
        report.manifests[manifest_for(path, repository)] |= needs
        if options.apply:
            path.write_text(updated, errors="surrogateescape")
        elif not options.quiet:
            sys.stdout.writelines(difflib.unified_diff(
                original.splitlines(True), updated.splitlines(True), f"a/{relative}", f"b/{relative}"))
    print(f"\n{report.files} files, {report.paths} paths rewritten{'' if options.apply else ' (dry run)'}")
    for title, rows in [("Unmapped (left untouched)", report.unmapped),
                        ("Renamed items aliased to their old names", report.aliased),
                        ("Items whose behaviour or signature changed", report.notes),
                        ("Error variants to update by hand", report.variants)]:
        print(f"{title}: {len(rows)}")
        for row in rows:
            print("  " + " | ".join(str(part) for part in row))
    if report.manifests:
        print(dependency_advice(repository, report.manifests))
    return 0


if __name__ == "__main__":
    sys.exit(main())
