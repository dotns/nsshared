#!/usr/bin/env python3
"""Generates or checks the account migration map docs/review/account-migration.json.

    account_migration.py write [--base REV]
    account_migration.py check [--base REV]

The map lists every public item of `nsshared_proto::account` at the base revision with
its new path in nsshared-control and a status:

- moved: same name, same signature and members, new path;
- renamed: new name, otherwise unchanged;
- changed: the signature or public members differ (`changes` lists the differing
  lines; `manual` marks items a path rewrite cannot migrate);
- split: the item maps to several new items;
- removed: no successor (`note` gives the reason).

It also maps every variant of every old account error enum. Both listings come from
rustdoc JSON through scripts/api_surface.py. `check` regenerates the map, verifies that
every old public item and error variant is covered exactly once and that the committed
file is current.
"""

import argparse
import json
import pathlib
import re
import subprocess
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import api_surface  # noqa: E402

ROOT = api_surface.ROOT
MAP = ROOT / "docs" / "review" / "account-migration.json"
BASE = "1bc1d39ef51d3e60a88a01d67244afc68ebd795c"
OLD = "nsshared_proto::account"
NEW = "nsshared_control::account"

# Name changes; every other item keeps its name.
RENAMES = {
    "validate_snapshot": "validate_admission_snapshot",
    "Direction": "ServiceDirection",
    "PUBLICATION_SIGNATURE_DOMAIN": "PUBLICATION_DOMAIN",
    "ROSTER_SIGNATURE_DOMAIN": "ROSTER_DOMAIN",
    "PROOF_DOMAIN": "PARTICIPANT_PROOF_DOMAIN",
    "EXPORTER_LABEL": "PARTICIPANT_EXPORTER_LABEL",
    "USAGE_PART_DOMAIN": "USAGE_PART_DIGEST_DOMAIN",
}
# Participant frame kind constants became variants of one enum.
FRAME_KINDS = {
    "AUTHENTICATE": "Authenticate", "AUTHENTICATED": "Authenticated", "REFUSED": "Refused",
    "ROSTER": "Roster", "REPORT": "Report", "ANSWER": "Answer", "ENROLL": "Enroll",
    "ENROLLED": "Enrolled", "RENEW": "Renew", "RENEWED": "Renewed",
}
# Items now defined outside nsshared-control.
ELSEWHERE = {
    "RealmId": "nsshared_identity::realm::RealmId",
    "RealmIdError": "nsshared_identity::realm::RealmIdError",
}
# Items whose responsibilities moved to several new items.
SPLITS = {
    "SourceError": (["publication::SourceError", "control::RouteError"],
                    "route command and receipt APIs report control::RouteError; Conflict and Reference moved there"),
    "GrantError": (["grants::GrantError", "node::L3AuthorityError"],
                   "NodeL3Authority reports node::L3AuthorityError; Policy became Contract"),
}
NOTES = {
    "USAGE_PART_DOMAIN": "was the NUL-terminated byte domain; now the text domain for service::domain_digest, "
                         "which appends the separator: never hash it directly",
    "MAX_PUBLICATION_BYTES": "one path only, in the control area",
}
MANUAL = {"USAGE_PART_DOMAIN"} | set(FRAME_KINDS)

# Error variant mapping where the variant name or payload changed. Values are
# "<new enum>::<variant>" relative to the account root; unmatched old variants that keep
# their name map to the same variant of the successor enum.
VARIANTS = {
    ("AccountError", "InvalidField"): "AccountError::Field",
    ("PublicationError", "Fields"): "publication::PublicationError::Field",
    ("PublicationError", "Encoding"): "publication::PublicationError::Contract(AccountError::Cbor(_))",
    ("SubnetReportError", "Fields"): "subnet::SubnetReportError::Field",
    ("SubnetReportError", "Encoding"): "subnet::SubnetReportError::Contract(AccountError::Cbor(_))",
    ("SubnetError", "Encoding"): "subnet::SubnetError::Contract(AccountError::Cbor(_))",
    ("BootstrapError", "Encoding"): "control::BootstrapError::Contract(AccountError::Cbor(_)); bound violations stay Bounds",
    ("GrantError", "Policy"): "grants::GrantError::Contract; from NodeL3Authority: node::L3AuthorityError::Contract",
    ("ParticipantRosterError", "WrongIssuer"): "relay::ParticipantRosterError::Issuer",
    ("ParticipantRosterError", "WrongRecipient"): "relay::ParticipantRosterError::Recipient",
    ("ParticipantRosterError", "StaleVersion"): "relay::ParticipantRosterError::Stale",
    ("ParticipantRosterError", "BadSignature"): "relay::ParticipantRosterError::Signature",
    ("BindingError", "Version"): "relay::BindingError::Stale",
    ("SourceError", "Conflict"): "control::RouteError::Conflict",
    ("SourceError", "Reference"): "control::RouteError::Reference",
}
# Variants that also appear in a second enum after a split.
ALSO = {
    ("SourceError", "Authority"): "from route command APIs: control::RouteError::Authority",
    ("SourceError", "Contract"): "from route command APIs: control::RouteError::Contract",
    ("SourceError", "Envelope"): "from route command APIs: control::RouteError::Envelope",
    ("SourceError", "Subnet"): "from route command APIs: control::RouteError::Subnet",
    ("GrantError", "Encoding"): "from NodeL3Authority: node::L3AuthorityError::Encoding",
    ("GrantError", "Field"): "from NodeL3Authority: node::L3AuthorityError::Field",
    ("GrantError", "Bounds"): "from NodeL3Authority: node::L3AuthorityError::Bounds",
    ("GrantError", "Ordering"): "from NodeL3Authority: node::L3AuthorityError::Ordering",
    ("GrantError", "Binding"): "from NodeL3Authority: node::L3AuthorityError::Binding",
}

PATH = re.compile(r"^(fn|const|static|type|struct|enum|trait|mod|union|macro|variant|field) ([A-Za-z0-9_:]+)")
TOP = {"fn": "fn", "const": "const", "static": "const", "type": "type", "struct": "type",
       "enum": "enum", "trait": "trait", "mod": "module", "union": "type", "macro": "macro"}


def parse(lines, prefix):
    """Groups listing lines into top-level items under `prefix`."""
    lines = [line for line in lines if prefix in line]
    types = set()
    for line in lines:
        match = PATH.match(line)
        if match and match.group(1) in ("struct", "enum", "trait", "union"):
            types.add(match.group(2))
    # A variant's shape line `struct Enum::Variant fields` names no type of its own.
    types = {path for path in types if path.rsplit("::", 1)[0] not in types}
    items = {}
    members = {}
    for line in lines:
        if line.startswith("impl "):
            owner = line.split(" ")[-1]
            if owner.startswith(prefix):
                members.setdefault(owner, set()).add(line.replace(owner, "@"))
            continue
        match = PATH.match(line)
        if not match:
            continue
        kind, path = match.group(1), match.group(2).rstrip(":")
        if kind == "field":
            owner = path.split(".")[0]
        elif kind == "variant":
            owner = path.rsplit("::", 1)[0]
        elif kind in ("fn", "const", "type", "struct") and path.rsplit("::", 1)[0] in types:
            # Associated items, and the field shape lines of struct-like enum variants.
            owner = path.rsplit("::", 1)[0]
        else:
            if not path.startswith(prefix):
                continue
            item = items.setdefault(path, {"kind": TOP[kind], "lines": set()})
            if kind in ("struct", "enum", "union", "trait"):
                item["kind"] = TOP[kind]
            item["lines"].add(line.replace(path, "@", 1))
            continue
        if owner.startswith(prefix):
            members.setdefault(owner, set()).add(line.replace(owner, "@"))
    for path, item in items.items():
        item["members"] = members.get(path, set())
        item["non_exhaustive"] = any("non_exhaustive" in line for line in item["lines"])
    return items


# Renamed types appear in other items' signatures; compare those by the new name.
TYPE_RENAMES = {"Direction": "ServiceDirection"}


def normalize(lines):
    out = set()
    for line in lines:
        for old, new in TYPE_RENAMES.items():
            line = re.sub(rf"\b{old}\b", new, line)
        out.add(line)
    return out


def listing(root, package, target, features=()):
    return api_surface.listing(root, package, target, features)


def build(base):
    revision = subprocess.check_output(["git", "rev-parse", base], cwd=ROOT, text=True).strip()
    with tempfile.TemporaryDirectory() as directory:
        api_surface.export(revision, directory)
        old_lines = listing(pathlib.Path(directory), "nsshared-proto",
                            ROOT / "target" / "api-surface" / revision[:12])
    new_lines = listing(ROOT, "nsshared-control", ROOT / "target" / "api-surface" / "current",
                        ["nsshared-control/unstable-account"])
    old = parse(old_lines, OLD)
    new = parse(new_lines, NEW)
    by_name = {}
    for path, item in new.items():
        by_name.setdefault(path.rsplit("::", 1)[1], []).append(path)
    entries = []
    for path in sorted(old):
        item = old[path]
        name = path.rsplit("::", 1)[1]
        entry = {"old": path, "kind": item["kind"]}
        if path == OLD:
            entry.update(status="moved", new=NEW)
        elif item["kind"] == "module":
            areas = sorted({new_item.rsplit("::", 1)[0] for other in old
                            if other.startswith(path + "::")
                            for new_item in successors(other, by_name)})
            areas = sorted({area for area in areas if area != NEW})
            if len(areas) == 1:
                entry.update(status="renamed", new=areas[0])
            else:
                entry.update(status="split", new=areas,
                             note="items of this module moved to several area modules")
        elif name in ELSEWHERE:
            entry.update(status="moved", new=ELSEWHERE[name],
                         note="defined in nsshared-identity; account no longer re-exports it")
        elif name in FRAME_KINDS:
            entry.update(status="changed", new=f"{NEW}::relay::FrameKind::{FRAME_KINDS[name]}",
                         note="u8 constant became a FrameKind variant; FrameKind::byte() gives the wire byte")
        elif name in SPLITS:
            targets, note = SPLITS[name]
            entry.update(status="split", new=[f"{NEW}::{target}" for target in targets], note=note)
        else:
            new_name = RENAMES.get(name, name)
            candidates = by_name.get(new_name, [])
            if len(candidates) != 1:
                raise SystemExit(f"{path}: {len(candidates)} successors named {new_name}")
            target = candidates[0]
            successor = new[target]
            old_view = normalize(item["lines"] | item["members"])
            new_view = successor["lines"] | successor["members"]
            entry["new"] = target
            if old_view == new_view:
                entry["status"] = "renamed" if new_name != name else "moved"
            else:
                entry["status"] = "changed"
                entry["changes"] = {"removed": sorted(old_view - new_view), "added": sorted(new_view - old_view)}
        if name in NOTES:
            entry["note"] = NOTES[name]
        if name in MANUAL:
            entry["manual"] = True
        entries.append(entry)
    return revision, entries, errors(old, new, entries)


def successors(path, by_name):
    name = path.rsplit("::", 1)[1]
    if name in FRAME_KINDS:
        return [f"{NEW}::relay::FrameKind"]
    if name in ELSEWHERE:
        return []
    if name in SPLITS:
        return [f"{NEW}::{SPLITS[name][0][0]}"]
    return by_name.get(RENAMES.get(name, name), [])


def variants(item):
    out = {}
    for line in item["members"]:
        if line.startswith("variant @::"):
            rest = line[len("variant @::"):]
            out[re.match(r"\w+", rest).group(0)] = rest
    return out


def errors(old, new, entries):
    result = []
    targets = {entry["old"]: entry for entry in entries}
    for path in sorted(old):
        item = old[path]
        name = path.rsplit("::", 1)[1]
        if item["kind"] != "enum" or not name.endswith("Error") or name in ELSEWHERE:
            continue
        entry = targets[path]
        successor = entry["new"][0] if isinstance(entry["new"], list) else entry["new"]
        new_item = new[successor]
        new_variants = variants(new_item)
        rows = []
        for variant, text in sorted(variants(item).items()):
            row = {"old": f"{name}::{text}"}
            if (name, variant) in VARIANTS:
                row["new"] = VARIANTS[(name, variant)]
                row["status"] = "renamed" if "::" in VARIANTS[(name, variant)].split("(")[0] else "changed"
            elif variant in new_variants:
                row["new"] = successor.removeprefix(NEW + "::") + "::" + new_variants[variant]
                row["status"] = "moved" if new_variants[variant] == text else "changed"
            else:
                raise SystemExit(f"{path}::{variant}: no successor variant")
            if (name, variant) in ALSO:
                row["also"] = ALSO[(name, variant)]
            rows.append(row)
        added = sorted(set(new_variants) - set(variants(item)) - {
            VARIANTS[(name, v)].split("::")[-1].split("(")[0] for v in variants(item) if (name, v) in VARIANTS})
        result.append({
            "old": path,
            "new": entry["new"],
            "non_exhaustive": {"old": item["non_exhaustive"], "new": new_item["non_exhaustive"]},
            "variants": rows,
            "new_variants": [new_variants[v] for v in added],
        })
    for name in ("RouteError", "L3AuthorityError"):
        path = next(p for p in new if p.endswith("::" + name))
        result.append({"old": None, "new": path, "non_exhaustive": {"old": None, "new": new[path]["non_exhaustive"]},
                       "variants": [], "new_variants": sorted(variants(new[path]).values())})
    return result


def document(base):
    revision, entries, error_rows = build(base)
    covered = [entry["old"] for entry in entries]
    if len(covered) != len(set(covered)):
        raise SystemExit("an old item is covered twice")
    return {
        "description": "Account API migration from nsshared_proto::account to nsshared_control::account; "
                       "generated by scripts/account_migration.py, do not edit.",
        "base": revision,
        "dependency": {
            "add": "nsshared-control",
            "note": "keep nsshared-proto for its other modules; pin nsshared-control to the same revision "
                    "with features = [\"unstable-account\"], which gates the candidate account module",
        },
        "statuses": ["moved", "renamed", "changed", "split", "removed"],
        "items": entries,
        "errors": error_rows,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=["write", "check"])
    parser.add_argument("--base", default=BASE)
    options = parser.parse_args()
    text = json.dumps(document(options.base), indent=2) + "\n"
    if options.command == "write":
        MAP.write_text(text)
        print(f"wrote {MAP.relative_to(ROOT)}")
        return 0
    if not MAP.exists() or MAP.read_text() != text:
        print(f"{MAP.relative_to(ROOT)} is stale; run `scripts/account_migration.py write`", file=sys.stderr)
        return 1
    print("account migration map is current; every old item and error variant is covered once")
    return 0


if __name__ == "__main__":
    sys.exit(main())
