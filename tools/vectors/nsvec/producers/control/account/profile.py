"""Independent account profile contracts; Python standard library only."""

import base64
import copy
import hashlib
import json

from nsvec import cbor, ed25519
from nsvec.signing import carrier as signed_carrier

CRATE = "nsshared-control"
GROUP = "account/profile"
TITLE = "Account profile: family registry, lifecycle, Node L3, usage unit and admission rosters"
SPEC = "docs/spec/account/profile.md"
EXTERNAL = None

def keys():
    """The fixture authorities `a` and `b` shared by the account producers."""
    return ed25519.public_key(bytes([1]) * 32), ed25519.public_key(bytes([2]) * 32)


FAMILIES = [
    ("enrollment", "own-node", "binding,capabilities,endpoints", "declarations"),
    ("realms-peers", "realm-peers", "realms,peer-contributions", "snapshots"),
    ("egress", "egress-grants", "resources,grants,payers", "declarations,listeners,snapshots"),
    ("exit-subnet", "exit-grants", "routes,grants,exclusions,bypasses,selection", "listeners,snapshots"),
    ("payer", "payer-bindings", "payers", "snapshots"),
    ("withdrawal", "resource-authority", "authority,incarnations", "snapshots"),
    ("public-edge", "public-edge", "backends,names,aliases,ports,domains,subjects,auth,materials", "declarations,listeners,snapshots"),
    ("relay", "relay-directory-roster", "directory|identity-classes", "snapshots"),
    ("usage", "usage-profile", "units,reporters,parameters", ""),
    ("node-control", "node-control-profile", "vocabulary,capabilities", ""),
    ("v1-replacement", "surface-map", "mappings,retirements", "declarations,listeners,snapshots"),
]


def vectors():
    a, b = keys()
    entries = [[i + 1, 1, name, publication, clears, "account-payload-profile",
                ["identities"] + (extra.split(",") if extra else []) + ["messages", "vectors"]]
               for i, (name, publication, clears, extra) in enumerate(FAMILIES)]
    out = [[("name", "family-registry"), ("kind", "registry"), ("bytes", cbor.encode([1, entries]))]]

    def vector(name, kind, value):
        out.append([("name", name), ("kind", kind), ("bytes", cbor.encode(value))])

    binding = [1, a, bytes([3]) * 32, 4]
    vector("identity-replacement", "lifecycle", [1, 0, binding, [2, b, bytes([4]) * 32, 1], bytes([5]) * 16, bytes([6]) * 16])
    vector("record-rotation", "lifecycle", [1, 1, binding, [1, a, bytes([4]) * 32, 5], bytes([5]) * 16, bytes([6]) * 16])
    namespace = bytes([7]) * 16
    vector("l3-scoped-rules", "l3", [1, a, b, 1, [[namespace, sorted([a, b])]], [[namespace, a, b, 6, 443, 443]]])
    vector("l3-empty-withdrawal", "l3", [1, a, b, 2, [], []])
    for name, window, boundary, direction in [("usage-unset", None, 0, 0), ("usage-measured-zero", [0], 1, 1)]:
        vector(name, "usage", [1, boundary, direction, bytes([8]) * 16, bytes([9]) * 16, bytes([5]) * 16, bytes([6]) * 16, 1234, window])
    roster_entries = sorted([[a, 0], [b, 1]])
    content = [1, a, b, 7, 1000, 86_401_000, roster_entries]

    def signed(name, value, expect="accept", corrupt=False):
        signed_roster = signed_carrier(bytes([1]) * 32, value, b"ns.account.roster.v1\0", corrupt)
        out.append([("name", name), ("kind", "signed-roster"), ("bytes", signed_roster), ("expect", expect)])

    signed("signed-roster", content)
    signed("signed-bad-signature", content, "reject", True)
    for name, index, value in [("signed-short-validity", 5, 86_400_999), ("signed-zero-version", 3, 0),
                                ("signed-duplicate-identity", 6, [roster_entries[0]] * 2), ("signed-unknown-class", 6, [[a, 2]])]:
        changed = copy.deepcopy(content)
        changed[index] = value
        signed(name, changed, "reject")
    snapshot = {"schema_version": 2, "issued_at_unix_ms": 1000, "roster_version": 7,
                "identities": [{"identity": base64.urlsafe_b64encode(identity).rstrip(b"=").decode(), "class": cls}
                               for identity, cls in [(a, "ordinary_node"), (b, "gateway_node")]]}

    def local(name, obj, expect="reject", pad_to=None):
        raw = obj if isinstance(obj, str) else json.dumps(obj, separators=(",", ":"))
        fields = [("name", name), ("kind", "snapshot"), ("bytes", raw.encode()), ("expect", expect)]
        if expect == "accept":
            fields.append(("count", len(obj["identities"])))
        if pad_to:
            fields.append(("pad_to", pad_to))
        out.append(fields)

    local("local-roster", snapshot, "accept")
    local("local-empty-withdrawal", {**snapshot, "identities": []}, "accept")
    local("local-missing-version", {k: v for k, v in snapshot.items() if k != "roster_version"})
    changed = copy.deepcopy(snapshot)
    del changed["identities"][0]["class"]
    local("local-missing-class", changed)
    local("local-unknown-field", {**snapshot, "unknown": 1})
    changed = copy.deepcopy(snapshot)
    changed["identities"][0]["unknown"] = 1
    local("local-unknown-entry-field", changed)
    local("local-oversized", snapshot, pad_to=1_048_577)
    local("local-duplicate-identity", {**snapshot, "identities": [snapshot["identities"][0]] * 2})
    local("local-unknown-class", {**snapshot, "identities": [{**snapshot["identities"][0], "class": "other"}]})
    local("local-object-class", {**snapshot, "identities": [{**snapshot["identities"][0], "class": {"ordinary_node": None}}]})
    local("local-max-bytes", snapshot, "accept", pad_to=1_048_576)
    local("local-zero-version", {**snapshot, "roster_version": 0})
    local("local-future", {**snapshot, "issued_at_unix_ms": 1001})
    local("local-stale", {**snapshot, "issued_at_unix_ms": 899})
    local("local-old-schema", {**snapshot, "schema_version": 1})
    local("local-duplicate-field", '{"schema_version":2,"schema_version":2,"issued_at_unix_ms":1000,"roster_version":7,"identities":[]}')
    local("local-invalid-key", {**snapshot, "identities": [{"identity": "invalid", "class": "ordinary_node"}]})
    # Refusal bytes are generated independently, including complete-but-invalid sets.
    def refuse(name, kind, value):
        vector(name, kind, value)
        out[-1].append(("expect", "reject"))

    refuse("registry-missing-family", "registry", [1, entries[:-1]])
    for name, tag, before, after in [
        ("rotation-changes-identity", 1, binding, [1, b, bytes([4]) * 32, 5]),
        ("rotation-stale-generation", 1, binding, [1, a, bytes([4]) * 32, 4]),
        ("rotation-changes-derivation", 1, binding, [2, a, bytes([4]) * 32, 5]),
        ("replacement-same-identity", 0, binding, [2, a, bytes([4]) * 32, 1]),
        ("replacement-stale-version", 0, binding, [1, b, bytes([4]) * 32, 1]),
        ("replacement-same-k", 0, binding, [2, b, bytes([3]) * 32, 1]),
    ]:
        refuse(name, "lifecycle", [1, tag, before, after, bytes([5]) * 16, bytes([6]) * 16])
    l3 = [1, a, b, 1, [[namespace, sorted([a, b])]], [[namespace, a, b, 6, 443, 443]]]
    for name, index, value in [("l3-missing-scope", 4, []), ("l3-duplicate-scope", 4, l3[4] * 2),
                               ("l3-duplicate-rule", 5, l3[5] * 2),
                               ("l3-duplicate-member", 4, [[namespace, [a, a]]]),
                               ("l3-unsorted-members", 4, [[namespace, sorted([a, b], reverse=True)]])]:
        changed = copy.deepcopy(l3)
        changed[index] = value
        refuse(name, "l3", changed)
    for name, index, value in [("l3-unknown-protocol", 3, 1), ("l3-zero-port", 4, 0),
                               ("l3-reversed-ports", 4, 444), ("l3-large-port", 5, 65536)]:
        changed = copy.deepcopy(l3)
        changed[5][0][index] = value
        refuse(name, "l3", changed)
    unit = [1, 0, 0, bytes([8]) * 16, bytes([9]) * 16, bytes([5]) * 16, bytes([6]) * 16, 1234, None]
    for name, index, value in [("usage-unknown-boundary", 1, 2), ("usage-unknown-direction", 2, 2),
                               ("usage-untyped-window", 8, 0)]:
        changed = copy.deepcopy(unit)
        changed[index] = value
        refuse(name, "usage", changed)
    refuse("usage-missing-window", "usage", unit[:-1])
    return out
