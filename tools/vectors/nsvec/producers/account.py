"""Independent L8 account candidate contracts; Python standard library only."""

import base64
import copy
import hashlib
import json

from .. import cbor
from . import bootstrap_envelope, enrollment, participant_roster, publication, subnet

CRATE = "nsshared-proto"
GROUP = "account"
TITLE = "L8 account payload candidate contracts"
SECTIONS = "repository docs/l8-account-payload-profile.md"

# RFC 8032 arithmetic, kept independent of the Rust implementation.
Q = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, Q - 2, Q) % Q


def point(x, y):
    return x, y, 1, x * y % Q


def add(p, q):
    x, y, z, t = p
    u, v, w, s = q
    a, b = (y - x) * (v - u) % Q, (y + x) * (v + u) % Q
    c, d = 2 * D * t * s % Q, 2 * z * w % Q
    e, f, g, h = b - a, d - c, d + c, b + a
    return e * f % Q, g * h % Q, f * g % Q, e * h % Q


def multiply(p, scalar):
    result = point(0, 1)
    while scalar:
        if scalar & 1:
            result = add(result, p)
        p = add(p, p)
        scalar >>= 1
    return result


def packed(p):
    x, y, z, _ = p
    inverse = pow(z, Q - 2, Q)
    x, y = x * inverse % Q, y * inverse % Q
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


Y = 4 * pow(5, Q - 2, Q) % Q
X2 = (Y * Y - 1) * pow(D * Y * Y + 1, Q - 2, Q) % Q
X = pow(X2, (Q + 3) // 8, Q)
if X * X % Q != X2:
    X = X * pow(2, (Q - 1) // 4, Q) % Q
BASE = point(X if X % 2 == 0 else Q - X, Y)


def key(seed):
    digest = hashlib.sha512(seed).digest()
    scalar = int.from_bytes(digest[:32], "little") & ((1 << 254) - 8) | (1 << 254)
    return packed(multiply(BASE, scalar)), scalar, digest[32:]


def sign(seed, message):
    public, scalar, prefix = key(seed)
    nonce = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % L
    encoded = packed(multiply(BASE, nonce))
    challenge = int.from_bytes(hashlib.sha512(encoded + public + message).digest(), "little") % L
    return encoded + ((nonce + challenge * scalar) % L).to_bytes(32, "little")


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
    # Calibrate the independent signer using RFC 8032 test 1 before producing signatures.
    seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    assert key(seed)[0].hex() == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    assert sign(seed, b"").hex() == ("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f"
                                  "b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
    a, b = key(bytes([1]) * 32)[0], key(bytes([2]) * 32)[0]
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
        encoded = cbor.encode(value)
        signature = sign(bytes([1]) * 32, b"ns.account.roster.v1\0" + encoded)
        if corrupt:
            signature = bytes([signature[0] ^ 1]) + signature[1:]
        out.append([("name", name), ("kind", "signed-roster"), ("bytes", cbor.encode([encoded, signature])), ("expect", expect)])

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
    out.extend(bootstrap_envelope.vectors(a, b, sign))
    out.extend(enrollment.vectors(a, b))
    out.extend(participant_roster.vectors(a, b, sign))
    out.extend(subnet.vectors(a, b))
    out.extend(publication.vectors(a, b, sign))
    return out
