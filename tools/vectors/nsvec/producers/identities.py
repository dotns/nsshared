"""Identity derivations: node ID, address group, N6 and N4 (quick-v2 §2.1-§2.3)."""

import base64

from .. import derive, x25519

CRATE = "ns-wire"
GROUP = "identities"
TITLE = "NS v2 identities: node ID, address group g, N6 and N4"
SECTIONS = "ns/quick-v2.md §2.1, §2.2, §2.3"

# Seed labels; seed = SHA-256(label). The first is the quick-v2 §2.3 demo identity.
IDENTITY_LABELS = [
    ("demo", "ns-demo-node-v2"),
    ("vector-1", "ns-vector-identity-1"),
    ("vector-2", "ns-vector-identity-2"),
    ("vector-3", "ns-vector-identity-3"),
    ("vector-4", "ns-vector-identity-4"),
]
DEMO_WG_LABEL = "ns-demo-wg-v2"

# Literal values printed in quick-v2 §2.3.
DEMO_LITERALS = {
    "I": "x9wqBt4ZKdMxi43oc78ScDDD7gAH8g4G6g_FQFZ0Wvs",
    "K": "NZkMHL1XEJhrcG68XIzeUZktuR/U1aR2e6u2dcRMzDk=",
    "node_id": "5kemem6slxrgyd63rcqa",
    "N6": "fda6:72ac:58cb:cc8d:1e39:e507:bda:5052",
    "N4": "fda6:72ac:58cb:cc8d:1e39:e507:bda:5053",
}


def b64url(data):
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def identity_vector(name, label):
    seed = derive.seed(label)
    ident = derive.identity(seed)
    raw_id = derive.node_id(ident)
    n6, n4 = derive.node_addr(ident, 0), derive.node_addr(ident, 1)
    return [
        ("name", name),
        ("seed_label", label),
        ("seed", seed),
        ("identity", ident),
        ("identity_b64url", b64url(ident)),
        ("node_id", raw_id),
        ("node_id_text", derive.node_id_text(raw_id)),
        ("g", derive.group_g(ident).to_bytes(15, "big")),
        ("n6", n6),
        ("n6_text", derive.ipv6_text(n6)),
        ("n4", n4),
        ("n4_text", derive.ipv6_text(n4)),
    ]


def vectors():
    out = [identity_vector(name, label) for name, label in IDENTITY_LABELS]
    demo = dict(out[0])
    wg_seed = derive.seed(DEMO_WG_LABEL)
    wg_key = x25519.public_key(wg_seed)
    out[0] += [
        ("wg_seed_label", DEMO_WG_LABEL),
        ("wg_seed", wg_seed),
        ("wg_key", wg_key),
        ("wg_key_b64", base64.b64encode(wg_key).decode("ascii")),
    ]
    actual = {
        "I": demo["identity_b64url"],
        "K": base64.b64encode(wg_key).decode("ascii"),
        "node_id": demo["node_id_text"],
        "N6": demo["n6_text"],
        "N4": demo["n4_text"],
    }
    for key, literal in DEMO_LITERALS.items():
        if actual[key] != literal:
            raise AssertionError(f"quick-v2 §2.3 {key}: derived {actual[key]}, spec says {literal}")
    return out
