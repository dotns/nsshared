"""Node-local IPv4 alias candidates H22(I, kind, i) in the default pool (quick-v2 §2.2, §6.2)."""

from .. import derive
from .identities import IDENTITY_LABELS

CRATE = "nsshared-wire"
GROUP = "alias4"
TITLE = "NS v2 IPv4 alias candidates in the default pool 100.64.0.0/10"
SECTIONS = "ns/quick-v2.md §2.2, §6.2"


def vectors():
    out = []
    pool = derive.DEFAULT_POOL
    for name, label in IDENTITY_LABELS[:3]:
        ident = derive.identity(derive.seed(label))
        for kind in derive.ALIAS_KINDS:
            vector = [("name", f"{name}-kind-{kind}"), ("identity", ident), ("kind", kind), ("pool", str(pool))]
            for index in range(derive.ALIAS_CANDIDATES):
                h22 = derive.alias_h22(ident, kind, index)
                candidate = derive.alias_candidate(ident, kind, index)
                assert h22 < 2**22 and candidate in pool
                vector += [("index", index), ("h22", h22), ("candidate", str(candidate))]
            out.append(vector)
    ident = derive.identity(derive.seed(IDENTITY_LABELS[0][1]))
    for name, kind, index, reason in [
        ("reject-kind-0", 0, 0, "invalid_kind"),
        ("reject-kind-5", 5, 0, "invalid_kind"),
        ("reject-kind-46", 46, 0, "invalid_kind"),
        ("reject-index-16", 4, 16, "invalid_index"),
        ("reject-index-255", 6, 255, "invalid_index"),
    ]:
        out.append(
            [
                ("name", name),
                ("identity", ident),
                ("kind", kind),
                ("index", index),
                ("expect", "reject"),
                ("reason", reason),
            ]
        )
    return out
