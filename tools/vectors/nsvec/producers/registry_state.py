"""Record and registry state: the §3.3 summary, export as RecordState / RegistryState,
member merge and restore refutations (quick-v2 §3.3, §7.2, §7.6)."""

from .. import cbor
from . import node_records
from .node_records import Signer, sign

CRATE = "nsshared-proto"
GROUP = "registry_state"
TITLE = "NS v2 record and registry state summaries, merges and restore refutations"
SECTIONS = "ns/quick-v2.md §3.3, §7.2, §7.6"

STATE_VERSION = 1
TIER_BITS = {"none": 1, "address": 2, "record": 4}
ISSUED = node_records.ISSUED_AT
NOW = ISSUED + 3600


class Rec:
    def __init__(self, signer, gen, wg_label, issued_at, relays=()):
        keyed = Signer(signer.seed_label, wg_label)  # same identity, WireGuard key K from wg_label
        self.gen = gen
        self.k = keyed.wg_key
        self.issued_at = issued_at
        *_, self.bytes = sign(keyed, gen, issued_at, issued_at + 604800, list(relays))

    def rank(self):
        return (self.issued_at, self.bytes)


def summary(records):
    """§3.3: R is the largest record of the highest generation by (issued_at, bytes);
    E the largest of that generation whose K differs from R's, or none."""
    if not records:
        return None, None
    top = max(r.gen for r in records)
    pool = [r for r in records if r.gen == top]
    current = max(pool, key=Rec.rank)
    others = [r for r in pool if r.k != current.k]
    return current, (max(others, key=Rec.rank) if others else None)


def record_state(identity, current, evidence):
    return cbor.encode(
        [STATE_VERSION, identity, current.bytes if current else None, evidence.bytes if evidence else None]
    )


def registry_state(identity, current, evidence, rev, tiers):
    record = [STATE_VERSION, identity, current.bytes if current else None, evidence.bytes if evidence else None]
    return cbor.encode([STATE_VERSION, record, rev[0], rev[1], tiers])


def merge_tiers(a, b):
    """§7.6: the larger revision wins; equal revisions OR their tiers."""
    (rev_a, tiers_a), (rev_b, tiers_b) = a, b
    if tiers_a == 0:
        return b
    if tiers_b == 0:
        return a
    if rev_a != rev_b:
        return max(a, b)
    return rev_a, tiers_a | tiers_b


def records_vector(name, records, kind):
    vector = [("name", name), ("kind", kind), ("record_count", len(records))]
    vector += [(f"record_{i}", r.bytes) for i, r in enumerate(records)]
    return vector


def vectors():
    signer = Signer("ns-state-node-v2", "ns-state-wg-1")
    identity = signer.identity
    foreign = Signer("ns-state-foreign-v2", "ns-state-wg-1")
    k1, k2, k3 = "ns-state-wg-1", "ns-state-wg-2", "ns-state-wg-3"
    r = {
        "g1": Rec(signer, 1, k1, ISSUED),
        "g2a": Rec(signer, 2, k1, ISSUED + 10),
        "g2a_late": Rec(signer, 2, k1, ISSUED + 30),
        "g2a_relay": Rec(signer, 2, k1, ISSUED + 10, [node_records.HOME_RELAY]),
        "g2b": Rec(signer, 2, k2, ISSUED + 20),
        "g2c": Rec(signer, 2, k3, ISSUED + 5),
        "g3": Rec(signer, 3, k2, ISSUED + 40),
    }
    out = []

    cases = [
        ("summary-single", ["g1"]),
        ("summary-advance", ["g1", "g2a"]),
        ("summary-stale-ignored", ["g2a", "g1"]),
        ("summary-refresh", ["g2a", "g2a_late"]),
        ("summary-equal-issued-at-bytes-decide", ["g2a", "g2a_relay"]),
        ("summary-conflict-keeps-evidence", ["g2a", "g2b"]),
        ("summary-conflict-three-keys", ["g2a", "g2b", "g2c"]),
        ("summary-conflict-then-refresh", ["g2a", "g2b", "g2a_late"]),
        ("summary-higher-gen-clears-conflict", ["g2a", "g2b", "g3"]),
    ]
    for name, keys in cases:
        records = [r[k] for k in keys]
        current, evidence = summary(records)
        out.append(
            records_vector(name, records, "summary")
            + [("state", record_state(identity, current, evidence)), ("conflicted", 1 if evidence else 0)]
        )

    merges = [
        ("merge-disjoint-keys", ["g2a"], ["g2b"]),
        ("merge-evidence-and-refresh", ["g2a", "g2c"], ["g2a_late"]),
        ("merge-higher-gen-wins", ["g2a", "g2b"], ["g3"]),
        ("merge-with-empty", ["g2a_late"], []),
    ]
    for name, left, right in merges:
        a, b = summary([r[k] for k in left]), summary([r[k] for k in right])
        merged = summary([r[k] for k in left + right])
        out.append(
            [
                ("name", name),
                ("kind", "merge"),
                ("state_a", record_state(identity, *a)),
                ("state_b", record_state(identity, *b)),
                ("state", record_state(identity, *merged)),
            ]
        )

    rev_a = (2, ISSUED + 10)
    rev_late = (2, ISSUED + 30)
    tier_merges = [
        ("tiers-equal-revision-union", ["g2a"], (rev_a, TIER_BITS["record"]), ["g2a"], (rev_a, TIER_BITS["none"])),
        ("tiers-larger-revision-wins", ["g2a"], (rev_a, TIER_BITS["record"] | TIER_BITS["none"]), ["g2a_late"], (rev_late, TIER_BITS["address"])),
        ("tiers-unpublished-side", ["g2a"], (rev_a, TIER_BITS["address"]), ["g2a"], ((0, 0), 0)),
    ]
    for name, left, pa, right, pb in tier_merges:
        a, b = summary([r[k] for k in left]), summary([r[k] for k in right])
        merged = summary([r[k] for k in left + right])
        rev, tiers = merge_tiers(pa, pb)
        out.append(
            [
                ("name", name),
                ("kind", "registry_merge"),
                ("now", NOW),
                ("state_a", registry_state(identity, *a, *pa)),
                ("state_b", registry_state(identity, *b, *pb)),
                ("state", registry_state(identity, *merged, rev, tiers)),
            ]
        )

    g2a, g2b, g2c, g1 = r["g2a"], r["g2b"], r["g2c"], r["g1"]
    other = Rec(foreign, 2, k2, ISSUED + 5)
    refutations = [
        ("restore-version-2", cbor.encode([2, identity, g2a.bytes, None]), "version"),
        ("restore-foreign-record", cbor.encode([1, identity, other.bytes, None]), "identity"),
        ("restore-evidence-without-record", cbor.encode([1, identity, None, g2b.bytes]), "evidence"),
        ("restore-evidence-same-key", cbor.encode([1, identity, r["g2a_late"].bytes, g2a.bytes]), "evidence"),
        ("restore-evidence-larger", cbor.encode([1, identity, g2c.bytes, g2b.bytes]), "evidence"),
        ("restore-evidence-other-gen", cbor.encode([1, identity, g2a.bytes, g1.bytes]), "evidence"),
    ]
    for name, encoded, reason in refutations:
        out.append([("name", name), ("kind", "restore"), ("state", encoded), ("expect", "reject"), ("reason", reason)])
    registry_refutations = [
        ("restore-tiers-high-bit", registry_state(identity, g2a, None, rev_a, 8)),
        ("restore-tiers-without-revision", registry_state(identity, g2a, None, (0, 0), 1)),
        ("restore-revision-without-tiers", registry_state(identity, g2a, None, rev_a, 0)),
        ("restore-tiers-without-record", registry_state(identity, None, None, rev_a, 1)),
    ]
    for name, encoded in registry_refutations:
        out.append(
            [("name", name), ("kind", "registry_restore"), ("state", encoded), ("expect", "reject"), ("reason", "tiers")]
        )
    return out
