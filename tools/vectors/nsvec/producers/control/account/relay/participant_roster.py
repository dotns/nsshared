"""Signed participant generations and supplied-clock decisions, independent of Rust."""

from nsvec import cbor
from nsvec import ed25519
from nsvec.producers.control.account import profile

CRATE = "nsshared-control"
GROUP = "account/relay/participant-roster"
TITLE = "Participant rosters"
SPEC = "docs/spec/account/relay.md"
EXTERNAL = None

DAY_MS = 86_400_000
DOMAIN = b"ns.account.roster.v1\0"


def vectors():
    return _vectors(*profile.keys(), ed25519.sign)


def _vectors(a, b, sign):
    entries = sorted([[a, 0], [b, 1]])
    baseline = [1, a, b, 7, 1000, 1000 + 3 * DAY_MS, entries]
    out = []

    def carrier(content, corrupt=False):
        raw = cbor.encode(content)
        seed = bytes([1 if content[1] == a else 2]) * 32
        signature = sign(seed, DOMAIN + raw)
        if corrupt:
            signature = bytes([signature[0] ^ 1]) + signature[1:]
        return cbor.encode([raw, signature])

    def emit(name, content=baseline, decision="accepted", last=6, now=1000,
             previous=None, status="valid", status_now=None, renewal=1000,
             corrupt=False, raw=None, last_epoch=None):
        canonical = carrier(content, corrupt)
        wire = canonical if raw is None else raw
        fields = [("name", "participant-roster-" + name), ("kind", "participant-roster"),
                  ("bytes", wire), ("canonical", canonical), ("content", cbor.encode(content)),
                  ("issuer", a), ("recipient", b), ("last_version", last),
                  ("now_ms", now), ("decision", decision),
                  ("expect", "accept" if decision == "accepted" else "reject")]
        if last_epoch is not None:
            fields.append(("last_epoch", last_epoch))
        if previous is not None:
            fields.extend([("previous", carrier(previous)), ("previous_now_ms", 1000),
                           ("previous_last_version", previous[3] - 1)])
        accepted = content if decision == "accepted" else previous
        if accepted is not None:
            offset = 1 if accepted[0] == 2 else 0
            mapping = ",".join(identity.hex() + ":" + str(cls) for identity, cls in accepted[6 + offset])
            if offset:
                fields.append(("generation_epoch", accepted[4]))
            fields.extend([("generation_issuer", accepted[1]),
                           ("generation_recipient", accepted[2]),
                           ("generation_version", accepted[3]),
                           ("generation_issued_ms", accepted[4 + offset]),
                           ("generation_deadline_ms", accepted[5 + offset]),
                           ("generation_mapping", mapping or "empty"),
                           ("last_renewal_ms", renewal),
                           ("status_now_ms", now if status_now is None else status_now),
                           ("status", status)])
        out.append(fields)

    emit("accepted")
    # Each replacement is verified after a separately signed complete predecessor.
    emit("complete-empty", baseline[:3] + [8] + baseline[4:6] + [[]],
         previous=baseline, last=7)
    emit("revocation", baseline[:3] + [8] + baseline[4:6] + [[[b, 1]]],
         previous=baseline, last=7)
    emit("class-only-change", baseline[:3] + [8] + baseline[4:6] +
         [[[identity, 1 - cls] for identity, cls in entries]], previous=baseline, last=7)
    emit("wrong-issuer", [1, b, b, 8] + baseline[4:], "wrong-issuer", previous=baseline, last=7)
    emit("wrong-recipient", [1, a, a, 8] + baseline[4:], "wrong-recipient",
         previous=baseline, last=7)
    emit("stale-version", baseline[:3] + [6] + baseline[4:], "stale-version",
         previous=baseline, last=7)
    emit("equal-version", decision="stale-version", previous=baseline, last=7)
    emit("future-issue", now=999, decision="future-issue")
    deadline = baseline[5]
    emit("before-expiry", now=deadline - 1, status="degraded")
    emit("at-expiry", now=deadline, decision="expired",
         previous=baseline[:3] + [6] + baseline[4:], status="expired")
    # Renewal differs from issue time so the clock consumer cannot substitute issue time.
    emit("before-degradation", renewal=5000, status_now=5000 + DAY_MS - 1)
    emit("at-degradation", renewal=5000, status_now=5000 + DAY_MS, status="degraded")
    emit("renewed", renewal=2 * DAY_MS, status_now=2 * DAY_MS + 1)
    emit("renewal-does-not-extend-expiry", renewal=deadline - 1,
         status_now=deadline, status="expired")
    emit("minimum-lifetime", baseline[:5] + [1000 + DAY_MS, entries])
    emit("short-lifetime", baseline[:5] + [1000 + DAY_MS - 1, entries], "short-lifetime")
    emit("reversed-lifetime", baseline[:5] + [999, entries], "short-lifetime")
    emit("bad-signature", baseline[:3] + [8] + baseline[4:], decision="bad-signature",
         corrupt=True, previous=baseline, last=7)
    emit("missing-class", baseline[:6] + [[[a]]], "missing-class")
    emit("duplicate-class", baseline[:6] + [[[a, 0, 1]]], "duplicate-class")
    emit("unknown-class", baseline[:6] + [[[a, 2]]], "unknown-class")
    emit("duplicate-identity", baseline[:6] + [[entries[0], entries[0]]], "duplicate-identity")
    emit("unsorted-identities", baseline[:6] + [list(reversed(entries))], "invalid-field")
    emit("zero-version", baseline[:3] + [0] + baseline[4:], "invalid-field")
    valid = carrier(baseline)
    emit("trailing", decision="trailing-bytes", raw=valid + b"\0")
    emit("nonminimal-carrier", decision="non-shortest", raw=b"\x98\x02" + valid[1:])
    separate = [2, a, b, 7, 3, 1000, 1000 + 3 * DAY_MS, entries]
    repeated = separate[:3] + [8] + separate[4:]
    emit("legacy-to-separate", separate[:3] + [8, 7] + separate[5:],
         previous=baseline, last=7, last_epoch=7)
    emit("separate-epoch", separate, last_epoch=3)
    emit("repeated-epoch", repeated, previous=separate, last=7, last_epoch=3)
    emit("repeated-epoch-again", separate[:3] + [9] + separate[4:],
         previous=repeated, last=8, last_epoch=3)
    emit("new-epoch", separate[:3] + [9, 4] + separate[5:],
         previous=repeated, last=8, last_epoch=3)
    emit("epoch-above-version", separate[:4] + [100] + separate[5:], last_epoch=99)
    emit("epoch-decrease", separate[:3] + [8, 2] + separate[5:], "epoch-decrease",
         previous=separate, last=7, last_epoch=3)
    high_epoch = separate[:4] + [100] + separate[5:]
    emit("legacy-epoch-decrease", baseline[:3] + [8] + baseline[4:], "epoch-decrease",
         previous=high_epoch, last=7, last_epoch=100)
    emit("zero-epoch", separate[:4] + [0] + separate[5:], "invalid-field", last_epoch=0)
    emit("epoch-does-not-bypass-version", separate[:4] + [100] + separate[5:],
         "stale-version", previous=separate, last=7, last_epoch=3)
    encoded = cbor.encode(separate)
    # The epoch follows the schema, both 32-byte keys and publication version.
    epoch_offset = len(cbor.encode(separate[:4]))
    nonminimal = encoded[:epoch_offset] + b"\x18\x03" + encoded[epoch_offset + 1:]
    emit("nonminimal-epoch", separate, "non-shortest", last_epoch=3,
         raw=cbor.encode([nonminimal, sign(bytes([1]) * 32, DOMAIN + nonminimal)]))
    changed = cbor.encode(separate[:4] + [4] + separate[5:])
    emit("epoch-signature-tampering", separate, "bad-signature", last_epoch=3,
         raw=cbor.encode([changed, sign(bytes([1]) * 32, DOMAIN + encoded)]))
    return out
