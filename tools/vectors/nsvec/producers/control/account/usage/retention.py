"""Independent participant retention seal and acknowledgement contracts."""
import copy
import hashlib

from nsvec import cbor
from nsvec.ed25519 import public_key

CRATE = "nsshared-control"
GROUP = "account/usage/retention"
TITLE = "Participant retention seals and acknowledgements"
SPEC = "docs/spec/account/usage.md"
EXTERNAL = None
DOMAIN = b"ns.account.retention.seal.v1\0"


def vectors():
    issuer, recipient = [public_key(bytes([i]) * 32) for i in (1, 2)]
    parts = [
        [bytes([6]) * 16, "l8-completed-io-v1", 1, 0, bytes([10]) * 32],
        [bytes([6]) * 16, "l8-relay-data-v1", 1, 0, bytes([11]) * 32],
        [bytes([6]) * 16, "l8-relay-data-v1", 1, 1, bytes([12]) * 32],
        [bytes([6]) * 16, "l8-relay-data-v1", 2, 0, bytes([13]) * 32],
        [bytes([7]) * 16, "l8-relay-data-v1", 1, 0, bytes([14]) * 32],
    ]
    seal = [1, 9, 2, issuer, recipient, 3, 7, parts]
    out = []

    def emit(name, kind, value, decision="accept", raw=None, **extra):
        encoded = cbor.encode(value) if raw is None else raw
        if kind == "seal" and decision == "accept":
            extra["digest"] = hashlib.sha256(DOMAIN + encoded).digest()
        out.append([("name", name), ("kind", kind), ("bytes", encoded),
                    ("decision", decision), *extra.items()])

    for name, manifest in [("populated", parts), ("empty", [])]:
        value = seal[:7] + [manifest]
        digest = hashlib.sha256(DOMAIN + cbor.encode(value)).digest()
        emit(name, "seal", value)
        for outcome in range(5):
            emit(f"{name}-outcome-{outcome}", "ack",
                 [1, 9, 3, issuer, recipient, 3, 7, digest, outcome], seal=name)
    for name, index, value in [
        ("schema", 0, 2), ("family", 1, 8), ("kind", 2, 0),
        ("issuer-width", 3, issuer[:-1]), ("recipient-width", 4, recipient[:-1]),
        ("zero-generation", 5, 0), ("zero-epoch", 6, 0),
        ("unsorted", 7, parts[::-1]), ("duplicate", 7, [parts[0], parts[0]]),
    ]:
        changed = copy.deepcopy(seal)
        changed[index] = value
        emit(name, "seal", changed, "reject")
    for name, index, value in [
        ("incarnation-width", 0, bytes(15)), ("unknown-profile", 1, "unknown"),
        ("zero-sequence", 2, 0), ("index-bound", 3, 8192),
        ("digest-width", 4, bytes(31)),
    ]:
        changed = copy.deepcopy(seal)
        changed[7][0][index] = value
        emit(name, "seal", changed, "reject")
    changed = copy.deepcopy(seal)
    changed[7] = [parts[0], parts[0][:4] + [bytes(32)]]
    emit("duplicate-key-other-digest", "seal", changed, "reject")
    digest = hashlib.sha256(DOMAIN + cbor.encode(seal)).digest()
    ack = [1, 9, 3, issuer, recipient, 3, 7, digest, 0]
    for index, value in [(0, 2), (1, 8), (2, 2), (3, issuer[:-1]),
                         (4, recipient[:-1]), (5, 0), (6, 0), (7, bytes(31)), (8, 5)]:
        changed = copy.deepcopy(ack)
        changed[index] = value
        emit(f"invalid-ack-{index}", "ack", changed, "reject")
    for kind, value in [("seal", seal), ("ack", ack)]:
        raw = cbor.encode(value)
        for name, encoded in [("trailing", raw + b"\0"), ("truncated", raw[:-1]),
                              ("nonminimal", raw[:1] + b"\x18\x01" + raw[2:]),
                              ("indefinite", b"\x9f" + raw[1:] + b"\xff")]:
            emit(f"{kind}-{name}", kind, None, "reject", raw=encoded)
    # A declared oversized collection is rejected before reading or allocating parts.
    empty = cbor.encode(seal[:7] + [[]])
    emit("collection-bound", "seal", None, "reject", raw=empty[:-1] + b"\x99\x20\x01")
    return out
