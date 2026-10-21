"""Independent canonical realm identities and membership-versus-route inputs."""
import copy
import json
from .. import cbor
from . import account, public_edge, confidential_auth, publication_subscription, publication_snapshot_request
from .publication import DOMAIN

CRATE = "nsshared-proto"
GROUP = "realm-identity-membership"
TITLE = "Canonical realm identity and independent membership authority"
SECTIONS = "docs/canonical-realm-identity.md"
A = "030C1G60R30C1G60R30C1G60R3"
B = "09144GJ289144GJ289144GJ289"
A_BYTES = bytes.fromhex("03030303030303030303030303030303")
B_BYTES = bytes.fromhex("09090909090909090909090909090909")


def vectors():
    out = []
    def emit(name, kind, raw, **extra):
        out.append([("name", name), ("kind", kind), ("bytes", raw), *extra.items()])
    for name, text, binary in [("A", A, A_BYTES), ("B", B, B_BYTES),
            ("zero", "0" * 26, bytes(16)), ("maximum", "7" + "Z" * 25, bytes([255]) * 16),
            ("published-ulid", "01ARZ3NDEKTSV4RRFFQ69G5FAV", bytes.fromhex("01563e3ab5d3d6764c61efb99302bd5b"))]:
        emit(name, "identity", binary, text=text)
    issuer, recipient = account.key(bytes([1]) * 32)[0], account.key(bytes([2]) * 32)[0]
    def signed(payload, version, family=2, kind="realm-peers", channel=1, served=A):
        content = cbor.encode([1, issuer, recipient, served, "collection", family, kind,
                               channel, True, version, 100, 200, 0, payload])
        return cbor.encode([content, account.sign(bytes([1]) * 32, DOMAIN + content)])
    edge_vectors = {dict(v)["name"]: dict(v)["bytes"] for v in public_edge.vectors()}
    edge = cbor.decode(edge_vectors["two-networks"])
    edge[2:4] = [A, "collection"]
    membership = cbor.encode([1, 2, [[A, []]]])
    emit("membership-A", "membership-event", signed(membership, 1))
    emit("routes-A-B", "edge-event", signed(cbor.encode(edge), 1, 7, "public-edge", 0))
    emit("membership-removed", "membership-event", signed(cbor.encode([1, 2, []]), 2))
    # Explicit expected decisions for consumers; route publication stays valid.
    emit("before-removal", "decisions", b"\x01", admitted=A_BYTES, refused=B_BYTES)
    emit("after-removal", "decisions", b"\x00", refused=A_BYTES)
    auth = {dict(v)["name"]: dict(v) for v in confidential_auth.vectors()}
    request = next(cbor.decode(v["bytes"]) for v in auth.values() if v["kind"] == "request")
    subscription = cbor.decode(dict(publication_subscription.vectors()[0])["bytes"])
    snapshot = cbor.decode(dict(publication_snapshot_request.vectors()[0])["bytes"])
    bad = [("lowercase", A.lower()), ("short", A[:-1]), ("long", A + "0"),
           ("overflow", "8" + A[1:]), ("separator", A[:12] + "-" + A[13:]),
           ("space", " " + A[1:]), ("trailing-space", A + " "), ("newline", A[:-1] + "\n"),
           ("old-label", "realm-a")]
    bad += [("alternate-" + char, A[:-1] + char) for char in "ILOU"]
    for name, text in bad:
        emit(name + "-membership", "membership", cbor.encode([1, 2, [[text, []]]]))
        emit(name + "-publication", "publication", signed(membership, 3, served=text))
        changed = copy.deepcopy(edge); changed[2] = text
        emit(name + "-edge", "edge", cbor.encode(changed))
        ack = cbor.decode(edge_vectors["installed"]); ack[2] = text
        emit(name + "-ack", "ack", cbor.encode(ack))
        changed = copy.deepcopy(request); changed[3] = text
        emit(name + "-auth-request", "auth-request", cbor.encode(changed))
        for kind, template in [("subscription", subscription), ("snapshot", snapshot)]:
            changed = copy.deepcopy(template); changed[2][0][2] = text
            emit(name + "-" + kind, kind, cbor.encode(changed))
        claims = dict(iss="issuer", sub="machine", realm=text, iat=100, exp=200, jti="token")
        emit(name + "-claims", "claims", json.dumps(claims, separators=(",", ":")).encode())
    return out
