"""Independent complete Node posture snapshots and correlated receipts."""
import copy
from nsvec import cbor, ed25519
from nsvec.producers.control.account.control import envelope

CRATE = "nsshared-control"
GROUP = "account/control/node-posture"
TITLE = "Ordinary Node posture"
SPEC = "docs/spec/account/control.md"
EXTERNAL = None


def vectors():
    scope = [bytes([3]) * 16, bytes([4]) * 16]
    fence = [bytes([5]) * 16, 6, 7]
    request_id = bytes([8]) * 16
    snapshot = ["linux", "Ubuntu 24.04", "x86_64", "1.2.3", "node-one",
                "encrypted", 123, ["192.0.2.1", "2001:db8::1"]]
    request = [1, scope, fence, request_id, snapshot]
    receipt = [1, scope, fence, request_id]
    out = []

    def emit(name, value, direction=0, error="none"):
        out.append([("name", name), ("direction", direction),
                    ("bytes", cbor.encode(value)), ("error", error)])

    emit("full", request)
    emit("receipt", receipt, 1)
    for status in ["encrypted", "unencrypted", "unknown"]:
        changed = copy.deepcopy(request)
        changed[4][5] = status
        emit(status, changed)
    changed = copy.deepcopy(request)
    changed[4][7] = []
    emit("empty-ips", changed)
    changed = copy.deepcopy(request)
    changed[4] = [""] * 5 + ["unknown", 0, []]
    emit("empty-facts", changed)
    changed = copy.deepcopy(request)
    changed[4] = ["é" * 512] * 5 + ["unknown", 0xffffffffffffffff,
                    ["ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255"] * 256]
    emit("at-bounds", changed)
    for index in range(5):
        changed = copy.deepcopy(request)
        changed[4][index] = "é" * 512 + "x"
        emit(f"text-over-bound-{index}", changed, error="cbor")
    for name, index, value, error in [
        ("unknown-encryption", 5, "other", "field"),
        ("ips-over-bound", 7, ["192.0.2.1"] * 257, "cbor"),
        ("ip-text-over-bound", 7, ["a" * 46], "cbor"),
        ("invalid-ip", 7, ["invalid"], "field"),
    ]:
        changed = copy.deepcopy(request)
        changed[4][index] = value
        emit(name, changed, error=error)
    changed = copy.deepcopy(request)
    changed[4].append(0)
    emit("snapshot-arity", changed, error="cbor")
    for direction, value in enumerate([request, receipt]):
        emit(f"arity-{direction}", value + [0], direction, "cbor")
        changed = copy.deepcopy(value)
        changed[0] = 2
        emit(f"version-{direction}", changed, direction, "field")
        for index, replacement in enumerate([bytes(16), 0, 0]):
            changed = copy.deepcopy(value)
            changed[2][index] = replacement
            emit(f"fence-{direction}-{index}", changed, direction, "field")
    for name, path, value in [
        ("nsd", [1, 0], bytes([9]) * 16),
        ("network", [1, 1], bytes([9]) * 16),
        ("runtime", [2, 0], bytes([9]) * 16),
        ("generation", [2, 1], 8), ("epoch", [2, 2], 8),
        ("request-id", [3], bytes([9]) * 16),
    ]:
        changed = copy.deepcopy(receipt)
        target = changed
        for index in path[:-1]:
            target = target[index]
        target[path[-1]] = value
        emit("mismatch-" + name, changed, 1, "correlation")
    node = ed25519.public_key(bytes([1]) * 32)
    authority = ed25519.public_key(bytes([2]) * 32)
    content = cbor.encode([1, 0, node, authority, "node.posture", 100,
                           request_id, cbor.encode(request)])
    out.append([("name", "envelope"), ("direction", 0), ("error", "envelope"),
                ("bytes", cbor.encode([content, ed25519.sign(bytes([1]) * 32, envelope.REQUEST + content)])),
                ("pin", envelope.pin(node)), ("subject", node), ("authority", authority)])
    return out
