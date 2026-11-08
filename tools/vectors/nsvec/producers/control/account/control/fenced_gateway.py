"""Independent fenced gateway observations and correlated receipts."""
import copy
from nsvec import cbor, ed25519
from nsvec.producers.control.account.control import envelope

CRATE = "nsshared-control"
GROUP = "account/control/fenced-gateway"
TITLE = "Fenced gateway reports"
SPEC = "docs/spec/account/control.md"
EXTERNAL = None


def vectors():
    scope = [bytes([3]) * 16, bytes([4]) * 16]
    fence = [bytes([5]) * 16, 6, 7]
    request_id = bytes([8]) * 16
    report = [2, request_id, "1.0", "abcdef", 0, False, 443, 8080,
              False, ["node.control"], ["edge.http"], [], None, None]
    request = [1, scope, fence, cbor.encode(report)]
    receipt = [1, scope, fence, cbor.encode([2, request_id, None, None])]
    out = []

    def emit(name, value, direction=0, error="none"):
        out.append([("name", name), ("direction", direction),
                    ("bytes", cbor.encode(value)), ("error", error)])

    emit("full", request)
    emit("receipt", receipt, 1)
    drain = copy.deepcopy(report)
    drain[8] = True
    emit("drain", [1, scope, fence, cbor.encode(drain)])
    for direction, value in enumerate([request, receipt]):
        emit(f"arity-{direction}", value + [0], direction, "cbor")
        changed = copy.deepcopy(value)
        changed[0] = 2
        emit(f"version-{direction}", changed, direction, "field")
        for index in [1, 2]:
            changed = copy.deepcopy(value)
            changed[index] = None
            emit(f"missing-context-{direction}-{index}", changed, direction, "cbor")
        for index, replacement in enumerate([bytes(16), 0, 0]):
            changed = copy.deepcopy(value)
            changed[2][index] = replacement
            emit(f"zero-fence-{direction}-{index}", changed, direction, "field")
            changed = copy.deepcopy(value)
            del changed[2][index]
            emit(f"missing-fence-{direction}-{index}", changed, direction, "cbor")
        changed = copy.deepcopy(value)
        changed[3] = value[3][:1] + b"\x18\x01" + value[3][2:]
        emit(f"nested-noncanonical-{direction}", changed, direction, "cbor")
    for name, path, value in [
        ("nsd", [1, 0], bytes([9]) * 16),
        ("network", [1, 1], bytes([9]) * 16),
        ("runtime", [2, 0], bytes([9]) * 16),
        ("generation", [2, 1], 8), ("epoch", [2, 2], 8),
        ("request-id", [3], cbor.encode([2, bytes([9]) * 16, None, None])),
    ]:
        changed = copy.deepcopy(receipt)
        target = changed
        for index in path[:-1]:
            target = target[index]
        target[path[-1]] = value
        emit("mismatch-" + name, changed, 1, "correlation")
    node = ed25519.public_key(bytes([1]) * 32)
    authority = ed25519.public_key(bytes([2]) * 32)
    for name, payload in [("report-envelope", request),
                          ("drain-envelope", [1, scope, fence, cbor.encode(drain)])]:
        content = cbor.encode([1, 0, node, authority, "gateway.report", 100,
                               request_id, cbor.encode(payload)])
        out.append([("name", name), ("direction", 0), ("error", "envelope"),
                    ("bytes", cbor.encode([content, ed25519.sign(bytes([1]) * 32, envelope.REQUEST + content)])),
                    ("pin", envelope.pin(node)), ("subject", node), ("authority", authority)])
    return out
