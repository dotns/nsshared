"""Independent ordinary Node liveness tuples and signed carriers."""
import copy
from nsvec import cbor, ed25519
from nsvec.producers.control.account.control import envelope

CRATE = "nsshared-control"
GROUP = "account/control/node-liveness"
TITLE = "Ordinary Node liveness"
SPEC = "docs/spec/account/control.md"
EXTERNAL = None


def vectors():
    scope = [bytes([3]) * 16, bytes([4]) * 16]
    fence = [bytes([5]) * 16, 6, 7]
    request_id = bytes([8]) * 16
    heartbeat = [1, request_id, 123, ["192.0.2.1", "2001:db8::1"], 9]
    request = [1, scope, fence, cbor.encode(heartbeat)]
    response = [1, scope, fence, cbor.encode([1, request_id, ["unknown.feature"]])]
    disconnect = [1, scope, fence, request_id]
    out = []

    def emit(name, operation, direction, value, error="none"):
        out.append([("name", name), ("operation", operation), ("direction", direction),
                    ("bytes", cbor.encode(value)), ("error", error)])

    for operation, forms in [("node.heartbeat", [request, response]),
                             ("machine.disconnect", [disconnect, [1, cbor.encode(disconnect)]])]:
        for direction, value in enumerate(forms):
            emit(f"{operation}-{direction}", operation, direction, value)
            changed = copy.deepcopy(value)
            changed[0] = 2
            emit(f"{operation}-{direction}-version", operation, direction, changed, "field")
            emit(f"{operation}-{direction}-arity", operation, direction, value + [0], "cbor")
        for name, position, value in [("runtime-id", 0, bytes(16)), ("generation", 1, 0), ("epoch", 2, 0)]:
            changed = copy.deepcopy(forms[0])
            changed[2][position] = value
            emit(operation + "-" + name, operation, 0, changed, "field")
        node = ed25519.public_key(bytes([1]) * 32)
        authority = ed25519.public_key(bytes([2]) * 32)
        content = cbor.encode([1, 0, node, authority, operation, 100, request_id, cbor.encode(forms[0])])
        out.append([("name", operation + "-envelope"), ("operation", operation),
                    ("direction", 0), ("error", "envelope"),
                    ("bytes", cbor.encode([content, ed25519.sign(bytes([1]) * 32, envelope.REQUEST + content)])),
                    ("pin", envelope.pin(node)), ("subject", node), ("authority", authority)])
    for name, inner, direction in [("addresses", [1, request_id, 0, ["192.0.2.1"] * 257, None], 0),
                                   ("features", [1, request_id, ["a"] * 257], 1),
                                   ("invalid-ip", [1, request_id, 0, ["invalid"], None], 0)]:
        emit(name, "node.heartbeat", direction, [1, scope, fence, cbor.encode(inner)],
             "field" if name == "invalid-ip" else "cbor")
    emit("gateway-request", "node.heartbeat", 0, heartbeat, "cbor")
    emit("gateway-response", "node.heartbeat", 1, [1, request_id, []], "cbor")
    emit("empty-heartbeat", "node.heartbeat", 0, [1, scope, fence, cbor.encode([1, request_id, 0, [], None])])
    return out
