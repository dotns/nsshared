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
    # Optional observations extend only the Node request; legacy tuples stay exact.
    keys = sorted(ed25519.public_key(bytes([seed]) * 32) for seed in range(1, 5))
    pairs = [[keys[0], keys[2]], [keys[0], keys[3]], [keys[1], keys[2]]]
    pair = [fence[0], 0xffffffffffffffff, pairs]
    rtt = [[key, tier, 0xffffffffffffffff, 0]
           for key, tier in zip(keys, ["lt30", "lt100", "ge100", "unreachable"])]

    def observation(name, udp=None, snapshot=None, gateways=None, error="none"):
        emit(name, "node.heartbeat", 0, request + [udp, snapshot, gateways], error)

    observation("udp-true", udp=True)
    observation("udp-false", udp=False)
    observation("pair-present", snapshot=pair)
    observation("pair-empty", snapshot=[fence[0], 0, []])
    observation("rtt-present", gateways=rtt)
    observation("rtt-empty", gateways=[])
    boundary_keys = sorted(ed25519.public_key(seed.to_bytes(32, "big")) for seed in range(256))
    observation("pair-at-bound", snapshot=[fence[0], 1, [[key, keys[0]] for key in boundary_keys]])
    observation("rtt-at-bound", gateways=[[key, "lt30", 0, 0xffffffffffffffff] for key in boundary_keys])
    observation("udp-wrong-type", udp=1, error="cbor")
    observation("observations-all", False, pair, rtt)
    observation("observations-all-null", error="field")
    observation("pair-runtime-mismatch", snapshot=[bytes([9]) * 16, 1, []], error="field")
    for name, entries in [("unsorted", list(reversed(pairs))), ("duplicate", [pairs[0]] * 2)]:
        observation("pair-" + name, snapshot=[fence[0], 1, entries], error="field")
    for name, entries in [("unsorted", list(reversed(rtt))), ("duplicate", [rtt[0]] * 2)]:
        observation("rtt-" + name, gateways=entries, error="field")
    observation("rtt-unknown-tier", gateways=[[keys[0], "unknown", 1, 0]], error="field")
    observation("pair-over-bound", snapshot=[fence[0], 1, [pairs[0]] * 257], error="cbor")
    observation("rtt-over-bound", gateways=[rtt[0]] * 257, error="cbor")
    for name, key in [("node-id", bytes(16)), ("legacy-id", "machine-1"),
                      ("invalid-key", bytes([2]) * 32)]:
        error = "field" if name == "invalid-key" else "cbor"
        observation("pair-peer-" + name, snapshot=[fence[0], 1, [[key, keys[2]]]], error=error)
        observation("pair-gateway-" + name, snapshot=[fence[0], 1, [[keys[0], key]]], error=error)
        observation("rtt-gateway-" + name, gateways=[[key, "lt30", 1, 0]], error=error)
    emit("endpoint-features", "node.heartbeat", 1,
         [1, scope, fence, cbor.encode([1, request_id, ["gateway_rtt.v1", "pair_transport_fallback.v1"]])])
    emit("withdraw-features", "node.heartbeat", 1,
         [1, scope, fence, cbor.encode([1, request_id, []])])
    return out
