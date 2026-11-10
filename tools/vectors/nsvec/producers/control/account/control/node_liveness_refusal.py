"""Independent bounded Node liveness refusal payloads and signed responses."""
import copy

from nsvec import cbor, ed25519
from nsvec.producers.control.account.control import envelope

CRATE = "nsshared-control"
GROUP = "account/control/node-liveness-refusal"
TITLE = "Correlated Node liveness refusals"
SPEC = "docs/spec/account/control.md"
EXTERNAL = None


def vectors():
    scope = [bytes([3]) * 16, bytes([4]) * 16]
    fence = [bytes([5]) * 16, 6, 7]
    request_id = bytes([8]) * 16
    # A transmission nonce is deliberately distinct from the logical request ID.
    nonce = bytes([9]) * 16
    node = ed25519.public_key(bytes([1]) * 32)
    authority = ed25519.public_key(bytes([2]) * 32)
    pairs = [("runtime_rebind_required", "lease_elapsed", 409),
             ("runtime_rebind_required", "authority_epoch_changed", 409),
             ("runtime_conflict", "runtime_stopped", 409),
             ("runtime_conflict", "runtime_superseded", 409),
             ("authority_revoked", "authority_changed", 403)]
    out = []

    def emit(name, value, accepted=True, raw=None):
        out.append([("name", name), ("kind", "payload"),
                    ("bytes", cbor.encode(value) if raw is None else raw),
                    ("expect", "accept" if accepted else "reject")])

    for operation in ["node.heartbeat", "node.posture"]:
        for code, reason, status in pairs:
            value = [1, operation, scope, fence, request_id, code, reason]
            name = operation + "-" + reason
            emit(name, value)
            out[-1] += [("operation", operation), ("code", code),
                        ("reason", reason), ("status", status)]
            content = cbor.encode([1, 1, authority, node, operation, 100, nonce,
                                   cbor.encode(value)])
            out.append([("name", name + "-envelope"), ("kind", "envelope"),
                        ("bytes", cbor.encode([content, ed25519.sign(
                            bytes([2]) * 32, envelope.RESPONSE + content)])),
                        ("pin", envelope.pin(authority)), ("subject", node),
                        ("authority", authority), ("nonce", nonce),
                        ("operation", operation), ("status", status)])

    value = [1, "node.heartbeat", scope, fence, request_id, pairs[0][0], pairs[0][1]]
    for name, index, replacement in [
        ("version", 0, 2), ("operation", 1, "machine.disconnect"),
        ("operation-type", 1, 0), ("scope-arity", 2, scope + [0]),
        ("scope-id-length", 2, [bytes(15), scope[1]]),
        ("zero-runtime", 3, [bytes(16), 6, 7]),
        ("zero-generation", 3, [fence[0], 0, 7]),
        ("zero-epoch", 3, [fence[0], 6, 0]),
        ("runtime-id-length", 3, [bytes(15), 6, 7]),
        ("fence-arity", 3, fence + [0]),
        ("zero-request-id", 4, bytes(16)), ("request-id-length", 4, bytes(15)),
        ("unknown-code", 5, "authority_unavailable"),
        ("unknown-reason", 6, "unknown"), ("reason-type", 6, None),
    ]:
        changed = copy.deepcopy(value)
        changed[index] = replacement
        emit(name, changed, False)
    for code in sorted({code for code, _, _ in pairs}):
        for reason in [reason for _, reason, _ in pairs]:
            if (code, reason) not in [(c, r) for c, r, _ in pairs]:
                emit(code + "-" + reason, value[:5] + [code, reason], False)
    emit("short-arity", value[:-1], False)
    emit("long-arity", value + [0], False)
    raw = cbor.encode(value)
    for name, changed in [
        ("trailing", raw + b"\x00"),
        ("truncated", raw[:-1]),
        ("noncanonical-version", raw[:1] + b"\x18\x01" + raw[2:]),
        ("noncanonical-arity", b"\x98\x07" + raw[1:]),
        ("indefinite-arity", b"\x9f" + raw[1:] + b"\xff"),
        ("negative-generation", raw.replace(cbor.encode(fence), b"\x83" + cbor.encode(fence[0]) + b"\x20\x07")),
        ("oversized", raw + bytes(256)),
    ]:
        emit(name, value, False, changed)
    return out
