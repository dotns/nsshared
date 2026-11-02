"""Original signed registration results, independent of receipt transport nonces."""
import hashlib
from nsvec import cbor, ed25519


def vectors():
    node = ed25519.public_key(bytes([1]) * 32)
    issuer = ed25519.public_key(bytes([2]) * 32)
    scope = [bytes([3]) * 16, bytes([3]) * 16]
    binding = [1, node, bytes([5]) * 32, 1]
    enrollment = cbor.encode([1, binding, ["node.control"]])
    request = cbor.encode([1, scope, enrollment, "explicit-gateway-profile", b"provisioned", None])
    digest = hashlib.sha256(request).digest()
    query = [1, bytes([11]) * 16, scope, digest]
    original_source = [1, issuer, node, "030C1G60R30C1G60R30C1G60R3",
                       "nodes", "explicit-gateway-profile", node, bytes([10]) * 16, 1, 1]
    out = []

    def emit(name, source=None, context=None, bad_signature=False, raw=None, accepted=False):
        source_bytes = cbor.encode(original_source if source is None else source)
        signature = ed25519.sign(bytes([2]) * 32, b"ns.account.source-binding.v1\0" + source_bytes)
        if bad_signature:
            signature = bytes([signature[0] ^ 1]) + signature[1:]
        acceptance = cbor.encode([1, scope, enrollment, "explicit-gateway-profile", 0,
                                  cbor.encode([source_bytes, signature])])
        attachment = cbor.encode([1, cbor.encode(query if context is None else context), acceptance])
        out.append([("name", "recovery-" + name), ("kind", "recovery"),
                    ("bytes", attachment if raw is None else raw),
                    ("decision", "accepted" if accepted else "refused"),
                    ("request", request), ("digest", digest),
                    ("original", acceptance), ("query", cbor.encode(query)),
                    ("query_nonce", bytes([20 if name == "same-original-new-nonce" else 19]) * 16)])
        return attachment

    original = emit("original", accepted=True)
    emit("same-original-new-nonce", accepted=True)
    for name, index, value in [("issuer", 1, node), ("recipient", 2, issuer),
                               ("realm", 3, "09144GJ289144GJ289144GJ289"),
                               ("scope", 4, "egress"), ("source-node", 6, issuer),
                               ("contribution", 7, bytes([12]) * 16),
                               ("epoch", 8, 2), ("generation", 9, 2)]:
        changed = original_source.copy()
        changed[index] = value
        emit(name, source=changed)
    emit("signature", bad_signature=True)
    for name, index, value in [("operation", 1, bytes([12]) * 16),
                               ("network", 2, [scope[0], bytes([12]) * 16]),
                               ("digest", 3, bytes([12]) * 32)]:
        changed = query.copy()
        changed[index] = value
        emit(name, context=changed)
    emit("version", raw=original[:1] + b"\x02" + original[2:])
    emit("nonminimal", raw=original[:1] + b"\x18\x01" + original[2:])
    emit("trailing", raw=original + b"\0")
    emit("missing", raw=cbor.encode([1, cbor.encode(query)]))
    return out
