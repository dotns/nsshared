"""Independent authenticated publication subscription request tuples."""
from .. import cbor
from . import account, bootstrap_envelope

CRATE = "nsshared-proto"
GROUP = "publication-subscription"
TITLE = "Authenticated publication subscription requests"
SECTIONS = "repository docs/control-exchange-candidate.md authenticated publication subscription"


def vectors():
    subscriber = account.key(bytes([1]) * 32)[0]
    issuer = account.key(bytes([2]) * 32)[0]
    scopes = [[issuer, subscriber, "realm-a", "edge"],
              [issuer, subscriber, "realm-b", "nodes"]]
    base = [1, subscriber, scopes, ["node.control", "public.edge"], [0], bytes([3]) * 16, 1]
    out = []

    def emit(name, value, accepted=True, raw=None):
        out.append([("name", name), ("bytes", cbor.encode(value) if raw is None else raw),
                    ("decision", "accepted" if accepted else "refused")])

    emit("populated", base)
    emit("empty", [1, subscriber, [], [], [], bytes([3]) * 16, 1])
    emit("max-attempt", base[:-1] + [2**32 - 1])
    emit("max-lists", [1, subscriber,
                      [[issuer, subscriber, "realm-a", f"scope-{i:02}"] for i in range(32)],
                      [f"cap-{i:02}" for i in range(64)], list(range(32)), bytes([3]) * 16, 1])
    for name, index, value in [
        ("duplicate-scopes", 2, scopes + [scopes[-1]]),
        ("unsorted-scopes", 2, list(reversed(scopes))),
        ("wrong-recipient", 2, [[issuer, issuer, "realm-a", "edge"]]),
        ("empty-realm", 2, [[issuer, subscriber, "", "edge"]]),
        ("scope-control", 2, [[issuer, subscriber, "realm-a", "edge\n"]]),
        ("oversized-scopes", 2, scopes * 17),
        ("invalid-capability", 3, ["Not.Valid"]),
        ("duplicate-capabilities", 3, ["node.control"] * 2),
        ("unsorted-capabilities", 3, ["z", "a"]),
        ("oversized-capabilities", 3, ["a"] * 65),
        ("long-capability", 3, ["a" * 65]),
        ("duplicate-ingress", 4, [0, 0]),
        ("unsorted-ingress", 4, [1, 0]),
        ("unknown-ingress", 4, [2]),
        ("oversized-ingress", 4, [0] * 33),
        ("zero-nonce", 5, bytes(16)),
        ("short-nonce", 5, bytes(15)),
        ("zero-attempt", 6, 0),
        ("overflow-attempt", 6, 2**32),
    ]:
        changed = list(base)
        changed[index] = value
        emit(name, changed, False)
    emit("unknown-field", base + [0], False)
    raw = cbor.encode(base)
    emit("nonminimal", None, False, raw[:1] + b"\x18\x01" + raw[2:])
    emit("trailing", None, False, raw + b"\0")
    emit("oversized-bytes", None, False, bytes(8193))
    # A declared array ceiling is refused before its elements are read.
    emit("declared-scopes", None, False, b"\x87" + cbor.encode(1) + cbor.encode(subscriber) + b"\x98\x21")
    content = cbor.encode([1, 0, subscriber, issuer, "config.stream", 100, bytes([4]) * 16, raw])
    out.append([("name", "signed"), ("bytes", cbor.encode([content, account.sign(bytes([1]) * 32, bootstrap_envelope.REQUEST + content)])),
                ("decision", "signed"), ("subscriber", subscriber), ("issuer", issuer),
                ("pin", bootstrap_envelope.pin(subscriber)), ("signing_input", bootstrap_envelope.REQUEST + content)])
    for name, payload, recipient, operation, direction in [
        ("subscriber-mismatch", [1, issuer, [], [], [], bytes([3]) * 16, 1], issuer, "config.stream", 0),
        ("issuer-mismatch", [1, subscriber, [[subscriber, subscriber, "realm-a", "edge"]], [], [], bytes([3]) * 16, 1], issuer, "config.stream", 0),
        ("missing-recipient", base, None, "config.stream", 0),
        ("wrong-recipient", base, subscriber, "config.stream", 0),
        ("wrong-operation", base, issuer, "info.get", 0),
        ("wrong-direction", base, issuer, "config.stream", 1),
    ]:
        content = cbor.encode([1, direction, subscriber, recipient, operation, 100, bytes([4]) * 16, cbor.encode(payload)])
        domain = bootstrap_envelope.REQUEST if direction == 0 else bootstrap_envelope.RESPONSE
        out.append([("name", "signed-" + name),
                    ("bytes", cbor.encode([content, account.sign(bytes([1]) * 32, domain + content)])),
                    ("decision", "signed-refused"), ("subscriber", subscriber), ("issuer", issuer),
                    ("pin", bootstrap_envelope.pin(subscriber)), ("signing_input", domain + content)])
    return out
