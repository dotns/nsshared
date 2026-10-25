"""Independent authenticated publication subscription request tuples."""
from nsvec import cbor, ed25519
from nsvec.producers.control.account.control import envelope as bootstrap_envelope

CRATE = "nsshared-control"
GROUP = "account/publication/subscription"
TITLE = "Authenticated publication subscription requests"
SPEC = "docs/spec/account/publication.md"
EXTERNAL = None


def vectors():
    subscriber = ed25519.public_key(bytes([1]) * 32)
    issuer = ed25519.public_key(bytes([2]) * 32)
    scopes = [[issuer, subscriber, "030C1G60R30C1G60R30C1G60R3", "edge"],
              [issuer, subscriber, "09144GJ289144GJ289144GJ289", "nodes"]]
    base = [1, subscriber, scopes, ["node.control", "public.edge"], [0], bytes([3]) * 16, 1, None]
    out = []

    def emit(name, value, accepted=True, raw=None):
        out.append([("name", name), ("bytes", cbor.encode(value) if raw is None else raw),
                    ("decision", "accepted" if accepted else "refused")])

    emit("populated", base)
    emit("empty", [1, subscriber, [], [], [], bytes([3]) * 16, 1, None])
    emit("max-attempt", base[:6] + [2**32 - 1, None])
    emit("max-lists", [1, subscriber,
                      [[issuer, subscriber, "030C1G60R30C1G60R30C1G60R3", f"scope-{i:02}"] for i in range(32)],
                      [f"cap-{i:02}" for i in range(64)], list(range(32)), bytes([3]) * 16, 1, None])
    for name, index, value in [
        ("duplicate-scopes", 2, scopes + [scopes[-1]]),
        ("unsorted-scopes", 2, list(reversed(scopes))),
        ("wrong-recipient", 2, [[issuer, issuer, "030C1G60R30C1G60R30C1G60R3", "edge"]]),
        ("empty-realm", 2, [[issuer, subscriber, "", "edge"]]),
        ("scope-control", 2, [[issuer, subscriber, "030C1G60R30C1G60R30C1G60R3", "edge\n"]]),
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
        ("scope-whitespace", 2, [[issuer, subscriber, "030C1G60R30C1G60R30C1G60R3", "edge a"]]),
    ]:
        changed = list(base)
        changed[index] = value
        emit(name, changed, False)
    signed_bindings = []
    emit("old-seven-elements", base[:-1], False)
    for network in (4, 5):
        binding = [bytes([3])*16, bytes([network])*16, 1, bytes([6])*16, 2, 3, bytes([7])*16]
        emit(f"bound-network-{network}", base[:-1] + [binding])
        signed_bindings.append((f"binding-network-{network}", base[:-1] + [binding], True))
        for index, name in [(3, "runtime-id"), (6, "session-request-id")]:
            invalid = list(binding); invalid[index] = bytes(16)
            payload = base[:-1] + [invalid]
            emit(f"zero-{name}-{network}", payload, False)
            signed_bindings.append((f"zero-{name}-{network}", payload, False))
        for index, name in [(0, "nsd-id"), (1, "network-id")]:
            allowed = list(binding); allowed[index] = bytes(16)
            emit(f"zero-{name}-{network}", base[:-1] + [allowed])
            signed_bindings.append((f"zero-{name}-{network}", base[:-1] + [allowed], True))
        for index in (2, 4, 5):
            invalid = list(binding); invalid[index] = 0
            emit(f"zero-binding-{network}-{index}", base[:-1] + [invalid], False)
        emit(f"short-binding-{network}", base[:-1] + [binding[:-1]], False)
    emit("unknown-field", base + [0], False)
    raw = cbor.encode(base)
    emit("nonminimal", None, False, raw[:1] + b"\x18\x01" + raw[2:])
    emit("trailing", None, False, raw + b"\0")
    emit("oversized-bytes", None, False, bytes(8193))
    # A declared array ceiling is refused before its elements are read.
    emit("declared-scopes", None, False, b"\x88" + cbor.encode(1) + cbor.encode(subscriber) + b"\x98\x21")
    content = cbor.encode([1, 0, subscriber, issuer, "config.stream", 100, bytes([4]) * 16, raw])
    out.append([("name", "signed"), ("bytes", cbor.encode([content, ed25519.sign(bytes([1]) * 32, bootstrap_envelope.REQUEST + content)])),
                ("decision", "signed"), ("subscriber", subscriber), ("issuer", issuer),
                ("pin", bootstrap_envelope.pin(subscriber)), ("signing_input", bootstrap_envelope.REQUEST + content)])
    for name, payload, recipient, operation, direction in [
        ("subscriber-mismatch", [1, issuer, [], [], [], bytes([3]) * 16, 1, None], issuer, "config.stream", 0),
        ("issuer-mismatch", [1, subscriber, [[subscriber, subscriber, "030C1G60R30C1G60R30C1G60R3", "edge"]], [], [], bytes([3]) * 16, 1, None], issuer, "config.stream", 0),
        ("missing-recipient", base, None, "config.stream", 0),
        ("wrong-recipient", base, subscriber, "config.stream", 0),
        ("wrong-operation", base, issuer, "info.get", 0),
        ("wrong-direction", base, issuer, "config.stream", 1),
    ]:
        content = cbor.encode([1, direction, subscriber, recipient, operation, 100, bytes([4]) * 16, cbor.encode(payload)])
        domain = bootstrap_envelope.REQUEST if direction == 0 else bootstrap_envelope.RESPONSE
        out.append([("name", "signed-" + name),
                    ("bytes", cbor.encode([content, ed25519.sign(bytes([1]) * 32, domain + content)])),
                    ("decision", "signed-refused"), ("subscriber", subscriber), ("issuer", issuer),
                    ("pin", bootstrap_envelope.pin(subscriber)), ("signing_input", domain + content)])
    for name, payload, accepted in signed_bindings:
        content = cbor.encode([1, 0, subscriber, issuer, "config.stream", 100, bytes([4])*16, cbor.encode(payload)])
        out.append([("name", "signed-" + name),
                    ("bytes", cbor.encode([content, ed25519.sign(bytes([1])*32, bootstrap_envelope.REQUEST + content)])),
                    ("decision", "signed" if accepted else "signed-refused"), ("subscriber", subscriber),
                    ("issuer", issuer), ("pin", bootstrap_envelope.pin(subscriber)),
                    ("signing_input", bootstrap_envelope.REQUEST + content)])
    return out
