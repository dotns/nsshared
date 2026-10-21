"""Independent snapshot poll requests and signed existing snapshot responses."""
from .. import cbor
from . import account, bootstrap_envelope

CRATE = "nsshared-proto"
GROUP = "publication-snapshot-request"
TITLE = "Independent publication snapshot polls"
SECTIONS = "repository docs/control-exchange-candidate.md independent publication snapshot poll"


def vectors():
    subscriber = account.key(bytes([1]) * 32)[0]
    issuer = account.key(bytes([2]) * 32)[0]
    correlation = bytes([5]) * 16
    scopes = [[issuer, subscriber, "030C1G60R30C1G60R30C1G60R3", "nodes"],
              [issuer, subscriber, "09144GJ289144GJ289144GJ289", "nodes"]]
    base = [1, subscriber, scopes, bytes([3]) * 16, 1, correlation]
    out = []

    def emit(name, value, accepted=True, raw=None):
        out.append([("name", name), ("mode", "request"),
                    ("bytes", cbor.encode(value) if raw is None else raw),
                    ("decision", "accepted" if accepted else "refused")])

    emit("populated", base)
    emit("empty", [1, subscriber, [], bytes([3]) * 16, 1, correlation])
    for name, index, value in [
        ("duplicate-scopes", 2, scopes + [scopes[-1]]),
        ("unsorted-scopes", 2, scopes[::-1]),
        ("wrong-recipient", 2, [[issuer, issuer, "030C1G60R30C1G60R30C1G60R3", "nodes"]]),
        ("empty-realm", 2, [[issuer, subscriber, "", "nodes"]]),
        ("oversized-scopes", 2, scopes * 17),
        ("control-scope", 2, [[issuer, subscriber, "030C1G60R30C1G60R30C1G60R3", "nodes\n"]]),
        ("zero-boot", 3, bytes(16)), ("zero-attempt", 4, 0),
        ("overflow-attempt", 4, 2**32), ("zero-correlation", 5, bytes(16)),
    ]:
        value_tuple = list(base)
        value_tuple[index] = value
        emit(name, value_tuple, False)
    emit("stream-kind-requested", base + [[11, "policy-version"]], False)
    emit("unknown-field", base + [0], False)
    raw = cbor.encode(base)
    emit("nonminimal", None, False, raw[:1] + b"\x18\x01" + raw[2:])
    emit("trailing", None, False, raw + b"\0")

    def envelope(payload, direction, nonce, recipient, signer_seed):
        signer = account.key(signer_seed)[0]
        content = cbor.encode([1, direction, signer, recipient, "config.snapshot", 100, nonce, payload])
        domain = bootstrap_envelope.REQUEST if direction == 0 else bootstrap_envelope.RESPONSE
        return cbor.encode([content, account.sign(signer_seed, domain + content)]), domain + content

    for name, payload, nonce, recipient in [
        ("nonce", raw, bytes([6]) * 16, issuer),
        ("recipient", raw, correlation, None),
        ("signer", cbor.encode([1, issuer, [], bytes([3]) * 16, 1, correlation]), correlation, issuer),
        ("issuer", cbor.encode([1, subscriber, [[subscriber, subscriber, "030C1G60R30C1G60R30C1G60R3", "nodes"]], bytes([3]) * 16, 1, correlation]), correlation, issuer),
    ]:
        wire, signing = envelope(payload, 0, nonce, recipient, bytes([1]) * 32)
        out.append([("name", "signed-request-" + name), ("mode", "signed-request"),
                    ("bytes", wire), ("signing_input", signing),
                    ("pin", bootstrap_envelope.pin(subscriber)), ("issuer", issuer),
                    ("decision", "refused")])
    request, signing = envelope(raw, 0, correlation, issuer, bytes([1]) * 32)
    out.append([("name", "signed-request"), ("mode", "signed-request"), ("bytes", request),
                ("signing_input", signing), ("pin", bootstrap_envelope.pin(subscriber)),
                ("issuer", issuer), ("decision", "accepted")])
    event = [1, issuer, subscriber, "030C1G60R30C1G60R30C1G60R3", "nodes", 11, "node-l3", 1,
             True, 8, 100, 200, 0, b"fixture-node-l3"]
    for name, changes, nonce, recipient in [
        ("accepted", {}, correlation, subscriber),
        ("unrequested-scope", {4: "other"}, correlation, subscriber),
        ("event-recipient", {2: issuer}, correlation, subscriber),
        ("stream-kind", {6: "policy-version", 7: 0}, correlation, subscriber),
        ("correlation", {}, bytes([6]) * 16, subscriber),
        ("carrier-recipient", {}, correlation, issuer),
        ("empty", None, correlation, subscriber),
        ("nonminimal", {}, correlation, subscriber),
        ("unknown-field", {}, correlation, subscriber),
    ]:
        value = list(event)
        for index, field in (changes or {}).items():
            value[index] = field
        content = cbor.encode(value)
        signed = cbor.encode([content, account.sign(bytes([2]) * 32, b"ns.account.publication.v1\0" + content)])
        snapshot = cbor.encode([1, [] if changes is None else [signed]])
        if name == "nonminimal":
            snapshot = snapshot[:1] + b"\x18\x01" + snapshot[2:]
        elif name == "unknown-field":
            snapshot = cbor.encode([1, [signed], 0])
        wire, signing = envelope(snapshot, 1, nonce, recipient, bytes([2]) * 32)
        out.append([("name", "response-" + name), ("mode", "response"), ("bytes", wire),
                    ("snapshot", snapshot), ("signing_input", signing),
                    ("issuer", issuer), ("pin", bootstrap_envelope.pin(issuer)),
                    ("decision", "accepted" if name in ("accepted", "empty") else "refused")])
    def signed_event(value, corrupt=False):
        content = cbor.encode(value)
        signature = account.sign(bytes([2]) * 32, b"ns.account.publication.v1\0" + content)
        if corrupt:
            signature = bytes([signature[0] ^ 1]) + signature[1:]
        return cbor.encode([content, signature])

    known = signed_event(event)
    for label, family, kind in [("unknown-kind", 11, "zz-future-kind"),
                                ("unknown-family", 99, "future-kind")]:
        for control, changes, corrupt, nonce in [
            ("accepted", {}, False, correlation),
            ("signature", {}, True, correlation),
            ("declared-stream", {7: 0}, False, correlation),
            ("scope", {4: "other"}, False, correlation),
            ("recipient", {2: issuer}, False, correlation),
            ("correlation", {}, False, bytes([6]) * 16),
            ("known-stream", {5: 11, 6: "policy-version"}, False, correlation),
        ]:
            extension = list(event)
            extension[5:7] = [family, kind]
            for index, value in changes.items():
                extension[index] = value
            snapshot = cbor.encode([1, [known, signed_event(extension, corrupt)]])
            wire, signing = envelope(snapshot, 1, nonce, subscriber, bytes([2]) * 32)
            out.append([("name", "mixed-" + label + "-" + control), ("mode", "response"),
                        ("bytes", wire), ("snapshot", snapshot), ("signing_input", signing),
                        ("issuer", issuer), ("pin", bootstrap_envelope.pin(issuer)),
                        ("extension_family", family), ("extension_kind", kind),
                        ("decision", "accepted" if control == "accepted" else "refused")])
    return out
