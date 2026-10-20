"""Independent candidate exchange tuples and machine verifier boundary inputs."""
import base64
import hashlib
import json
from .. import cbor
from . import account, bootstrap_envelope

CRATE = "nsshared-proto"
GROUP = "control-exchange"
TITLE = "Candidate control exchange and machine trust boundaries"
SECTIONS = "repository docs/control-exchange-candidate.md"


def vectors():
    node = account.key(bytes([1]) * 32)[0]
    authority = account.key(bytes([2]) * 32)[0]
    scope = [bytes([3]) * 16, bytes([4]) * 16]
    binding = [1, node, bytes([5]) * 32, 1]
    enrollment = cbor.encode([1, binding, ["node.control"]])
    request = [1, scope, enrollment, "ordinary-node-v1", b"provisioned", None]
    acceptance = [1, scope, enrollment, "ordinary-node-v1", 0]
    out = []

    def emit(name, kind, value, decision="accepted", raw=None, extra=()):
        out.append([("name", name), ("kind", kind),
                    ("bytes", cbor.encode(value) if raw is None else raw),
                    ("decision", decision), *extra])

    for kind, value in [("registration", request), ("acceptance", acceptance),
                        ("authentication", [1, scope, binding, "control"]),
                        ("token-response", [1, "a.b.c"]), ("information-request", [1])]:
        emit(kind, kind, value)
        raw = cbor.encode(value)
        emit(kind + "-trailing", kind, None, "encoding", raw + b"\0")
        emit(kind + "-nonminimal", kind, None, "encoding", raw[:1] + b"\x18\x01" + raw[2:])
    pin = bootstrap_envelope.pin(authority)
    discovery = [1, 1, "https://control.example/", [1],
                 [[0, "https://control.example/"]], None, [], [pin]]
    info = [1, cbor.encode(discovery), "realm-default", "provider", "1.0", ["auth_key"], ["node.control"]]
    emit("information", "information", info)
    emit("information-bad-method", "information", info[:5] + [["unknown"]] + info[6:], "field")
    emit("authentication-purpose", "authentication", [1, scope, binding, "wss"], "field")
    emit("registration-empty-credential", "registration", request[:4] + [b"", None], "field")
    emit("registration-missing-lifecycle", "registration", request[:-1], "encoding")

    for name, changed, signer, decision in [
        ("matching", acceptance, authority, "accepted"),
        ("scope", [1, [scope[0], bytes([9]) * 16], *acceptance[2:]], authority, "scope"),
        ("profile", acceptance[:3] + ["other", 0], authority, "profile"),
        ("binding", [1, scope, cbor.encode([1, [1, node, bytes([9]) * 32, 1], ["node.control"]]), *acceptance[3:]], authority, "binding"),
        ("capabilities", [1, scope, cbor.encode([1, binding, ["other"]]), *acceptance[3:]], authority, "capabilities"),
        ("decision", acceptance[:-1] + [1], authority, "lifecycle"),
        ("authority", acceptance, node, "authority"),
    ]:
        seed = bytes([2 if signer == authority else 1]) * 32
        content = cbor.encode([1, 1, signer, node, "machine.register", 100, bytes([7]) * 16, cbor.encode(changed)])
        carrier = [content, account.sign(seed, bootstrap_envelope.RESPONSE + content)]
        emit("accept-" + name, "match", carrier, decision,
             extra=[("request", cbor.encode(request)), ("node", node), ("pin", pin),
                    ("signing_input", bootstrap_envelope.RESPONSE + content)])
    content = cbor.encode([1, 0, node, authority, "machine.register", 100, bytes([7]) * 16, cbor.encode(request)])
    emit("signed-registration", "signed-request", [content, account.sign(bytes([1]) * 32, bootstrap_envelope.REQUEST + content)],
         extra=[("node", node), ("authority", authority), ("pin", bootstrap_envelope.pin(node)),
                ("signing_input", bootstrap_envelope.REQUEST + content)])

    auth_value = [1, scope, binding, "control"]
    auth_content = cbor.encode([1, 0, node, authority, "machine.auth", 100, bytes([8]) * 16, cbor.encode(auth_value)])
    emit("signed-authentication", "signed-authentication", [auth_content, account.sign(bytes([1]) * 32, bootstrap_envelope.REQUEST + auth_content)],
         extra=[("node", node), ("authority", authority), ("pin", bootstrap_envelope.pin(node)),
                ("signing_input", bootstrap_envelope.REQUEST + auth_content)])
    for name, after, transition, rebind, result, declared in [
        ("equal", binding, None, False, "accepted", 1),
        ("replacement", [2, account.key(bytes([6]) * 32)[0], bytes([9]) * 32, 1], 0, False, "accepted", 2),
        ("rotation", [1, node, bytes([9]) * 32, 2], 1, True, "accepted", 3),
        ("rotation-denied", [1, node, bytes([9]) * 32, 2], 1, False, "rebind", 3),
    ]:
        life = None if transition is None else cbor.encode([1, transition, binding, after, bytes([1]) * 16, bytes([2]) * 16])
        enrollment_after = cbor.encode([1, after, ["node.control"]])
        staged = [1, scope, enrollment_after, "ordinary-node-v1", b"provisioned", life]
        accepted = [1, scope, enrollment_after, "ordinary-node-v1", declared]
        signed = cbor.encode([1, 1, authority, after[1], "machine.register", 100, bytes([9]) * 16, cbor.encode(accepted)])
        emit("lifecycle-" + name, "match", [signed, account.sign(bytes([2]) * 32, bootstrap_envelope.RESPONSE + signed)], result,
             extra=[("request", cbor.encode(staged)), ("node", after[1]), ("pin", pin),
                    ("signing_input", bootstrap_envelope.RESPONSE + signed),
                    ("committed", enrollment), ("rebind", "yes" if rebind else "no")])

    claims = dict(iss="issuer", sub="machine-a", realm="realm-a", aud="nsd-machine-control",
                  mid_kty="ed25519", mid_pub=node.hex(), iat=100, exp=200, jti="token-a")
    def json_emit(name, kind, value, decision="accepted", now=100):
        emit(name, kind, None, decision, json.dumps(value, separators=(",", ":")).encode(),
             [("now", str(now)), ("node", node)])
    for name, aud in [("absent", None), ("unrelated", "unrelated"), ("array", ["one", "two"]),
                      ("machine", "nsd-machine-control"), ("array-machine", ["one", "nsd-machine-control"])]:
        value = dict(claims)
        if aud is None:
            del value["aud"]
        else:
            value["aud"] = aud
        json_emit("gateway-audience-" + name, "gateway-claims", value)
        json_emit("nsd-audience-" + name, "nsd-audience", value,
                  "accepted" if name == "machine" else "audience")
    for name, field, value, decision in [("subject", "sub", "other", "subject"),
                                        ("key-type", "mid_kty", "rsa", "self-binding"),
                                        ("key", "mid_pub", "00" * 32, "self-binding")]:
        changed = dict(claims)
        changed[field] = value
        json_emit("claims-" + name, "gateway-claims", changed, decision)
    for now, decision in [(200, "accepted"), (230, "accepted"), (231, "expired")]:
        json_emit("expiry-" + str(now), "gateway-claims", claims, decision, now)
    jwk = dict(kty="RSA", kid="a", alg="RS256", use="sig", n="AQID", e="AQAB")
    json_emit("key-set", "keys", {"keys": [jwk]})
    for field, value in [("use", "enc"), ("kty", "EC"), ("alg", "HS256"), ("kid", ""), ("n", "!!")]:
        changed = dict(jwk)
        changed[field] = value
        json_emit("key-set-wrong-" + field, "keys", {"keys": [changed]}, "key")
    missing_use = dict(jwk)
    del missing_use["use"]
    json_emit("key-set-absent-use", "keys", {"keys": [missing_use]})
    json_emit("key-set-leading-zero-component", "keys", {"keys": [dict(jwk, n="AAEC")]})
    def thumb(key):
        data = json.dumps({"e": key["e"], "kty": "RSA", "n": key["n"]}, separators=(",", ":"), sort_keys=True).encode()
        return base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
    other_key = dict(jwk, kid="b", n="BAUG")
    for name, keys, pins, stored, kid, result in [
        ("first-use", [jwk], [], None, "a", "accepted"),
        ("static-filter", [jwk, other_key], [thumb(jwk)], None, "a", "accepted"),
        ("pinned-rotation", [other_key], [thumb(jwk), thumb(other_key)], None, "b", "accepted"),
        ("substitution", [other_key], [thumb(jwk)], None, "b", "untrusted"),
        ("stored-no-append", [jwk, other_key], [], [thumb(jwk)], "b", "unknown"),
        ("unknown-kid", [jwk], [thumb(jwk)], None, "b", "unknown"),
        ("missing-single", [jwk], [], None, None, "accepted"),
        ("missing-ambiguous", [jwk, other_key], [], None, None, "ambiguous"),
        ("static-over-stored", [other_key], [thumb(other_key)], [thumb(jwk)], "b", "accepted"),
    ]:
        emit("trust-" + name, "trust", None, result,
             json.dumps({"keys": keys}, separators=(",", ":")).encode(),
             [("pins_json", json.dumps(pins)), ("stored_json", json.dumps(stored)),
              ("kid_json", json.dumps(kid)), ("pin_a", thumb(jwk)), ("pin_b", thumb(other_key))])
    return out
