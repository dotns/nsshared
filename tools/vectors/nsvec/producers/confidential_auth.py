"""Independent confidential auth candidate producer; fixture values only."""
import copy
import base64
import hashlib
import json

from .. import cbor
from .account import key, sign

CRATE = "nsshared-proto"
GROUP = "confidential-auth"
TITLE = "Confidential auth candidate fixture producer"
SECTIONS = "docs/confidential-auth-candidate.md"


def vectors():
    realm = bytes([3]) * 16
    gateway = key(bytes([2]) * 32)[0]
    authority = key(bytes([1]) * 32)[0]
    material = [0, "auth", 7]
    ca = [2, "ca", 4]
    pending = [1, bytes([8]) * 16, gateway, "served", "edge", realm, material]
    subject = cbor.encode([1, 0, realm, "external:visitor"])
    bindings = [cbor.encode([1, realm, 1, name, subject, True, 200])
                for name in ("api", "basic", "mtls", "signed")]
    jwt_binding = cbor.encode([1, cbor.encode([1, realm, 1, "jwt", subject, True, 200]),
                               "issuer", "sub", "visitor", ["read"]])
    public = [1, realm, [material, ca], sorted(bindings), [jwt_binding],
              [["issuer", "https://issuer.example", ["edge"], material]]]

    def secrets(name):
        value = "11" * 32 if name == "cookie" else "22" * 32 if name == "hmac" else "fixture client secret"
        return [[name, 2, 200, value],
                [[name, 1, 180, "33" * 32]]]

    provider = ["oidc", 0, "https://id.example", "client", secrets("client"),
                ["openid", "profile"], "resource", "external:{sub}", "idp:{iss}",
                "external namespace", "organization", 0, "https://web.example"]
    verifiers = [[0, "key-id", "sha256:" + "ab" * 32],
                 [1, "user name", "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHRmb3J0ZXN0cw$" + "YWJj" * 10 + "YWI"],
                 [3, "spiffe://example/workload", ca],
                 [2, "kid", secrets("hmac")]]
    credentials = [["visitor", binding, ["read"], verifier]
                   for binding, verifier in zip(bindings, verifiers)]
    methods = [[0, "oidc", "https://route.example"], [1, "ca", None],
               [2, "__ns_realm__", None], [3, "issuer", None], [4, "__ns_realm__", None],
               [5, "__ns_realm__", None]]
    config = [1, realm, 7, "oidc", [provider], secrets("cookie"),
              [["visitor", subject, True, "Visitor name"]], credentials,
              cbor.encode(public), [["issuer", True, 0, None]],
              [["jwt", "visitor"]], [["route", methods, False, True]]]
    response = [1, cbor.encode(pending), cbor.encode(config)]
    out = []

    def emit(name, kind, value, accepted=True, raw=None, extra=()):
        out.append([("name", name), ("kind", kind),
                    ("bytes", cbor.encode(value) if raw is None else raw),
                    ("request", cbor.encode(pending)),
                    ("expect", "accept" if accepted else "reject"), *extra])

    emit("request", "request", pending)
    emit("configuration", "configuration", config)
    emit("confidential_auth_generation", "response", response)
    for name, source in [("fixed-jwks", ["issuer", True, 1, "https://keys.example/jwks"]),
                         ("inline-jwks", ["issuer", False, 2, '{"keys":[]}'])]:
        changed = copy.deepcopy(config)
        changed[9] = [source]
        emit(name, "configuration", changed)
    empty = copy.deepcopy(config)
    empty[3], empty[4], empty[6], empty[7] = None, [], [], []
    empty[8], empty[9], empty[10], empty[11] = cbor.encode([1, realm, [material], [], [], []]), [], [], []
    emit("complete-empty", "configuration", empty)
    generic = copy.deepcopy(config)
    generic[4][0][6:9] = [None, None, None]
    generic[4][0][10:12] = [None, None]
    generic[11][0][1][0][2] = None
    emit("generic-oidc", "configuration", generic)
    maximum_secret = copy.deepcopy(config)
    maximum_secret[5][0][3] = "x" * 8192
    emit("maximum-secret", "configuration", maximum_secret)

    for name, index, replacement in [
        ("correlation", 1, bytes([9]) * 16), ("recipient", 2, authority),
        ("served-realm", 3, "other"), ("scope", 4, "other"),
        ("realm", 5, bytes([9]) * 16), ("reference", 6, [0, "other", 7]),
        ("generation", 6, [0, "auth", 8]),
    ]:
        changed = copy.deepcopy(pending)
        changed[index] = replacement
        emit("wrong-" + name, "response", [1, cbor.encode(changed), cbor.encode(config)], False)
    for name, index, replacement in [("payload-realm", 1, bytes([9]) * 16),
                                      ("payload-generation", 2, 8)]:
        changed = copy.deepcopy(config)
        changed[index] = replacement
        if index == 1:
            # Empty metadata makes this independently well-formed for the other realm.
            changed[4], changed[6], changed[7], changed[9], changed[10], changed[11] = [], [], [], [], [], []
            changed[3] = None
            changed[8] = cbor.encode([1, replacement, [], [], [], []])
        emit("wrong-" + name, "response", [1, cbor.encode(pending), cbor.encode(changed)], False)
    for name, change in [
        ("zero-generation", lambda x: x.__setitem__(2, 0)),
        ("missing-verifier", lambda x: x[7][0][3].__setitem__(2, "")),
        ("wrong-default", lambda x: x.__setitem__(3, "missing")),
        ("insecure-issuer", lambda x: x[4][0].__setitem__(2, "http://id.example")),
        ("whitespace-redirect", lambda x: x[4][0].__setitem__(12, "https://web.example/a b")),
        ("missing-organization", lambda x: x[4][0].__setitem__(10, None)),
        ("unknown-verifier", lambda x: x[7][0][3].__setitem__(0, 9)),
        ("duplicate-credential", lambda x: x[7].append(copy.deepcopy(x[7][-1]))),
        ("duplicate-method", lambda x: x[11][0][1].append(copy.deepcopy(x[11][0][1][0]))),
        ("wrong-redirect-kind", lambda x: x[11][0][1][1].__setitem__(2, "https://web.example")),
        ("zero-secret-version", lambda x: x[5][0].__setitem__(1, 0)),
        ("missing-client-secret", lambda x: x[4][0][4][0].__setitem__(3, "")),
        ("null-cookie", lambda x: x.__setitem__(5, None)),
        ("unknown-provider", lambda x: x[4][0].__setitem__(1, 1)),
        ("unknown-organization", lambda x: x[4][0].__setitem__(11, 9)),
        ("oversized-secret", lambda x: x[5][0].__setitem__(3, "x" * 8193)),
        ("wrong-binding", lambda x: x[7][0].__setitem__(0, "missing")),
        ("unknown-method", lambda x: x[11][0][1][0].__setitem__(0, 9)),
        ("wrong-method-reference", lambda x: x[11][0][1][0].__setitem__(1, "missing")),
        ("unknown-key-source", lambda x: x[9][0].__setitem__(2, 9)),
        ("missing-key-source", lambda x: x.__setitem__(9, [])),
        ("missing-jwt-join", lambda x: x.__setitem__(10, [])),
        ("wrong-jwt-consumer", lambda x: x[10][0].__setitem__(1, "missing")),
        ("duplicate-provider", lambda x: x[4].append(copy.deepcopy(x[4][0]))),
        ("secret-reference", lambda x: x[5][1][0].__setitem__(0, "other")),
        ("secret-version", lambda x: x[5][1][0].__setitem__(1, 2)),
    ]:
        changed = copy.deepcopy(config)
        change(changed)
        emit(name, "configuration", changed, False)
    emit("unknown-field", "configuration", config + [None], False)
    emit("missing-field", "configuration", config[:-1], False)
    raw = cbor.encode(config)
    emit("noncanonical", "configuration", None, False, raw[:1] + b"\x18\x01" + raw[2:])
    emit("trailing", "configuration", None, False, raw + b"\x00")
    for kind, value in [("request", pending), ("response-codec", response)]:
        encoded = cbor.encode(value)
        emit(kind + "-noncanonical", kind, None, False, encoded[:1] + b"\x18\x01" + encoded[2:])
        emit(kind + "-trailing", kind, None, False, encoded + b"\x00")
        emit(kind + "-unknown-field", kind, value + [None], False)
        emit(kind + "-missing-field", kind, value[:-1], False)
    for label, direction, signer_seed, signer, recipient, payload in [
        ("signed-request", 0, bytes([2]) * 32, gateway, authority, cbor.encode(pending)),
        ("signed-response", 1, bytes([1]) * 32, authority, gateway, cbor.encode(response)),
    ]:
        content = cbor.encode([1, direction, signer, recipient, "edge.auth.config.get", 100,
                               bytes([6]) * 16, payload])
        domain = b"ns.account.call." + (b"request" if direction == 0 else b"response") + b".v1\0"
        signature = sign(signer_seed, domain + content)
        x = base64.urlsafe_b64encode(signer).decode().rstrip("=")
        jwk = json.dumps({"crv": "Ed25519", "kty": "OKP", "x": x}, separators=(",", ":"))
        pin = base64.urlsafe_b64encode(hashlib.sha256(jwk.encode()).digest()).decode().rstrip("=")
        emit(label, "envelope", [content, signature], extra=[("pin", pin)])
    return out
