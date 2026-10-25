"""Independent confidential material candidate producer; fixture values only."""
import copy
import base64
import hashlib
import json

from nsvec import cbor
from nsvec.ed25519 import public_key, sign

CRATE = "nsshared-control"
GROUP = "account/edge/material-request"
TITLE = "Confidential certificate and client-CA material (fixture producer)"
SPEC = "docs/spec/account/edge.md"
EXTERNAL = None


def vectors():
    out = []
    for kind, label in [(1, "certificate"), (2, "client-ca")]:
        pending = [1, bytes([8]) * 16, public_key(bytes([2]) * 32),
                   "030C1G60R30C1G60R30C1G60R3", "edge", bytes([3]) * 16,
                   [kind, label, 7]]
        cert = [1, "-----BEGIN CERTIFICATE-----\nfixture chain\n-----END CERTIFICATE-----\n",
                "-----BEGIN PRIVATE KEY-----\nfixture key\n-----END PRIVATE KEY-----\n"]
        ca = [2, "-----BEGIN CERTIFICATE-----\nfixture CA\n-----END CERTIFICATE-----\n"
              "-----BEGIN X509 CRL-----\nfixture CRL\n-----END X509 CRL-----\n", "example.test"]
        response = [1, cbor.encode(pending), ["a.example.test", "b.example.test"], 200, cert if kind == 1 else ca]

        def emit(name, target, value, reason="accept", raw=None):
            out.append([("name", label + "-" + name), ("kind", target),
                        ("request", cbor.encode(pending)),
                        ("bytes", cbor.encode(value) if raw is None else raw),
                        ("expect", "accept" if reason == "accept" else "reject"),
                        ("reason", reason)])

        emit("request", "request", pending)
        emit("generation", "response", response)
        for direction, seed, recipient in [(0, bytes([2]) * 32, public_key(bytes([1]) * 32)),
                                           (1, bytes([1]) * 32, pending[2])]:
            signer = public_key(seed)
            payload = cbor.encode(pending if direction == 0 else response)
            content = cbor.encode([1, direction, signer, recipient, "edge.material.get",
                                   100, bytes([6]) * 16, payload])
            domain = b"ns.account.call." + (b"request" if direction == 0 else b"response") + b".v1\0"
            signature = sign(seed, domain + content)
            x = base64.urlsafe_b64encode(signer).decode().rstrip("=")
            jwk = json.dumps({"crv": "Ed25519", "kty": "OKP", "x": x}, separators=(",", ":"))
            pin = base64.urlsafe_b64encode(hashlib.sha256(jwk.encode()).digest()).decode().rstrip("=")
            emit("envelope-" + str(direction), "envelope", [content, signature])
            out[-1].append(("pin", pin))
        for name, index, value, reason in [
            ("wrong-realm", 5, bytes([9]) * 16, "realm"),
            ("wrong-generation", 6, [kind, label, 8], "generation"),
            ("wrong-echo", 1, bytes([9]) * 16, "echo"),
            ("wrong-recipient", 2, public_key(bytes([1]) * 32), "echo"),
            ("wrong-served-realm", 3, "09144GJ289144GJ289144GJ289", "echo"),
            ("wrong-scope", 4, "other", "echo"),
            ("wrong-reference", 6, [kind, "other", 7], "echo"),
        ]:
            changed = copy.deepcopy(pending)
            changed[index] = value
            bad = copy.deepcopy(response)
            bad[1] = cbor.encode(changed)
            emit(name, "response", bad, reason)
        changed = copy.deepcopy(response)
        changed[4] = ca if kind == 1 else cert
        emit("wrong-values-kind", "response", changed, "kind")
        for bad_kind in (0, 3):
            changed = copy.deepcopy(pending)
            changed[6][0] = bad_kind
            emit("forbidden-kind-" + str(bad_kind), "request", changed, "kind" if bad_kind == 0 else "contract")
        for target, value in [("request", pending), ("response", response)]:
            raw = cbor.encode(value)
            emit(target + "-noncanonical", target, None, "contract", raw[:1] + b"\x18\x01" + raw[2:])
            emit(target + "-trailing", target, None, "contract", raw + b"\x00")
            emit(target + "-unknown-field", target, value + [None], "contract")
            emit(target + "-missing-field", target, value[:-1], "contract")
        for name, hosts in [("duplicate-host", ["a.test", "a.test"]),
                            ("unordered-host", ["b.test", "a.test"]),
                            ("uppercase-host", ["A.test"]), ("wildcard-host", ["*.test"]),
                            ("trailing-dot", ["a.test."]), ("empty-label", ["a..test"]),
                            ("oversized-host", ["a" * 64 + ".test"]),
                            ("oversized-hosts", [f"h{i:03}.test" for i in range(257)])]:
            changed = copy.deepcopy(response)
            changed[2] = hosts
            emit(name, "response", changed, "contract")
        for name, values in [("empty-pem", [kind, "", response[4][2]]),
                             ("blank-pem", [kind, " \n", response[4][2]]),
                             ("missing-value", [kind, response[4][1]]),
                             ("unknown-value-field", response[4] + [None]),
                             ("unknown-value-kind", [9, "value", "value"]),
                             ("null-values", None),
                             ("missing-second-value", [kind, response[4][1], ""])]:
            changed = copy.deepcopy(response)
            changed[4] = values
            emit(name, "response", changed, "kind" if name == "unknown-value-kind" else "contract")
        changed = copy.deepcopy(response)
        changed[4][1] = "x" * 1_048_577
        emit("oversized", "response", changed, "contract")
        changed = copy.deepcopy(response)
        changed[1] = b"\x87\x18\x01" + cbor.encode(pending)[2:]
        emit("nested-noncanonical", "response", changed, "contract")
        for deadline in (0, 2**64 - 1):
            changed = copy.deepcopy(response)
            changed[3] = deadline
            emit("deadline-" + str(deadline), "response", changed)
    return out
