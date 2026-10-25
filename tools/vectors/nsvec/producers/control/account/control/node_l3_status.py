"""Independent exact Node L3 signed-event/status fixtures; fixture authorities."""
import copy
import hashlib
from nsvec import cbor, ed25519
from nsvec.producers.control.account.publication import envelope as publication

CRATE = "nsshared-control"
GROUP = "account/control/node-l3-status"
TITLE = "Node L3 applied status (fixture authorities)"
SPEC = "docs/spec/account/control.md"
EXTERNAL = None


def vectors():
    seed = bytes([2]) * 32
    issuer = ed25519.public_key(seed)
    recipient = ed25519.public_key(bytes([1]) * 32)
    realm = "030C1G60R30C1G60R30C1G60R3"
    key = [issuer, recipient, realm, "nodes", 11, "node-l3"]
    source = [1, issuer, recipient, realm, "nodes", "explicit-gateway-profile",
              recipient, bytes([10]) * 16, 1, 1]
    policy = [1, issuer, recipient, 1, [], []]
    authority = cbor.encode([1, [], cbor.encode(policy)])

    def event(payload, version=1, outcome=0, issued=100):
        content = cbor.encode([1, *key, 1, True, version, issued, 200, outcome, payload])
        return cbor.encode([content, ed25519.sign(seed, publication.DOMAIN + content)])

    signed = event(authority)
    digest = lambda raw: hashlib.sha256(b"ns.account.node-l3.v1\0" + raw).digest()
    request = [1, bytes([7]) * 16, key, cbor.encode(source), 1, digest(signed), [0]]
    out = []

    def emit(name, value=request, inner=signed, binding=source, decision="accept", raw=None):
        wire = cbor.encode(value) if raw is None else raw
        def envelope(direction, signer, target, payload, signing_seed):
            content = cbor.encode([1, direction, signer, target, "node.l3.status", 150, bytes([8]) * 16, payload])
            domain = b"ns.account.call.request.v1\0" if direction == 0 else b"ns.account.call.response.v1\0"
            return cbor.encode([content, ed25519.sign(signing_seed, domain + content)])
        response = cbor.encode([1, wire])
        out.append([("name", name), ("bytes", wire), ("event", inner),
                    ("source", cbor.encode(binding)), ("digest", digest(inner)),
                    ("response", response), ("decision", decision),
                    ("request-envelope", envelope(0, recipient, issuer, wire, bytes([1]) * 32)),
                    ("response-envelope", envelope(1, issuer, recipient, response, seed))])

    emit("applied")
    emit("same-version-different-digest", inner=event(authority, issued=101), decision="mismatch")
    replacement = copy.deepcopy(source)
    replacement[9] = 2
    emit("replaced-source", binding=replacement, decision="mismatch")
    rejected = copy.deepcopy(request)
    rejected[6] = [1, "installation refused"]
    emit("rejected", rejected)
    failed = event(cbor.encode(["denied"]), version=2, outcome=1)
    value = copy.deepcopy(request)
    value[4:7] = [2, digest(failed), [2]]
    emit("fetch-failed-denied", value, inner=failed)
    empty = event(b"", version=3)
    value = copy.deepcopy(request)
    value[4:7] = [3, digest(empty), [0]]
    emit("empty-withdrawal", value, inner=empty)
    for label, index, replacement in [("family", 4, 4), ("kind", 5, "subnet-routes")]:
        value = copy.deepcopy(request)
        value[2][index] = replacement
        emit("wrong-" + label, value, decision="refuse")
    for index in (1, 2, 3, 4):
        binding = copy.deepcopy(source)
        binding[index] = ({1: recipient, 2: issuer, 3: "040G2081040G2081040G208104", 4: "egress"})[index]
        value = copy.deepcopy(request)
        value[3] = cbor.encode(binding)
        emit("binding-field-" + str(index), value, decision="refuse")
    for label, index, replacement in [
        ("zero-id", 1, bytes(16)), ("zero-version", 4, 0),
        ("short-digest", 5, bytes(31)), ("unknown-status", 6, [3]),
        ("empty-reason", 6, [1, ""]), ("control-reason", 6, [1, "bad\nreason"]),
        ("long-reason", 6, [1, "é" * 129]), ("status-extra", 6, [0, 1])]:
        value = copy.deepcopy(request)
        value[index] = replacement
        emit(label, value, decision="refuse")
    emit("extra-field", request + [0], decision="refuse")
    canonical = cbor.encode(request)
    emit("nonminimal-schema", raw=canonical[:1] + b"\x18\x01" + canonical[2:], decision="refuse")
    emit("trailing-byte", raw=canonical + b"\x00", decision="refuse")
    value = copy.deepcopy(request)
    value[3] = b"\x98\x0a" + value[3][1:]
    emit("nonminimal-source", value, decision="refuse")
    value = copy.deepcopy(request)
    value[6] = [2]
    emit("failure-status-for-data", value, decision="mismatch")
    value = copy.deepcopy(request)
    value[4:7] = [2, digest(failed), [0]]
    emit("applied-for-failure", value, inner=failed, decision="mismatch")
    for label, index, replacement in [("issuer", 1, recipient), ("recipient", 2, issuer), ("revision", 3, 2)]:
        bad_policy = copy.deepcopy(policy)
        bad_policy[index] = replacement
        bad = event(cbor.encode([1, [], cbor.encode(bad_policy)]))
        value = copy.deepcopy(request)
        value[5] = digest(bad)
        emit("policy-" + label, value, inner=bad, decision="mismatch")
    return out
