"""Independent provider report bytes and expected decisions; fixture authority only."""
import copy
from nsvec import cbor, ed25519
from nsvec.producers.control.account.control import envelope as bootstrap_envelope

CRATE = "nsshared-control"
GROUP = "account/subnet/report"
TITLE = "Ordinary provider Subnet route reports (fixture authority)"
SPEC = "docs/spec/account/subnet.md"
EXTERNAL = None


def vectors():
    nsd_seed, node_seed = bytes([2])*32, bytes([1])*32
    nsd, node = ed25519.public_key(nsd_seed), ed25519.public_key(node_seed)
    realm = "030C1G60R30C1G60R30C1G60R3"
    network, nsd_id = bytes([3])*16, bytes([21])*16
    source = [1, nsd, node, realm, "nodes", "explicit-gateway-profile", node,
              bytes([10])*16, 1, 1]

    def binding(value):
        raw = cbor.encode(value)
        return cbor.encode([raw, ed25519.sign(nsd_seed, b"ns.account.source-binding.v1\0" + raw)])

    a = binding(source)
    replacement = copy.deepcopy(source)
    replacement[7], replacement[9] = bytes([11])*16, 2
    b = binding(replacement)
    ref1 = cbor.encode([nsd_id, network, bytes([31])*16])
    ref2 = cbor.encode([nsd_id, network, bytes([32])*16])
    explicit = [1, [[4, bytes([10, 1, 0, 0]), 16]]]
    offers = [[7, explicit], [9, [0, []]]]
    allocations = [[7, ref1], [9, ref2]]
    out = []

    def emit(name, mode, value, decision="accept", **fields):
        raw = value if isinstance(value, bytes) else cbor.encode(value)
        out.append([("name", name), ("mode", mode), ("bytes", raw),
                    ("decision", decision), *fields.items()])
        return raw

    emit("source-a", "binding", a)
    emit("source-b", "binding", b)
    emit("authority", "authority", [nsd_id, network])
    reports = {}
    for name, src, gen, offered, allocated, decision in [
        ("initial", a, 1, offers, allocations, "replace"),
        ("retry", a, 1, offers, allocations, "retry"),
        ("update", a, 2, [[7, [1, []]], offers[1]], allocations, "replace"),
        ("withdraw-one", a, 3, [offers[1]], [allocations[1]], "replace"),
        ("withdraw-all", a, 4, [], [], "replace"),
        ("reoffer", a, 5, offers, allocations, "replace"),
        ("replacement", b, 1, offers, [[7, cbor.encode([nsd_id, network, bytes([41])*16])],
                                     [9, cbor.encode([nsd_id, network, bytes([42])*16])]], "replace"),
    ]:
        reports[name] = emit(name, "report", [1, src, gen, offered], decision)
        emit(name + "-response", "response", [1, src, gen, allocated])
    emit("equal-conflict", "report", [1, a, 1, [offers[0]]], "conflict")
    emit("stale-restoration", "report", reports["initial"], "stale")
    emit("delayed-retired", "report", reports["reoffer"], "authority")
    for name, index, value in [("egress", 4, "egress"),
                                ("wrong-profile", 5, "gateway-v1"),
                                ("wrong-node", 6, nsd),
                                ("wrong-record", 7, bytes([12])*16)]:
        changed = copy.deepcopy(source)
        changed[index] = value
        emit(name, "report", [1, binding(changed), 6, offers], "refuse")
    for name, offered in [
        ("unknown-mapping", [[8, explicit]]),
        ("outside-real", [[7, [1, [[4, bytes([11, 0, 0, 0]), 8]]]]]),
        ("default-nonzero-real", [[7, [0, []]]]),
        ("wrong-family", [[7, [1, [[6, bytes(16), 0]]]]]),
    ]:
        emit(name, "report", [1, a, 6, offered], "mapping")
    malformed = [
        ("zero-generation", [1, a, 0, offers]),
        ("zero-id", [1, a, 1, [[0, explicit]]]),
        ("overflow-id", [1, a, 1, [[2**32, explicit]]]),
        ("duplicate-id", [1, a, 1, [offers[0], offers[0]]]),
        ("unsorted-id", [1, a, 1, offers[::-1]]),
        ("too-many-offers", [1, a, 1, [[i+1, [1, []]] for i in range(257)]]),
        ("too-many-prefixes", [1, a, 1, [[7, [1, [[4, i.to_bytes(4, "big"), 32] for i in range(257)]]]]]),
        ("overlap", [1, a, 1, [[7, [1, [[4, bytes([10, 0, 0, 0]), 8], [4, bytes([10, 1, 0, 0]), 16]]]]]]),
        ("misaligned", [1, a, 1, [[7, [1, [[4, bytes([10, 1, 0, 1]), 16]]]]]]),
        ("mixed-default", [1, a, 1, [[9, [0, [[4, bytes(4), 0]]]]]]),
        ("unknown-selection", [1, a, 1, [[7, [2, []]]]]),
        ("missing-offers", [1, a, 1]),
        ("extra-field", [1, a, 1, offers, 0]),
        ("unknown-schema", [2, a, 1, offers]),
    ]
    for name, value in malformed:
        emit(name, "malformed-report", value, "refuse")
    raw = reports["initial"]
    emit("nonminimal", "malformed-report", b"\x98\x04" + raw[1:], "refuse")
    emit("trailing", "malformed-report", raw + b"\0", "refuse")
    emit("truncated", "malformed-report", raw[:-1], "refuse")
    emit("offer-boundary", "boundary", [1, a, 1, [[i+1, [1, []]] for i in range(256)]])
    emit("prefix-boundary", "boundary", [1, a, 1, [[7, [1, [[4, i.to_bytes(4, "big"), 32] for i in range(256)]]]]])
    for name, allocated in [
        ("missing-allocation", allocations[:1]),
        ("extra-allocation", allocations + [[10, ref1]]),
        ("wrong-mapping", [[8, ref1], allocations[1]]),
        ("replaced-reference", [[7, cbor.encode([nsd_id, network, bytes([33])*16])], allocations[1]]),
        ("wrong-reference-nsd", [[7, cbor.encode([bytes([22])*16, network, bytes([31])*16])], allocations[1]]),
        ("wrong-reference-network", [[7, cbor.encode([nsd_id, bytes([4])*16, bytes([31])*16])], allocations[1]]),
        ("duplicate-reference", [allocations[0], [9, ref1]]),
    ]:
        emit(name, "invalid-response", [1, a, 1, allocated], "refuse")
    for name, value in [
        ("response-zero-generation", [1, a, 0, allocations]),
        ("response-unknown-schema", [2, a, 1, allocations]),
        ("response-too-many", [1, a, 1, [[i+1, ref1] for i in range(257)]]),
        ("response-zero-id", [1, a, 1, [[0, ref1]]]),
        ("response-unsorted", [1, a, 1, allocations[::-1]]),
        ("response-duplicate", [1, a, 1, [allocations[0]]*2]),
        ("response-invalid-reference", [1, a, 1, [[7, b"\x80"]]]),
        ("response-reference-trailing", [1, a, 1, [[7, ref1 + b"\0"]]]),
    ]:
        emit(name, "malformed-response", value, "refuse")

    def carrier(payload, response, nonce=bytes([6])*16, recipient=None, operation="node.subnet.report", signer_seed=None):
        signer_seed = signer_seed or (nsd_seed if response else node_seed)
        signer = ed25519.public_key(signer_seed)
        if recipient is None:
            recipient = node if response else nsd
        content = cbor.encode([1, int(response), signer, recipient, operation, 100, nonce, payload])
        domain = bootstrap_envelope.RESPONSE if response else bootstrap_envelope.REQUEST
        return cbor.encode([content, ed25519.sign(signer_seed, domain + content)])

    response = cbor.encode([1, a, 1, allocations])
    for suffix, kwargs, decision in [
        ("valid", {}, "accept"),
        ("fresh-retry", {"nonce": bytes([8])*16}, "accept"),
        ("zero-nonce", {"nonce": bytes(16)}, "refuse"),
        ("wrong-operation", {"operation": "node.route.select"}, "refuse"),
        ("wrong-recipient", {"recipient": nsd}, "refuse"),
        ("wrong-signer", {"signer_seed": bytes([3])*32}, "refuse"),
    ]:
        emit("response-carrier-" + suffix, "response-carrier", carrier(response, True, **kwargs), decision,
             pending_nonce=bytes([8 if suffix == "fresh-retry" else 6])*16)
    for suffix, kwargs, decision in [
        ("valid", {}, "accept"),
        ("fresh-retry", {"nonce": bytes([8])*16}, "accept"),
        ("zero-nonce", {"nonce": bytes(16)}, "refuse"),
        ("wrong-operation", {"operation": "node.route.select"}, "refuse"),
        ("wrong-recipient", {"recipient": node}, "refuse"),
        ("wrong-signer", {"signer_seed": bytes([3])*32}, "refuse"),
    ]:
        emit("request-carrier-" + suffix, "request-carrier", carrier(raw, False, **kwargs), decision)
    return out
