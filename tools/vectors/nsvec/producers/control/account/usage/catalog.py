"""Independent scoped catalogue payloads and signed replacement sequence."""
import copy
from nsvec import cbor, ed25519

CRATE = "nsshared-control"
GROUP = "account/usage/catalog"
TITLE = "Usage and Node-control catalogues (fixture authority)"
SPEC = "docs/spec/account/usage.md"
EXTERNAL = None
USAGE = ["l8-completed-io-v1", "l8-relay-data-v1"]
REALM = "030C1G60R30C1G60R30C1G60R3"


def vectors():
    seed = bytes([2]) * 32
    issuer = ed25519.public_key(seed)
    reporter = ed25519.public_key(bytes([1]) * 32)
    membership = [bytes([3]) * 16, bytes([3]) * 16]
    usage = [1, reporter, USAGE]
    control = [1, membership, 2, [0, 1, 2, 3, 4]]
    out = []
    # y=2 has no Ed25519 x coordinate; calibrate the invalid-point fixture.
    x_squared = 3 * pow(4 * ed25519.D + 1, ed25519.P - 2, ed25519.P) % ed25519.P
    assert pow(x_squared, (ed25519.P - 1) // 2, ed25519.P) == ed25519.P - 1

    def emit(name, kind, raw, expect="accept", **fields):
        out.append([("name", name), ("kind", kind), ("bytes", raw),
                    ("expect", expect), *fields.items()])

    for kind, base in [("usage", usage), ("control", control)]:
        emit(kind + "-complete", kind, cbor.encode(base))
        changed = copy.deepcopy(base)
        changed[-1] = changed[-1][:1]
        emit(kind + "-singleton", kind, cbor.encode(changed))
        mutations = [("schema", 0, 2), ("empty", len(base)-1, []),
                     ("duplicate", len(base)-1, [base[-1][0]] * 2),
                     ("unsorted", len(base)-1, base[-1][::-1]),
                     ("unknown", len(base)-1, ["future"] if kind == "usage" else [5]),
                     ("wrong-list", len(base)-1, 0),
                     ("wrong-item", len(base)-1, [0] if kind == "usage" else ["0"])]
        if kind == "usage":
            mutations += [("reporter-width", 1, bytes(31)), ("reporter-invalid", 1, (2).to_bytes(32, "little")),
                          ("reporter-type", 1, "reporter"),
                          ("too-many", 2, USAGE + [USAGE[1]])]
        else:
            mutations += [("vocabulary", 2, 1), ("membership-arity", 1, membership[:1]),
                          ("nsd-width", 1, [bytes(15), membership[1]]),
                          ("network-width", 1, [membership[0], bytes(17)]),
                          ("membership-type", 1, b"membership"),
                          ("overflow", 3, [256]), ("too-many", 3, [0, 1, 2, 3, 4, 5])]
        for label, index, value in mutations:
            changed = copy.deepcopy(base)
            changed[index] = value
            emit(kind + "-" + label, kind, cbor.encode(changed), "reject")
        raw = cbor.encode(base)
        for label, bad in [("trailing", raw + b"\x00"), ("truncated", raw[:-1]),
                           ("nonminimal-array", bytes([0x98, len(base)]) + raw[1:]),
                           ("nonminimal-schema", raw[:1] + b"\x18\x01" + raw[2:]),
                           ("indefinite", b"\x9f" + raw[1:] + b"\xff"),
                           ("extra-field", cbor.encode(base + [0])),
                           ("missing-field", cbor.encode(base[:-1]))]:
            emit(kind + "-" + label, kind, bad, "reject")
    # A structurally valid membership remains descriptive until context comparison.
    emit("control-zero-identifiers", "control", cbor.encode([1, [bytes(16), bytes(16)], 2, [0]]))

    def signed(value, domain):
        content = cbor.encode(value)
        signature = ed25519.sign(seed, domain + content)
        return cbor.encode([content, signature]), signature

    binding, _ = signed([1, issuer, reporter, REALM, "nodes", "explicit-gateway-profile",
                         reporter, bytes([10])*16, 1, 1], b"ns.account.source-binding.v1\0")
    delivery = cbor.encode([0, bytes([4])*16, 1])
    for name, family, kind, version, payload, action in [
        ("install-usage", 9, "usage-profile", 1, cbor.encode(usage), "replace"),
        ("install-control", 10, "node-control-profile", 1, cbor.encode(control), "replace"),
        ("malformed-replacement", 9, "usage-profile", 2,
         cbor.encode([1, reporter, USAGE[::-1]]), "refused"),
        ("withdraw-usage", 9, "usage-profile", 2, b"", "withdraw"),
        ("replay-usage", 9, "usage-profile", 1, cbor.encode(usage), "refused"),
    ]:
        event, signature = signed([1, issuer, reporter, REALM, "nodes", family, kind, 0,
                                   True, version, 100, 200, 0, payload],
                                  b"ns.account.publication.v1\0")
        wire, outer_signature = signed([1, binding, delivery, event],
                                       b"ns.account.source-publication.v1\0")
        emit(name, "publication", event, action, signature=signature,
             source_publication=wire, source_signature=outer_signature,
             binding=binding, delivery=delivery)
    for name, family, kind, payload, decision in [
        ("wrong-reporter-context", 9, "usage-profile", [1, issuer, USAGE], "refused"),
        ("malformed-control-replacement", 10, "node-control-profile",
         [1, membership, 2, [1, 0]], "refused"),
        ("different-membership-context", 10, "node-control-profile",
         [1, [bytes([4])*16, membership[1]], 2, [0]], "replace"),
    ]:
        event, signature = signed([1, issuer, reporter, REALM, "nodes", family, kind,
                                   0, True, 2, 100, 200, 0, cbor.encode(payload)],
                                  b"ns.account.publication.v1\0")
        emit(name, "context", event, decision, signature=signature)
    return out
