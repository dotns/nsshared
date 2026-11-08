"""Signed Exit readiness decisions and atomic Snapshot refusal, without Rust input."""
from nsvec import cbor, ed25519
from nsvec.signing import carrier
from nsvec.producers.control.account.control import envelope
from nsvec.producers.control.account.subnet.readiness import example

CRATE = "nsshared-control"
GROUP = "account/subnet/readiness-publication"
TITLE = "Exit readiness publication acceptance paths"
SPEC = "docs/spec/account/exit-readiness.md"
EXTERNAL = None


def vectors():
    values = example()
    context = values["context"]
    signed = cbor.decode(cbor.decode(context[3])[1])[1]
    source = cbor.decode(cbor.decode(signed)[0])
    seed = bytes([2])*32
    pending = cbor.encode([1, bytes([3])*16, 1, bytes([4])*16])
    request = cbor.encode([1, source[2], [[source[1], source[2], source[3], "nodes"]], bytes([3])*16, 1, bytes([4])*16])
    positive = cbor.encode(values["publication"])
    empty = values["publication"][:-1] + [[]]
    out = []

    def event(kind, payload, version=1, outcome=0):
        return carrier(seed, [1, source[1], source[2], source[3], "nodes", 2 if kind == "realm-peers" else 4,
                              kind, 1, True, version, 0, 20, outcome, payload], b"ns.account.publication.v1\0")

    for name, payload, version, outcome, plain_decision, foreign_node in [
        ("positive", positive, 1, 0, "replace", False),
        ("empty", cbor.encode(empty), 1, 0, "replace", False),
        ("withdraw", b"", 2, 0, "withdraw", False),
        ("failed-empty", cbor.encode(empty), 1, 1, "fetch_failed", False),
        ("failed-positive", positive, 1, 1, "refused", False),
        ("version-mismatch", positive, 2, 0, "refused", False),
        ("malformed-payload", b"\x80", 1, 0, "refused", False),
        ("foreign-source-node", positive, 1, 0, "replace", True),
        ("foreign-source-node-withdraw", b"", 2, 0, "withdraw", True),
    ]:
        binding = list(source)
        if foreign_node:
            binding[6] = values["context"][7][1]
        binding = carrier(seed, binding, b"ns.account.source-binding.v1\0")

        def wrap(raw):
            return carrier(seed, [1, binding, pending, raw], b"ns.account.source-publication.v1\0")

        raw = event("exit-readiness", payload, version, outcome)
        peer = event("realm-peers", b"")
        snapshot = cbor.encode([1, [wrap(peer), wrap(raw)]])
        response = carrier(seed, [1, 1, source[1], source[2], "config.snapshot", 0, bytes([4])*16, snapshot], envelope.RESPONSE)
        out.append([("name", name), ("bytes", raw), ("source", binding), ("pending", pending),
                    ("wrapped", wrap(raw)), ("plain_snapshot", cbor.encode([1, [peer, raw]])),
                    ("source_snapshot", snapshot), ("request", request), ("response", response),
                    ("pin", envelope.pin(source[1])), ("plain_decision", plain_decision),
                    ("source_decision", "refused" if foreign_node else plain_decision)])
    return out
