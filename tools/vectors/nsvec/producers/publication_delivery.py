"""Independent complete SourcePublication and LF/CRLF boundary fixtures."""
import base64
from .. import cbor
from . import account

CRATE = "nsshared-proto"
GROUP = "publication-delivery"
TITLE = "Candidate publication stream delivery (fixture authority)"
SECTIONS = "repository docs/control-exchange-candidate.md publication stream framing"


def vectors():
    seed = bytes([2])*32
    issuer = account.key(seed)[0]
    node = account.key(bytes([1])*32)[0]

    def signed(value, domain):
        raw = cbor.encode(value)
        return cbor.encode([raw, account.sign(seed, domain + raw)])

    binding = signed([1, issuer, node, "030C1G60R30C1G60R30C1G60R3", "nodes",
                      "explicit-gateway-profile", node, bytes([10])*16, 1, 1],
                     b"ns.account.source-binding.v1\0")
    context = cbor.encode([0, bytes([3])*16, 1])

    def publication(size):
        event = signed([1, issuer, node, "030C1G60R30C1G60R30C1G60R3", "nodes",
                        11, "policy-version", 0, True, 8, 100, 200, 0, b"x"*size],
                       b"ns.account.publication.v1\0")
        return signed([1, binding, context, event], b"ns.account.source-publication.v1\0")

    limit = 1_048_576
    probe = publication(limit)
    exact = publication(limit - (len(probe) - limit))
    assert len(exact) == limit
    over = publication(limit - (len(probe) - limit) + 1)
    out = []
    for name, raw, ending in [("lf-at-decoded-ceiling", exact, b"\n"),
                              ("crlf-at-framed-ceiling", exact, b"\r\n"),
                              ("crlf-over-ceiling", over, b"\r\n"),
                              ("lf-over-decoded-ceiling", over, b"\n")]:
        encoded = base64.urlsafe_b64encode(raw).rstrip(b"=")
        frame = b"event: config-envelope.v1" + ending + b"data: " + encoded + ending*2
        out.append([("name", name), ("bytes", raw), ("frame", frame),
                    ("binding", binding), ("context", context),
                    ("encoded_length", len(encoded)), ("framed_length", len(frame)),
                    ("decision", "terminate" if len(raw) > limit else "replace")])
    return out
