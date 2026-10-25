"""Independent correlated snapshots containing valid neighboring grants."""
from nsvec import cbor, ed25519
from nsvec.producers.control.account.control import envelope as bootstrap_envelope
from nsvec.producers.control.account.subnet import mapping as provider_mapping

CRATE = "nsshared-control"
GROUP = "account/subnet/mapping-actions"
TITLE = "Atomic provider mapping actions (fixture authorities)"
SPEC = "docs/spec/account/subnet.md"
EXTERNAL = None


def vectors():
    fixtures = [dict(fields) for fields in provider_mapping.vectors()]
    adjacent = next(fields["bytes"] for fields in fixtures if fields["name"] == "provider-p")
    issuer = ed25519.public_key(bytes([2]) * 32)
    subscriber = ed25519.public_key(bytes([1]) * 32)
    request = cbor.encode([1, subscriber,
                          [[issuer, subscriber, "030C1G60R30C1G60R30C1G60R3", "nodes"]],
                          bytes([4]) * 16, 1, bytes([5]) * 16])
    out = []
    for fields in fixtures:
        if fields["name"] in {"populated", "replacement", "typed-empty", "withdrawal",
                              "zero-id", "duplicate-id", "descending-id", "overflow-id",
                              "invalid-cidr", "invalid-family", "invalid-length",
                              "invalid-address", "too-many", "noncanonical", "trailing"}:
            snapshot = cbor.encode([1, [adjacent, fields["bytes"]]])
            content = cbor.encode([1, 1, issuer, subscriber, "config.snapshot", 100,
                                   bytes([5]) * 16, snapshot])
            envelope = cbor.encode([content, ed25519.sign(
                bytes([2]) * 32, bootstrap_envelope.RESPONSE + content)])
            out.append([("name", fields["name"]), ("bytes", envelope),
                        ("request", request), ("pin", bootstrap_envelope.pin(issuer)),
                        ("source", fields["source"]), ("snapshot", snapshot),
                        ("adjacent", adjacent), ("mapping", fields["bytes"]),
                        ("decision", fields["decision"])])
    return out
