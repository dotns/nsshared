"""Independent correlated snapshots containing valid neighboring grants."""
from .. import cbor
from . import account, bootstrap_envelope, provider_mapping

CRATE = "nsshared-proto"
GROUP = "provider-mapping-actions"
TITLE = "Atomic provider mapping actions (fixture authorities)"
SECTIONS = "docs/l8-public-edge-candidate.md"


def vectors():
    fixtures = [dict(fields) for fields in provider_mapping.vectors()]
    adjacent = next(fields["bytes"] for fields in fixtures if fields["name"] == "provider-p")
    issuer = account.key(bytes([2]) * 32)[0]
    subscriber = account.key(bytes([1]) * 32)[0]
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
            envelope = cbor.encode([content, account.sign(
                bytes([2]) * 32, bootstrap_envelope.RESPONSE + content)])
            out.append([("name", fields["name"]), ("bytes", envelope),
                        ("request", request), ("pin", bootstrap_envelope.pin(issuer)),
                        ("source", fields["source"]), ("snapshot", snapshot),
                        ("adjacent", adjacent), ("mapping", fields["bytes"]),
                        ("decision", fields["decision"])])
    return out
