"""Independent mapping eligibility snapshots with fixture authorities."""
from .. import cbor
from . import account, publication, source_selection, subnet, subnet_publication_views

CRATE = "nsshared-control"
GROUP = "provider-mapping"
TITLE = "Provider mapping replacement (fixture authorities)"
SECTIONS = "docs/l8-public-edge-candidate.md"


def vectors():
    seed = bytes([2]) * 32
    issuer = account.key(seed)[0]
    p, q = [account.key(bytes([i]) * 32)[0] for i in (1, 3)]
    realm = "030C1G60R30C1G60R30C1G60R3"
    pending = cbor.encode([1, bytes([4]) * 16, 1, bytes([5]) * 16])

    def signed(value, domain):
        raw = cbor.encode(value)
        return cbor.encode([raw, account.sign(seed, domain + raw)])

    def binding(node, generation=1, scope="nodes", source_node=None):
        return signed([1, issuer, node, realm, scope, "explicit-gateway-profile",
                       source_node or node, bytes([10]) * 16, 1, generation], source_selection.BINDING)

    out = []
    first = [[1, subnet.prefix("10.0.0.0/8")], [7, subnet.prefix("2001:db8::/32")]]
    replacement = [[7, subnet.prefix("2001:db8:1::/48")]]

    def emit(name, mappings, node=p, revision=2, accepted=False, kind="provider-mappings",
             channel=1, generation=1, recipient=None, scope="nodes", source_node=None,
             raw_payload=None, accepted_source=None, accepted_network=None):
        source = binding(node, generation, scope, source_node)
        payload = cbor.encode([1, mappings]) if raw_payload is None else raw_payload
        inner = signed([1, issuer, node, realm, scope, 4, kind, channel, True,
                        revision, 100, 200, 0, payload], publication.DOMAIN)
        outer = signed([1, source, pending, inner], source_selection.PUBLICATION)
        out.append([("name", name), ("bytes", outer), ("source", accepted_source or binding(node)),
                    ("pending", pending), ("issuer", issuer), ("recipient", recipient or node),
                    ("nsd", bytes([21]) * 16), ("network", accepted_network or bytes([3]) * 16),
                    ("decision", "accept" if accepted else "refuse"),
                    ("payload", payload if payload else "empty")])

    emit("populated", first, revision=1, accepted=True)
    emit("other-provider", first, node=q, revision=1, accepted=True)
    emit("wrong-recipient", first, recipient=q)
    emit("wrong-kind", first, kind="subnet-routes")
    emit("wrong-channel", first, channel=0)
    emit("wrong-source", first, generation=2)
    emit("wrong-source-node", first, source_node=q,
         accepted_source=binding(p, source_node=q))
    emit("wrong-scope", first, scope="egress", accepted_source=binding(p, scope="egress"))
    emit("wrong-network", first, accepted_network=bytes([21]) * 16)
    emit("old-source", first, generation=1, accepted_source=binding(p, generation=2))
    emit("zero-id", [[0, subnet.prefix("10.0.0.0/8")]])
    emit("duplicate-id", [first[0], first[0]])
    emit("descending-id", list(reversed(first)))
    emit("overflow-id", [[2**32, first[0][1]]])
    emit("invalid-cidr", [[1, [4, bytes([10, 1, 0, 0]), 8]]])
    emit("invalid-family", [[1, [5, bytes(4), 0]]])
    emit("invalid-length", [[1, [4, bytes(4), 33]]])
    emit("invalid-address", [[1, [4, bytes(16), 0]]])
    emit("too-many", [[i + 1, first[0][1]] for i in range(257)])
    emit("noncanonical", [], raw_payload=bytes.fromhex("82180180"))
    emit("trailing", [], raw_payload=bytes.fromhex("82018000"))
    emit("replacement", replacement, accepted=True)
    emit("old-version", first, revision=1)
    emit("typed-empty", [], revision=3, accepted=True)
    emit("withdrawal", [], revision=4, accepted=True, raw_payload=b"")
    return subnet_publication_views.vectors()[:3] + out
