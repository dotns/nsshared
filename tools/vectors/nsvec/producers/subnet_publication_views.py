"""Independent multi-provider grant and client route snapshots; fixture authorities."""
import copy
from .. import cbor
from . import account, publication, source_selection, subnet

CRATE = "nsshared-proto"
GROUP = "subnet-publication-views"
TITLE = "Provider grants and client Subnet route views (fixture authorities)"
SECTIONS = "docs/grant-authority-candidate.md; docs/source-selection-candidate.md"


def vectors():
    seed = bytes([2]) * 32
    issuer = account.key(seed)[0]
    p, q, client = [account.key(bytes([i]) * 32)[0] for i in (1, 3, 4)]
    nsd, network = bytes([21]) * 16, bytes([3]) * 16
    realm = "030C1G60R30C1G60R30C1G60R3"
    pending = [1, bytes([4]) * 16, 1, bytes([5]) * 16]

    def signed(value, domain):
        raw = cbor.encode(value)
        return cbor.encode([raw, account.sign(seed, domain + raw)])

    def binding(node, scope="nodes", generation=1, source_node=None):
        return signed([1, issuer, node, realm, scope, "explicit-gateway-profile",
                       source_node or node, bytes([10]) * 16, 1, generation], source_selection.BINDING)

    def route(provider, tag, destination):
        real = subnet.prefix(destination)
        return [cbor.encode([nsd, network, bytes([tag]) * 16]), real,
                subnet.mapped(real), provider, client, [], [], [1, [real]]]

    rp, rq = route(p, 1, "10.0.0.0/8"), route(q, 2, "172.16.0.0/12")

    def routes(revision, entries):
        return [1, 4, nsd, network, client, revision, entries]

    def grants(provider, revision, entries):
        values = []
        for entry in entries:
            embedded = routes(1, [entry])
            values.append([entry[0], client, provider, [[network, bytes([23]) * 16]],
                           bytes([31]) * 16, 10000, [1, cbor.encode(embedded)]])
        return [1, 4, issuer, provider, revision, values]

    out = []

    def emit(name, node, kind, payload, revision=1, accepted=True, scope="nodes",
             source=None, accepted_node=None, accepted_source=None,
             accepted_nsd=nsd, accepted_network=network):
        source = source or binding(node, scope)
        inner = signed([1, issuer, node, realm, scope, 4 if kind != "egress-grants" else 3,
                        kind, 1, True, revision, 100, 200, 0, cbor.encode(payload)], publication.DOMAIN)
        outer = signed([1, source, cbor.encode(pending), inner], source_selection.PUBLICATION)
        out.append([("name", name), ("bytes", outer), ("source", accepted_source or binding(node)),
                    ("pending", cbor.encode(pending)), ("issuer", issuer),
                    ("recipient", accepted_node or node), ("nsd", accepted_nsd),
                    ("network", accepted_network), ("decision", "accept" if accepted else "refuse")])

    emit("provider-p", p, "exit-grants", grants(p, 1, [rp]))
    emit("provider-q", q, "exit-grants", grants(q, 1, [rq]))
    emit("client-both", client, "subnet-routes", routes(1, [rp, rq]))
    emit("swapped-route-kind", client, "exit-grants", routes(1, [rp, rq]), accepted=False)
    emit("swapped-grant-kind", p, "subnet-routes", grants(p, 1, [rp]), accepted=False)
    emit("wrong-recipient", client, "subnet-routes", routes(1, [rp]), accepted=False, accepted_node=p)
    emit("wrong-payload-recipient", p, "subnet-routes", routes(1, [rp]), accepted=False)
    emit("wrong-source", client, "subnet-routes", routes(1, [rp]), accepted=False, source=binding(client, generation=2))
    emit("wrong-source-node", client, "subnet-routes", routes(1, [rp]), accepted=False,
         source=binding(client, source_node=p), accepted_source=binding(client, source_node=p))
    emit("wrong-source-scope", client, "subnet-routes", routes(1, [rp]), accepted=False,
         scope="egress", accepted_source=binding(client, "egress"))
    emit("exit-wrong-scope", p, "exit-grants", grants(p, 1, [rp]), accepted=False,
         scope="egress", accepted_source=binding(p, "egress"))
    emit("wrong-membership-nsd", client, "subnet-routes", routes(1, [rp]), accepted=False, accepted_nsd=network)
    emit("wrong-membership-network", client, "subnet-routes", routes(1, [rp]), accepted=False, accepted_network=nsd)
    emit("wrong-grant-revision", p, "exit-grants", grants(p, 2, [rp]), accepted=False)
    emit("wrong-grant-recipient", p, "exit-grants", grants(q, 1, [rq]), accepted=False)
    emit("wrong-revision", client, "subnet-routes", routes(2, [rp]), accepted=False)
    altered = copy.deepcopy(routes(1, [rp]))
    altered[3] = nsd
    altered[6][0][0] = cbor.encode([nsd, nsd, bytes([1]) * 16])
    emit("wrong-payload-network", client, "subnet-routes", altered, accepted=False)
    emit("wrong-served-realm", client, "subnet-routes", altered, accepted=False, accepted_network=nsd)
    egress_route = [rp[0], client, p, [[network, bytes([23]) * 16]],
                    bytes([32]) * 16, 10000, [0, "backend", "service.example", 6, 443, None]]
    egress_payload = [1, 3, issuer, p, 1, [egress_route]]
    emit("egress-nodes-refused", p, "egress-grants", egress_payload, accepted=False)
    emit("egress-contribution", p, "egress-grants", egress_payload, scope="egress",
         accepted_source=binding(p, "egress"))
    emit("provider-p-empty", p, "exit-grants", grants(p, 2, []), 2)
    emit("client-q-only", client, "subnet-routes", routes(2, [rq]), 2)
    emit("client-empty", client, "subnet-routes", routes(3, []), 3)
    return out
