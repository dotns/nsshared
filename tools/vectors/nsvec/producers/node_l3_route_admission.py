"""Independent mapped selection versus direct Node host permission fixtures."""
import ipaddress
import json
from .. import cbor, derive
from . import account, subnet

CRATE = "nsshared-proto"
GROUP = "node-l3-route-admission"
TITLE = "Node L3 mapped route admission (fixture authorities)"
SECTIONS = "docs/node-l3-status-candidate.md; docs/grant-authority-candidate.md"


def vectors():
    issuer, client, provider = [account.key(bytes([i]) * 32)[0] for i in (2, 1, 3)]
    nsd, network, service = [bytes([i]) * 16 for i in (21, 3, 9)]
    real = subnet.prefix("10.0.0.0/8")
    mapping = subnet.mapped(real)
    resource = cbor.encode([nsd, network, service])
    route = [resource, real, mapping, provider, client, [subnet.prefix("10.1.0.0/16")],
             [subnet.prefix("10.2.0.0/16")], [1, [subnet.prefix("10.0.0.0/9")]]]
    view = cbor.encode([1, 4, nsd, network, client, 1, [route]])
    policy = cbor.encode([1, issuer, client, 1, [], []])
    out = []
    for label, destination in [("selected", "10.3.1.2"), ("excluded", "10.1.1.2"),
                               ("unselected", "10.200.1.2"), ("direct-n4", str(ipaddress.IPv6Address(derive.node_addr(provider, 1)))),
                               ("direct-n6", str(ipaddress.IPv6Address(derive.node_addr(provider, 0))))]:
        address = ipaddress.ip_address(destination)
        mapped = ipaddress.IPv6Address(mapping[1][:12] + address.packed) if label in ("selected", "excluded", "unselected") else address
        allowed = label == "selected"
        for protocol in (6, 17, 1):
            out.append([("name", f"{label}-{protocol}"), ("bytes", view), ("policy", policy),
                        ("resource", resource), ("provider", provider), ("client", client),
                        ("destination", str(mapped)), ("protocol", protocol),
                        ("selected", "yes" if allowed else "no"),
                        ("cover", json.dumps(subnet.selected(route), separators=(",", ":")))])
    return out
