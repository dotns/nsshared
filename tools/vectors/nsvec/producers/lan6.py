"""Published LAN prefixes `lan6(I, subnet_id)/96` with IPv4 embed and extract (next §4.1)."""

import ipaddress

from .. import derive
from .identities import IDENTITY_LABELS

CRATE = "ns-wire"
GROUP = "lan6"
TITLE = "NS v2 published LAN prefixes lan6(I, subnet_id) with embedded IPv4"
SECTIONS = "ns/next.md §4.1"

SUBNET_IDS = [0, 1, 0x1234, 0xFFFF]
IPV4_SAMPLES = ["0.0.0.0", "10.0.0.1", "192.168.1.10", "255.255.255.255"]


def vectors():
    out = []
    for name, label in IDENTITY_LABELS[:3]:
        ident = derive.identity(derive.seed(label))
        for subnet_id in SUBNET_IDS:
            prefix = derive.lan6_prefix(ident, subnet_id)
            vector = [
                ("name", f"{name}-subnet-{subnet_id}"),
                ("identity", ident),
                ("subnet_id", subnet_id),
                ("prefix", prefix),
                ("prefix_text", f"{derive.ipv6_text(prefix)}/96"),
            ]
            for ipv4 in IPV4_SAMPLES:
                embedded = derive.lan6_embed(prefix, ipv4)
                assert embedded[:12] == prefix[:12] and str(ipaddress.IPv4Address(embedded[12:])) == ipv4
                vector += [("ipv4", ipv4), ("embedded", embedded), ("embedded_text", derive.ipv6_text(embedded))]
            # The node's own N6 lies outside every lan6 prefix, so extract yields nothing.
            n6 = derive.node_addr(ident, 0)
            assert n6[:12] != prefix[:12]
            vector.append(("outside", n6))
            out.append(vector)
    return out
