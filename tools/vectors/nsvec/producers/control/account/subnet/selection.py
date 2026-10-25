"""Independent Subnet selection candidate; CIDR arithmetic uses Python ipaddress."""

import copy
import ipaddress
import json

from nsvec import cbor
from nsvec.producers.control.account import profile

CRATE = "nsshared-control"
GROUP = "account/subnet/selection"
TITLE = "Subnet selection and coverage"
SPEC = "docs/spec/account/subnet.md"
EXTERNAL = None


def prefix(text):
    network = ipaddress.ip_network(text)
    return [network.version, network.network_address.packed, network.prefixlen]


def network(value):
    family, address, length = value
    cls = ipaddress.IPv4Network if family == 4 else ipaddress.IPv6Network
    return cls((int.from_bytes(address, "big"), length))


def mapped(real):
    if real[0] == 6:
        return real[:]
    return [6, bytes.fromhex("fd00112233445566778899aa") + real[1], 96 + real[2]]


def prefix_json(value):
    return [value[0], value[1].hex(), value[2]]


def route_json(route):
    resource, real, mapping, provider, client, exclusions, bypasses, selection = route
    return dict(resource=[part.hex() for part in cbor.decode(resource)],
                real=prefix_json(real), mapped=prefix_json(mapping),
                provider=provider.hex(), client=client.hex(),
                exclusions=list(map(prefix_json, exclusions)),
                bypasses=list(map(prefix_json, bypasses)),
                selection=[selection[0], list(map(prefix_json, selection[1]))])


def selected(route):
    _, real, _, _, _, exclusions, _, selection = route
    destinations = [network(real)] if selection[0] == 0 else list(map(network, selection[1]))
    for exclusion in map(network, exclusions):
        remaining = []
        for destination in destinations:
            if destination.subnet_of(exclusion):
                continue
            if exclusion.subnet_of(destination):
                remaining.extend(destination.address_exclude(exclusion))
            else:
                remaining.append(destination)
        destinations = remaining
    destinations = list(ipaddress.collapse_addresses(destinations))
    covered = real[0] == 4 and bool(destinations)
    return dict(selected=[prefix_json(prefix(str(item))) for item in destinations],
                coverage=dict(tcp=covered, udp=covered, echo=covered))


def vectors():
    return _vectors(*profile.keys())


def _vectors(provider, client):
    out = []
    nsd, realm = bytes([21]) * 16, bytes([22]) * 16

    def route(real="10.0.0.0/8", tag=1, choices=("10.0.0.0/8",),
              exclusions=(), bypasses=(), identifier=1):
        real = prefix(real)
        return [cbor.encode([nsd, realm, bytes([identifier]) * 16]), real,
                mapped(real), provider, client, list(map(prefix, exclusions)),
                list(map(prefix, bypasses)), [tag, list(map(prefix, choices))]]

    def publication(routes):
        return [1, 4, nsd, realm, client, 1, routes]

    def emit(name, value, decision="accept", raw=None):
        canonical = cbor.encode(value)
        accepted = decision == "accept"
        fields = [("name", "subnet-" + name), ("kind", "subnet-selection"),
                  ("bytes", canonical if raw is None else (raw if raw else "-")), ("canonical", canonical),
                  ("decision", decision), ("expect", "accept" if accepted else "reject")]
        if not accepted:
            fields.append(("reason", decision))
        if accepted:
            fields += [("scope", json.dumps(dict(nsd=nsd.hex(), network=realm.hex(),
                                                 recipient=client.hex(), revision=1), separators=(",", ":"))),
                       ("routes", json.dumps(list(map(route_json, value[6])), separators=(",", ":"))),
                       ("output", json.dumps(list(map(selected, value[6])), separators=(",", ":")))]
        else:
            fields.append(("output", "[]"))
        out.append(fields)

    base = publication([route()])
    emit("explicit", base)
    emit("nested-default-specific", publication([
        route("0.0.0.0/0", 0, (), exclusions=("192.0.2.0/24",),
              bypasses=("198.51.100.0/24",)),
        route("10.1.0.0/16", choices=("10.1.2.0/24",), identifier=2)]))
    emit("ipv6-no-coverage", publication([route("2001:db8::/32", choices=("2001:db8:1::/48",))]))
    emit("exclusions-and-bypasses", publication([route(
        choices=("10.1.0.0/16",), exclusions=("10.1.2.0/24", "10.2.0.0/16"),
        bypasses=("10.1.3.0/24",))]))
    emit("empty-selection", publication([route(choices=())]))
    emit("empty-withdrawal", publication([]))
    emit("fully-excluded", publication([route(exclusions=("10.0.0.0/8",))]))
    emit("selection-within-exclusion", publication([route(choices=("10.1.0.0/16",), exclusions=("10.0.0.0/8",))]))
    emit("ipv4-host", publication([route("255.255.255.255/32", choices=("255.255.255.255/32",))]))
    emit("ipv6-host", publication([route("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128", choices=("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128",))]))
    emit("ipv4-default-host-exclusion", publication([route("0.0.0.0/0", 0, (), exclusions=("0.0.0.0/32",))]))
    emit("ipv6-default-host-exclusion", publication([route("::/0", 0, (), exclusions=("::/128",))]))
    emit("adjacent-selection", publication([route(choices=("10.0.0.0/9", "10.128.0.0/9"))]))
    emit("prefix-count-boundary", publication([route(choices=tuple(f"10.0.0.{i}/32" for i in range(256)))]))
    emit("route-count-boundary", publication([route(identifier=i) for i in range(256)]))

    for name, index, value, decision in [
        ("mapped-length", 2, [6, mapped(prefix("10.0.0.0/8"))[1], 103], "mapped-prefix"),
        ("mapped-network", 2, mapped(prefix("11.0.0.0/8")), "mapped-prefix"),
        ("mapped-family", 2, prefix("10.0.0.0/8"), "mapped-prefix"),
        ("outside-exclusion", 5, [prefix("11.0.0.0/8")], "outside-exclusion"),
        ("outside-bypass", 6, [prefix("11.0.0.0/8")], "outside-bypass"),
        ("outside-selection", 7, [1, [prefix("11.0.0.0/8")]], "outside-selection"),
        ("wrong-family-selection", 7, [1, [prefix("::/0")]], "outside-selection"),
        ("overlapping-exclusions", 5, [prefix("10.0.0.0/9"), prefix("10.1.0.0/16")], "overlap"),
        ("overlapping-bypasses", 6, [prefix("10.0.0.0/9"), prefix("10.1.0.0/16")], "overlap"),
        ("overlapping-selection", 7, [1, [prefix("10.0.0.0/9"), prefix("10.1.0.0/16")]], "overlap"),
        ("duplicate-prefix", 5, [prefix("10.0.0.0/9")] * 2, "noncanonical-set"),
        ("unsorted-prefix", 6, [prefix("10.2.0.0/16"), prefix("10.1.0.0/16")], "noncanonical-set"),
        ("misaligned-prefix", 1, [4, bytes([10, 1, 0, 0]), 8], "misaligned-prefix"),
        ("invalid-length", 1, [4, bytes(4), 33], "invalid-prefix"),
        ("unknown-prefix-family", 1, [5, bytes(4), 8], "unknown-family"),
        ("mixed-selection", 7, [0, [prefix("10.0.0.0/8")]], "mixed-selection"),
        ("nondefault-real", 7, [0, []], "invalid-default"),
        ("unknown-selection", 7, [2, []], "unknown-selection"),
        ("prefix-count-limit", 7, [1, [prefix("10.0.0.0/32")] * 257], "bounds"),
        ("invalid-provider", 3, bytes([2]) + bytes(31), "identity"),
        ("wrong-client", 4, provider, "scope"),
        ("wrong-resource-scope", 0, cbor.encode([bytes(16), realm, bytes(16)]), "scope"),
    ]:
        changed = copy.deepcopy(base)
        changed[6][0][index] = value
        emit(name, changed, decision)
    changed = copy.deepcopy(base)
    changed[6][0][5] = [prefix("10.1.0.0/16")]
    changed[6][0][6] = [prefix("10.1.1.0/24")]
    emit("exclusion-bypass-overlap", changed, "overlap")
    changed = publication([route("2001:db8::/32", choices=())])
    changed[6][0][2] = prefix("2001:db9::/32")
    emit("ipv6-mapped-mismatch", changed, "mapped-prefix")
    for name, index, value, decision in [
        ("unknown-family", 1, 5, "unknown-family"),
        ("unknown-schema", 0, 2, "schema"),
        ("zero-revision", 5, 0, "scope"),
        ("route-count-limit", 6, [route()] * 257, "bounds"),
        ("duplicate-route", 6, [route()] * 2, "noncanonical-set"),
        ("unsorted-route", 6, [route(identifier=2), route()], "noncanonical-set"),
    ]:
        changed = copy.deepcopy(base)
        changed[index] = value
        emit(name, changed, decision)
    raw = cbor.encode(base)
    emit("trailing", base, "trailing-bytes", raw=raw + b"\0")
    emit("nonminimal-array", base, "non-shortest", raw=b"\x98\x07" + raw[1:])
    emit("nonminimal-schema", base, "non-shortest", raw=raw[:1] + b"\x18\x01" + raw[2:])
    emit("missing-publication", base, "truncated", raw=b"")
    emit("missing-routes", base[:-1], "invalid-encoding")
    emit("truncated", base, "truncated", raw=raw[:-1])
    changed = copy.deepcopy(base)
    changed[6][0][0] += b"\0"
    emit("invalid-m6-reference", changed, "m6-reference")
    return out
