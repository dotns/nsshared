"""Independent public-edge and material/service fixture producer."""

import copy
import hashlib

from nsvec import cbor
from nsvec.ed25519 import public_key, sign
from nsvec.producers.control.account.publication.envelope import DOMAIN

CRATE = "nsshared-control"
GROUP = "account/edge/routing"
TITLE = "Public-edge routes, material and declarations (fixture authority)"
SPEC = "docs/spec/account/edge.md"
EXTERNAL = None


def m6(value):
    """M6 canonical map subset; never invokes or reads a Rust encoder."""
    if isinstance(value, dict):
        pairs = sorted(((cbor.encode(k), m6(v)) for k, v in value.items()),
                       key=lambda item: (len(item[0]), item[0]))
        return cbor.head(5, len(pairs)) + b"".join(k + v for k, v in pairs)
    if isinstance(value, list):
        return cbor.head(4, len(value)) + b"".join(m6(v) for v in value)
    return cbor.encode(value)


def vectors():
    out = []
    realm, nsd, network = bytes([3]) * 16, bytes([4]) * 16, bytes([5]) * 16
    publisher, recipient = public_key(bytes([1]) * 32), public_key(bytes([2]) * 32)
    materials = [[i, name, 2] for i, name in enumerate(["auth", "cert", "ca"])]
    headers = cbor.encode([1, True, "x-subject", "x-signature", "auth", 30, True])
    policy = cbor.encode([1, realm, [], []])
    subject = cbor.encode([1, 0, realm, "external:visitor"])
    binding = cbor.encode([1, realm, 1, "credential", subject, True, 200])
    jwt_binding = cbor.encode([1, binding, "issuer", "sub", "visitor", ["read"]])
    auth = [1, realm, materials, [binding], [jwt_binding], [["issuer", "https://id.example", ["edge"], copy.deepcopy(materials[0])]]]
    reference = cbor.encode([nsd, network, bytes([6]) * 16])
    options = [0, "backend.example", ["backend.example", False],
               ["chain", "waf", "authz", "rate", "connections", "slow", "sessions",
                "rewrite", "response-headers", "forwarded-subject", "audit"],
               65536, 131072, [["192.0.2.0/24"], ["198.51.100.0/24"], True],
               [["application", "web"]]]
    route = ["route-a", "web.example", ["alias.example"], ["web.example"], reference,
             publisher, 0, 443, 8080, policy, headers, materials, options]
    unavailable = copy.deepcopy(route)
    unavailable[:4] = ["route-b", None, [], []]
    unavailable[5] = None
    unavailable[6:9] = [6, 8443, 8081]
    complete = [1, 7, "030C1G60R30C1G60R30C1G60R3", "edge", [[realm, cbor.encode(auth), [route, unavailable]],
                [bytes([9]) * 16, cbor.encode([1, bytes([9]) * 16, [], [], [], []]), []]]]

    def emit(name, kind, value, accept=True, raw=None):
        out.append([("name", name), ("kind", kind),
                    ("bytes", cbor.encode(value) if raw is None else raw),
                    ("expect", "accept" if accept else "reject")])

    protocol_names = copy.deepcopy(complete)
    protocol_names[4] = protocol_names[4][:1]
    tcp = copy.deepcopy(unavailable)
    tcp[5] = recipient
    udp = copy.deepcopy(tcp)
    udp[0], udp[5], udp[6] = "route-c", publisher, 17
    protocol_names[4][0][2] = [copy.deepcopy(route), tcp, udp]
    emit("protocol-names-valid", "protocol-names", protocol_names)
    for label, index, position, replacement in [
        ("http-null", 0, 1, None),
        ("raw-text", 1, 1, "raw.example"),
        ("raw-empty-text", 1, 1, ""),
        ("raw-alias", 1, 2, ["alias.example"]),
        ("raw-domain", 2, 3, ["web.example"]),
        ("duplicate-listener", 2, 6, 6),
        ("http-tcp-conflict", 1, 7, 443),
    ]:
        changed = copy.deepcopy(protocol_names)
        changed[4][0][2][index][position] = replacement
        emit("protocol-names-" + label, "protocol-names", changed, False)
    emit("protocol-names-http", "protocol-names", [
        *complete[:4], [[realm, cbor.encode(auth), [route]]]])
    emit("complete", "edge", complete)
    two_networks = copy.deepcopy(complete)
    second = copy.deepcopy(route)
    second[0:4] = ["route-z", "second.example", [], []]
    second[4] = cbor.encode([nsd, bytes([9]) * 16, bytes([6]) * 16])
    second[5] = recipient
    second[9] = cbor.encode([1, bytes([9]) * 16, [], []])
    second[10] = cbor.encode([1, False, None, None, None, None, False])
    second[11] = []
    two_networks[4][1][2] = [second]
    emit("two-networks", "edge", two_networks)
    def realm_pair(protocols=(6, 6), ports=(9443, 9444),
                   backends=(None, None), virtual_ports=(8080, 8081),
                   names=("local.example", "local.example"),
                   aliases=((), ()), domains=((), ())):
        contributions = []
        for index, realm_id in enumerate((realm, bytes([9]) * 16)):
            material = [0, "auth", 2 + index]
            public_route = copy.deepcopy(route)
            public_route[:4] = ["realm-route", names[index] if protocols[index] == 0 else None,
                                list(aliases[index]), list(domains[index])]
            public_route[5:9] = [backends[index], protocols[index], ports[index],
                                 virtual_ports[index]]
            public_route[9] = cbor.encode([1, realm_id, [], []])
            public_route[11] = [material]
            public_auth = cbor.encode([1, realm_id, [material], [], [], []])
            contributions.append([realm_id, public_auth, [public_route]])
        return [1, 7, "030C1G60R30C1G60R30C1G60R3", "edge", contributions]

    cases = [
        ("listener-tcp-duplicate", False, {"ports": (9443, 9443)}),
        ("listener-udp-duplicate", False, {"protocols": (17, 17), "ports": (9443, 9443)}),
        ("listener-tcp-distinct-ports", True, {}),
        ("listener-udp-distinct-ports", True, {"protocols": (17, 17)}),
        ("listener-tcp-udp-same-number", True, {"protocols": (6, 17), "ports": (9443, 9443)}),
        ("http-primary-collision", False, {"protocols": (0, 0), "ports": (9443, 9443)}),
        ("http-alias-primary-collision", False, {"protocols": (0, 0), "ports": (9443, 9443),
            "names": ("first.example", "shared.example"), "aliases": (("shared.example",), ())}),
        ("http-domain-primary-collision", False, {"protocols": (0, 0), "ports": (9443, 9443),
            "names": ("first.example", "shared.example"), "domains": (("shared.example",), ())}),
        ("http-alias-domain-collision", False, {"protocols": (0, 0), "ports": (9443, 9443),
            "names": ("first.example", "second.example"), "aliases": (("shared.example",), ()),
            "domains": ((), ("shared.example",))}),
        ("http-distinct-hosts-shared-port", True, {"protocols": (0, 0), "ports": (9443, 9443),
            "names": ("first.example", "second.example")}),
        ("http-same-host-distinct-ports", True, {"protocols": (0, 0)}),
        ("http-same-alias-distinct-ports", True, {"protocols": (0, 0),
            "names": ("first.example", "second.example"),
            "aliases": (("shared.example",), ("shared.example",))}),
        ("http-same-domain-distinct-ports", True, {"protocols": (0, 0),
            "names": ("first.example", "second.example"),
            "domains": (("shared.example",), ("shared.example",))}),
        ("overlap-http-before-tcp", False, {"protocols": (0, 6), "ports": (9443, 9443)}),
        ("overlap-tcp-before-http", False, {"protocols": (6, 0), "ports": (9443, 9443)}),
        ("overlap-http-tcp-distinct-ports", True, {"protocols": (0, 6)}),
        ("overlap-http-udp-same-number", True, {"protocols": (0, 17), "ports": (9443, 9443)}),
        ("backend-tcp-duplicate", False, {"backends": (publisher, publisher), "virtual_ports": (8080, 8080)}),
        ("backend-udp-duplicate", False, {"protocols": (17, 17), "backends": (publisher, publisher),
            "virtual_ports": (8080, 8080)}),
        ("backend-http-tcp-duplicate", False, {"protocols": (0, 6), "backends": (publisher, publisher),
            "virtual_ports": (8080, 8080)}),
        ("backend-distinct-identities", True, {"backends": (publisher, recipient), "virtual_ports": (8080, 8080)}),
        ("backend-distinct-virtual-ports", True, {"backends": (publisher, publisher)}),
        ("backend-distinct-transports", True, {"protocols": (6, 17), "backends": (publisher, publisher),
            "virtual_ports": (8080, 8080)}),
        ("backend-no-connector", True, {"virtual_ports": (8080, 8080)}),
        ("realm-names-materials", True, {"protocols": (0, 0), "aliases": (("alias.example",), ("alias.example",)),
            "domains": (("domain.example",), ("domain.example",))}),
    ]
    for label, accepted, inputs in cases:
        value = realm_pair(**inputs)
        for index in range(2):
            isolated = copy.deepcopy(value)
            isolated[4] = isolated[4][index:index + 1]
            emit(f"scope-{label}-isolated-{index}", "edge-isolated", isolated)
        emit("scope-" + label, "edge-cross-realm", value, accepted)

    emit("empty", "edge", [1, 7, "030C1G60R30C1G60R30C1G60R3", "edge", []])
    reduced = copy.deepcopy(complete)
    reduced[4][0][2] = [route]
    reduced[4] = reduced[4][:1]
    emit("omitted-route", "edge", reduced)
    for transport in range(1, 4):
        changed = copy.deepcopy(complete)
        changed[4][0][2][0][12][0] = transport
        emit(f"transport-{transport}", "edge", changed)
    minimal = copy.deepcopy(complete)
    minimal[4] = minimal[4][:1]
    minimal[4][0][1] = cbor.encode([1, realm, [], [], [], []])
    minimal[4][0][2] = [copy.deepcopy(unavailable)]
    minimal[4][0][2][0][10] = cbor.encode([1, False, None, None, None, None, False])
    minimal[4][0][2][0][11] = []
    minimal[4][0][2][0][12] = [0, None, None, [None] * 11, None, None, None, []]
    emit("no-connector-minimal", "edge", minimal)
    emit("too-many-realms", "edge", None, False,
         cbor.head(4, 5) + b"".join(cbor.encode(v) for v in complete[:4]) + cbor.head(4, 257))
    for name, edit in [
        ("duplicate-name", lambda v: v[4][0][2][1].__setitem__(1, "web.example")),
        ("duplicate-alias", lambda v: v[4][0][2][1].__setitem__(2, ["alias.example"])),
        ("port-conflict", lambda v: v[4][0][2].append(copy.deepcopy(route))),
        ("bad-backend", lambda v: v[4][0][2][0].__setitem__(5, bytes(31))),
        ("generation-mismatch", lambda v: v[4][0][2][0][11][0].__setitem__(2, 3)),
        ("uppercase-name", lambda v: v[4][0][2][0].__setitem__(1, "Web.example")),
        ("zero-port", lambda v: v[4][0][2][0].__setitem__(8, 0)),
        ("unknown-protocol", lambda v: v[4][0][2][0].__setitem__(6, 99)),
        ("duplicate-realm", lambda v: v[4].append(copy.deepcopy(v[4][0]))),
    ]:
        value = copy.deepcopy(complete)
        edit(value)
        emit(name, "edge", value, False)
    for name, change in [
        ("domain-alias-collision", lambda v: v[4][0][2][1].__setitem__(3, ["alias.example"])),
        ("raw-tcp-http-conflict", lambda v: v[4][0][2][1].__setitem__(7, 443)),
        ("invalid-transport", lambda v: v[4][0][2][0][12].__setitem__(0, 4)),
        ("invalid-source-prefix", lambda v: v[4][0][2][0][12][6][0].__setitem__(0, "192.0.2.1/24")),
        ("unsafe-upstream-sni", lambda v: v[4][0][2][0][12][2].__setitem__(0, "Upper.example")),
    ]:
        changed = copy.deepcopy(complete)
        change(changed)
        emit(name, "edge", changed, False)
    wrong_publisher = copy.deepcopy(complete)
    wrong_publisher[4][0][2][0][5] = recipient
    emit("wrong-publisher", "join", wrong_publisher, False)
    collision = copy.deepcopy(complete)
    collision[4][0][2][1][5] = publisher
    collision[4][0][2][1][6:9] = [6, 443, 8080]
    emit("virtual-port-conflict", "edge", collision, False)

    for label, bad_issuer in [("http-issuer", "http://id.example"),
                              ("invalid-issuer-host", "https://%"),
                              ("noncanonical-issuer-port", "https://id.example:000"),
                              ("backslash-issuer", "https://id.example\\bad")]:
        changed = copy.deepcopy(auth)
        changed[5][0][1] = bad_issuer
        emit(label, "auth", changed, False)
    for name, value in [("auth", auth)]:
        emit(name, "auth", value)
        bad = copy.deepcopy(value)
        bad[2][0][2] = 0
        emit("zero-generation", "auth", bad, False)
        bad = copy.deepcopy(value)
        bad[5][0][3][2] = 3
        emit("authority-generation-mismatch", "auth", bad, False)

    ack = [1, bytes([7]) * 16, "030C1G60R30C1G60R30C1G60R3", "edge", realm, materials[0], 0]
    emit("installed", "material-ack", ack)
    rejected = copy.deepcopy(ack)
    rejected[-1] = 1
    emit("rejected", "material-ack", rejected)
    for name, pos, replacement in [("wrong-ack-id", 1, bytes([9]) * 16),
                                    ("wrong-ack-scope", 3, "other"),
                                    ("wrong-ack-generation", 5, [0, "auth", 3])]:
        changed = copy.deepcopy(ack)
        changed[pos] = replacement
        emit(name, "material-match", changed, False)

    declaration = {"declaration_key": "web", "display_name": "Presentation only",
                   "description": None, "enabled": True, "protocols": ["tcp"],
                   "backend_host": ["dns", "backend.example"], "backend_port": 80,
                   "port_mode": "fixed", "requested_port": 8080}
    report = {"scope": [publisher, nsd, network], "strict_mode": True,
              "declarations": [declaration]}
    intent = {"service_ref": [nsd, network, bytes([6]) * 16],
              "publisher_identity": publisher, "listener_revision": 2, "port": 8080,
              "protocols": ["tcp"], "backend_host": ["dns", "backend.example"],
              "backend_port": 80, "enforcement_policy_version": 1,
              "enforcement_policy_digest": bytes([8]) * 32}
    for kind, body, domain in [(0, declaration, "ns.account.declaration.v1"),
                                (1, report, "ns.service.report.v1"),
                                (2, intent, "ns.service.listener.v1")]:
        raw = m6(body)
        digest = hashlib.sha256(domain.encode() + b"\0" + raw).digest()
        metadata = [["web", ["service.tcp"], [["team", "Platform Engineering"]]]]
        exits = [["exit", [0], True, ["exit.tcp"], [["team", "Platform Engineering"]]]]
        if kind == 1:
            digest = hashlib.sha256(b"ns.account.service-floor.v1\0" + cbor.encode([raw, metadata, exits])).digest()
        request = [1, bytes([7]) * 16, publisher, nsd, network, 2, kind, raw]
        if kind == 1:
            request += [metadata, exits]
        request += [digest]
        emit(f"request-{kind}", "request", request)
        response = request[:7] + [digest, [["web"], ["exit"], []] if kind == 1 else 0]
        emit(f"response-{kind}", "response", response)
        changed = copy.deepcopy(request)
        changed[-1] = bytes(32)
        emit(f"bad-digest-{kind}", "request", changed, False)
        changed = copy.deepcopy(response)
        changed[5] = 3
        emit(f"wrong-response-revision-{kind}", "response-match", changed, False)
        if kind != 0:
            changed = copy.deepcopy(request)
            changed[2] = recipient
            emit(f"wrong-owner-{kind}", "request", changed, False)
    report["declarations"] = []
    raw = m6(report)
    emit("empty-report", "request", [1, bytes([7]) * 16, publisher, nsd, network, 2, 1,
                                      raw, [], [], hashlib.sha256(b"ns.account.service-floor.v1\0" + cbor.encode([raw, [], []])).digest()])
    for kind, value in [("edge", complete), ("auth", auth), ("material-ack", ack),
                        ("request", request), ("response", response)]:
        raw = cbor.encode(value)
        for name, data in [("trailing", raw + b"\0"), ("truncated", raw[:-1]),
                            ("nonminimal", raw[:1] + b"\x18\x01" + raw[2:])]:
            emit(kind + "-" + name, kind, None, False, data)

    def event(name, payload, version, expires=200, scope="edge", channel=0):
        content = cbor.encode([1, publisher, recipient, "030C1G60R30C1G60R30C1G60R3", scope, 7,
                               "public-edge", channel, True, version, 100, expires, 0, payload])
        emit(name, "event", None, raw=cbor.encode([
            content, sign(bytes([1]) * 32, DOMAIN + content)]))

    event("install", cbor.encode(complete), 1)
    event("malformed-no-renewal", b"\x80", 2, 300)
    event("remove-omitted", cbor.encode(reduced), 2)
    event("withdraw", cbor.encode([1, 7, "030C1G60R30C1G60R30C1G60R3", "edge", []]), 3)
    event("replay", cbor.encode(complete), 2)
    event("empty-carrier", b"", 4)
    event("wrong-signed-scope", cbor.encode(complete), 5, scope="other")
    event("wrong-channel", cbor.encode(complete), 5, channel=1)
    wrong_inner = copy.deepcopy(complete)
    wrong_inner[3] = "other"
    event("wrong-inner-scope", cbor.encode(wrong_inner), 5)
    return out
