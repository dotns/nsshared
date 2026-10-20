"""Independent public-edge and material/service candidate fixture producer."""

import copy
import hashlib

from .. import cbor
from .account import key, sign
from .publication import DOMAIN

CRATE = "nsshared-proto"
GROUP = "public-edge"
TITLE = "Public-edge, material and declaration candidate fixture authority"
SECTIONS = "docs/l8-public-edge-candidate.md"


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
    publisher, recipient = key(bytes([1]) * 32)[0], key(bytes([2]) * 32)[0]
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
    unavailable[:4] = ["route-b", "offline.example", [], []]
    unavailable[5] = None
    unavailable[6:9] = [6, 8443, 8081]
    complete = [1, 7, "served", "edge", [[realm, cbor.encode(auth), [route, unavailable]],
                [bytes([9]) * 16, cbor.encode([1, bytes([9]) * 16, [], [], [], []]), []]]]

    def emit(name, kind, value, accept=True, raw=None):
        out.append([("name", name), ("kind", kind),
                    ("bytes", cbor.encode(value) if raw is None else raw),
                    ("expect", "accept" if accept else "reject")])

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
    emit("empty", "edge", [1, 7, "served", "edge", []])
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

    ack = [1, bytes([7]) * 16, "served", "edge", realm, materials[0], 0]
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
        request = [1, bytes([7]) * 16, publisher, nsd, network, 2, kind, raw, digest]
        emit(f"request-{kind}", "request", request)
        response = request[:7] + [digest, 0]
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
                                      raw, hashlib.sha256(b"ns.service.report.v1\0" + raw).digest()])
    for kind, value in [("edge", complete), ("auth", auth), ("material-ack", ack),
                        ("request", request), ("response", response)]:
        raw = cbor.encode(value)
        for name, data in [("trailing", raw + b"\0"), ("truncated", raw[:-1]),
                            ("nonminimal", raw[:1] + b"\x18\x01" + raw[2:])]:
            emit(kind + "-" + name, kind, None, False, data)

    def event(name, payload, version, expires=200, scope="edge", channel=0):
        content = cbor.encode([1, publisher, recipient, "served", scope, 7,
                               "public-edge", channel, True, version, 100, expires, 0, payload])
        emit(name, "event", None, raw=cbor.encode([
            content, sign(bytes([1]) * 32, DOMAIN + content)]))

    event("install", cbor.encode(complete), 1)
    event("malformed-no-renewal", b"\x80", 2, 300)
    event("remove-omitted", cbor.encode(reduced), 2)
    event("withdraw", cbor.encode([1, 7, "served", "edge", []]), 3)
    event("replay", cbor.encode(complete), 2)
    event("empty-carrier", b"", 4)
    event("wrong-signed-scope", cbor.encode(complete), 5, scope="other")
    event("wrong-channel", cbor.encode(complete), 5, channel=1)
    wrong_inner = copy.deepcopy(complete)
    wrong_inner[3] = "other"
    event("wrong-inner-scope", cbor.encode(wrong_inner), 5)
    return out
