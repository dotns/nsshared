"""Independent signed report exchanges and exact pending-context refusals."""
import copy
import hashlib
from nsvec import cbor, ed25519
from nsvec.producers.control.account.control import envelope as bootstrap_envelope
from nsvec.producers.control.account.edge import routing as public_edge
from nsvec.producers.control.account.usage import reports as usage

CRATE = "nsshared-control"
GROUP = "account/control/reports"
TITLE = "Control report operations"
SPEC = "docs/spec/account/control.md"
EXTERNAL = None


def vectors():
    node = ed25519.public_key(bytes([1]) * 32)
    authority = ed25519.public_key(bytes([2]) * 32)
    request_id = bytes([7]) * 16
    heartbeat = [1, request_id, 123, ["192.0.2.1", "2001:db8::1"], 9]
    certificate = ["cert", ["web.example"], "issuer", 200, "sha256:abc", 2, None]
    gateway = [1, request_id, "1.0", "0123456789abcdef", 0, False, 443, 8080,
               True, ["node.control"], ["edge.http"], [certificate]]
    edge = {dict(v)["name"]: dict(v)["bytes"] for v in public_edge.vectors()}
    units = {dict(v)["name"]: dict(v)["bytes"] for v in usage.vectors()}
    material = cbor.decode(edge["installed"])
    forms = [("machine.heartbeat", heartbeat, [1, request_id, ["unknown.feature"]]),
             ("gateway.report", gateway, [1, request_id]),
             ("gateway.services_report", cbor.decode(edge["request-1"]), cbor.decode(edge["response-1"])),
             ("gateway.usage_report", cbor.decode(units["service-report"]), cbor.decode(units["ack"])),
             ("gateway.material_status", material, [1, edge["installed"]])]
    out = []

    def emit(name, kind, value=None, accept=True, raw=None, **extra):
        out.append([("name", name), ("kind", kind), ("bytes", cbor.encode(value) if raw is None else raw),
                    ("expect", "accept" if accept else "refuse"), *extra.items()])

    for operation, request, response in forms:
        for direction, value in enumerate([request, response]):
            seed, signer, recipient = (bytes([1]) * 32, node, authority) if direction == 0 else (bytes([2]) * 32, authority, node)
            domain = bootstrap_envelope.REQUEST if direction == 0 else bootstrap_envelope.RESPONSE
            payload = cbor.encode(value)
            for suffix, raw, accepted, kind in [("", payload, True, operation),
                    ("-noncanonical", payload[:1] + b"\x18\x01" + payload[2:], False, operation),
                    ("-unknown-operation", payload, False, "gateway.unknown")]:
                content = cbor.encode([1, direction, signer, recipient, kind, 100, request_id, raw])
                emit(f"{operation}-{direction}{suffix}", "envelope", [content, ed25519.sign(seed, domain + content)], accepted,
                     operation=operation, direction=direction, pin=bootstrap_envelope.pin(signer),
                     recipient=recipient, signing_input=domain + content)
        emit(operation + "-request", "payload", request, operation=operation, direction=0)
        emit(operation + "-response", "payload", response, operation=operation, direction=1)
    emit("heartbeat-empty", "payload", [1, request_id, 0, [], None], operation="machine.heartbeat", direction=0)
    minimal = [1, request_id, None, None, None, None, None, None, False, [], [], []]
    emit("gateway-empty", "payload", minimal, operation="gateway.report", direction=0)
    for name, operation, value in [("addresses", "machine.heartbeat", heartbeat), ("certificates", "gateway.report", gateway)]:
        value = copy.deepcopy(value)
        value[3 if name == "addresses" else 11] *= 257
        emit("oversized-" + name, "payload", value, False, operation=operation, direction=0)
    for name, position, value in [("port-zero", 6, 0), ("count-overflow", 4, 2**32), ("duplicate-capability", 9, ["node.control", "node.control"])]:
        changed = copy.deepcopy(gateway)
        changed[position] = value
        emit(name, "payload", changed, False, operation="gateway.report", direction=0)
    for name, value in [("invalid-address", [1, request_id, 0, ["example.org"], None]),
                        ("oversized-features", [1, request_id, ["feature"] * 257]),
                        ("bytes-features", [1, request_id, b""])]:
        emit(name, "payload", value, False, operation="machine.heartbeat", direction=0 if name == "invalid-address" else 1)
    for name, position, value in [("id", 1, bytes([9])*16), ("served", 2, "09144GJ289144GJ289144GJ289"), ("scope", 3, "other"),
                                  ("realm", 4, bytes([9])*16), ("reference", 5, [0, "other", 2]),
                                  ("generation", 5, [0, "auth", 3]), ("kind", 5, [1, "auth", 2]), ("status", 6, 1)]:
        changed = copy.deepcopy(material)
        changed[position] = value
        emit("material-correlation-" + name, "material-match", [1, cbor.encode(changed)], False, pending=edge["installed"])
    answer = cbor.decode(units["ack"])
    relay = cbor.decode(units["unknown-mapping"])
    answer[-1] = [3, node, node, 7, relay[-1][-1]]
    emit("service-unknown-mapping", "service-unknown", answer, False, pending=units["service-report"])
    response = cbor.decode(edge["response-1"])
    for name, outcome in [("missing-service", [[], ["exit"], []]), ("missing-exit", [["web"], [], []]),
                           ("unknown-service", [["other"], ["exit"], []]), ("unknown-exit", [["web"], ["other"], []]),
                           ("wrong-kind", [[], ["exit", "web"], []]),
                           ("contradictory", [["web"], ["exit"], [[0, "web", "refused"]]]),
                           ("rejected", [[], ["exit"], [[0, "web", "policy refused"]]])]:
        changed = copy.deepcopy(response)
        changed[-1] = outcome
        emit("floor-" + name, "floor-match", changed, name == "rejected", pending=edge["request-1"])
    floor = cbor.decode(edge["request-1"])
    def floor_hash(value):
        value[-1] = hashlib.sha256(b"ns.account.service-floor.v1\0" + cbor.encode(value[7:10])).digest()
        return value
    for name, edit in [
            ("metadata-missing", lambda v: v.__setitem__(8, [])),
            ("metadata-unknown", lambda v: v[8][0].__setitem__(0, "other")),
            ("metadata-duplicate", lambda v: v[8].append(copy.deepcopy(v[8][0]))),
            ("metadata-oversized", lambda v: v.__setitem__(8, v[8] * 257)),
            ("exit-oversized", lambda v: v.__setitem__(9, v[9] * 257)),
            ("exit-duplicate", lambda v: v[9].append(copy.deepcopy(v[9][0]))),
            ("labels-duplicate", lambda v: v[8][0][2].append(copy.deepcopy(v[8][0][2][0]))),
            ("labels-oversized", lambda v: v[8][0].__setitem__(2, v[8][0][2] * 257)),
            ("prefix-host-bits", lambda v: v[9][0].__setitem__(1, [1, [[4, bytes([192, 0, 2, 1]), 24]]])),
            ("prefix-overlap", lambda v: v[9][0].__setitem__(1, [1, [[4, bytes([192, 0, 2, 0]), 24], [4, bytes([192, 0, 2, 0]), 25]]])),
            ("prefix-oversized", lambda v: v[9][0].__setitem__(1, [1, [[4, bytes(4), 0]] * 257])),
            ("selection-unknown", lambda v: v[9][0].__setitem__(1, [2])),
    ]:
        changed = copy.deepcopy(floor)
        edit(changed)
        emit(name, "payload", floor_hash(changed), False, operation="gateway.services_report", direction=0)
    for name, selection in [("explicit-empty", [1, []]),
                             ("explicit-prefixes", [1, [[4, bytes([192, 0, 2, 0]), 24], [6, bytes.fromhex("20010db8000000000000000000000000"), 32]]])]:
        changed = copy.deepcopy(floor)
        changed[9][0][1] = selection
        changed[9][0][2] = False
        emit(name, "payload", floor_hash(changed), operation="gateway.services_report", direction=0)
    for name, outcomes in [("duplicate-accepted", [["web", "web"], ["exit"], []]),
                            ("oversized-accepted", [["web"] * 257, ["exit"], []]),
                            ("duplicate-rejected", [[], ["exit"], [[0, "web", "reason"], [0, "web", "reason"]]]),
                            ("empty-reason", [[], ["exit"], [[0, "web", ""]]]),
                            ("unknown-rejection-kind", [[], ["exit"], [[2, "web", "reason"]]])]:
        changed = copy.deepcopy(response)
        changed[-1] = outcomes
        emit(name, "payload", changed, False, operation="gateway.services_report", direction=1)
    for name, outcomes in [("exit-rejected", [["web"], [], [[1, "exit", "scope refused"]]]),
                            ("unknown-rejected", [[], ["exit"], [[0, "other", "reason"]]])]:
        changed = copy.deepcopy(response)
        changed[-1] = outcomes
        emit("floor-" + name, "floor-match", changed, name == "exit-rejected", pending=edge["request-1"])
    for operation in ["gateway.services_report", "gateway.usage_report"]:
        request = next(form[1] for form in forms if form[0] == operation)
        content = cbor.encode([1, 0, authority, authority, operation, 100, request_id, cbor.encode(request)])
        domain = bootstrap_envelope.REQUEST
        emit(operation + "-wrong-signer", "envelope", [content, ed25519.sign(bytes([2]) * 32, domain + content)], False,
             operation=operation, direction=0, pin=bootstrap_envelope.pin(authority), recipient=authority, signing_input=domain + content)
    empty_floor = cbor.decode(edge["empty-report"])
    empty_receipt = empty_floor[:7] + [empty_floor[-1], [[], [], []]]
    emit("empty-floor-request", "payload", empty_floor, operation="gateway.services_report", direction=0)
    emit("empty-floor-response", "payload", empty_receipt, operation="gateway.services_report", direction=1)
    emit("floor-empty", "floor-match", empty_receipt, pending=edge["empty-report"])
    for name, kind in [("certificate", 1), ("client-ca", 2)]:
        report = copy.deepcopy(material)
        report[1] = bytes([8 + kind]) * 16
        report[5] = [kind, name, 2]
        emit(name + "-material-request", "payload", report, operation="gateway.material_status", direction=0)
        emit(name + "-material-response", "payload", [1, cbor.encode(report)], operation="gateway.material_status", direction=1)
    emit("relay-usage-request", "payload", raw=units["relay-report"], operation="gateway.usage_report", direction=0)
    emit("relay-usage-response", "payload", raw=units["unknown-mapping"], operation="gateway.usage_report", direction=1)
    return out
