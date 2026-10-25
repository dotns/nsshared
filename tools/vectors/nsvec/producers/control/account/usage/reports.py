"""Independent completed-I/O, historical DATA and correlated answer candidates."""

import copy
import hashlib

from nsvec import cbor
from nsvec.ed25519 import public_key
from nsvec.producers.control.account.grants import grant_authority

CRATE = "nsshared-control"
GROUP = "account/usage/reports"
TITLE = "Service and relay usage reports"
SPEC = "docs/spec/account/usage.md"
EXTERNAL = None
DOMAIN = b"ns.account.usage.part.v1\0"


def report(kind, reporter, incarnation, rows, sequence=1, part_index=0, part_count=1):
    fields = [1, 9, kind, reporter, incarnation,
              ["l8-completed-io-v1", "l8-relay-data-v1"][kind],
              sequence, [100, 200], part_index, part_count, rows]
    digest = hashlib.sha256(DOMAIN + cbor.encode(fields)).digest()
    return fields[:10] + [digest, rows]


def vectors():
    a, b = [public_key(bytes([i]) * 32) for i in (1, 2)]
    node = lambda identity: hashlib.blake2s(identity, digest_size=12, key=b"ns-node-id-v2").digest()
    realm, other, subject = bytes([22]) * 16, bytes([26]) * 16, bytes([23]) * 16
    incarnation, token = bytes([6]) * 16, bytes([31]) * 16
    resource = cbor.encode([bytes([21]) * 16, realm, bytes([24]) * 16])
    service = [1, 0, 0, realm, subject, token, incarnation, 1234, None]
    relay = [1, node(a), node(b), 0, 1, a, b, 7, 0, incarnation, 1248]
    out = []

    def emit(name, kind, value, decision="accept", raw=None, **extra):
        out.append([("name", name), ("kind", kind),
                    ("bytes", cbor.encode(value) if raw is None else raw),
                    ("decision", decision), *extra.items()])

    grants = grant_authority.vectors()
    grant = next(dict(v)["bytes"] for v in grants if dict(v)["name"] == "egress")
    emit("historical-grant", "grant", None, raw=grant)
    for name, direction, quantity, window in [
        ("tcp-partial", 0, 1234, None), ("udp-send", 1, 64, [0]),
        ("echo-probe-reply-failed", 0, 8, None), ("echo-reply", 1, 8, [12]),
        ("failed-send", 0, 0, None), ("public-ingress", 1, 41, None),
    ]:
        unit = copy.deepcopy(service)
        unit[2], unit[7], unit[8] = direction, quantity, window
        if name == "public-ingress":
            unit[1] = 1
        emit(name, "service", unit, quantity=quantity, direction=direction)
    alternate = copy.deepcopy(service)
    alternate[3] = other
    emit("same-user-other-realm", "service", alternate, quantity=1234, direction=0)
    for name, index, value in [("identity-subject", 4, a), ("short-subject", 4, subject[:-1]),
                               ("text-subject", 4, "01ABC"), ("missing-realm", 3, None),
                               ("missing-subject", 4, None), ("unknown-boundary", 1, 2),
                               ("unknown-direction", 2, 2), ("untyped-window", 8, 0)]:
        changed = copy.deepcopy(service)
        changed[index] = value
        emit(name, "service", changed, "reject")
    emit("missing-payer-component", "service", service[:4] + service[5:], "reject")
    raw = cbor.encode(service)
    for name, replacement in [("tagged-subject", b"\xc2\x50" + subject),
                               ("nonminimal-subject", b"\x58\x10" + subject)]:
        emit(name, "service", None, "reject", raw=raw.replace(b"\x50" + subject, replacement))
    for name, source_class, destination_class, direction, epoch in [
        ("gateway-forward", 0, 1, 0, 7), ("gateway-return", 0, 1, 1, 7),
        ("gateway-source-forward", 1, 0, 0, 7), ("gateway-source-return", 1, 0, 1, 7),
        ("ordinary", 0, 0, 0, 8), ("historical-epoch", 0, 1, 0, 7),
    ]:
        changed = copy.deepcopy(relay)
        changed[3:5], changed[7], changed[8] = [source_class, destination_class], epoch, direction
        emit(name, "relay", changed)
    for name, index, value in [("relay-unknown-direction", 8, 2), ("relay-unknown-class", 3, 2),
                               ("relay-zero-epoch", 7, 0), ("relay-short-node", 1, node(a)[:-1]),
                               ("relay-zero-bytes", 10, 0)]:
        changed = copy.deepcopy(relay)
        changed[index] = value
        emit(name, "relay", changed, "reject")
    service_report = report(0, a, incarnation, [[resource, b, a, 0, cbor.encode(service)]])
    relay_report = report(1, b, incarnation, [cbor.encode(relay)])
    for name, value in [("service-report", service_report), ("relay-report", relay_report)]:
        emit(name, "report", value)
    for operation in (1, 2, 3):
        emit(f"service-operation-{operation}", "report",
             report(0, a, incarnation, [[resource, b, a, operation, cbor.encode(
                 service if operation == 1 else service[:2] + [operation - 2] + service[3:7] + [8, None])]]))
    public = copy.deepcopy(service)
    public[1] = 1
    emit("public-ingress-report", "report", report(0, a, incarnation, [[resource, b, a, 4, cbor.encode(public)]]))
    emit("multipart-first", "report", report(0, a, incarnation, service_report[11], part_count=2))
    emit("multipart-second", "report", report(0, a, incarnation, service_report[11], sequence=2, part_index=1, part_count=2))
    emit("empty-sequence-probe", "report", report(0, a, incarnation, []))
    emit("other-realm-report", "report", report(0, a, incarnation, [[resource, b, a, 0, cbor.encode(alternate)]]))
    for name, index, value in [("report-zero-sequence", 6, 0), ("report-invalid-window", 7, [200, 100]),
                               ("report-invalid-index", 8, 1), ("report-zero-parts", 9, 0),
                               ("report-wrong-profile", 5, "l8-relay-data-v1"),
                               ("report-wrong-incarnation", 4, bytes([9]) * 16),
                               ("report-wrong-reporter", 3, b),
                               ("report-bad-digest", 10, bytes(32)),
                               ("report-unknown-kind", 2, 2)]:
        changed = copy.deepcopy(service_report)
        changed[index] = value
        emit(name, "report", changed, "reject")
    changed = copy.deepcopy(service_report)
    changed[11][0][3] = 5
    emit("report-unknown-operation", "report", changed, "reject")

    def answer(value, outcome):
        return [1, value[3], value[4], value[5], value[6], value[8], value[10], outcome]

    for name, outcome in [("ack", [0, 1]), ("duplicate-ack", [0, 1]),
                           ("conflict-absent", [1, None]), ("conflict-malformed", [1, [0]]),
                           ("conflict-zero", [1, [1, 0]]), ("conflict-present", [1, [1, 3]]),
                           ("permanent-forbidden", [2, 0]), ("permanent-invalid", [2, 1])]:
        emit(name, "answer", answer(service_report, outcome))
    second_part = report(0, a, incarnation, service_report[11], sequence=2, part_index=1, part_count=2)
    emit("multipart-ack", "answer", answer(second_part, [0, 2]))
    emit("relay-ack", "answer", answer(relay_report, [0, 1]))
    emit("unknown-mapping", "answer", answer(relay_report, [3, a, b, 7, node(a)]))
    for name, outcome in [("ack-stale-watermark", [0, 0]), ("answer-unknown-outcome", [4]),
                           ("answer-unknown-permanent", [2, 2]), ("answer-untyped-watermark", [1, 0])]:
        emit(name, "answer", answer(service_report, outcome), "reject")
    # Canonical refusal applies independently to every new wire shape.
    for name, kind, value in [("service", "service", service), ("relay", "relay", relay),
                               ("report", "report", relay_report),
                               ("answer", "answer", answer(relay_report, [0, 1]))]:
        raw = cbor.encode(value)
        for suffix, encoded in [("trailing", raw + b"\0"), ("truncated", raw[:-1]),
                                 ("nonminimal", raw[:1] + b"\x18\x01" + raw[2:])]:
            emit(name + "-" + suffix, kind, None, "reject", raw=encoded)
    return out
