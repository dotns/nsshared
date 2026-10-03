"""Region rendezvous frames 10 RENDEZVOUS_REQUEST, 11 RENDEZVOUS_RESPONSE and 12
REGISTRY_RECORD: bodies and full frames, valid and rejected (quick-v2 §7.1, §7.2, §8.5, §12.1;
rendezvous §5.3). The bodies follow the definitions proposed with the region module of
ns-rendezvous for quick-v2 §8.5, which leaves them to the rendezvous v2 message types."""

import ipaddress
import json

from .. import cbor, ed25519
from . import node_records, rendezvous_mailbox, rendezvous_registry
from . import rendezvous_common as common

CRATE = common.CRATE
GROUP = "region_bodies"
TITLE = "NS rendezvous v2 region frames 10-12, valid and rejected"
SECTIONS = "ns/quick-v2.md §7.1, §7.2, §8.5, §12.1; ns/rendezvous.md §5.3"

VERSION = 2
RENDEZVOUS_REQUEST, RENDEZVOUS_RESPONSE, REGISTRY_RECORD = 10, 11, 12
NO_HELLO = ("directory", "publish", "lookup_node")
NOT_FORWARDED = ("hello", "directory")
NOT_FORWARDED_RESULTS = ("challenge", "directory")


def frame(ftype, body):
    """`[ver u8 = 2, type u8, body]` with the body as a nested item (quick-v2 §8.5)."""
    return cbor.encode([VERSION, ftype, cbor.decode(body)])


def request_body(request_id, owner_epoch, ip, port, nonce, actor, text):
    """`[request_id u64, owner_epoch u64, client_addr [ip bytes4 / bytes16, port u16],
    challenge_nonce bytes32, actor (bytes32 or null), request text]`."""
    return cbor.encode([request_id, owner_epoch, [ip, port], nonce, actor, text])


def response_body(request_id, owner_epoch, text):
    """`[request_id u64, owner_epoch u64, response text]`."""
    return cbor.encode([request_id, owner_epoch, text])


def registry_body(record, dns, nonce, proof):
    """`[record, dns bool, challenge_nonce bytes32, proof bytes64]`, the record nested."""
    return cbor.encode([cbor.decode(record), dns, nonce, proof])


# --- Independent checks ---------------------------------------------------------------


def _decode(body, arity):
    try:
        item = cbor.decode(body)
    except cbor.CborError as err:
        return None, "trailing_bytes" if str(err) == "trailing bytes" else "non_canonical"
    return (item, None) if type(item) is list and len(item) == arity else (None, "schema")


def check_request(body):
    item, reason = _decode(body, 6)
    if reason:
        return reason
    request_id, owner_epoch, addr, nonce, actor, text = item
    if type(request_id) is not int or type(owner_epoch) is not int or type(addr) is not list or len(addr) != 2:
        return "schema"
    ip, port = addr
    if type(ip) is not bytes or type(port) is not int or type(nonce) is not bytes or len(nonce) != 32:
        return "schema"
    if actor is not None and (type(actor) is not bytes or len(actor) != 32) or type(text) is not str:
        return "schema"
    if len(ip) not in (4, 16):
        return "client_addr_length"
    if port > 0xFFFF:
        return "port_width"
    if request_id == 0:
        return "zero_request_id"
    if nonce == bytes(32):
        return "zero_challenge_nonce"
    if len(ip) == 16 and ipaddress.IPv6Address(ip).ipv4_mapped is not None:
        return "mapped_client_addr"
    if rendezvous_mailbox.check(text, "request") is not None:
        return "message"
    operation = json_name(text, "operation")
    if operation in NOT_FORWARDED:
        return "not_forwarded"
    if operation not in NO_HELLO and actor is None:
        return "missing_actor"
    return None


def check_response(body):
    item, reason = _decode(body, 3)
    if reason:
        return reason
    request_id, owner_epoch, text = item
    if type(request_id) is not int or type(owner_epoch) is not int or type(text) is not str:
        return "schema"
    if request_id == 0:
        return "zero_request_id"
    if rendezvous_mailbox.check(text, "response") is not None:
        return "message"
    return "response_not_forwarded" if json_name(text, "result") in NOT_FORWARDED_RESULTS else None


def check_registry(body):
    item, reason = _decode(body, 4)
    if reason:
        return reason
    record, dns, nonce, proof = item
    if type(record) is not list or type(dns) is not bool or type(nonce) is not bytes or len(nonce) != 32:
        return "schema"
    if type(proof) is not bytes or len(proof) != 64:
        return "schema"
    if nonce == bytes(32):
        return "zero_challenge_nonce"
    return "record" if node_records.validate(cbor.encode(record)) is not None else None


CHECKS = {RENDEZVOUS_REQUEST: check_request, RENDEZVOUS_RESPONSE: check_response, REGISTRY_RECORD: check_registry}
KINDS = {RENDEZVOUS_REQUEST: "request", RENDEZVOUS_RESPONSE: "response", REGISTRY_RECORD: "registry_record"}


def json_name(text, key):
    """The operation or result name of a JSON message already checked as valid."""
    return json.loads(text)[key]


# --- Vectors ------------------------------------------------------------------------


def positive(name, ftype, body, fields):
    reason = CHECKS[ftype](body)
    if reason is not None:
        raise AssertionError(f"valid region body {name} rejected: {reason}")
    data = frame(ftype, body)
    assert data == bytes([0x83, VERSION, ftype]) + body
    return [("name", name), ("kind", KINDS[ftype]), ("type", ftype)] + fields + [
        ("body_len", len(body)),
        ("body", body),
        ("frame", data),
    ]


def negative(name, ftype, body, reason):
    actual = CHECKS[ftype](body)
    if actual != reason:
        raise AssertionError(f"negative region body {name}: expected {reason}, checker says {actual}")
    return [("name", name), ("kind", KINDS[ftype]), ("body", body), ("expect", "reject"), ("reason", reason)]


def request_fields(request_id, owner_epoch, ip, port, nonce, actor, text):
    fields = [
        ("request_id", request_id),
        ("owner_epoch", owner_epoch),
        ("client_ip", str(ipaddress.ip_address(ip))),
        ("client_port", port),
        ("challenge_nonce", nonce),
    ]
    return fields + ([("actor", actor)] if actor is not None else []) + [("message", text)]


def vectors():
    owner = common.Key("ns-rendezvous-actor-1")
    mailbox_id = common.fixed("ns-rendezvous-mailbox-id-1", 16)
    v4 = ipaddress.IPv4Address("198.51.100.23").packed
    v6 = ipaddress.IPv6Address("2001:db8::1:23").packed
    recv = common.request("recv", {"id": common.b64u(mailbox_id), "after": 0, "wait_ms": 15000})
    lookup = common.request("lookup_node", {"node_id": common.b64u(common.fixed("ns-region-lookup-node", 12))})

    signer = node_records.Signer("ns-registry-publisher-v2", "ns-registry-publisher-wg-v2")
    record = common.record(signer)
    proofs = {}
    for dns in (True, False):
        message = rendezvous_registry.proof_message(common.NONCE, common.AUTHORITY, record, dns)
        proofs[dns] = ed25519.sign(signer.seed, message)
    publish = common.request("publish", rendezvous_registry.publish_value(record, True, proofs[True]))

    out = []
    requests = [
        ("request-recv-ipv4", (1, 7, v4, 50123, common.NONCE, owner.public, recv)),
        ("request-publish-ipv6", (2**64 - 1, 0, v6, 443, common.NONCE, None, publish)),
        ("request-lookup-node-ipv4", (24, 2**32, v4, 1, common.OTHER_NONCE, None, lookup)),
    ]
    for name, args in requests:
        out.append(positive(name, RENDEZVOUS_REQUEST, request_body(*args), request_fields(*args)))

    responses = [
        ("response-sent", (1, 7, common.response("sent", {"seq": 1}))),
        ("response-unavailable", (2**64 - 1, 0, common.response("error", "unavailable"))),
        ("response-record", (24, 2**32, common.response("record", {"record": common.b64u(record)}))),
    ]
    for name, (request_id, owner_epoch, text) in responses:
        fields = [("request_id", request_id), ("owner_epoch", owner_epoch), ("message", text)]
        out.append(positive(name, RENDEZVOUS_RESPONSE, response_body(request_id, owner_epoch, text), fields))

    for dns in (True, False):
        fields = [
            ("record", record),
            ("dns", common.text_bool(dns)),
            ("challenge_nonce", common.NONCE),
            ("proof", proofs[dns]),
            ("authority", common.AUTHORITY),
            ("now", common.NOW),
        ]
        body = registry_body(record, dns, common.NONCE, proofs[dns])
        out.append(positive(f"registry-record-dns-{common.text_bool(dns)}", REGISTRY_RECORD, body, fields))

    base = (1, 7, v4, 50123, common.NONCE, owner.public, recv)

    def req(**changes):
        names = ("request_id", "owner_epoch", "ip", "port", "nonce", "actor", "text")
        values = dict(zip(names, base))
        values.update(changes)
        return request_body(*(values[n] for n in names))

    hello = common.request("hello", {"actor": common.b64u(owner.public), "signature": common.b64u(bytes(64))})
    rows = [
        ("request-zero-request-id", RENDEZVOUS_REQUEST, req(request_id=0), "zero_request_id"),
        ("request-zero-challenge-nonce", RENDEZVOUS_REQUEST, req(nonce=bytes(32)), "zero_challenge_nonce"),
        ("request-mapped-ipv4", RENDEZVOUS_REQUEST, req(ip=ipaddress.IPv6Address("::ffff:198.51.100.23").packed), "mapped_client_addr"),
        ("request-ip-5-bytes", RENDEZVOUS_REQUEST, req(ip=v4 + b"\x00"), "client_addr_length"),
        ("request-port-65536", RENDEZVOUS_REQUEST, req(port=65536), "port_width"),
        ("request-hello-not-forwarded", RENDEZVOUS_REQUEST, req(text=hello), "not_forwarded"),
        ("request-directory-not-forwarded", RENDEZVOUS_REQUEST, req(text=common.request("directory", None)), "not_forwarded"),
        ("request-recv-missing-actor", RENDEZVOUS_REQUEST, req(actor=None), "missing_actor"),
        ("request-invalid-json", RENDEZVOUS_REQUEST, req(text='{"operation":"close","value":{}}'), "message"),
        ("request-trailing-bytes", RENDEZVOUS_REQUEST, req() + b"\x00", "trailing_bytes"),
        ("response-zero-request-id", RENDEZVOUS_RESPONSE, response_body(0, 7, common.response("ok", None)), "zero_request_id"),
        (
            "response-challenge-not-forwarded",
            RENDEZVOUS_RESPONSE,
            response_body(1, 7, common.response("challenge", {"nonce": common.b64u(common.NONCE), "authority": common.AUTHORITY, "capabilities": []})),
            "response_not_forwarded",
        ),
        (
            "response-directory-not-forwarded",
            RENDEZVOUS_RESPONSE,
            response_body(1, 7, common.response("directory", rendezvous_registry.directory_value())),
            "response_not_forwarded",
        ),
        ("registry-record-zero-nonce", REGISTRY_RECORD, registry_body(record, True, bytes(32), proofs[True]), "zero_challenge_nonce"),
    ]
    bad_record = bytearray(record)
    bad_record[-5] ^= 0x01
    rows.append(("registry-record-bad-record", REGISTRY_RECORD, registry_body(bytes(bad_record), True, common.NONCE, proofs[True]), "record"))
    out += [negative(*row) for row in rows]

    # A valid REGISTRY_RECORD frame read as a RENDEZVOUS_RESPONSE.
    registry_frame = frame(REGISTRY_RECORD, registry_body(record, True, common.NONCE, proofs[True]))
    out.append(
        [
            ("name", "frame-wrong-type"),
            ("kind", "frame"),
            ("frame", registry_frame),
            ("expected_type", RENDEZVOUS_RESPONSE),
            ("expect", "reject"),
            ("reason", "wrong_type"),
        ]
    )
    return out
