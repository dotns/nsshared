"""In-tunnel control messages v2, valid and rejected (quick-v2 §9, §12.1, §12.3; canonical
snapshot order of quick-protocol §12.7 as referenced by quick-v2 §9)."""

import hashlib
import ipaddress
import re

from .. import cbor
from . import node_records
from .relay_packets import expand

CRATE = "ns-wire"
GROUP = "control_messages"
TITLE = "NS v2 in-tunnel control messages, valid and rejected"
SECTIONS = "ns/quick-v2.md §9, §12.1, §12.3; ns/quick-protocol.md §12.7"

VERSION = 2
ACK, ENDPOINTS, RECORD, PROBE_REQUEST, PROBE_REPLY = range(5)
ACKED_TYPES = (ENDPOINTS, RECORD)
MAX_BYTES = 1200
MAX_CANDIDATES = 8
MAX_RELAYS = 4
CANDIDATE_KINDS = (0, 1, 2)
HOME_RELAY = node_records.HOME_RELAY

_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


def ack_hash(datagram):
    """The 16-byte unkeyed BLAKE2s of the exact acknowledged datagram bytes (quick-v2 §9)."""
    return hashlib.blake2s(datagram, digest_size=16).digest()


def candidate(address, port, kind):
    return [ipaddress.ip_address(address).packed, port, kind]


def candidate_key(entry):
    """Address-family width, raw IP bytes, numeric port, kind (quick-protocol §12.7)."""
    ip, port, kind = entry
    return (len(ip), ip, port, kind)


def relay_order(relays, home=HOME_RELAY):
    """The active home relay first, the rest in canonical byte order (quick-protocol §12.7)."""
    rest = sorted((r for r in relays if r != home), key=lambda r: r.encode())
    return ([home] if home in relays else []) + rest


def message(mtype, body, version=VERSION):
    """`[ver u8 = 2, type u8, body]` (quick-v2 §9)."""
    return cbor.encode([version, mtype, body])


def dns_relay_ok(text):
    """A lowercase DNS-name relay identifier `host:port` (quick-v2 §8.6); the vectors use no
    IP literals."""
    if not 1 <= len(text.encode()) <= 255 or text.count(":") != 1:
        return False
    host, port = text.split(":")
    if not re.fullmatch(r"[1-9][0-9]{0,4}", port) or int(port) > 65535:
        return False
    return all(_LABEL.match(label) for label in host.split("."))


def check(datagram):
    """Returns None for a valid datagram or the first violated rule (quick-v2 §9, §12.1)."""
    if len(datagram) > MAX_BYTES:
        return "too_large"
    try:
        item, offset = cbor._decode_at(datagram, 0)
    except cbor.CborError:
        return "non_canonical"
    if offset != len(datagram):
        # A RECORD's nested record is the last item, so its decoder sees the trailing bytes.
        is_record = type(item) is list and len(item) == 3 and item[:2] == [VERSION, RECORD]
        return "record" if is_record else "trailing_bytes"
    if type(item) is not list or len(item) != 3 or type(item[0]) is not int or type(item[1]) is not int:
        return "schema"
    version, mtype, body = item
    if version != VERSION:
        return "version"
    if mtype not in (ACK, ENDPOINTS, RECORD, PROBE_REQUEST, PROBE_REPLY):
        return "unknown_type"
    if type(body) is not list:
        return "schema"
    if mtype == ACK:
        if len(body) != 2 or type(body[0]) is not int:
            return "schema"
        if body[0] not in ACKED_TYPES:
            return "ack_type"
        return None if type(body[1]) is bytes and len(body[1]) == 16 else "schema"
    if mtype in (PROBE_REQUEST, PROBE_REPLY):
        return None if len(body) == 1 and type(body[0]) is bytes and len(body[0]) == 32 else "schema"
    if mtype == RECORD:
        if len(body) != 1:
            return "schema"
        return None if node_records.validate(cbor.encode(body[0])) is None else "record"
    if len(body) != 3 or type(body[0]) is not int or type(body[1]) is not list:
        return "schema"
    revision, candidates, relays = body
    if len(candidates) > MAX_CANDIDATES:
        return "too_many_candidates"
    for entry in candidates:
        if type(entry) is not list or len(entry) != 3 or type(entry[0]) is not bytes:
            return "schema"
        if len(entry[0]) not in (4, 16):
            return "candidate_ip_length"
        if type(entry[1]) is not int or type(entry[2]) is not int:
            return "schema"
        if not 1 <= entry[1] <= 65535:
            return "candidate_port"
        if entry[2] not in CANDIDATE_KINDS:
            return "candidate_kind"
    if type(relays) is not list:
        return "schema"
    if len(relays) > MAX_RELAYS:
        return "too_many_relays"
    if any(type(r) is not str for r in relays):
        return "schema"
    if not all(dns_relay_ok(r) for r in relays):
        return "relay_id"
    if revision == 0:
        return "zero_revision"
    keys = [candidate_key(c) for c in candidates]
    if any(a >= b for a, b in zip(keys, keys[1:])):
        return "candidate_order"
    rest = [r.encode() for r in relays[1:]]
    if any(a >= b for a, b in zip(rest, rest[1:])) or (relays and relays[0] in relays[1:]):
        return "relay_order"
    return None


def positive(name, mtype, datagram, fields):
    reason = check(datagram)
    if reason is not None:
        raise AssertionError(f"valid control message {name} rejected: {reason}")
    vector = [("name", name), ("type", mtype)] + fields
    vector += [("datagram_len", len(datagram)), ("datagram", datagram)]
    if mtype in ACKED_TYPES:
        vector.append(("ack_hash", ack_hash(datagram)))
    return vector


def negative(name, datagram, reason):
    actual = check(datagram)
    if actual != reason:
        raise AssertionError(f"negative control message {name}: expected {reason}, checker says {actual}")
    return [("name", name), ("datagram", datagram), ("expect", "reject"), ("reason", reason)]


def endpoints_fields(revision, candidates, relays):
    fields = [("revision", revision), ("candidate_count", len(candidates))]
    for ip, port, kind in candidates:
        fields += [("candidate_ip", ip), ("candidate_port", port), ("candidate_kind", kind)]
    fields.append(("relay_count", len(relays)))
    return fields + [("relay", r) for r in relays]


def endpoints(name, revision, candidates, relays):
    candidates = sorted(candidates, key=candidate_key)
    relays = relay_order(relays)
    datagram = message(ENDPOINTS, [revision, candidates, relays])
    return positive(name, ENDPOINTS, datagram, endpoints_fields(revision, candidates, relays)), datagram


def max_endpoints(revision):
    """Eight IPv6 candidates and four relays filling the datagram to exactly 1200 bytes."""
    candidates = [candidate(f"2001:db8::{i + 1:x}", 51820 + i, i % 3) for i in range(MAX_CANDIDATES)]
    tags = ["hkg-a1", "ams-e5", "fra-b2", "sjc-c3"]
    probe = [node_records.relay_of_length(200, t) for t in tags]
    spare = MAX_BYTES - len(message(ENDPOINTS, [revision, candidates, relay_order(probe)]))
    assert spare >= 0
    lengths = [200 + spare // 4 + (1 if i < spare % 4 else 0) for i in range(4)]
    relays = [node_records.relay_of_length(n, t) for n, t in zip(lengths, tags)]
    assert all(len(r) <= 255 for r in relays)
    # One relay a byte longer: still canonical, but the datagram is 1201 bytes.
    longer = relays[:3] + [node_records.relay_of_length(lengths[3] + 1, tags[3])]
    return candidates, relays, longer


def vectors():
    demo = node_records.Signer("ns-demo-node-v2", "ns-demo-wg-v2")
    week = node_records.ISSUED_AT + node_records.MAX_SERVICE_SECONDS
    out = []

    basic_candidates = [
        candidate("2001:db8::20", 51820, 2),
        candidate("203.0.113.7", 41641, 1),
        candidate("192.168.1.20", 51820, 0),
    ]
    relays = ["sjc-c3.relay.ns.io:443", HOME_RELAY, "fra-b2.relay.ns.io:51822"]
    basic, basic_datagram = endpoints("endpoints", 1, basic_candidates, relays)
    out.append(basic)
    out.append(endpoints("endpoints-empty", 2, [], [])[0])
    out.append(endpoints("endpoints-without-home", 3, basic_candidates[1:], relays[::2])[0])
    same_ip = [candidate("192.168.1.20", port, kind) for port, kind in ((51820, 2), (51820, 0), (9, 0))]
    out.append(endpoints("endpoints-same-ip-order", 4, same_ip, [HOME_RELAY])[0])
    max_candidates, max_relays, longer_relays = max_endpoints(node_records.U64_MAX)
    edge, edge_datagram = endpoints("endpoints-max-1200-bytes", node_records.U64_MAX, max_candidates, max_relays)
    assert len(edge_datagram) == MAX_BYTES
    out.append(edge)

    _, _, _, record = node_records.sign(demo, 1, node_records.ISSUED_AT, week, [HOME_RELAY])
    record_datagram = message(RECORD, [cbor.decode(record)])
    assert record_datagram == bytes.fromhex("830202 81".replace(" ", "")) + record
    out.append(positive("record", RECORD, record_datagram, [("record", record)]))

    for name, type_in, acked in (("ack-endpoints", ENDPOINTS, basic_datagram), ("ack-record", RECORD, record_datagram)):
        digest = ack_hash(acked)
        datagram = message(ACK, [type_in, digest])
        out.append(positive(name, ACK, datagram, [("type_in", type_in), ("hash", digest), ("acked", acked)]))

    nonce = expand("ns-vector-probe-nonce", 32)
    out.append(positive("probe-request", PROBE_REQUEST, message(PROBE_REQUEST, [nonce]), [("nonce", nonce)]))
    out.append(positive("probe-reply", PROBE_REPLY, message(PROBE_REPLY, [nonce]), [("nonce", nonce)]))

    # Negative vectors: each breaks exactly one rule.
    probe = message(PROBE_REQUEST, [nonce])
    for version in (1, 3):
        out.append(negative(f"version-{version}", message(PROBE_REQUEST, [nonce], version), "version"))
    out.append(negative("unknown-type-5", message(5, [nonce]), "unknown_type"))
    out.append(negative("trailing-bytes", probe + b"\x00", "trailing_bytes"))
    out.append(negative("non-canonical-type", b"\x83\x02\x18\x03" + probe[3:], "non_canonical"))
    out.append(negative("envelope-arity-2", cbor.encode([VERSION, PROBE_REQUEST]), "schema"))
    out.append(negative("probe-nonce-31-bytes", message(PROBE_REPLY, [nonce[:31]]), "schema"))
    out.append(negative("probe-arity-2", message(PROBE_REQUEST, [nonce, nonce]), "schema"))
    for type_in in (0, 3):
        out.append(negative(f"ack-type-in-{type_in}", message(ACK, [type_in, ack_hash(probe)]), "ack_type"))
    out.append(negative("ack-hash-32-bytes", message(ACK, [ENDPOINTS, hashlib.blake2s(probe).digest()]), "schema"))

    def bad_endpoints(name, revision, candidates, relays, reason):
        return negative(name, message(ENDPOINTS, [revision, candidates, relays]), reason)

    sorted_basic = sorted(basic_candidates, key=candidate_key)
    ordered = relay_order(relays)
    out.append(bad_endpoints("endpoints-revision-0", 0, sorted_basic, ordered, "zero_revision"))
    nine = sorted([candidate(f"2001:db8::{i + 1:x}", 51820, 0) for i in range(9)], key=candidate_key)
    out.append(bad_endpoints("endpoints-9-candidates", 1, nine, [], "too_many_candidates"))
    five = relay_order(relays + ["ams-e5.relay.ns.io:51822", "nrt-d4.relay.ns.io:51822"])
    out.append(bad_endpoints("endpoints-5-relays", 1, [], five, "too_many_relays"))
    out.append(bad_endpoints("endpoints-candidate-ip-5-bytes", 1, [[bytes(5), 51820, 0]], [], "candidate_ip_length"))
    for port in (0, 65536):
        out.append(
            bad_endpoints(f"endpoints-candidate-port-{port}", 1, [[sorted_basic[0][0], port, 0]], [], "candidate_port")
        )
    out.append(bad_endpoints("endpoints-candidate-kind-3", 1, [[sorted_basic[0][0], 51820, 3]], [], "candidate_kind"))
    out.append(bad_endpoints("endpoints-candidates-unsorted", 1, sorted_basic[::-1], ordered, "candidate_order"))
    out.append(
        bad_endpoints("endpoints-candidate-repeated", 1, [sorted_basic[0], sorted_basic[0]], ordered, "candidate_order")
    )
    unsorted = [ordered[0]] + ordered[1:][::-1]
    out.append(bad_endpoints("endpoints-relays-unsorted", 1, sorted_basic, unsorted, "relay_order"))
    out.append(bad_endpoints("endpoints-home-repeated", 1, sorted_basic, ordered + [ordered[0]], "relay_order"))
    out.append(bad_endpoints("endpoints-relay-uppercase", 1, sorted_basic, ["HKG-A1.relay.ns.io:51822"], "relay_id"))
    out.append(bad_endpoints("endpoints-relay-no-port", 1, sorted_basic, ["hkg-a1.relay.ns.io"], "relay_id"))
    too_large = message(ENDPOINTS, [node_records.U64_MAX, max_candidates, relay_order(longer_relays)])
    assert len(too_large) == MAX_BYTES + 1
    out.append(negative("endpoints-1201-bytes", too_large, "too_large"))
    tampered = bytearray(record_datagram)
    tampered[-10] ^= 0x01
    out.append(negative("record-bad-signature", bytes(tampered), "record"))
    out.append(negative("record-trailing-bytes", record_datagram + b"\x00", "record"))
    return out
