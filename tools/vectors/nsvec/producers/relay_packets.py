"""Relay packets v2: header, bodies, REGISTER signature, session key and MACs, valid and
rejected (quick-v2 §8.1-§8.3, §12.1-§12.3)."""

import hashlib
import hmac
import ipaddress

from .. import cbor, derive, ed25519, x25519
from ..kdf import hkdf
from . import node_records

CRATE = "nsshared-wire"
GROUP = "relay_packets"
TITLE = "NS v2 relay packets, REGISTER signatures, session keys and MACs, valid and rejected"
SECTIONS = "ns/quick-v2.md §8.1, §8.2, §8.3, §12.1, §12.2, §12.3"

MAGIC = b"NSR2"
HEADER_BYTES = 29
MAX_PACKET_BYTES = 2048
MAX_CONTROL_BYTES = 1200
MAX_DATA_BODY_BYTES = 2019
MAX_RELAY_NAME_BYTES = 255
ZERO_SLOT = bytes(12)
TS_WINDOW_SECONDS = 120
MIN_TTL, DEFAULT_TTL, MAX_TTL = 30, 90, 3600

REGISTER, REGISTERED, PRESENCE, REFLECT, REFLECTED, DATA, STATUS, REVOKE = range(1, 9)
TO_RELAY, FROM_RELAY, NODE_TO_NODE = "to-relay", "from-relay", "node-to-node"
DIRECTION = {
    REGISTER: TO_RELAY,
    REGISTERED: FROM_RELAY,
    PRESENCE: TO_RELAY,
    REFLECT: TO_RELAY,
    REFLECTED: FROM_RELAY,
    DATA: NODE_TO_NODE,
    STATUS: FROM_RELAY,
    REVOKE: TO_RELAY,
}

REGISTER_CONTEXT = b"ns/relay-register/v2"
SESSION_CONTEXT = b"ns/relay-session/v2"
CTL_CONTEXT = b"ns/relay-ctl/v2"
REPLY_CONTEXT = b"ns/relay-reply/v2"
MAC_CONTEXT = {
    PRESENCE: CTL_CONTEXT,
    REFLECT: CTL_CONTEXT,
    REVOKE: CTL_CONTEXT,
    REGISTERED: REPLY_CONTEXT,
    REFLECTED: REPLY_CONTEXT,
}
STATUS_CODES = range(1, 7)
# A u-coordinate of order 8 (RFC 7748 §6.1 small-order inputs give an all-zero output).
ORDER_8_U = "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"
REVOKE_REASONS = (0, 1)

TS = node_records.ISSUED_AT + 60
RELAY_NAME = node_records.HOME_RELAY
INCARNATION = 1


def expand(label, length):
    """`length` deterministic filler bytes: SHA-256(label ‖ counter_be32) blocks."""
    out = b""
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(label.encode("ascii") + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:length]


def packet(ptype, src, dst, body, magic=MAGIC):
    """`magic ‖ type ‖ src ‖ dst ‖ body` (quick-v2 §8.1)."""
    return magic + bytes([ptype]) + src + dst + body


def observed(address, port):
    """`[ip bytes4|bytes16, port u16]`; IPv4 is four bytes (quick-v2 §8.2)."""
    return [ipaddress.ip_address(address).packed, port]


def mac_input(ptype, src, dst, unsigned):
    """`context ‖ CBOR([magic, type, src, dst, body array without mac])` (quick-v2 §8.3);
    the magic is a 4-byte byte string as in the unchanged v1 rule (quick-protocol §12.5)."""
    return MAC_CONTEXT[ptype] + cbor.encode([MAGIC, ptype, src, dst, unsigned])


def mac(sk, ptype, src, dst, unsigned):
    return hmac.new(sk, mac_input(ptype, src, dst, unsigned), hashlib.sha256).digest()


def sealed(sk, ptype, src, dst, unsigned):
    """The whole packet with the MAC appended to the body array."""
    return packet(ptype, src, dst, cbor.encode(unsigned + [mac(sk, ptype, src, dst, unsigned)]))


def register_message(record_item, incarnation, ts, node_ephemeral, relay_name):
    """`"ns/relay-register/v2" ‖ CBOR([record, incarnation, ts, node_ephemeral, relay_name])`
    with the record nested as its own array (quick-v2 §8.3, §12.2)."""
    return REGISTER_CONTEXT + cbor.encode([record_item, incarnation, ts, node_ephemeral, relay_name])


def session_info(src, incarnation, node_ephemeral, relay_ephemeral, reg_hash):
    """`"ns/relay-session/v2" ‖ src_slot ‖ incarnation_be64 ‖ node_ephemeral ‖
    relay_ephemeral ‖ reg_hash` (quick-v2 §8.3)."""
    return SESSION_CONTEXT + src + incarnation.to_bytes(8, "big") + node_ephemeral + relay_ephemeral + reg_hash


def session_key(own_secret, peer_public, info):
    """`sk = HKDF-SHA256(ikm = X25519(own, peer), info)`, zero-length salt; None for an
    all-zero shared secret (quick-v2 §8.3 rule 1)."""
    shared = x25519.x25519(own_secret, peer_public)
    if shared == bytes(32):
        return None, shared
    return hkdf(shared, info, 32), shared


# --- Independent structural check (quick-v2 §8.1-§8.2, §12.1) -------------------------


def _uint(value):
    return type(value) is int


def _bytes(value, length=None):
    return type(value) is bytes and (length is None or len(value) == length)


def _check_observed(value):
    if not (type(value) is list and len(value) == 2 and _bytes(value[0]) and _uint(value[1])):
        return "schema"
    if len(value[0]) not in (4, 16):
        return "observed_ip"
    if not 1 <= value[1] <= 65535:
        return "observed_port"
    return None


def _check_record_shape(record):
    if not (type(record) is list and len(record) == 8):
        return "schema"
    ver, ident, wg_key, gen, issued_at, expires, relays, sig = record
    if not _uint(ver):
        return "schema"
    if ver != node_records.VERSION:
        return "record_version"
    if not (_bytes(ident, 32) and _bytes(wg_key, 32) and _bytes(sig, 64)):
        return "schema"
    if not all(_uint(v) for v in (gen, issued_at, expires)):
        return "schema"
    if type(relays) is not list or len(relays) > node_records.MAX_RELAYS:
        return "schema"
    if any(type(r) is not str or len(r.encode()) > MAX_RELAY_NAME_BYTES for r in relays):
        return "schema"
    return None


def check_body(ptype, item):
    """Returns None for a body of the canonical shape and value rules, or the violated rule."""
    if type(item) is not list:
        return "schema"
    if ptype == REGISTER:
        if len(item) != 6:
            return "schema"
        record, incarnation, ts, node_ephemeral, relay_name, sig = item
        reason = _check_record_shape(record)
        if reason:
            return reason
        if not (_uint(incarnation) and _uint(ts) and _bytes(node_ephemeral, 32) and type(relay_name) is str):
            return "schema"
        if not 1 <= len(relay_name.encode()) <= MAX_RELAY_NAME_BYTES:
            return "relay_name_length"
        return None if _bytes(sig, 64) else "schema"
    if ptype == REGISTERED:
        if len(item) != 7:
            return "schema"
        incarnation, relay_ephemeral, ttl, addr, ack_seq, caps, tag = item
        if not (_uint(incarnation) and _bytes(relay_ephemeral, 32) and _uint(ttl)):
            return "schema"
        if not MIN_TTL <= ttl <= MAX_TTL:
            return "presence_ttl"
        if addr is not None:
            reason = _check_observed(addr)
            if reason:
                return reason
        if not (_uint(ack_seq) and type(caps) is list and all(type(c) is str for c in caps) and _bytes(tag, 32)):
            return "schema"
        return "capabilities_not_provisional" if caps and ack_seq != 0 else None
    if ptype == STATUS:
        if len(item) != 3 or not (_uint(item[0]) and _bytes(item[1], 12) and _uint(item[2])):
            return "schema"
        if item[0] > 255:
            return "type_in"
        return None if item[2] in STATUS_CODES else "status_code"
    shapes = {
        PRESENCE: (_uint, _uint, lambda v: _bytes(v, 32)),
        REFLECT: (_uint, _uint, lambda v: _bytes(v, 16), lambda v: _bytes(v, 32)),
        REFLECTED: (_uint, _uint, lambda v: _bytes(v, 16), lambda v: v is not None, lambda v: _bytes(v, 32)),
        REVOKE: (_uint, _uint, _uint, lambda v: _bytes(v, 32)),
    }[ptype]
    if len(item) != len(shapes) or not all(check(v) for check, v in zip(shapes, item)):
        return "schema"
    if ptype == REFLECTED:
        reason = _check_observed(item[3])
        if reason:
            return reason
    if ptype == REVOKE and item[2] not in REVOKE_REASONS:
        return "revoke_reason"
    return "zero_seq" if item[1] == 0 else None


def check_packet(data):
    """Decodes a whole packet structurally, no signature or MAC; returns None or the first
    violated rule (quick-v2 §8.1-§8.2, §12.1)."""
    if len(data) > MAX_PACKET_BYTES:
        return "too_large"
    if len(data) < HEADER_BYTES:
        return "too_short"
    if data[:4] != MAGIC:
        return "bad_magic"
    ptype, src, dst, body = data[4], data[5:17], data[17:29], data[29:]
    if ptype not in DIRECTION:
        return "unknown_type"
    src_zero, dst_zero = src == ZERO_SLOT, dst == ZERO_SLOT
    expected = {TO_RELAY: (False, True), FROM_RELAY: (True, False), NODE_TO_NODE: (False, False)}
    if (src_zero, dst_zero) != expected[DIRECTION[ptype]]:
        return "direction"
    if ptype != DATA and len(data) > MAX_CONTROL_BYTES:
        return "too_large"
    if ptype == DATA:
        return None if 1 <= len(body) <= MAX_DATA_BODY_BYTES else "data_length"
    try:
        item = cbor.decode(body)
    except cbor.CborError as err:
        return "trailing_bytes" if str(err) == "trailing bytes" else "non_canonical"
    return check_body(ptype, item)


def check_mac(data, sk):
    """Structural check, then the control / reply MAC under `sk` (quick-v2 §8.3)."""
    reason = check_packet(data)
    if reason:
        return reason
    ptype, src, dst = data[4], data[5:17], data[17:29]
    item = cbor.decode(data[29:])
    expected = mac(sk, ptype, src, dst, item[:-1])
    return None if hmac.compare_digest(expected, item[-1]) else "bad_mac"


def check_register(data, published, now):
    """§8.3 rule 1 in order against empty marks: structure, src = NodeId(record.I),
    relay_name, ts window, record validity and expiry, REGISTER signature."""
    reason = check_packet(data)
    if reason:
        return reason
    if data[4] != REGISTER:
        return "not_register"
    record, incarnation, ts, node_ephemeral, relay_name, sig = cbor.decode(data[29:])
    if data[5:17] != derive.node_id(record[1]):
        return "source_mismatch"
    if relay_name != published:
        return "relay_name"
    if abs(now - ts) > TS_WINDOW_SECONDS:
        return "timestamp"
    if node_records.validate(cbor.encode(record)) is not None:
        return "record"
    if now >= record[5]:
        return "record_expired"
    message = register_message(record, incarnation, ts, node_ephemeral, relay_name)
    return None if ed25519.verify(record[1], message, sig) else "bad_signature"


# --- Vectors ------------------------------------------------------------------------


class Session:
    """A fixed node identity, its record, a REGISTER and the derived session key."""

    def __init__(self):
        self.node = node_records.Signer("ns-demo-node-v2", "ns-demo-wg-v2")
        self.peer = node_records.Signer("ns-vector-identity-1", "ns-vector-wg-1")
        self.slot = derive.node_id(self.node.identity)
        self.peer_slot = derive.node_id(self.peer.identity)
        week = node_records.ISSUED_AT + node_records.MAX_SERVICE_SECONDS
        _, _, _, self.record = node_records.sign(self.node, 1, node_records.ISSUED_AT, week, [RELAY_NAME])
        self.record_item = cbor.decode(self.record)
        assert cbor.encode(self.record_item) == self.record
        self.node_secret = derive.seed("ns-vector-relay-node-ephemeral")
        self.relay_secret = derive.seed("ns-vector-relay-ephemeral")
        self.node_ephemeral = x25519.public_key(self.node_secret)
        self.relay_ephemeral = x25519.public_key(self.relay_secret)
        self.message = register_message(self.record_item, INCARNATION, TS, self.node_ephemeral, RELAY_NAME)
        self.signature = ed25519.sign(self.node.seed, self.message)
        self.body_item = [self.record_item, INCARNATION, TS, self.node_ephemeral, RELAY_NAME, self.signature]
        self.body = cbor.encode(self.body_item)
        self.reg_hash = hashlib.sha256(self.body).digest()
        self.packet = packet(REGISTER, self.slot, ZERO_SLOT, self.body)
        self.info = session_info(self.slot, INCARNATION, self.node_ephemeral, self.relay_ephemeral, self.reg_hash)
        self.sk, self.shared = session_key(self.node_secret, self.relay_ephemeral, self.info)
        relay_sk, relay_shared = session_key(self.relay_secret, self.node_ephemeral, self.info)
        assert self.sk is not None and (relay_sk, relay_shared) == (self.sk, self.shared)


def positive_packet(name, s, ptype, src, dst, fields, unsigned=None, body=None):
    """A valid packet vector; MAC types are sealed under `s.sk`."""
    vector = [("name", name), ("kind", "packet"), ("type", ptype), ("src", src), ("dst", dst)]
    vector += fields
    if ptype in MAC_CONTEXT:
        data = sealed(s.sk, ptype, src, dst, unsigned)
        vector += [
            ("sk", s.sk),
            ("mac_context", MAC_CONTEXT[ptype].decode()),
            ("mac_input", mac_input(ptype, src, dst, unsigned)),
            ("mac", mac(s.sk, ptype, src, dst, unsigned)),
        ]
        reason = check_mac(data, s.sk)
    else:
        data = packet(ptype, src, dst, body)
        reason = check_packet(data)
    if reason is not None:
        raise AssertionError(f"valid packet {name} rejected: {reason}")
    vector += [("body", data[HEADER_BYTES:]), ("packet_len", len(data)), ("packet", data)]
    return vector, data


def negative(name, kind, data, reason, extra=()):
    vector = [("name", name), ("kind", kind)] + list(extra) + [("packet", data)]
    return vector + [("expect", "reject"), ("reason", reason)]


def negative_packet(name, data, reason):
    actual = check_packet(data)
    if actual != reason:
        raise AssertionError(f"negative packet {name}: expected {reason}, checker says {actual}")
    return negative(name, "packet", data, reason)


def observed_fields(addr):
    if addr is None:
        return []
    return [("observed_ip", addr[0]), ("observed_port", addr[1])]


def registered(s, name, ttl, addr, ack_seq, caps):
    unsigned = [INCARNATION, s.relay_ephemeral, ttl, addr, ack_seq, list(caps)]
    fields = [("incarnation", INCARNATION), ("relay_ephemeral", s.relay_ephemeral), ("presence_ttl_s", ttl)]
    fields += observed_fields(addr)
    fields += [("ack_seq", ack_seq), ("capability_count", len(caps))]
    fields += [("capability", c) for c in caps]
    return positive_packet(name, s, REGISTERED, ZERO_SLOT, s.slot, fields, unsigned)


def flip(data, index, mask=0x01):
    out = bytearray(data)
    out[index] ^= mask
    return bytes(out)


def capability_of_size(s, total):
    """A provisional REGISTERED whose whole packet is exactly `total` bytes."""
    def size(cap):
        unsigned = [INCARNATION, s.relay_ephemeral, DEFAULT_TTL, None, 0, [cap]]
        return len(sealed(s.sk, REGISTERED, ZERO_SLOT, s.slot, unsigned))

    base = size("")
    for n in range(total - base, total - base - 3, -1):
        cap = "c" * n
        if size(cap) == total:
            return cap
    raise AssertionError(f"no capability gives a {total}-byte packet")


def vectors():
    s = Session()
    out = []

    # REGISTER, its signature, reg_hash and the session key (quick-v2 §8.3).
    reason = check_register(s.packet, RELAY_NAME, TS)
    if reason is not None:
        raise AssertionError(f"valid REGISTER rejected: {reason}")
    out.append(
        [
            ("name", "register"),
            ("kind", "register"),
            ("seed", s.node.seed),
            ("identity", s.node.identity),
            ("record", s.record),
            ("incarnation", INCARNATION),
            ("ts", TS),
            ("now", TS),
            ("node_ephemeral_secret", s.node_secret),
            ("node_ephemeral", s.node_ephemeral),
            ("relay_name", RELAY_NAME),
            ("signed_message", s.message),
            ("signature", s.signature),
            ("body", s.body),
            ("reg_hash", s.reg_hash),
            ("src", s.slot),
            ("dst", ZERO_SLOT),
            ("packet_len", len(s.packet)),
            ("packet", s.packet),
        ]
    )
    out.append(
        [
            ("name", "session-key"),
            ("kind", "session"),
            ("register", s.packet),
            ("node_ephemeral_secret", s.node_secret),
            ("node_ephemeral", s.node_ephemeral),
            ("relay_ephemeral_secret", s.relay_secret),
            ("relay_ephemeral", s.relay_ephemeral),
            ("src", s.slot),
            ("incarnation", INCARNATION),
            ("reg_hash", s.reg_hash),
            ("shared_secret", s.shared),
            ("info", s.info),
            ("sk", s.sk),
        ]
    )

    v4 = observed("203.0.113.7", 41641)
    v6 = observed("2001:db8::7", 41641)
    caps = ["vector-cap-a", "vector-cap-b"]
    provisional, provisional_packet = registered(s, "registered-provisional", DEFAULT_TTL, v4, 0, caps)
    out.append(provisional)
    out.append(registered(s, "registered-provisional-ipv6", MIN_TTL, v6, 0, [])[0])
    out.append(registered(s, "registered-provisional-wss", MAX_TTL, None, 0, caps)[0])
    out.append(registered(s, "registered-confirming", DEFAULT_TTL, v4, 1, [])[0])
    out.append(registered(s, "registered-confirming-wss", DEFAULT_TTL, None, 7, [])[0])

    presence, presence_packet = positive_packet(
        "presence", s, PRESENCE, s.slot, ZERO_SLOT, [("incarnation", INCARNATION), ("seq", 1)], [INCARNATION, 1]
    )
    out.append(presence)
    nonce = expand("ns-vector-reflect-nonce", 16)
    out.append(
        positive_packet(
            "reflect",
            s,
            REFLECT,
            s.slot,
            ZERO_SLOT,
            [("incarnation", INCARNATION), ("seq", 2), ("nonce", nonce)],
            [INCARNATION, 2, nonce],
        )[0]
    )
    for suffix, addr in (("ipv4", v4), ("ipv6", v6)):
        out.append(
            positive_packet(
                f"reflected-{suffix}",
                s,
                REFLECTED,
                ZERO_SLOT,
                s.slot,
                [("incarnation", INCARNATION), ("seq", 2), ("nonce", nonce)] + observed_fields(addr),
                [INCARNATION, 2, nonce, addr],
            )[0]
        )

    initiation = bytes([1, 0, 0, 0]) + expand("ns-vector-wg-initiation", 144)
    data_vector, data_packet = positive_packet(
        "data-handshake-initiation", s, DATA, s.slot, s.peer_slot, [("data", initiation)], body=initiation
    )
    out.append(data_vector)
    out.append(positive_packet("data-min", s, DATA, s.slot, s.peer_slot, [("data", b"\x04")], body=b"\x04")[0])
    largest = bytes([4, 0, 0, 0]) + expand("ns-vector-wg-transport", MAX_DATA_BODY_BYTES - 4)
    data_max, data_max_packet = positive_packet(
        "data-max", s, DATA, s.slot, s.peer_slot, [("data", largest)], body=largest
    )
    assert len(data_max_packet) == MAX_PACKET_BYTES
    out.append(data_max)

    for code in STATUS_CODES:
        type_in = 9 if code == 5 else DATA
        body = cbor.encode([type_in, s.peer_slot, code])
        fields = [("type_in", type_in), ("destination", s.peer_slot), ("status", code)]
        out.append(positive_packet(f"status-{code}", s, STATUS, ZERO_SLOT, s.slot, fields, body=body)[0])
    revokes = {}
    for reason_code, seq in ((0, 3), (1, 4)):
        vector, revokes[reason_code] = positive_packet(
            f"revoke-{reason_code}",
            s,
            REVOKE,
            s.slot,
            ZERO_SLOT,
            [("incarnation", INCARNATION), ("seq", seq), ("reason", reason_code)],
            [INCARNATION, seq, reason_code],
        )
        out.append(vector)

    # A control packet of exactly 1200 bytes is the largest accepted (quick-v2 §8.1, §12.3).
    cap = capability_of_size(s, MAX_CONTROL_BYTES)
    edge, edge_packet = registered(s, "registered-1200-bytes", DEFAULT_TTL, None, 0, [cap])
    assert len(edge_packet) == MAX_CONTROL_BYTES
    out.append(edge)

    # Negative vectors: each breaks exactly one rule.
    rv = s.relay_ephemeral
    out.append(negative_packet("bad-magic", b"NSR1" + presence_packet[4:], "bad_magic"))
    out.append(negative_packet("v1-magic", b"KNR1" + presence_packet[4:], "bad_magic"))
    out.append(negative_packet("too-short", presence_packet[: HEADER_BYTES - 1], "too_short"))
    out.append(negative_packet("header-only-presence", presence_packet[:HEADER_BYTES], "non_canonical"))
    out.append(negative_packet("unknown-type-0", flip(presence_packet, 4, PRESENCE ^ 0), "unknown_type"))
    out.append(negative_packet("unknown-type-9", flip(presence_packet, 4, PRESENCE ^ 9), "unknown_type"))
    body = presence_packet[HEADER_BYTES:]
    for name, ptype, src, dst, pbody in (
        ("register-dst-not-zero", REGISTER, s.slot, s.peer_slot, s.body),
        ("register-src-zero", REGISTER, ZERO_SLOT, ZERO_SLOT, s.body),
        ("presence-src-zero", PRESENCE, ZERO_SLOT, ZERO_SLOT, body),
        ("registered-src-not-zero", REGISTERED, s.peer_slot, s.slot, provisional_packet[HEADER_BYTES:]),
        ("registered-dst-zero", REGISTERED, ZERO_SLOT, ZERO_SLOT, provisional_packet[HEADER_BYTES:]),
        ("data-dst-zero", DATA, s.slot, ZERO_SLOT, initiation),
        ("data-src-zero", DATA, ZERO_SLOT, s.peer_slot, initiation),
        ("status-src-not-zero", STATUS, s.peer_slot, s.slot, cbor.encode([DATA, s.peer_slot, 1])),
    ):
        out.append(negative_packet(name, packet(ptype, src, dst, pbody), "direction"))

    too_large_control = sealed(
        s.sk, REGISTERED, ZERO_SLOT, s.slot, [INCARNATION, rv, DEFAULT_TTL, None, 0, [cap + "c"]]
    )
    assert len(too_large_control) == MAX_CONTROL_BYTES + 1
    out.append(negative_packet("control-1201-bytes", too_large_control, "too_large"))
    out.append(negative_packet("data-2049-bytes", data_max_packet + b"\x00", "too_large"))
    out.append(negative_packet("data-empty", data_packet[:HEADER_BYTES], "data_length"))
    out.append(negative_packet("trailing-bytes", presence_packet + b"\x00", "trailing_bytes"))
    non_shortest = cbor.head(cbor.ARRAY, 3) + cbor.head(cbor.UINT, INCARNATION, 1) + cbor.encode(1) + body[-34:]
    non_canonical = presence_packet[:HEADER_BYTES] + non_shortest
    out.append(negative_packet("non-canonical-incarnation", non_canonical, "non_canonical"))
    out.append(
        negative_packet(
            "presence-arity-2", packet(PRESENCE, s.slot, ZERO_SLOT, cbor.encode([INCARNATION, 1])), "schema"
        )
    )

    def resealed(ptype, src, dst, unsigned):
        return sealed(s.sk, ptype, src, dst, unsigned)

    out.append(
        negative_packet(
            "capabilities-with-ack-seq",
            resealed(REGISTERED, ZERO_SLOT, s.slot, [INCARNATION, rv, DEFAULT_TTL, v4, 1, caps]),
            "capabilities_not_provisional",
        )
    )
    for ttl in (MIN_TTL - 1, MAX_TTL + 1):
        out.append(
            negative_packet(
                f"presence-ttl-{ttl}",
                resealed(REGISTERED, ZERO_SLOT, s.slot, [INCARNATION, rv, ttl, v4, 0, []]),
                "presence_ttl",
            )
        )
    out.append(
        negative_packet(
            "presence-seq-zero", resealed(PRESENCE, s.slot, ZERO_SLOT, [INCARNATION, 0]), "zero_seq"
        )
    )
    out.append(
        negative_packet(
            "reflected-wss-null-observed-addr",
            resealed(REFLECTED, ZERO_SLOT, s.slot, [INCARNATION, 2, nonce, None]),
            "schema",
        )
    )
    out.append(
        negative_packet(
            "reflected-observed-ip-5-bytes",
            resealed(REFLECTED, ZERO_SLOT, s.slot, [INCARNATION, 2, nonce, [bytes(5), 41641]]),
            "observed_ip",
        )
    )
    for port in (0, 65536):
        out.append(
            negative_packet(
                f"registered-observed-port-{port}",
                resealed(REGISTERED, ZERO_SLOT, s.slot, [INCARNATION, rv, DEFAULT_TTL, [v4[0], port], 0, []]),
                "observed_port",
            )
        )
    for code in (0, 7):
        out.append(
            negative_packet(
                f"status-code-{code}",
                packet(STATUS, ZERO_SLOT, s.slot, cbor.encode([DATA, s.peer_slot, code])),
                "status_code",
            )
        )
    out.append(
        negative_packet(
            "status-type-in-256",
            packet(STATUS, ZERO_SLOT, s.slot, cbor.encode([256, s.peer_slot, 5])),
            "type_in",
        )
    )
    out.append(
        negative_packet(
            "revoke-reason-2", resealed(REVOKE, s.slot, ZERO_SLOT, [INCARNATION, 5, 2]), "revoke_reason"
        )
    )
    v1_record = cbor.encode([1] + s.record_item[1:])
    out.append(
        negative_packet(
            "register-record-version-1",
            packet(REGISTER, s.slot, ZERO_SLOT, cbor.encode([cbor.decode(v1_record)] + s.body_item[1:])),
            "record_version",
        )
    )
    out.append(
        negative_packet(
            "register-empty-relay-name",
            packet(REGISTER, s.slot, ZERO_SLOT, cbor.encode(s.body_item[:4] + ["", s.signature])),
            "relay_name_length",
        )
    )

    # MAC failures: the packet is well formed, the MAC under sk does not verify.
    def mac_negative(name, data):
        if check_packet(data) is not None or check_mac(data, s.sk) != "bad_mac":
            raise AssertionError(f"MAC vector {name} is not a pure MAC failure")
        return negative(name, "mac", data, "bad_mac", [("sk", s.sk)])

    out.append(mac_negative("presence-bad-mac", flip(presence_packet, len(presence_packet) - 1)))
    out.append(mac_negative("registered-bad-mac", flip(provisional_packet, len(provisional_packet) - 32)))
    presence_item = [INCARNATION, 1]
    wrong_context = hmac.new(
        s.sk, REPLY_CONTEXT + cbor.encode([MAGIC, PRESENCE, s.slot, ZERO_SLOT, presence_item]), hashlib.sha256
    ).digest()
    out.append(
        mac_negative(
            "presence-reply-context-mac",
            packet(PRESENCE, s.slot, ZERO_SLOT, cbor.encode(presence_item + [wrong_context])),
        )
    )
    other_key = hashlib.sha256(b"ns-vector-other-session-key").digest()
    out.append(
        mac_negative(
            "revoke-other-session-key",
            sealed(other_key, REVOKE, s.slot, ZERO_SLOT, [INCARNATION, 3, 0]),
        )
    )
    # The header is MACed: a REFLECTED re-addressed to another node does not verify.
    reflected = sealed(s.sk, REFLECTED, ZERO_SLOT, s.slot, [INCARNATION, 2, nonce, v4])
    out.append(mac_negative("reflected-readdressed", packet(REFLECTED, ZERO_SLOT, s.peer_slot, reflected[29:])))

    # An all-zero X25519 output is rejected before HKDF (quick-v2 §8.3 rule 1). Both are
    # small-order u-coordinates (RFC 7748 §6.1 "check for the all-zero value").
    for name, public in (
        ("zero-shared-secret-u0", bytes(32)),
        ("zero-shared-secret-order-8", bytes.fromhex(ORDER_8_U)),
    ):
        assert session_key(s.node_secret, public, b"")[0] is None
        out.append(
            [
                ("name", name),
                ("kind", "session"),
                ("register", s.packet),
                ("node_ephemeral_secret", s.node_secret),
                ("relay_ephemeral", public),
                ("expect", "reject"),
                ("reason", "zero_shared_secret"),
            ]
        )

    # REGISTER admission failures after the structural checks (quick-v2 §8.3 rule 1).
    def register_negative(name, data, reason, now=TS):
        actual = check_register(data, RELAY_NAME, now)
        if actual != reason:
            raise AssertionError(f"REGISTER vector {name}: expected {reason}, checker says {actual}")
        return negative(name, "register", data, reason, [("relay_name", RELAY_NAME), ("now", now)])

    mismatch = packet(REGISTER, s.peer_slot, ZERO_SLOT, s.body)
    out.append(register_negative("register-src-mismatch", mismatch, "source_mismatch"))
    out.append(register_negative("register-ts-121-s-late", s.packet, "timestamp", TS + TS_WINDOW_SECONDS + 1))
    out.append(register_negative("register-ts-121-s-early", s.packet, "timestamp", TS - TS_WINDOW_SECONDS - 1))
    out.append(register_negative("register-bad-signature", flip(s.packet, len(s.packet) - 40), "bad_signature"))
    other_name = s.body_item[:4] + ["fra-b2.relay.ns.io:51822", s.signature]
    out.append(
        register_negative(
            "register-other-relay-name", packet(REGISTER, s.slot, ZERO_SLOT, cbor.encode(other_name)), "relay_name"
        )
    )
    return out
