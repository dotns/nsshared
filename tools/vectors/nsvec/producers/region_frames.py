"""Relay region member frames v2, types 1-9, valid and rejected (quick-v2 §8.5, §12.1; frame
semantics of quick-protocol §12.8 as modified by quick-v2 §8.5)."""

from .. import cbor, derive
from . import relay_packets
from .control_messages import dns_relay_ok

CRATE = "ns-wire"
GROUP = "region_frames"
TITLE = "NS v2 relay region frames, valid and rejected"
SECTIONS = "ns/quick-v2.md §8.5, §12.1; ns/quick-protocol.md §12.8"

VERSION = 2
HELLO, SNAPSHOT, PRESENT, GONE, MARKS, FORWARD, MISS, PING, PONG = range(1, 10)
MAX_FRAME_BYTES = 4096
MAX_ENTRIES = 256
MAX_DATAGRAM_BYTES = relay_packets.MAX_PACKET_BYTES
U32_MAX = 2**32 - 1
U64_MAX = cbor.U64_MAX
CONTROL, DATA = 0, 1
CHANNEL_NAMES = {CONTROL: "control", DATA: "data"}
REGION = "hkg.relay.ns.io:51822"


def frame(ftype, body, version=VERSION):
    """`[ver u8 = 2, type u8, body]` (quick-v2 §8.5)."""
    return cbor.encode([version, ftype, body])


def prefixed(data):
    """The 4-byte big-endian length prefix and the frame (quick-protocol §12.8)."""
    return len(data).to_bytes(4, "big") + data


class Owner:
    def __init__(self, label):
        self.seed = derive.seed(label)
        self.identity = derive.identity(self.seed)
        self.slot = derive.node_id(self.identity)


def present(owner, gen, incarnation, carrier, boot_epoch, revision):
    return [owner.slot, owner.identity, gen, incarnation, carrier, boot_epoch, revision]


def marks(owner, committed_gen, committed_key, conflicted, high_water):
    return [owner.identity, committed_gen, committed_key, conflicted, high_water]


# --- Independent check (quick-v2 §8.5, §12.1; quick-protocol §12.8) --------------------


def _uint(value, maximum=U64_MAX):
    return type(value) is int and value <= maximum


def _bytes(value, length):
    return type(value) is bytes and len(value) == length


def _shape(body, checks):
    return type(body) is list and len(body) == len(checks) and all(c(v) for c, v in zip(checks, body))


def _u(v):
    return _uint(v)


def _list(v):
    return type(v) is list


def _bool(v):
    return type(v) is bool


def _b(n):
    return lambda v: _bytes(v, n)


EVENT = (_b(12), _b(32), _u, _u, _u, _u, _u)
MARKS_SHAPE = (_b(32), _u, _b(32), _bool, _u)
LIVENESS = (_u, _u, _u)


def _check_event(body, field_set, field_reason):
    if not _shape(body, EVENT):
        return "schema"
    if body[4] not in field_set:
        return field_reason
    if body[0] != derive.node_id(body[1]):
        return "slot_mismatch"
    return "zero_revision" if body[6] == 0 else None


def check_body(ftype, body):
    if ftype == HELLO:
        if not _shape(body, (lambda v: type(v) is str, _u, _u, _u, _u)):
            return "schema"
        name, member_id, _, channel_kind, conn_gen = body
        if not dns_relay_ok(name):
            return "region_name"
        if not 1 <= member_id <= 16:
            return "member_id"
        if channel_kind not in CHANNEL_NAMES:
            return "channel_kind"
        if conn_gen > U32_MAX:
            return "field_width"
        return "zero_conn_gen" if conn_gen == 0 else None
    if ftype == SNAPSHOT:
        if not _shape(body, (_u, _u, _u, _u, _list, _list, _bool)):
            return "schema"
        snapshot_id, base_revision, _, chunk_index, presence, mark_entries, _ = body
        if chunk_index > U32_MAX:
            return "field_width"
        if len(presence) + len(mark_entries) > MAX_ENTRIES:
            return "too_many_entries"
        for entry in presence:
            reason = _check_event(entry, (0, 1), "carrier")
            if reason:
                return reason
        if any(not _shape(entry, MARKS_SHAPE) for entry in mark_entries):
            return "schema"
        if snapshot_id == 0:
            return "zero_snapshot_id"
        if any(entry[6] > base_revision for entry in presence):
            return "entry_after_cut"
        for entries in (presence, mark_entries):
            owners = [entry[1] if entries is presence else entry[0] for entry in entries]
            if len(set(owners)) != len(owners):
                return "duplicate_owner"
        return None
    if ftype == PRESENT:
        return _check_event(body, (0, 1), "carrier")
    if ftype == GONE:
        return _check_event(body, (0, 1, 2, 3), "gone_reason")
    if ftype == MARKS:
        return None if _shape(body, MARKS_SHAPE) else "schema"
    if ftype == FORWARD:
        if not _shape(body, (_u, _b(32), lambda v: type(v) is bytes)):
            return "schema"
        forward_id, source_owner, datagram = body
        if len(datagram) > MAX_DATAGRAM_BYTES:
            return "datagram_too_large"
        if forward_id == 0:
            return "zero_forward_id"
        if relay_packets.check_packet(datagram) is not None:
            return "datagram"
        if datagram[4] != relay_packets.DATA:
            return "datagram_not_data"
        return None if datagram[5:17] == derive.node_id(source_owner) else "source_owner_mismatch"
    if ftype == MISS:
        if not _shape(body, (_u, _u, _u)):
            return "schema"
        if body[0] > U32_MAX:
            return "field_width"
        return None if body[2] in (1, 2) else "miss_status"
    if not _shape(body, LIVENESS):
        return "schema"
    nonce, data_conn_gen, consumed = body
    if data_conn_gen > U32_MAX:
        return "field_width"
    if nonce == 0:
        return "zero_nonce"
    return "progress_without_data_connection" if data_conn_gen == 0 and consumed != 0 else None


def check(data):
    """Returns None for a valid unprefixed frame or the first violated rule."""
    if len(data) > MAX_FRAME_BYTES:
        return "too_large"
    try:
        item = cbor.decode(data)
    except cbor.CborError as err:
        return "trailing_bytes" if str(err) == "trailing bytes" else "non_canonical"
    if not (type(item) is list and len(item) == 3 and _uint(item[0]) and _uint(item[1])):
        return "schema"
    version, ftype, body = item
    if version != VERSION:
        return "version"
    if not HELLO <= ftype <= PONG:
        return "unknown_type"
    return check_body(ftype, body)


def check_prefixed(wire):
    if len(wire) < 4:
        return "truncated"
    length = int.from_bytes(wire[:4], "big")
    if not 1 <= length <= MAX_FRAME_BYTES:
        return "frame_length"
    if len(wire) - 4 < length:
        return "truncated"
    if len(wire) - 4 > length:
        return "trailing_frame_bytes"
    return check(wire[4:])


def check_channel(ftype, channel, established):
    """One HELLO first; then the control connection carries types 2-5 and 7-9 and the data
    connection only FORWARD (quick-protocol §12.8)."""
    if not established:
        return None if ftype == HELLO else "hello_required"
    if ftype == HELLO:
        return "duplicate_hello"
    return None if (ftype == FORWARD) == (channel == DATA) else "wrong_channel"


# --- Vectors ------------------------------------------------------------------------


def text_bool(value):
    return "true" if value else "false"


def event_fields(prefix, body):
    kind = "carrier" if prefix == "present" else "reason"
    keys = ("slot", "identity", "gen", "incarnation", kind, "boot_epoch", "revision")
    return [(f"{prefix}_{k}", v) for k, v in zip(keys, body)]


def marks_fields(prefix, body):
    keys = ("identity", "committed_gen", "committed_key", "conflicted", "incarnation_high_water")
    return [(f"{prefix}_{k}", text_bool(v) if k == "conflicted" else v) for k, v in zip(keys, body)]


def positive(name, ftype, body, fields):
    data = frame(ftype, body)
    reason = check(data)
    if reason is None:
        reason = check_prefixed(prefixed(data))
    if reason is not None:
        raise AssertionError(f"valid frame {name} rejected: {reason}")
    channel = DATA if ftype == FORWARD else CONTROL
    vector = [("name", name), ("type", ftype), ("channel", CHANNEL_NAMES[channel])] + fields
    return vector + [("frame_len", len(data)), ("frame", data), ("prefixed", prefixed(data))], data


def negative(name, data, reason):
    actual = check(data)
    if actual != reason:
        raise AssertionError(f"negative frame {name}: expected {reason}, checker says {actual}")
    return [("name", name), ("kind", "frame"), ("frame", data), ("expect", "reject"), ("reason", reason)]


def negative_prefixed(name, wire, reason):
    actual = check_prefixed(wire)
    if actual != reason:
        raise AssertionError(f"negative prefixed frame {name}: expected {reason}, checker says {actual}")
    return [("name", name), ("kind", "prefixed"), ("prefixed", wire), ("expect", "reject"), ("reason", reason)]


def negative_channel(name, data, channel, established, reason):
    actual = check(data) or check_channel(cbor.decode(data)[1], channel, established)
    if actual != reason:
        raise AssertionError(f"negative channel {name}: expected {reason}, checker says {actual}")
    return [
        ("name", name),
        ("kind", "channel"),
        ("frame", data),
        ("channel", CHANNEL_NAMES[channel]),
        ("established", text_bool(established)),
        ("expect", "reject"),
        ("reason", reason),
    ]


def snapshot_vector(name, snapshot_id, base_revision, marks_revision, chunk_index, presence, mark_entries, more):
    body = [snapshot_id, base_revision, marks_revision, chunk_index, presence, mark_entries, more]
    fields = [
        ("snapshot_id", snapshot_id),
        ("base_revision", base_revision),
        ("marks_revision", marks_revision),
        ("chunk_index", chunk_index),
        ("presence_count", len(presence)),
    ]
    for entry in presence:
        fields += event_fields("present", entry)
    fields.append(("marks_count", len(mark_entries)))
    for entry in mark_entries:
        fields += marks_fields("marks", entry)
    fields.append(("more", text_bool(more)))
    return positive(name, SNAPSHOT, body, fields)


def fill_snapshot(entry_of, base_revision):
    """The most entries of one kind that fit a 4096-byte frame, then single-byte widenings
    of the generation (23 -> 24) until the frame is exactly 4096 bytes."""
    entries = []
    while True:
        candidate = entries + [entry_of(len(entries), 1)]
        if len(frame(SNAPSHOT, [1, base_revision, 1, 0, *split(candidate), False])) > MAX_FRAME_BYTES:
            break
        entries = candidate
    spare = MAX_FRAME_BYTES - len(frame(SNAPSHOT, [1, base_revision, 1, 0, *split(entries), False]))
    assert spare <= len(entries)
    entries = [entry_of(i, 24 if i < spare else 1) for i in range(len(entries))]
    return entries


def split(entries):
    """(presence entries, mark entries) of a homogeneous entry list."""
    if entries and len(entries[0]) == 7:
        return entries, []
    return [], entries


def vectors():
    owners = [Owner(f"ns-vector-region-owner-{i}") for i in range(80)]
    key_a = derive.seed("ns-vector-region-wg-a")
    key_b = derive.seed("ns-vector-region-wg-b")
    session = relay_packets.Session()
    out = []

    def hello(name, member_id, boot_epoch, channel, conn_gen, region=REGION):
        body = [region, member_id, boot_epoch, channel, conn_gen]
        fields = [
            ("region_name", region),
            ("member_id", member_id),
            ("boot_epoch", boot_epoch),
            ("channel_kind", channel),
            ("conn_gen", conn_gen),
        ]
        return positive(name, HELLO, body, fields)

    hello_control, hello_frame = hello("hello-control", 1, 1790000000123, CONTROL, 1)
    out.append(hello_control)
    out.append(hello("hello-data", 16, U64_MAX, DATA, U32_MAX)[0])

    p1 = present(owners[0], 1, 1, 0, 1790000000123, 5)
    p2 = present(owners[1], 3, 7, 1, 1790000000123, 9)
    m1 = marks(owners[0], 1, key_a, False, 1)
    m2 = marks(owners[2], 4, min(key_a, key_b), True, 2)
    out.append(snapshot_vector("snapshot-empty", 1, 0, 0, 0, [], [], False)[0])
    small, small_frame = snapshot_vector("snapshot-two-and-two", 2, 9, 4, 0, [p1, p2], [m1, m2], True)
    out.append(small)
    out.append(snapshot_vector("snapshot-last-chunk", 2, 9, 4, 1, [], [m1], False)[0])

    base = 1000
    max_presence = fill_snapshot(lambda i, gen: present(owners[i], gen, 1, i % 2, 7, 1 + i), base)
    vector, max_presence_frame = snapshot_vector("snapshot-max-presence", 1, base, 1, 0, max_presence, [], False)
    assert len(max_presence_frame) == MAX_FRAME_BYTES
    out.append(vector)
    max_marks = fill_snapshot(lambda i, gen: marks(owners[i], gen, key_a, False, 1), base)
    vector, max_marks_frame = snapshot_vector("snapshot-max-marks", 1, base, 1, 0, [], max_marks, False)
    assert len(max_marks_frame) == MAX_FRAME_BYTES
    out.append(vector)

    present_udp, present_frame = positive("present-udp", PRESENT, p1, event_fields("present", p1))
    out.append(present_udp)
    p_max = present(owners[3], U64_MAX, U64_MAX, 1, U64_MAX, U64_MAX)
    out.append(positive("present-wss-max", PRESENT, p_max, event_fields("present", p_max))[0])
    for reason in range(4):
        g = present(owners[4], 2, 3 + reason, reason, 1790000000123, 10 + reason)
        out.append(positive(f"gone-{reason}", GONE, g, event_fields("gone", g))[0])
    out.append(positive("marks", MARKS, m1, marks_fields("marks", m1))[0])
    marks_conflicted, marks_frame = positive("marks-conflicted", MARKS, m2, marks_fields("marks", m2))
    out.append(marks_conflicted)

    def forward(name, forward_id, owner_identity, datagram):
        fields = [("forward_id", forward_id), ("source_owner", owner_identity), ("datagram", datagram)]
        return positive(name, FORWARD, [forward_id, owner_identity, datagram], fields)

    initiation = bytes([1, 0, 0, 0]) + relay_packets.expand("ns-vector-wg-initiation", 144)
    datagram = relay_packets.packet(relay_packets.DATA, session.slot, session.peer_slot, initiation)
    forward_vector, forward_frame = forward("forward", 1, session.node.identity, datagram)
    out.append(forward_vector)
    largest = bytes([4, 0, 0, 0]) + relay_packets.expand(
        "ns-vector-wg-transport", relay_packets.MAX_DATA_BODY_BYTES - 4
    )
    largest_datagram = relay_packets.packet(relay_packets.DATA, session.slot, session.peer_slot, largest)
    assert len(largest_datagram) == MAX_DATAGRAM_BYTES
    out.append(forward("forward-max-datagram", U64_MAX, session.node.identity, largest_datagram)[0])

    def miss(name, data_conn_gen, forward_id, status):
        fields = [("data_conn_gen", data_conn_gen), ("forward_id", forward_id), ("status", status)]
        return positive(name, MISS, [data_conn_gen, forward_id, status], fields)

    miss_vector, miss_frame = miss("miss-1", 1, 1, 1)
    out.append(miss_vector)
    out.append(miss("miss-2-max", U32_MAX, U64_MAX, 2)[0])
    out.append(miss("miss-zero-correlation", 0, 0, 1)[0])

    def liveness(name, ftype, nonce, data_conn_gen, consumed):
        fields = [("nonce", nonce), ("data_conn_gen", data_conn_gen), ("consumed_forward_id", consumed)]
        return positive(name, ftype, [nonce, data_conn_gen, consumed], fields)

    ping, ping_frame = liveness("ping", PING, 1, 1, 0)
    out.append(ping)
    out.append(liveness("ping-without-data-connection", PING, 2, 0, 0)[0])
    out.append(liveness("pong-max", PONG, U64_MAX, U32_MAX, U64_MAX)[0])

    # Negative vectors: each breaks exactly one rule.
    def with_field(body, index, value):
        changed = list(body)
        changed[index] = value
        return changed

    for version in (1, 3):
        out.append(negative(f"version-{version}", frame(PING, [1, 1, 0], version), "version"))
    for ftype in (0, 10, 11, 12, 13, 255):
        out.append(negative(f"unknown-type-{ftype}", frame(ftype, [1, 1, 0]), "unknown_type"))
    out.append(negative("trailing-bytes", ping_frame + b"\x00", "trailing_bytes"))
    out.append(negative("non-canonical-nonce", b"\x83\x02\x08\x83\x18\x01" + ping_frame[5:], "non_canonical"))
    out.append(negative("envelope-arity-2", cbor.encode([VERSION, PING]), "schema"))
    out.append(negative("ping-arity-4", frame(PING, [1, 1, 0, 0]), "schema"))
    # One more single-byte widening makes the largest snapshot one byte too large.
    widen = next(i for i, entry in enumerate(max_presence) if entry[2] == 1)
    too_large_entries = list(max_presence)
    too_large_entries[widen] = with_field(max_presence[widen], 2, 24)
    too_large = frame(SNAPSHOT, [1, base, 1, 0, too_large_entries, [], False])
    assert len(too_large) == MAX_FRAME_BYTES + 1
    out.append(negative("snapshot-4097-bytes", too_large, "too_large"))
    extra = present(owners[len(max_presence)], 1, 1, 0, 7, 1)
    one_more = frame(SNAPSHOT, [1, base, 1, 0, max_presence + [extra], [], False])
    out.append(negative("snapshot-one-entry-too-many", one_more, "too_large"))

    # One field of a valid body replaced: (name, type, body, index, value, reason).
    hello_body = cbor.decode(hello_frame)[2]
    snapshot_body = cbor.decode(small_frame)[2]
    forward_body = cbor.decode(forward_frame)[2]
    miss_body = cbor.decode(miss_frame)[2]
    presence_packet = relay_packets.sealed(
        session.sk, relay_packets.PRESENCE, session.slot, relay_packets.ZERO_SLOT, [1, 1]
    )
    gone = present(owners[4], 2, 3, 0, 1790000000123, 10)
    replaced = [
        ("hello-channel-kind-2", HELLO, hello_body, 3, 2, "channel_kind"),
        ("hello-member-id-0", HELLO, hello_body, 1, 0, "member_id"),
        ("hello-member-id-17", HELLO, hello_body, 1, 17, "member_id"),
        ("hello-conn-gen-0", HELLO, hello_body, 4, 0, "zero_conn_gen"),
        ("hello-conn-gen-2-32", HELLO, hello_body, 4, U32_MAX + 1, "field_width"),
        ("hello-region-uppercase", HELLO, hello_body, 0, REGION.upper(), "region_name"),
        ("present-carrier-2", PRESENT, p1, 4, 2, "carrier"),
        ("present-slot-mismatch", PRESENT, p1, 0, owners[1].slot, "slot_mismatch"),
        ("present-revision-0", PRESENT, p1, 6, 0, "zero_revision"),
        ("present-null-gen", PRESENT, p1, 2, None, "schema"),
        ("present-v1-slot-16-bytes", PRESENT, p1, 0, owners[0].slot + bytes(4), "schema"),
        ("gone-reason-4", GONE, gone, 4, 4, "gone_reason"),
        ("marks-conflicted-as-uint", MARKS, m1, 3, 0, "schema"),
        ("snapshot-id-0", SNAPSHOT, snapshot_body, 0, 0, "zero_snapshot_id"),
        ("snapshot-entry-after-cut", SNAPSHOT, snapshot_body, 1, 8, "entry_after_cut"),
        ("snapshot-chunk-index-2-32", SNAPSHOT, snapshot_body, 3, U32_MAX + 1, "field_width"),
        (
            "snapshot-duplicate-presence-owner",
            SNAPSHOT,
            snapshot_body,
            4,
            [p1, present(owners[0], 2, 1, 0, 1790000000123, 6)],
            "duplicate_owner",
        ),
        ("snapshot-duplicate-marks-owner", SNAPSHOT, snapshot_body, 5, [m1, m1], "duplicate_owner"),
        (
            "snapshot-presence-entry-slot-mismatch",
            SNAPSHOT,
            snapshot_body,
            4,
            [with_field(p1, 0, owners[1].slot)],
            "slot_mismatch",
        ),
        ("snapshot-more-as-uint", SNAPSHOT, snapshot_body, 6, 1, "schema"),
        ("snapshot-null-presence-list", SNAPSHOT, snapshot_body, 4, None, "schema"),
        ("forward-id-0", FORWARD, forward_body, 0, 0, "zero_forward_id"),
        ("forward-presence-packet", FORWARD, forward_body, 2, presence_packet, "datagram_not_data"),
        ("forward-bad-magic", FORWARD, forward_body, 2, b"KNR1" + datagram[4:], "datagram"),
        ("forward-source-owner-mismatch", FORWARD, forward_body, 1, session.peer.identity, "source_owner_mismatch"),
        ("forward-datagram-2049-bytes", FORWARD, forward_body, 2, largest_datagram + b"\x00", "datagram_too_large"),
        ("forward-v1-source-owner-pair", FORWARD, forward_body, 1, [bytes(32), session.node.identity], "schema"),
        ("miss-status-0", MISS, miss_body, 2, 0, "miss_status"),
        ("miss-status-3", MISS, miss_body, 2, 3, "miss_status"),
        ("miss-data-conn-gen-2-32", MISS, miss_body, 0, U32_MAX + 1, "field_width"),
        ("ping-nonce-0", PING, [1, 1, 0], 0, 0, "zero_nonce"),
        ("pong-progress-without-data-connection", PONG, [3, 0, 0], 2, 5, "progress_without_data_connection"),
    ]
    for name, ftype, body, index, value, reason in replaced:
        out.append(negative(name, frame(ftype, with_field(body, index, value)), reason))
    out.append(negative("marks-v1-seven-fields", frame(MARKS, [bytes(32)] + m1[:4] + [None, 1]), "schema"))

    # Length prefix (quick-protocol §12.8): checked before the frame is allocated.
    out.append(negative_prefixed("prefix-zero", bytes(4), "frame_length"))
    out.append(negative_prefixed("prefix-4097", (MAX_FRAME_BYTES + 1).to_bytes(4, "big") + too_large, "frame_length"))
    out.append(negative_prefixed("prefix-max-u32", b"\xff\xff\xff\xff" + ping_frame, "frame_length"))
    out.append(negative_prefixed("prefix-3-bytes", b"\x00\x00\x00", "truncated"))
    out.append(negative_prefixed("prefix-truncated-frame", prefixed(ping_frame)[:-1], "truncated"))
    out.append(negative_prefixed("prefix-trailing-frame-bytes", prefixed(ping_frame) + b"\x00", "trailing_frame_bytes"))
    short = (len(ping_frame) - 1).to_bytes(4, "big") + ping_frame
    out.append(negative_prefixed("prefix-short-by-one", short, "trailing_frame_bytes"))
    out.append(negative_prefixed("prefixed-version-1", prefixed(frame(PING, [1, 1, 0], 1)), "version"))

    # Channel rules: valid frames on the wrong connection or phase.
    out.append(negative_channel("forward-on-control", forward_frame, CONTROL, True, "wrong_channel"))
    for name, data in (
        ("present-on-data", present_frame),
        ("marks-on-data", marks_frame),
        ("ping-on-data", ping_frame),
        ("miss-on-data", miss_frame),
        ("snapshot-on-data", small_frame),
    ):
        out.append(negative_channel(name, data, DATA, True, "wrong_channel"))
    out.append(negative_channel("hello-after-hello", hello_frame, CONTROL, True, "duplicate_hello"))
    out.append(negative_channel("ping-before-hello", ping_frame, CONTROL, False, "hello_required"))
    out.append(negative_channel("forward-before-hello", forward_frame, DATA, False, "hello_required"))
    return out
