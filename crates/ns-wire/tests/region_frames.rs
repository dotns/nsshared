//! Region member protocol v2 frames: quick-v2 §8.5 and the inherited quick-protocol §12.8
//! framing, body and channel rules.

#![allow(clippy::unwrap_used, clippy::panic, reason = "test fixture helpers")]

use ns_wire::{
    CborError, Identity, MAX_REGION_FORWARD_DATAGRAM_BYTES, MAX_REGION_FRAME_BYTES, NodeId,
    REGION_FRAME_VERSION, Reflect, RegionCarrier, RegionChannel, RegionChannelError,
    RegionEnvelope, RegionForward, RegionFrame, RegionFrameError, RegionFrameType, RegionGone,
    RegionGoneReason, RegionHello, RegionLiveness, RegionMarks, RegionMiss, RegionMissStatus,
    RegionPresent, RegionSnapshot, RelayBody, RelayId, RelayPacket, RelayPacketError, RelayType,
    check_region_channel, decode_region_envelope, encode_region_envelope, prefix_region_frame,
    region_frame_length, split_region_frame,
};
use proptest::prelude::*;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// Minimal canonical CBOR builder for hand-made frames.
#[derive(Default)]
struct Raw(Vec<u8>);

impl Raw {
    fn head(mut self, major: u8, value: u64) -> Self {
        let major = major << 5;
        match value {
            0..=23 => self.0.push(major | value as u8),
            24..=0xff => self.0.extend_from_slice(&[major | 24, value as u8]),
            0x100..=0xffff => {
                self.0.push(major | 25);
                self.0.extend_from_slice(&(value as u16).to_be_bytes());
            }
            0x1_0000..=0xffff_ffff => {
                self.0.push(major | 26);
                self.0.extend_from_slice(&(value as u32).to_be_bytes());
            }
            _ => {
                self.0.push(major | 27);
                self.0.extend_from_slice(&value.to_be_bytes());
            }
        }
        self
    }
    fn uint(self, value: u64) -> Self {
        self.head(0, value)
    }
    fn bytes(mut self, value: &[u8]) -> Self {
        self = self.head(2, value.len() as u64);
        self.0.extend_from_slice(value);
        self
    }
    fn text(mut self, value: &str) -> Self {
        self = self.head(3, value.len() as u64);
        self.0.extend_from_slice(value.as_bytes());
        self
    }
    fn array(self, length: u64) -> Self {
        self.head(4, length)
    }
    fn boolean(mut self, value: bool) -> Self {
        self.0.push(if value { 0xf5 } else { 0xf4 });
        self
    }
    fn raw(mut self, value: &[u8]) -> Self {
        self.0.extend_from_slice(value);
        self
    }
    /// Starts a frame `[2, frame_type, ...]`.
    fn frame(frame_type: u64) -> Self {
        Self::default()
            .array(3)
            .uint(u64::from(REGION_FRAME_VERSION))
            .uint(frame_type)
    }
}

fn owner(seed: u8) -> Identity {
    [seed; 32]
}

fn present(identity: Identity, revision: u64) -> RegionPresent {
    RegionPresent {
        slot: NodeId::derive(&identity),
        identity,
        generation: 3,
        incarnation: 7,
        carrier: RegionCarrier::Udp,
        boot_epoch: 0xdead_beef,
        revision,
    }
}

fn gone(identity: Identity, revision: u64) -> RegionGone {
    RegionGone {
        slot: NodeId::derive(&identity),
        identity,
        generation: 3,
        incarnation: 7,
        reason: RegionGoneReason::Superseded,
        boot_epoch: 0xdead_beef,
        revision,
    }
}

fn marks(identity: Identity) -> RegionMarks {
    RegionMarks {
        identity,
        committed_gen: 3,
        committed_key: [0x44; 32],
        conflicted: false,
        incarnation_high_water: 9,
    }
}

fn hello() -> RegionHello {
    RegionHello {
        region_name: RelayId::parse("hkg.relay.ns.io:51822").unwrap(),
        member_id: 2,
        boot_epoch: 99,
        channel: RegionChannel::Control,
        conn_gen: 1,
    }
}

fn data_packet(source: &Identity, payload: Vec<u8>) -> Vec<u8> {
    RelayPacket {
        src: NodeId::derive(source),
        dst: NodeId::derive(&owner(0xee)),
        body: RelayBody::Data(payload),
    }
    .encode()
    .unwrap()
}

fn forward(source: Identity) -> RegionForward {
    RegionForward {
        forward_id: 1,
        source_owner: source,
        datagram: data_packet(&source, vec![1, 2, 3]),
    }
}

fn liveness() -> RegionLiveness {
    RegionLiveness {
        nonce: 1,
        data_conn_gen: 4,
        consumed_forward_id: 12,
    }
}

fn snapshot() -> RegionSnapshot {
    RegionSnapshot {
        snapshot_id: 1,
        base_revision: 10,
        marks_revision: 20,
        chunk_index: 0,
        presence: vec![present(owner(1), 5), present(owner(2), 10)],
        marks: vec![marks(owner(1)), marks(owner(3))],
        more: false,
    }
}

fn decode(frame: &[u8]) -> Result<RegionFrame, RegionFrameError> {
    RegionFrame::decode(frame)
}

fn assert_round_trip(frame: &RegionFrame) {
    let encoded = frame.encode().unwrap();
    assert!(encoded.len() <= MAX_REGION_FRAME_BYTES);
    assert_eq!(decode(&encoded).as_ref(), Ok(frame));
    let wire = frame.encode_prefixed().unwrap();
    assert_eq!(
        wire.get(..4),
        Some(&(encoded.len() as u32).to_be_bytes()[..])
    );
    assert_eq!(RegionFrame::decode_prefixed(&wire).as_ref(), Ok(frame));
}

// ---------------------------------------------------------------------------
// Vectors and round trips
// ---------------------------------------------------------------------------

#[test]
fn ping_encodes_to_the_expected_bytes() {
    let frame = RegionFrame::Ping(liveness());
    assert_eq!(
        frame.encode().unwrap(),
        [0x83, 0x02, 0x08, 0x83, 0x01, 0x04, 0x0c]
    );
    assert_eq!(
        frame.encode_prefixed().unwrap(),
        [0, 0, 0, 7, 0x83, 0x02, 0x08, 0x83, 0x01, 0x04, 0x0c]
    );
}

#[test]
fn present_body_has_the_v2_seven_field_layout() {
    let entry = present(owner(1), 5);
    let encoded = RegionFrame::Present(entry).encode().unwrap();
    let expected = Raw::frame(3)
        .array(7)
        .bytes(NodeId::derive(&owner(1)).as_bytes())
        .bytes(&owner(1))
        .uint(3)
        .uint(7)
        .uint(0)
        .uint(0xdead_beef)
        .uint(5);
    assert_eq!(encoded, expected.0);
}

#[test]
fn every_frame_type_round_trips() {
    for frame in [
        RegionFrame::Hello(hello()),
        RegionFrame::Snapshot(snapshot()),
        RegionFrame::Present(present(owner(1), 1)),
        RegionFrame::Gone(gone(owner(1), 2)),
        RegionFrame::Marks(marks(owner(1))),
        RegionFrame::Forward(forward(owner(1))),
        RegionFrame::Miss(RegionMiss {
            data_conn_gen: 0,
            forward_id: 0,
            status: RegionMissStatus::Exhausted,
        }),
        RegionFrame::Ping(liveness()),
        RegionFrame::Pong(RegionLiveness {
            nonce: 3,
            data_conn_gen: 0,
            consumed_forward_id: 0,
        }),
    ] {
        assert_round_trip(&frame);
    }
}

#[test]
fn empty_snapshot_lists_are_empty_arrays() {
    let frame = RegionFrame::Snapshot(RegionSnapshot {
        snapshot_id: 1,
        base_revision: 0,
        marks_revision: 0,
        chunk_index: 0,
        presence: Vec::new(),
        marks: Vec::new(),
        more: false,
    });
    let encoded = frame.encode().unwrap();
    assert_eq!(
        encoded,
        [
            0x83, 0x02, 0x02, 0x87, 0x01, 0x00, 0x00, 0x00, 0x80, 0x80, 0xf4
        ]
    );
    assert_round_trip(&frame);
}

#[test]
fn forward_carries_a_maximum_size_data_packet() {
    let source = owner(5);
    let datagram = data_packet(&source, vec![0x55; 2019]);
    assert_eq!(datagram.len(), MAX_REGION_FORWARD_DATAGRAM_BYTES);
    assert_round_trip(&RegionFrame::Forward(RegionForward {
        forward_id: u64::MAX,
        source_owner: source,
        datagram,
    }));
}

#[test]
fn reserved_types_have_numbers_and_an_envelope_extension_point() {
    assert_eq!(RegionFrameType::RendezvousRequest.as_u8(), 10);
    assert_eq!(RegionFrameType::RendezvousResponse.as_u8(), 11);
    assert_eq!(RegionFrameType::RegistryRecord.as_u8(), 12);
    for value in 1..=12 {
        let frame_type = RegionFrameType::from_u8(value).unwrap();
        assert_eq!(frame_type.as_u8(), value);
        assert_eq!(frame_type.is_reserved(), value >= 10);
    }
    assert_eq!(RegionFrameType::from_u8(0), None);
    assert_eq!(RegionFrameType::from_u8(13), None);

    let body = Raw::default().array(1).bytes(b"opaque").0;
    let frame = encode_region_envelope(10, &body).unwrap();
    assert_eq!(
        decode_region_envelope(&frame),
        Ok(RegionEnvelope {
            frame_type: 10,
            body: &body,
        })
    );
}

// ---------------------------------------------------------------------------
// Framing refutations
// ---------------------------------------------------------------------------

#[test]
fn refutation_length_prefix_zero_or_above_limit() {
    assert_eq!(
        region_frame_length([0, 0, 0, 0]),
        Err(RegionFrameError::FrameLength(0))
    );
    assert_eq!(
        region_frame_length(4097_u32.to_be_bytes()),
        Err(RegionFrameError::FrameLength(4097))
    );
    assert_eq!(
        region_frame_length(u32::MAX.to_be_bytes()),
        Err(RegionFrameError::FrameLength(u32::MAX))
    );
    assert_eq!(region_frame_length(4096_u32.to_be_bytes()), Ok(4096));
    assert_eq!(region_frame_length(1_u32.to_be_bytes()), Ok(1));
    assert_eq!(
        split_region_frame(&[0, 0, 0, 0]),
        Err(RegionFrameError::FrameLength(0))
    );
    assert_eq!(
        prefix_region_frame(&[]),
        Err(RegionFrameError::FrameLength(0))
    );
}

#[test]
fn refutation_truncated_prefixed_frame() {
    assert_eq!(
        split_region_frame(&[0, 0, 0]),
        Err(RegionFrameError::Truncated)
    );
    assert_eq!(
        split_region_frame(&[0, 0, 0, 2, 0x83]),
        Err(RegionFrameError::Truncated)
    );
}

#[test]
fn refutation_trailing_bytes_after_prefixed_frame() {
    let mut wire = RegionFrame::Ping(liveness()).encode_prefixed().unwrap();
    wire.push(0);
    assert_eq!(
        RegionFrame::decode_prefixed(&wire),
        Err(RegionFrameError::TrailingFrameBytes)
    );
}

#[test]
fn refutation_frame_above_limit() {
    assert_eq!(
        decode(&[0; MAX_REGION_FRAME_BYTES + 1]),
        Err(RegionFrameError::TooLarge(MAX_REGION_FRAME_BYTES + 1))
    );
    assert_eq!(
        prefix_region_frame(&[0; MAX_REGION_FRAME_BYTES + 1]),
        Err(RegionFrameError::TooLarge(MAX_REGION_FRAME_BYTES + 1))
    );
    assert_eq!(
        encode_region_envelope(10, &[0; MAX_REGION_FRAME_BYTES]),
        Err(RegionFrameError::TooLarge(MAX_REGION_FRAME_BYTES + 3))
    );
}

#[test]
fn refutation_trailing_bytes_inside_frame() {
    let mut frame = RegionFrame::Ping(liveness()).encode().unwrap();
    frame.push(0);
    assert_eq!(
        decode(&frame),
        Err(RegionFrameError::Cbor(CborError::TrailingBytes))
    );
}

#[test]
fn refutation_non_canonical_cbor() {
    // Non-shortest version.
    let frame = Raw::default().array(3).raw(&[0x18, 0x02]).uint(8).0;
    assert_eq!(
        decode(&frame),
        Err(RegionFrameError::Cbor(CborError::NonShortest))
    );
    // Non-shortest body integer.
    let frame = Raw::frame(8).array(3).raw(&[0x18, 0x01]).uint(0).uint(0).0;
    assert_eq!(
        decode(&frame),
        Err(RegionFrameError::Cbor(CborError::NonShortest))
    );
    // Indefinite-length envelope.
    assert_eq!(
        decode(&[0x9f, 0x02, 0x08, 0xff]),
        Err(RegionFrameError::Cbor(CborError::IndefiniteLength))
    );
    // A map body.
    assert_eq!(
        decode(&Raw::frame(8).raw(&[0xa0]).0),
        Err(RegionFrameError::Cbor(CborError::Map))
    );
    // A missing body.
    assert_eq!(
        decode(&Raw::frame(8).0),
        Err(RegionFrameError::Cbor(CborError::Truncated))
    );
}

#[test]
fn refutation_unknown_version() {
    for version in [0, 1, 3, 256] {
        let frame = Raw::default()
            .array(3)
            .uint(version)
            .uint(8)
            .array(3)
            .uint(1)
            .uint(0)
            .uint(0)
            .0;
        assert_eq!(decode(&frame), Err(RegionFrameError::Version(version)));
    }
}

#[test]
fn refutation_wrong_envelope_arity() {
    let frame = Raw::default().array(2).uint(2).uint(8).0;
    assert_eq!(
        decode(&frame),
        Err(RegionFrameError::Cbor(CborError::ArrayLength {
            expected: 3,
            actual: 2
        }))
    );
}

#[test]
fn refutation_unknown_types() {
    for frame_type in [0, 13, 255, 256, u64::MAX] {
        let frame = Raw::frame(frame_type).array(0).0;
        assert_eq!(
            decode(&frame),
            Err(RegionFrameError::UnknownType(frame_type))
        );
    }
}

#[test]
fn refutation_reserved_types_decode_as_unknown() {
    for frame_type in [10_u8, 11, 12] {
        let body = Raw::default().array(1).uint(1).0;
        let frame = encode_region_envelope(frame_type, &body).unwrap();
        assert_eq!(
            decode(&frame),
            Err(RegionFrameError::UnknownType(u64::from(frame_type)))
        );
        let wire = prefix_region_frame(&frame).unwrap();
        assert_eq!(
            RegionFrame::decode_prefixed(&wire),
            Err(RegionFrameError::UnknownType(u64::from(frame_type)))
        );
    }
}

#[test]
fn refutation_wrong_body_arity_for_every_type() {
    for (frame_type, arity) in [
        (1, 5),
        (2, 7),
        (3, 7),
        (4, 7),
        (5, 5),
        (6, 3),
        (7, 3),
        (8, 3),
        (9, 3),
    ] {
        let frame = Raw::frame(frame_type).array(arity + 1).0;
        assert_eq!(
            decode(&frame),
            Err(RegionFrameError::Cbor(CborError::ArrayLength {
                expected: arity,
                actual: arity + 1
            })),
            "type {frame_type}"
        );
    }
}

#[test]
fn refutation_wrong_field_types_and_widths() {
    // Text where the PING nonce integer belongs.
    let frame = Raw::frame(8).array(3).text("1").uint(0).uint(0).0;
    assert_eq!(
        decode(&frame),
        Err(RegionFrameError::Cbor(CborError::UnexpectedType))
    );
    // A 16-byte v1 slot.
    let frame = Raw::frame(3).array(7).bytes(&[0; 16]).0;
    assert_eq!(
        decode(&frame),
        Err(RegionFrameError::Cbor(CborError::StringLength {
            expected: 12,
            actual: 16
        }))
    );
    // A 31-byte identity.
    let frame = Raw::frame(5).array(5).bytes(&[0; 31]).0;
    assert_eq!(
        decode(&frame),
        Err(RegionFrameError::Cbor(CborError::StringLength {
            expected: 32,
            actual: 31
        }))
    );
    // An integer where the `conflicted` boolean belongs.
    let frame = Raw::frame(5)
        .array(5)
        .bytes(&[1; 32])
        .uint(1)
        .bytes(&[2; 32])
        .uint(0)
        .uint(0)
        .0;
    assert_eq!(
        decode(&frame),
        Err(RegionFrameError::Cbor(CborError::UnexpectedType))
    );
    // Null where the `more` boolean belongs.
    let frame = Raw::frame(2)
        .array(7)
        .uint(1)
        .uint(0)
        .uint(0)
        .uint(0)
        .array(0)
        .array(0)
        .raw(&[0xf6])
        .0;
    assert_eq!(
        decode(&frame),
        Err(RegionFrameError::Cbor(CborError::UnexpectedType))
    );
}

#[test]
fn refutation_u32_field_width() {
    let too_wide = u64::from(u32::MAX) + 1;
    let frame = Raw::frame(1)
        .array(5)
        .text("hkg.relay.ns.io:51822")
        .uint(1)
        .uint(0)
        .uint(0)
        .uint(too_wide)
        .0;
    assert_eq!(
        decode(&frame),
        Err(RegionFrameError::FieldWidth {
            field: "conn_gen",
            value: too_wide
        })
    );
    let frame = Raw::frame(2)
        .array(7)
        .uint(1)
        .uint(0)
        .uint(0)
        .uint(too_wide)
        .0;
    assert_eq!(
        decode(&frame),
        Err(RegionFrameError::FieldWidth {
            field: "chunk_index",
            value: too_wide
        })
    );
    for frame_type in [7, 8, 9] {
        let frame = if frame_type == 7 {
            Raw::frame(7).array(3).uint(too_wide).0
        } else {
            Raw::frame(frame_type).array(3).uint(1).uint(too_wide).0
        };
        assert_eq!(
            decode(&frame),
            Err(RegionFrameError::FieldWidth {
                field: "data_conn_gen",
                value: too_wide
            })
        );
    }
}

// ---------------------------------------------------------------------------
// Body refutations
// ---------------------------------------------------------------------------

fn hello_frame(region: &str, member_id: u64, channel_kind: u64, conn_gen: u64) -> Vec<u8> {
    Raw::frame(1)
        .array(5)
        .text(region)
        .uint(member_id)
        .uint(7)
        .uint(channel_kind)
        .uint(conn_gen)
        .0
}

#[test]
fn refutation_hello_region_name() {
    for region in [
        "",
        "HKG.relay.ns.io:51822",
        "hkg.relay.ns.io",
        "hkg.relay.ns.io:0",
    ] {
        assert!(matches!(
            decode(&hello_frame(region, 1, 0, 1)),
            Err(RegionFrameError::RegionName(_))
        ));
    }
    let long = "a".repeat(256);
    assert!(matches!(
        decode(&hello_frame(&long, 1, 0, 1)),
        Err(RegionFrameError::Cbor(CborError::StringLength { .. }))
    ));
    let invalid_utf8 = Raw::frame(1).array(5).head(3, 1).raw(&[0xff]).0;
    assert_eq!(
        decode(&invalid_utf8),
        Err(RegionFrameError::Cbor(CborError::InvalidUtf8))
    );
}

#[test]
fn refutation_hello_member_id_range() {
    for member_id in [0, 17, 255, 256] {
        assert_eq!(
            decode(&hello_frame("hkg.relay.ns.io:51822", member_id, 0, 1)),
            Err(RegionFrameError::MemberId(member_id))
        );
    }
    for member_id in [1, 16] {
        assert!(decode(&hello_frame("hkg.relay.ns.io:51822", member_id, 1, 1)).is_ok());
    }
    let mut bad = hello();
    bad.member_id = 17;
    assert_eq!(
        RegionFrame::Hello(bad).encode(),
        Err(RegionFrameError::MemberId(17))
    );
}

#[test]
fn refutation_hello_channel_kind_range() {
    for kind in [2, 255] {
        assert_eq!(
            decode(&hello_frame("hkg.relay.ns.io:51822", 1, kind, 1)),
            Err(RegionFrameError::ChannelKind(kind))
        );
    }
}

#[test]
fn refutation_hello_zero_conn_gen() {
    assert_eq!(
        decode(&hello_frame("hkg.relay.ns.io:51822", 1, 0, 0)),
        Err(RegionFrameError::ZeroConnGen)
    );
    let mut bad = hello();
    bad.conn_gen = 0;
    assert_eq!(
        RegionFrame::Hello(bad).encode(),
        Err(RegionFrameError::ZeroConnGen)
    );
}

fn present_frame(slot: &[u8], identity: &Identity, carrier: u64, revision: u64) -> Vec<u8> {
    Raw::frame(3)
        .array(7)
        .bytes(slot)
        .bytes(identity)
        .uint(1)
        .uint(1)
        .uint(carrier)
        .uint(1)
        .uint(revision)
        .0
}

#[test]
fn refutation_present_carrier_range() {
    let identity = owner(1);
    let slot = NodeId::derive(&identity);
    for carrier in [2, 255] {
        assert_eq!(
            decode(&present_frame(slot.as_bytes(), &identity, carrier, 1)),
            Err(RegionFrameError::Carrier(carrier))
        );
    }
}

#[test]
fn refutation_slot_is_not_node_id_of_identity() {
    let identity = owner(1);
    let other = NodeId::derive(&owner(2));
    assert_eq!(
        decode(&present_frame(other.as_bytes(), &identity, 0, 1)),
        Err(RegionFrameError::SlotMismatch)
    );
    let mut entry = present(identity, 1);
    entry.slot = other;
    assert_eq!(
        RegionFrame::Present(entry).encode(),
        Err(RegionFrameError::SlotMismatch)
    );
    let mut retired = gone(identity, 1);
    retired.slot = NodeId::from_bytes([0; 12]);
    assert_eq!(
        decode(&{
            let mut valid = RegionFrame::Gone(gone(identity, 1)).encode().unwrap();
            // Replace the 12 slot bytes after `[2, 4, [` and the bytes12 head.
            for byte in valid.iter_mut().skip(5).take(12) {
                *byte = 0;
            }
            valid
        }),
        Err(RegionFrameError::SlotMismatch)
    );
    assert_eq!(
        RegionFrame::Gone(retired).encode(),
        Err(RegionFrameError::SlotMismatch)
    );
}

#[test]
fn refutation_zero_event_revision() {
    let identity = owner(1);
    let slot = NodeId::derive(&identity);
    assert_eq!(
        decode(&present_frame(slot.as_bytes(), &identity, 0, 0)),
        Err(RegionFrameError::ZeroRevision)
    );
    assert_eq!(
        RegionFrame::Gone(gone(identity, 0)).encode(),
        Err(RegionFrameError::ZeroRevision)
    );
}

#[test]
fn refutation_gone_reason_range() {
    let identity = owner(1);
    for reason in [4, 255] {
        let frame = Raw::frame(4)
            .array(7)
            .bytes(NodeId::derive(&identity).as_bytes())
            .bytes(&identity)
            .uint(1)
            .uint(1)
            .uint(reason)
            .0;
        assert_eq!(decode(&frame), Err(RegionFrameError::GoneReason(reason)));
    }
}

#[test]
fn refutation_miss_status_range() {
    for status in [0, 3, 255] {
        let frame = Raw::frame(7).array(3).uint(1).uint(1).uint(status).0;
        assert_eq!(decode(&frame), Err(RegionFrameError::MissStatus(status)));
    }
}

#[test]
fn refutation_zero_snapshot_id() {
    let mut chunk = snapshot();
    chunk.snapshot_id = 0;
    assert_eq!(
        RegionFrame::Snapshot(chunk).encode(),
        Err(RegionFrameError::ZeroSnapshotId)
    );
    let frame = Raw::frame(2)
        .array(7)
        .uint(0)
        .uint(0)
        .uint(0)
        .uint(0)
        .array(0)
        .array(0)
        .boolean(false)
        .0;
    assert_eq!(decode(&frame), Err(RegionFrameError::ZeroSnapshotId));
}

#[test]
fn refutation_snapshot_entry_limit() {
    let frame = Raw::frame(2)
        .array(7)
        .uint(1)
        .uint(0)
        .uint(0)
        .uint(0)
        .array(257)
        .0;
    assert_eq!(decode(&frame), Err(RegionFrameError::TooManyEntries(257)));
    let frame = Raw::frame(2)
        .array(7)
        .uint(1)
        .uint(0)
        .uint(0)
        .uint(0)
        .array(0)
        .array(257)
        .0;
    assert_eq!(decode(&frame), Err(RegionFrameError::TooManyEntries(257)));
    let mut chunk = snapshot();
    chunk.presence.clear();
    chunk.marks = (0..=256_u16)
        .map(|index| {
            let mut identity = [0; 32];
            identity[..2].copy_from_slice(&index.to_be_bytes());
            marks(identity)
        })
        .collect();
    assert_eq!(
        RegionFrame::Snapshot(chunk).encode(),
        Err(RegionFrameError::TooManyEntries(257))
    );
}

#[test]
fn refutation_snapshot_presence_entry_after_cut() {
    let mut chunk = snapshot();
    chunk.presence = vec![present(owner(1), 11)];
    assert_eq!(
        RegionFrame::Snapshot(chunk.clone()).encode(),
        Err(RegionFrameError::EntryAfterCut {
            revision: 11,
            base_revision: 10
        })
    );
    chunk.base_revision = 0;
    chunk.presence = vec![present(owner(1), 1)];
    assert_eq!(
        RegionFrame::Snapshot(chunk).encode(),
        Err(RegionFrameError::EntryAfterCut {
            revision: 1,
            base_revision: 0
        })
    );
}

#[test]
fn refutation_snapshot_nested_entry_rules() {
    let mut chunk = snapshot();
    chunk.presence[0].revision = 0;
    assert_eq!(
        RegionFrame::Snapshot(chunk.clone()).encode(),
        Err(RegionFrameError::ZeroRevision)
    );
    chunk.presence[0] = present(owner(1), 1);
    chunk.presence[0].slot = NodeId::derive(&owner(9));
    assert_eq!(
        RegionFrame::Snapshot(chunk).encode(),
        Err(RegionFrameError::SlotMismatch)
    );
}

#[test]
fn refutation_snapshot_duplicate_owner() {
    let mut chunk = snapshot();
    chunk.presence = vec![present(owner(1), 1), present(owner(1), 2)];
    assert_eq!(
        RegionFrame::Snapshot(chunk.clone()).encode(),
        Err(RegionFrameError::DuplicateOwner("presence"))
    );
    chunk.presence = vec![present(owner(1), 1)];
    chunk.marks = vec![marks(owner(2)), marks(owner(2))];
    assert_eq!(
        RegionFrame::Snapshot(chunk).encode(),
        Err(RegionFrameError::DuplicateOwner("mark"))
    );
}

#[test]
fn refutation_zero_forward_id() {
    let mut frame = forward(owner(1));
    frame.forward_id = 0;
    assert_eq!(
        RegionFrame::Forward(frame.clone()).encode(),
        Err(RegionFrameError::ZeroForwardId)
    );
    let raw = Raw::frame(6)
        .array(3)
        .uint(0)
        .bytes(&frame.source_owner)
        .bytes(&frame.datagram)
        .0;
    assert_eq!(decode(&raw), Err(RegionFrameError::ZeroForwardId));
}

#[test]
fn refutation_forward_datagram_too_large() {
    let raw = Raw::frame(6)
        .array(3)
        .uint(1)
        .bytes(&owner(1))
        .bytes(&[0; MAX_REGION_FORWARD_DATAGRAM_BYTES + 1])
        .0;
    assert_eq!(
        decode(&raw),
        Err(RegionFrameError::DatagramTooLarge(
            MAX_REGION_FORWARD_DATAGRAM_BYTES + 1
        ))
    );
}

#[test]
fn refutation_forward_malformed_relay_packet() {
    let mut frame = forward(owner(1));
    frame.datagram[0] ^= 0xff;
    assert_eq!(
        RegionFrame::Forward(frame.clone()).encode(),
        Err(RegionFrameError::Datagram(RelayPacketError::BadMagic))
    );
    frame.datagram.truncate(10);
    let raw = Raw::frame(6)
        .array(3)
        .uint(1)
        .bytes(&frame.source_owner)
        .bytes(&frame.datagram)
        .0;
    assert_eq!(
        decode(&raw),
        Err(RegionFrameError::Datagram(RelayPacketError::TooShort(10)))
    );
    // A DATA header with an empty body.
    let mut header_only = forward(owner(1));
    header_only.datagram.truncate(29);
    assert_eq!(
        RegionFrame::Forward(header_only).encode(),
        Err(RegionFrameError::Datagram(RelayPacketError::DataLength(0)))
    );
}

#[test]
fn refutation_forward_non_data_packet() {
    let source = owner(1);
    let reflect = RelayPacket {
        src: NodeId::derive(&source),
        dst: NodeId::from_bytes([0; 12]),
        body: RelayBody::Reflect(Reflect {
            incarnation: 1,
            seq: 1,
            nonce: [0; 16],
            mac: [0; 32],
        }),
    }
    .encode()
    .unwrap();
    let raw = Raw::frame(6)
        .array(3)
        .uint(1)
        .bytes(&source)
        .bytes(&reflect)
        .0;
    assert_eq!(
        decode(&raw),
        Err(RegionFrameError::DatagramNotData(RelayType::Reflect))
    );
}

#[test]
fn refutation_forward_source_owner_mismatch() {
    let mut frame = forward(owner(1));
    frame.source_owner = owner(2);
    assert_eq!(
        RegionFrame::Forward(frame.clone()).encode(),
        Err(RegionFrameError::SourceOwnerMismatch)
    );
    let raw = Raw::frame(6)
        .array(3)
        .uint(1)
        .bytes(&frame.source_owner)
        .bytes(&frame.datagram)
        .0;
    assert_eq!(decode(&raw), Err(RegionFrameError::SourceOwnerMismatch));
}

#[test]
fn refutation_liveness_zero_nonce() {
    for frame_type in [8, 9] {
        let raw = Raw::frame(frame_type).array(3).uint(0).uint(1).uint(0).0;
        assert_eq!(decode(&raw), Err(RegionFrameError::ZeroNonce));
    }
}

#[test]
fn refutation_liveness_progress_without_data_connection() {
    for frame_type in [8, 9] {
        let raw = Raw::frame(frame_type).array(3).uint(1).uint(0).uint(5).0;
        assert_eq!(
            decode(&raw),
            Err(RegionFrameError::ProgressWithoutDataConnection(5))
        );
    }
}

// ---------------------------------------------------------------------------
// Channel rules
// ---------------------------------------------------------------------------

const CONTROL_TYPES: [RegionFrameType; 9] = [
    RegionFrameType::Snapshot,
    RegionFrameType::Present,
    RegionFrameType::Gone,
    RegionFrameType::Marks,
    RegionFrameType::Miss,
    RegionFrameType::Ping,
    RegionFrameType::Pong,
    RegionFrameType::RendezvousRequest,
    RegionFrameType::RendezvousResponse,
];

#[test]
fn channels_carry_their_frame_types() {
    for channel in [RegionChannel::Control, RegionChannel::Data] {
        assert_eq!(
            check_region_channel(channel, false, RegionFrameType::Hello),
            Ok(())
        );
    }
    for frame_type in CONTROL_TYPES {
        assert_eq!(
            check_region_channel(RegionChannel::Control, true, frame_type),
            Ok(())
        );
    }
    assert_eq!(
        check_region_channel(RegionChannel::Data, true, RegionFrameType::Forward),
        Ok(())
    );
}

#[test]
fn refutation_wrong_channel() {
    for frame_type in CONTROL_TYPES {
        assert_eq!(
            check_region_channel(RegionChannel::Data, true, frame_type),
            Err(RegionChannelError::WrongChannel {
                frame_type,
                channel: RegionChannel::Data
            })
        );
    }
    assert_eq!(
        check_region_channel(RegionChannel::Control, true, RegionFrameType::Forward),
        Err(RegionChannelError::WrongChannel {
            frame_type: RegionFrameType::Forward,
            channel: RegionChannel::Control
        })
    );
}

#[test]
fn refutation_frame_before_hello() {
    for channel in [RegionChannel::Control, RegionChannel::Data] {
        for frame_type in [RegionFrameType::Forward, RegionFrameType::Ping] {
            assert_eq!(
                check_region_channel(channel, false, frame_type),
                Err(RegionChannelError::HelloRequired(frame_type))
            );
        }
    }
}

#[test]
fn refutation_second_hello() {
    for channel in [RegionChannel::Control, RegionChannel::Data] {
        assert_eq!(
            check_region_channel(channel, true, RegionFrameType::Hello),
            Err(RegionChannelError::DuplicateHello)
        );
    }
}

#[test]
fn refutation_registry_record_channel_undefined() {
    for channel in [RegionChannel::Control, RegionChannel::Data] {
        assert_eq!(
            check_region_channel(channel, true, RegionFrameType::RegistryRecord),
            Err(RegionChannelError::ChannelUndefined(
                RegionFrameType::RegistryRecord
            ))
        );
    }
}

// ---------------------------------------------------------------------------
// Property round trips
// ---------------------------------------------------------------------------

fn identity_strategy() -> impl Strategy<Value = Identity> {
    any::<[u8; 32]>()
}

fn present_strategy() -> impl Strategy<Value = RegionPresent> {
    (
        identity_strategy(),
        any::<u64>(),
        any::<u64>(),
        any::<bool>(),
        any::<u64>(),
        1..=u64::MAX,
    )
        .prop_map(
            |(identity, generation, incarnation, wss, boot_epoch, revision)| RegionPresent {
                slot: NodeId::derive(&identity),
                identity,
                generation,
                incarnation,
                carrier: if wss {
                    RegionCarrier::Wss
                } else {
                    RegionCarrier::Udp
                },
                boot_epoch,
                revision,
            },
        )
}

fn marks_strategy() -> impl Strategy<Value = RegionMarks> {
    (
        identity_strategy(),
        any::<u64>(),
        any::<[u8; 32]>(),
        any::<bool>(),
        any::<u64>(),
    )
        .prop_map(
            |(identity, committed_gen, committed_key, conflicted, incarnation_high_water)| {
                RegionMarks {
                    identity,
                    committed_gen,
                    committed_key,
                    conflicted,
                    incarnation_high_water,
                }
            },
        )
}

fn reason_strategy() -> impl Strategy<Value = RegionGoneReason> {
    prop_oneof![
        Just(RegionGoneReason::Expired),
        Just(RegionGoneReason::Revoked),
        Just(RegionGoneReason::Superseded),
        Just(RegionGoneReason::Closed),
    ]
}

fn region_name_strategy() -> impl Strategy<Value = RelayId> {
    (
        "[a-z][a-z0-9]{0,20}(\\.[a-z][a-z0-9]{0,20}){1,3}",
        1..=u16::MAX,
    )
        .prop_map(|(host, port)| RelayId::parse(&format!("{host}:{port}")).unwrap())
}

fn liveness_strategy() -> impl Strategy<Value = RegionLiveness> {
    (1..=u64::MAX, any::<u32>(), any::<u64>()).prop_map(|(nonce, data_conn_gen, consumed)| {
        RegionLiveness {
            nonce,
            data_conn_gen,
            consumed_forward_id: if data_conn_gen == 0 { 0 } else { consumed },
        }
    })
}

fn snapshot_strategy() -> impl Strategy<Value = RegionSnapshot> {
    (
        1..=u64::MAX,
        any::<u64>(),
        any::<u32>(),
        prop::collection::vec(present_strategy(), 0..12),
        prop::collection::vec(marks_strategy(), 0..12),
        any::<bool>(),
    )
        .prop_map(
            |(snapshot_id, marks_revision, chunk_index, presence, marks, more)| {
                let base_revision = presence
                    .iter()
                    .map(|entry| entry.revision)
                    .max()
                    .unwrap_or(0);
                RegionSnapshot {
                    snapshot_id,
                    base_revision,
                    marks_revision,
                    chunk_index,
                    presence,
                    marks,
                    more,
                }
            },
        )
        .prop_filter("unique owners per list", |snapshot| {
            snapshot.validate().is_ok()
        })
}

fn frame_strategy() -> impl Strategy<Value = RegionFrame> {
    prop_oneof![
        (
            region_name_strategy(),
            1..=16_u8,
            any::<u64>(),
            any::<bool>(),
            1..=u32::MAX
        )
            .prop_map(|(region_name, member_id, boot_epoch, data, conn_gen)| {
                RegionFrame::Hello(RegionHello {
                    region_name,
                    member_id,
                    boot_epoch,
                    channel: if data {
                        RegionChannel::Data
                    } else {
                        RegionChannel::Control
                    },
                    conn_gen,
                })
            }),
        snapshot_strategy().prop_map(RegionFrame::Snapshot),
        present_strategy().prop_map(RegionFrame::Present),
        (present_strategy(), reason_strategy()).prop_map(|(entry, reason)| {
            RegionFrame::Gone(RegionGone {
                slot: entry.slot,
                identity: entry.identity,
                generation: entry.generation,
                incarnation: entry.incarnation,
                reason,
                boot_epoch: entry.boot_epoch,
                revision: entry.revision,
            })
        }),
        marks_strategy().prop_map(RegionFrame::Marks),
        (
            1..=u64::MAX,
            identity_strategy(),
            prop::collection::vec(any::<u8>(), 1..=2019)
        )
            .prop_map(|(forward_id, source_owner, payload)| {
                RegionFrame::Forward(RegionForward {
                    forward_id,
                    source_owner,
                    datagram: data_packet(&source_owner, payload),
                })
            }),
        (any::<u32>(), any::<u64>(), any::<bool>()).prop_map(
            |(data_conn_gen, forward_id, full)| {
                RegionFrame::Miss(RegionMiss {
                    data_conn_gen,
                    forward_id,
                    status: if full {
                        RegionMissStatus::Exhausted
                    } else {
                        RegionMissStatus::NoEligibleDestination
                    },
                })
            }
        ),
        liveness_strategy().prop_map(RegionFrame::Ping),
        liveness_strategy().prop_map(RegionFrame::Pong),
    ]
}

proptest! {
    #[test]
    fn frames_round_trip(frame in frame_strategy()) {
        let encoded = frame.encode().unwrap();
        prop_assert!(encoded.len() <= MAX_REGION_FRAME_BYTES);
        prop_assert_eq!(decode(&encoded), Ok(frame.clone()));
        let wire = frame.encode_prefixed().unwrap();
        prop_assert_eq!(split_region_frame(&wire), Ok(&encoded[..]));
        prop_assert_eq!(RegionFrame::decode_prefixed(&wire), Ok(frame));
    }

    #[test]
    fn envelope_round_trips(frame_type in any::<u8>(), payload in prop::collection::vec(any::<u8>(), 0..64)) {
        let body = Raw::default().bytes(&payload).0;
        let frame = encode_region_envelope(frame_type, &body).unwrap();
        prop_assert_eq!(
            decode_region_envelope(&frame),
            Ok(RegionEnvelope { frame_type, body: &body })
        );
    }

    #[test]
    fn arbitrary_bytes_never_panic(input in prop::collection::vec(any::<u8>(), 0..256)) {
        let _ = decode(&input);
        let _ = RegionFrame::decode_prefixed(&input);
    }
}
