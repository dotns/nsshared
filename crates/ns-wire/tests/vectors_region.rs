//! Generated relay region frame vectors, types 1-9 (quick-v2 §8.5, §12.1,
//! quick-protocol §12.8).

#![allow(clippy::unwrap_used, clippy::panic, reason = "test fixture helpers")]

mod support;

use ns_wire::{
    CborError, NodeId, RegionCarrier, RegionChannel, RegionChannelError, RegionForward,
    RegionFrame, RegionFrameError, RegionFrameType, RegionGone, RegionGoneReason, RegionHello,
    RegionLiveness, RegionMarks, RegionMiss, RegionMissStatus, RegionPresent, RegionSnapshot,
    RelayId, check_region_channel, split_region_frame,
};
use support::vectors::{Vector, decode_hex, load};

fn int<T: TryFrom<u64>>(v: &Vector, key: &str) -> T {
    T::try_from(v.u64(key)).unwrap_or_else(|_| panic!("{}: `{key}` out of range", v.name()))
}

fn boolean(v: &Vector, text: &str) -> bool {
    match text {
        "true" => true,
        "false" => false,
        other => panic!("{}: not a boolean: {other}", v.name()),
    }
}

fn channel(v: &Vector) -> RegionChannel {
    match v.get("channel") {
        "control" => RegionChannel::Control,
        "data" => RegionChannel::Data,
        other => panic!("{}: channel {other}", v.name()),
    }
}

/// Every value of `key` parsed with `parse`, checked against the `count` entries.
fn column<T>(v: &Vector, key: &str, count: usize, parse: impl Fn(&str) -> T) -> Vec<T> {
    let values = v.all(key);
    assert_eq!(values.len(), count, "{}: `{key}`", v.name());
    values.into_iter().map(parse).collect()
}

fn hex32(text: &str) -> [u8; 32] {
    decode_hex(text).unwrap().try_into().unwrap()
}

fn carrier(value: u64) -> RegionCarrier {
    match value {
        0 => RegionCarrier::Udp,
        1 => RegionCarrier::Wss,
        other => panic!("carrier {other}"),
    }
}

fn gone_reason(value: u64) -> RegionGoneReason {
    match value {
        0 => RegionGoneReason::Expired,
        1 => RegionGoneReason::Revoked,
        2 => RegionGoneReason::Superseded,
        3 => RegionGoneReason::Closed,
        other => panic!("GONE reason {other}"),
    }
}

/// The `present_*` (or `gone_*`) columns as `(slot, I, gen, incarnation, enum, epoch,
/// revision)` tuples.
type Event = (NodeId, [u8; 32], u64, u64, u64, u64, u64);

fn events(v: &Vector, prefix: &str, last: &str, count: usize) -> Vec<Event> {
    let u = |key: &str| {
        column(v, &format!("{prefix}_{key}"), count, |s| {
            s.parse::<u64>().unwrap()
        })
    };
    let slots = column(v, &format!("{prefix}_slot"), count, |s| {
        NodeId::from_bytes(decode_hex(s).unwrap().try_into().unwrap())
    });
    let identities = column(v, &format!("{prefix}_identity"), count, hex32);
    let (gens, incarnations, enums, epochs, revisions) = (
        u("gen"),
        u("incarnation"),
        u(last),
        u("boot_epoch"),
        u("revision"),
    );
    (0..count)
        .map(|i| {
            (
                slots[i],
                identities[i],
                gens[i],
                incarnations[i],
                enums[i],
                epochs[i],
                revisions[i],
            )
        })
        .collect()
}

fn presents(v: &Vector, count: usize) -> Vec<RegionPresent> {
    events(v, "present", "carrier", count)
        .into_iter()
        .map(
            |(slot, identity, generation, incarnation, value, boot_epoch, revision)| {
                RegionPresent {
                    slot,
                    identity,
                    generation,
                    incarnation,
                    carrier: carrier(value),
                    boot_epoch,
                    revision,
                }
            },
        )
        .collect()
}

fn marks(v: &Vector, count: usize) -> Vec<RegionMarks> {
    let u = |key: &str| {
        column(v, &format!("marks_{key}"), count, |s| {
            s.parse::<u64>().unwrap()
        })
    };
    let identities = column(v, "marks_identity", count, hex32);
    let keys = column(v, "marks_committed_key", count, hex32);
    let conflicted = column(v, "marks_conflicted", count, |s| boolean(v, s));
    let (gens, high_water) = (u("committed_gen"), u("incarnation_high_water"));
    (0..count)
        .map(|i| RegionMarks {
            identity: identities[i],
            committed_gen: gens[i],
            committed_key: keys[i],
            conflicted: conflicted[i],
            incarnation_high_water: high_water[i],
        })
        .collect()
}

/// Builds the typed frame of a positive vector.
fn build(v: &Vector) -> RegionFrame {
    let liveness = || RegionLiveness {
        nonce: v.u64("nonce"),
        data_conn_gen: int(v, "data_conn_gen"),
        consumed_forward_id: v.u64("consumed_forward_id"),
    };
    match v.u64("type") {
        1 => RegionFrame::Hello(RegionHello {
            region_name: RelayId::parse(v.get("region_name")).unwrap(),
            member_id: int(v, "member_id"),
            boot_epoch: v.u64("boot_epoch"),
            channel: match v.u64("channel_kind") {
                0 => RegionChannel::Control,
                1 => RegionChannel::Data,
                other => panic!("{}: channel_kind {other}", v.name()),
            },
            conn_gen: int(v, "conn_gen"),
        }),
        2 => RegionFrame::Snapshot(RegionSnapshot {
            snapshot_id: v.u64("snapshot_id"),
            base_revision: v.u64("base_revision"),
            marks_revision: v.u64("marks_revision"),
            chunk_index: int(v, "chunk_index"),
            presence: presents(v, int(v, "presence_count")),
            marks: marks(v, int(v, "marks_count")),
            more: boolean(v, v.get("more")),
        }),
        3 => RegionFrame::Present(presents(v, 1).remove(0)),
        4 => {
            let (slot, identity, generation, incarnation, reason, boot_epoch, revision) =
                events(v, "gone", "reason", 1)[0];
            RegionFrame::Gone(RegionGone {
                slot,
                identity,
                generation,
                incarnation,
                reason: gone_reason(reason),
                boot_epoch,
                revision,
            })
        }
        5 => RegionFrame::Marks(marks(v, 1).remove(0)),
        6 => RegionFrame::Forward(RegionForward {
            forward_id: v.u64("forward_id"),
            source_owner: v.hex_array("source_owner"),
            datagram: v.hex("datagram"),
        }),
        7 => RegionFrame::Miss(RegionMiss {
            data_conn_gen: int(v, "data_conn_gen"),
            forward_id: v.u64("forward_id"),
            status: match v.u64("status") {
                1 => RegionMissStatus::NoEligibleDestination,
                2 => RegionMissStatus::Exhausted,
                other => panic!("{}: MISS status {other}", v.name()),
            },
        }),
        8 => RegionFrame::Ping(liveness()),
        9 => RegionFrame::Pong(liveness()),
        other => panic!("{}: type {other}", v.name()),
    }
}

#[test]
fn region_frames_match_vectors() {
    let vectors = load("region_frames");
    let mut types = Vec::new();
    for v in vectors.iter().filter(|v| !v.is_reject()) {
        let name = v.name();
        let frame = build(v);
        let encoded = v.hex("frame");
        let wire = v.hex("prefixed");
        assert_eq!(encoded.len(), int::<usize>(v, "frame_len"), "{name}");

        // Encode equals the fixture; decode then re-encode equals the fixture.
        assert_eq!(frame.encode().unwrap(), encoded, "{name}");
        assert_eq!(frame.encode_prefixed().unwrap(), wire, "{name}");
        let decoded = RegionFrame::decode(&encoded).unwrap();
        assert_eq!(decoded, frame, "{name}");
        assert_eq!(decoded.encode().unwrap(), encoded, "{name}");
        assert_eq!(
            RegionFrame::decode_prefixed(&wire).unwrap(),
            frame,
            "{name}"
        );
        assert_eq!(
            split_region_frame(&wire).unwrap(),
            encoded.as_slice(),
            "{name}"
        );

        // The frame is carried on its connection kind (quick-protocol §12.8).
        let established = frame.frame_type() != RegionFrameType::Hello;
        assert_eq!(
            check_region_channel(channel(v), established, frame.frame_type()),
            Ok(()),
            "{name}"
        );
        types.push(v.u64("type"));
    }
    types.sort_unstable();
    types.dedup();
    assert_eq!(types, [1, 2, 3, 4, 5, 6, 7, 8, 9]);
}

fn frame_error_matches(reason: &str, error: &RegionFrameError) -> bool {
    match reason {
        "too_large" => matches!(error, RegionFrameError::TooLarge(_)),
        "trailing_bytes" => *error == RegionFrameError::Cbor(CborError::TrailingBytes),
        "non_canonical" | "schema" => matches!(error, RegionFrameError::Cbor(_)),
        "version" => matches!(error, RegionFrameError::Version(_)),
        "unknown_type" => matches!(error, RegionFrameError::UnknownType(_)),
        "field_width" => matches!(error, RegionFrameError::FieldWidth { .. }),
        "region_name" => matches!(error, RegionFrameError::RegionName(_)),
        "member_id" => matches!(error, RegionFrameError::MemberId(_)),
        "channel_kind" => matches!(error, RegionFrameError::ChannelKind(_)),
        "zero_conn_gen" => *error == RegionFrameError::ZeroConnGen,
        "carrier" => matches!(error, RegionFrameError::Carrier(_)),
        "gone_reason" => matches!(error, RegionFrameError::GoneReason(_)),
        "miss_status" => matches!(error, RegionFrameError::MissStatus(_)),
        "slot_mismatch" => *error == RegionFrameError::SlotMismatch,
        "zero_revision" => *error == RegionFrameError::ZeroRevision,
        "zero_snapshot_id" => *error == RegionFrameError::ZeroSnapshotId,
        "too_many_entries" => matches!(error, RegionFrameError::TooManyEntries(_)),
        "entry_after_cut" => matches!(error, RegionFrameError::EntryAfterCut { .. }),
        "duplicate_owner" => matches!(error, RegionFrameError::DuplicateOwner(_)),
        "zero_forward_id" => *error == RegionFrameError::ZeroForwardId,
        "datagram_too_large" => matches!(error, RegionFrameError::DatagramTooLarge(_)),
        "datagram" => matches!(error, RegionFrameError::Datagram(_)),
        "datagram_not_data" => matches!(error, RegionFrameError::DatagramNotData(_)),
        "source_owner_mismatch" => *error == RegionFrameError::SourceOwnerMismatch,
        "zero_nonce" => *error == RegionFrameError::ZeroNonce,
        "progress_without_data_connection" => {
            matches!(error, RegionFrameError::ProgressWithoutDataConnection(_))
        }
        "frame_length" => matches!(error, RegionFrameError::FrameLength(_)),
        "truncated" => *error == RegionFrameError::Truncated,
        "trailing_frame_bytes" => *error == RegionFrameError::TrailingFrameBytes,
        other => panic!("unknown reason {other}"),
    }
}

#[test]
fn rejected_region_frames_match_vectors() {
    let vectors = load("region_frames");
    let mut negatives = 0;
    for v in vectors.iter().filter(|v| v.is_reject()) {
        let name = v.name();
        let reason = v.reason();
        match v.get("kind") {
            "frame" => {
                let error = RegionFrame::decode(&v.hex("frame")).unwrap_err();
                assert!(frame_error_matches(reason, &error), "{name}: {error:?}");
            }
            "prefixed" => {
                let error = RegionFrame::decode_prefixed(&v.hex("prefixed")).unwrap_err();
                assert!(frame_error_matches(reason, &error), "{name}: {error:?}");
            }
            "channel" => {
                let frame = RegionFrame::decode(&v.hex("frame")).unwrap();
                let established = boolean(v, v.get("established"));
                let error =
                    check_region_channel(channel(v), established, frame.frame_type()).unwrap_err();
                let matched = match reason {
                    "wrong_channel" => matches!(error, RegionChannelError::WrongChannel { .. }),
                    "duplicate_hello" => error == RegionChannelError::DuplicateHello,
                    "hello_required" => matches!(error, RegionChannelError::HelloRequired(_)),
                    other => panic!("{name}: unknown reason {other}"),
                };
                assert!(matched, "{name}: {error:?}");
            }
            other => panic!("{name}: unknown kind {other}"),
        }
        negatives += 1;
    }
    assert!(negatives >= 50);
}
