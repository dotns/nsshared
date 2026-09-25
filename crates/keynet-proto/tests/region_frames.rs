use keynet_proto::{
    CONTROL_REGION_FRAME_TYPES, DATA_POST_HELLO_REGION_FRAME_TYPES, DATA_REGION_FRAME_TYPES,
    MAX_REGION_FORWARD_DATAGRAM_BYTES, MAX_REGION_FRAME_BYTES, MAX_REGION_SNAPSHOT_ENTRIES,
    RegionCarrier, RegionChannel, RegionDecodeError, RegionEncodeError, RegionForward, RegionFrame,
    RegionFrameType, RegionGone, RegionGoneReason, RegionHello, RegionMarks, RegionMiss,
    RegionMissStatus, RegionOwner, RegionPing, RegionPong, RegionPresence, RegionSettled,
    RegionSnapshot, RelayHeader, decode_region_frame_prefix,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::PathBuf,
};

const REGION_FRAME_CASES: &str = "hello_control,hello_data,snapshot_nested,present,gone,marks,forward,miss,ping,pong,settled,non_shortest,indefinite_length,wrong_arity,wrong_type,wrong_width,trailing_bytes,wrong_channel,zero_prefix,oversized_prefix,frame_limit,datagram_limit,snapshot_entry_limit,settled_zero_generation,settled_zero_forward_id,settled_wrong_channel";

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/keynet-v1")
}

fn blocks(text: &str) -> Result<Vec<BTreeMap<&str, &str>>, String> {
    text.split("\n\n")
        .filter(|block| !block.trim().is_empty())
        .map(|block| {
            let mut fields = BTreeMap::new();
            for line in block.lines().filter(|line| !line.starts_with('#')) {
                let (key, value) = line
                    .split_once('=')
                    .ok_or_else(|| "invalid region frame vector line".to_owned())?;
                if fields.insert(key, value).is_some() {
                    return Err(format!("duplicate region frame vector field: {key}"));
                }
            }
            Ok(fields)
        })
        .collect()
}

fn field<'a>(block: &'a BTreeMap<&str, &str>, name: &str) -> Result<&'a str, String> {
    block
        .get(name)
        .copied()
        .ok_or_else(|| format!("missing region frame vector field: {name}"))
}

fn hex_bytes(input: &str) -> Result<Vec<u8>, String> {
    if !input.len().is_multiple_of(2) {
        return Err("odd region frame vector hex length".to_owned());
    }
    (0..input.len() / 2)
        .map(|index| {
            u8::from_str_radix(&input[index * 2..index * 2 + 2], 16)
                .map_err(|error| error.to_string())
        })
        .collect()
}

fn channel(input: &str) -> Result<RegionChannel, String> {
    match input {
        "control" => Ok(RegionChannel::Control),
        "data" => Ok(RegionChannel::Data),
        _ => Err("invalid region frame vector channel".to_owned()),
    }
}

fn frame_type_name(frame_type: RegionFrameType) -> &'static str {
    match frame_type {
        RegionFrameType::Hello => "hello",
        RegionFrameType::Snapshot => "snapshot",
        RegionFrameType::Present => "present",
        RegionFrameType::Gone => "gone",
        RegionFrameType::Marks => "marks",
        RegionFrameType::Forward => "forward",
        RegionFrameType::Miss => "miss",
        RegionFrameType::Ping => "ping",
        RegionFrameType::Pong => "pong",
        RegionFrameType::Settled => "settled",
    }
}

fn presence(carrier: RegionCarrier) -> RegionPresence {
    RegionPresence {
        slot: [0x10; 16],
        network_id: [0x20; 32],
        identity: [0x30; 32],
        generation: 1,
        incarnation: 2,
        carrier,
        boot_epoch: 3,
        revision: 4,
    }
}

fn marks(revoked_through: Option<u64>) -> RegionMarks {
    RegionMarks {
        network_id: [0x20; 32],
        identity: [0x30; 32],
        committed_generation: 5,
        committed_key: [0x40; 32],
        conflicted: true,
        revoked_through,
        incarnation_high_water: 6,
    }
}

fn hello(channel: RegionChannel) -> RegionFrame {
    RegionFrame::Hello(RegionHello {
        region_name: "relay-a".to_owned(),
        member_id: 1,
        boot_epoch: 2,
        channel,
        conn_gen: 3,
    })
}

fn sample_frames() -> Vec<(RegionChannel, RegionFrame)> {
    let present = presence(RegionCarrier::Udp);
    vec![
        (RegionChannel::Control, hello(RegionChannel::Control)),
        (RegionChannel::Data, hello(RegionChannel::Data)),
        (
            RegionChannel::Control,
            RegionFrame::Snapshot(RegionSnapshot {
                snapshot_id: 1,
                base_revision: 2,
                marks_revision: 3,
                chunk_index: 4,
                presence_entries: vec![present],
                mark_entries: vec![marks(None)],
                more: true,
            }),
        ),
        (
            RegionChannel::Control,
            RegionFrame::Present(presence(RegionCarrier::Wss)),
        ),
        (
            RegionChannel::Control,
            RegionFrame::Gone(RegionGone {
                slot: [0x10; 16],
                network_id: [0x20; 32],
                identity: [0x30; 32],
                generation: 1,
                incarnation: 2,
                reason: RegionGoneReason::Superseded,
                boot_epoch: 3,
                revision: 4,
            }),
        ),
        (RegionChannel::Control, RegionFrame::Marks(marks(Some(7)))),
        (
            RegionChannel::Data,
            RegionFrame::Forward(RegionForward {
                forward_id: 1,
                source_owner: RegionOwner {
                    network_id: [0x20; 32],
                    identity: [0x30; 32],
                },
                datagram: vec![0; 37],
            }),
        ),
        (
            RegionChannel::Control,
            RegionFrame::Miss(RegionMiss {
                data_conn_gen: 1,
                forward_id: 2,
                status: RegionMissStatus::NoEligibleDestination,
            }),
        ),
        (
            RegionChannel::Control,
            RegionFrame::Ping(RegionPing {
                nonce: 1,
                data_conn_gen: 2,
                consumed_forward_id: 3,
            }),
        ),
        (
            RegionChannel::Control,
            RegionFrame::Pong(RegionPong {
                nonce: 1,
                data_conn_gen: 2,
                consumed_forward_id: 3,
            }),
        ),
        (
            RegionChannel::Control,
            RegionFrame::Settled(RegionSettled {
                data_conn_gen: 1,
                settled_forward_id: 2,
            }),
        ),
    ]
}

fn round_trip(frame: &RegionFrame, channel: RegionChannel) -> Result<Vec<u8>, String> {
    let encoded = frame
        .encode(channel)
        .map_err(|error| format!("{error:?}"))?;
    let decoded = RegionFrame::decode(&encoded, channel).map_err(|error| format!("{error:?}"))?;
    if decoded != *frame {
        return Err("region frame round trip changed the frame".to_owned());
    }
    Ok(encoded)
}

fn prefixed(body: Vec<u8>) -> Result<Vec<u8>, String> {
    let length = u32::try_from(body.len()).map_err(|error| error.to_string())?;
    let mut output = Vec::with_capacity(body.len() + 4);
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(&body);
    Ok(output)
}

fn assert_rejected(input: &[u8], channel: RegionChannel, label: &str) -> Result<(), String> {
    if RegionFrame::decode(input, channel).is_ok() {
        return Err(format!("accepted malformed region frame: {label}"));
    }
    Ok(())
}

fn fixture_usize(vector: &BTreeMap<&str, &str>, name: &str) -> Result<usize, String> {
    field(vector, name)?
        .parse()
        .map_err(|error: std::num::ParseIntError| error.to_string())
}

fn assert_generated_fixture_case(case: &str, vector: &BTreeMap<&str, &str>) -> Result<(), String> {
    match case {
        "frame_limit" => {
            let limit = fixture_usize(vector, "limit")?;
            let one_over = fixture_usize(vector, "one_over")?;
            let encoded = capped_snapshot(0)
                .encode(RegionChannel::Control)
                .map_err(|error| format!("{error:?}"))?;
            if limit != MAX_REGION_FRAME_BYTES
                || one_over != MAX_REGION_FRAME_BYTES + 1
                || encoded.len() != limit + 4
                || capped_snapshot(1).encode(RegionChannel::Control)
                    != Err(RegionEncodeError::FrameTooLarge)
            {
                return Err("sealed frame-size boundary changed".to_owned());
            }
        }
        "datagram_limit" => {
            let limit = fixture_usize(vector, "limit")?;
            let one_over = fixture_usize(vector, "one_over")?;
            let at_limit = RegionFrame::Forward(RegionForward {
                forward_id: 1,
                source_owner: RegionOwner {
                    network_id: [0x20; 32],
                    identity: [0x30; 32],
                },
                datagram: vec![0; limit],
            });
            let over_limit = RegionFrame::Forward(RegionForward {
                forward_id: 1,
                source_owner: RegionOwner {
                    network_id: [0x20; 32],
                    identity: [0x30; 32],
                },
                datagram: vec![0; one_over],
            });
            if limit != MAX_REGION_FORWARD_DATAGRAM_BYTES
                || one_over != MAX_REGION_FORWARD_DATAGRAM_BYTES + 1
                || round_trip(&at_limit, RegionChannel::Data).is_err()
                || over_limit.encode(RegionChannel::Data) != Err(RegionEncodeError::InvalidFrame)
            {
                return Err("sealed datagram-size boundary changed".to_owned());
            }
        }
        "snapshot_entry_limit" => {
            let limit = fixture_usize(vector, "limit")?;
            let one_over = fixture_usize(vector, "one_over")?;
            let at_limit = RegionFrame::Snapshot(RegionSnapshot {
                snapshot_id: 1,
                base_revision: 2,
                marks_revision: 3,
                chunk_index: 4,
                presence_entries: vec![presence(RegionCarrier::Udp); limit],
                mark_entries: Vec::new(),
                more: false,
            });
            let over_limit = RegionFrame::Snapshot(RegionSnapshot {
                snapshot_id: 1,
                base_revision: 2,
                marks_revision: 3,
                chunk_index: 4,
                presence_entries: vec![presence(RegionCarrier::Udp); one_over],
                mark_entries: Vec::new(),
                more: false,
            });
            if limit != MAX_REGION_SNAPSHOT_ENTRIES
                || one_over != MAX_REGION_SNAPSHOT_ENTRIES + 1
                || at_limit.encode(RegionChannel::Control) != Err(RegionEncodeError::FrameTooLarge)
                || over_limit.encode(RegionChannel::Control) != Err(RegionEncodeError::InvalidFrame)
            {
                return Err("sealed snapshot-entry boundary changed".to_owned());
            }
        }
        _ => {
            return Err(format!(
                "unknown generated region frame fixture case: {case}"
            ));
        }
    }
    Ok(())
}

#[test]
fn region_frame_contract_is_available() -> Result<(), String> {
    let frame = RegionFrame::Ping(RegionPing {
        nonce: 1,
        data_conn_gen: 2,
        consumed_forward_id: 3,
    });
    let _ = round_trip(&frame, RegionChannel::Control)?;
    Ok(())
}

#[test]
fn hello_encoder_rejects_zero_connection_generation() {
    let hello = RegionFrame::Hello(RegionHello {
        region_name: "relay-a".to_owned(),
        member_id: 1,
        boot_epoch: 2,
        channel: RegionChannel::Control,
        conn_gen: 0,
    });

    assert!(
        hello.encode(RegionChannel::Control).is_err(),
        "HELLO connection generation zero is reserved"
    );
}

#[test]
fn hello_decoder_rejects_zero_connection_generation() {
    let encoded = [
        0x00, 0x00, 0x00, 0x10, 0x83, 0x01, 0x01, 0x85, 0x67, b'r', b'e', b'l', b'a', b'y', b'-',
        b'a', 0x01, 0x02, 0x00, 0x00,
    ];

    assert!(
        RegionFrame::decode(&encoded, RegionChannel::Control).is_err(),
        "HELLO connection generation zero is reserved"
    );
}

#[test]
fn settled_encoder_rejects_zero_generation_and_zero_forward_id() {
    for (data_conn_gen, settled_forward_id) in [(0, 1), (1, 0), (0, 0)] {
        let settled = RegionFrame::Settled(RegionSettled {
            data_conn_gen,
            settled_forward_id,
        });
        assert_eq!(
            settled.encode(RegionChannel::Control),
            Err(RegionEncodeError::InvalidFrame),
            "SETTLED generation and forward id zero are reserved"
        );
    }
}

#[test]
fn settled_decoder_rejects_zero_generation_and_zero_forward_id() {
    let accepted = [0x00, 0x00, 0x00, 0x06, 0x83, 0x01, 0x0a, 0x82, 0x01, 0x02];
    assert_eq!(
        RegionFrame::decode(&accepted, RegionChannel::Control),
        Ok(RegionFrame::Settled(RegionSettled {
            data_conn_gen: 1,
            settled_forward_id: 2,
        }))
    );
    let zero_generation = [0x00, 0x00, 0x00, 0x06, 0x83, 0x01, 0x0a, 0x82, 0x00, 0x02];
    let zero_forward_id = [0x00, 0x00, 0x00, 0x06, 0x83, 0x01, 0x0a, 0x82, 0x01, 0x00];
    for encoded in [zero_generation, zero_forward_id] {
        assert_eq!(
            RegionFrame::decode(&encoded, RegionChannel::Control),
            Err(RegionDecodeError::InvalidEncoding),
            "SETTLED generation and forward id zero are reserved"
        );
    }
}

#[test]
fn all_region_frame_types_and_nested_bodies_round_trip() -> Result<(), String> {
    for (channel, frame) in sample_frames() {
        let _ = round_trip(&frame, channel)?;
    }
    let mut unconflicted_marks = marks(None);
    unconflicted_marks.conflicted = false;
    let _ = round_trip(
        &RegionFrame::Snapshot(RegionSnapshot {
            snapshot_id: 7,
            base_revision: 8,
            marks_revision: 9,
            chunk_index: 10,
            presence_entries: Vec::new(),
            mark_entries: vec![unconflicted_marks],
            more: false,
        }),
        RegionChannel::Control,
    )?;
    Ok(())
}

#[test]
fn region_enums_and_integer_widths_round_trip() -> Result<(), String> {
    for carrier in [RegionCarrier::Udp, RegionCarrier::Wss] {
        let _ = round_trip(
            &RegionFrame::Present(presence(carrier)),
            RegionChannel::Control,
        )?;
    }
    for reason in [
        RegionGoneReason::Expired,
        RegionGoneReason::Revoked,
        RegionGoneReason::Superseded,
        RegionGoneReason::Shutdown,
    ] {
        let _ = round_trip(
            &RegionFrame::Gone(RegionGone {
                slot: [0x10; 16],
                network_id: [0x20; 32],
                identity: [0x30; 32],
                generation: u64::MAX,
                incarnation: u64::MAX,
                reason,
                boot_epoch: u64::MAX,
                revision: u64::MAX,
            }),
            RegionChannel::Control,
        )?;
    }
    for status in [
        RegionMissStatus::NoEligibleDestination,
        RegionMissStatus::DestinationExhausted,
    ] {
        let _ = round_trip(
            &RegionFrame::Miss(RegionMiss {
                data_conn_gen: u32::MAX,
                forward_id: u64::MAX,
                status,
            }),
            RegionChannel::Control,
        )?;
    }
    let _ = round_trip(
        &RegionFrame::Settled(RegionSettled {
            data_conn_gen: u32::MAX,
            settled_forward_id: u64::MAX,
        }),
        RegionChannel::Control,
    )?;
    for value in [
        0,
        23,
        24,
        255,
        256,
        65_535,
        65_536,
        u64::from(u32::MAX),
        u64::from(u32::MAX) + 1,
        u64::MAX,
    ] {
        let _ = round_trip(
            &RegionFrame::Ping(RegionPing {
                nonce: value,
                data_conn_gen: u32::MAX,
                consumed_forward_id: value,
            }),
            RegionChannel::Control,
        )?;
    }
    Ok(())
}

#[test]
fn malformed_cbor_forms_are_rejected_for_every_frame_type() -> Result<(), String> {
    for (channel, frame) in sample_frames() {
        let encoded = round_trip(&frame, channel)?;
        let body = encoded[4..].to_vec();

        let mut non_shortest = body.clone();
        non_shortest[1] = 0x18;
        non_shortest.insert(2, 1);
        assert_rejected(&prefixed(non_shortest)?, channel, "non-shortest integer")?;

        let mut indefinite = body.clone();
        indefinite[0] = 0x9f;
        assert_rejected(&prefixed(indefinite)?, channel, "indefinite array")?;

        let mut wrong_arity = body.clone();
        wrong_arity[3] = 0x80;
        assert_rejected(&prefixed(wrong_arity)?, channel, "wrong body arity")?;

        let mut wrong_type = body.clone();
        wrong_type[1] = 0xf5;
        assert_rejected(&prefixed(wrong_type)?, channel, "wrong CBOR type")?;

        let mut wrong_width = body.clone();
        wrong_width[1] = 0x19;
        wrong_width.insert(2, 1);
        wrong_width.insert(3, 0);
        assert_rejected(&prefixed(wrong_width)?, channel, "wrong integer width")?;

        let mut trailing = body;
        trailing.push(0);
        assert_rejected(&prefixed(trailing)?, channel, "trailing byte")?;
    }
    Ok(())
}

#[test]
fn fixed_widths_and_declared_ranges_are_rejected() -> Result<(), String> {
    let mut present = round_trip(
        &RegionFrame::Present(presence(RegionCarrier::Udp)),
        RegionChannel::Control,
    )?[4..]
        .to_vec();
    present[4] = 0x4f;
    assert_rejected(
        &prefixed(present)?,
        RegionChannel::Control,
        "present slot width",
    )?;

    let gone_frame = RegionFrame::Gone(RegionGone {
        slot: [0x10; 16],
        network_id: [0x20; 32],
        identity: [0x30; 32],
        generation: 1,
        incarnation: 2,
        reason: RegionGoneReason::Expired,
        boot_epoch: 3,
        revision: 4,
    });
    let mut gone_body = round_trip(&gone_frame, RegionChannel::Control)?[4..].to_vec();
    gone_body[4] = 0x4f;
    assert_rejected(
        &prefixed(gone_body)?,
        RegionChannel::Control,
        "gone slot width",
    )?;

    let mut mark =
        round_trip(&RegionFrame::Marks(marks(None)), RegionChannel::Control)?[4..].to_vec();
    mark[5] = 31;
    assert_rejected(
        &prefixed(mark)?,
        RegionChannel::Control,
        "marks network width",
    )?;

    let forward = RegionFrame::Forward(RegionForward {
        forward_id: 1,
        source_owner: RegionOwner {
            network_id: [0x20; 32],
            identity: [0x30; 32],
        },
        datagram: vec![0; 37],
    });
    let mut forward = round_trip(&forward, RegionChannel::Data)?[4..].to_vec();
    forward[7] = 31;
    assert_rejected(
        &prefixed(forward)?,
        RegionChannel::Data,
        "forward owner width",
    )?;

    let mut invalid_carrier = round_trip(
        &RegionFrame::Present(presence(RegionCarrier::Udp)),
        RegionChannel::Control,
    )?[4..]
        .to_vec();
    invalid_carrier[91] = 2;
    assert_rejected(
        &prefixed(invalid_carrier)?,
        RegionChannel::Control,
        "carrier range",
    )?;

    let mut invalid_reason = round_trip(&gone_frame, RegionChannel::Control)?[4..].to_vec();
    invalid_reason[91] = 4;
    assert_rejected(
        &prefixed(invalid_reason)?,
        RegionChannel::Control,
        "gone reason range",
    )?;

    let miss = RegionFrame::Miss(RegionMiss {
        data_conn_gen: 1,
        forward_id: 2,
        status: RegionMissStatus::NoEligibleDestination,
    });
    let mut invalid_status = round_trip(&miss, RegionChannel::Control)?[4..].to_vec();
    invalid_status[6] = 0;
    assert_rejected(
        &prefixed(invalid_status)?,
        RegionChannel::Control,
        "miss status range",
    )?;

    let mut invalid_hello_channel =
        round_trip(&hello(RegionChannel::Control), RegionChannel::Control)?[4..].to_vec();
    invalid_hello_channel[14] = 2;
    assert_rejected(
        &prefixed(invalid_hello_channel)?,
        RegionChannel::Control,
        "hello channel range",
    )?;

    let mut zero_member =
        round_trip(&hello(RegionChannel::Control), RegionChannel::Control)?[4..].to_vec();
    zero_member[12] = 0;
    assert_rejected(
        &prefixed(zero_member)?,
        RegionChannel::Control,
        "zero member",
    )?;

    let mut excessive_member =
        round_trip(&hello(RegionChannel::Control), RegionChannel::Control)?[4..].to_vec();
    excessive_member[12] = 17;
    assert_rejected(
        &prefixed(excessive_member)?,
        RegionChannel::Control,
        "excessive member",
    )?;

    let mut uppercase_region =
        round_trip(&hello(RegionChannel::Control), RegionChannel::Control)?[4..].to_vec();
    uppercase_region[5] = b'R';
    assert_rejected(
        &prefixed(uppercase_region)?,
        RegionChannel::Control,
        "noncanonical region name",
    )?;
    Ok(())
}

#[test]
fn prefix_rejection_happens_without_a_body() -> Result<(), String> {
    if decode_region_frame_prefix([0, 0, 0, 0]) != Err(RegionDecodeError::InvalidPrefix) {
        return Err("zero prefix was accepted".to_owned());
    }
    if decode_region_frame_prefix([0, 0, 0x10, 1]) != Err(RegionDecodeError::InvalidPrefix) {
        return Err("over-limit prefix was accepted".to_owned());
    }
    if RegionFrame::decode(&[0, 0, 0, 0], RegionChannel::Control)
        != Err(RegionDecodeError::InvalidPrefix)
        || RegionFrame::decode(&[0, 0, 0x10, 1], RegionChannel::Control)
            != Err(RegionDecodeError::InvalidPrefix)
    {
        return Err("invalid prefix required a body before rejection".to_owned());
    }
    Ok(())
}

#[test]
fn channel_contract_rejects_wrong_channels_and_exposes_post_hello_rules() -> Result<(), String> {
    if CONTROL_REGION_FRAME_TYPES.len() != 9
        || !CONTROL_REGION_FRAME_TYPES.contains(&RegionFrameType::Settled)
        || DATA_REGION_FRAME_TYPES.len() != 2
        || DATA_POST_HELLO_REGION_FRAME_TYPES != [RegionFrameType::Forward]
    {
        return Err("declared region channel inventories changed".to_owned());
    }
    for frame_type in [
        RegionFrameType::Hello,
        RegionFrameType::Snapshot,
        RegionFrameType::Present,
        RegionFrameType::Gone,
        RegionFrameType::Marks,
        RegionFrameType::Forward,
        RegionFrameType::Miss,
        RegionFrameType::Ping,
        RegionFrameType::Pong,
        RegionFrameType::Settled,
    ] {
        let control_post_hello = matches!(
            frame_type,
            RegionFrameType::Snapshot
                | RegionFrameType::Present
                | RegionFrameType::Gone
                | RegionFrameType::Marks
                | RegionFrameType::Miss
                | RegionFrameType::Ping
                | RegionFrameType::Pong
                | RegionFrameType::Settled
        );
        if frame_type.is_legal_on(RegionChannel::Control)
            != (frame_type != RegionFrameType::Forward)
            || frame_type.is_legal_on(RegionChannel::Data)
                != matches!(
                    frame_type,
                    RegionFrameType::Hello | RegionFrameType::Forward
                )
            || frame_type.is_legal_after_hello_on(RegionChannel::Control) != control_post_hello
            || frame_type.is_legal_after_hello_on(RegionChannel::Data)
                != (frame_type == RegionFrameType::Forward)
        {
            return Err("region channel typing drifted".to_owned());
        }
    }
    let forward = RegionFrame::Forward(RegionForward {
        forward_id: 1,
        source_owner: RegionOwner {
            network_id: [0x20; 32],
            identity: [0x30; 32],
        },
        datagram: vec![0; 37],
    });
    let encoded = forward
        .encode(RegionChannel::Data)
        .map_err(|error| format!("{error:?}"))?;
    if forward.encode(RegionChannel::Control).is_ok()
        || RegionFrame::decode(&encoded, RegionChannel::Control)
            != Err(RegionDecodeError::WrongChannel)
    {
        return Err("forward was accepted on the control channel".to_owned());
    }
    let ping = RegionFrame::Ping(RegionPing {
        nonce: 1,
        data_conn_gen: 2,
        consumed_forward_id: 3,
    });
    let encoded = ping
        .encode(RegionChannel::Control)
        .map_err(|error| format!("{error:?}"))?;
    if ping.encode(RegionChannel::Data).is_ok()
        || RegionFrame::decode(&encoded, RegionChannel::Data)
            != Err(RegionDecodeError::WrongChannel)
    {
        return Err("ping was accepted on the data channel".to_owned());
    }
    let settled = RegionFrame::Settled(RegionSettled {
        data_conn_gen: 1,
        settled_forward_id: 2,
    });
    let encoded = settled
        .encode(RegionChannel::Control)
        .map_err(|error| format!("{error:?}"))?;
    if settled.encode(RegionChannel::Data).is_ok()
        || RegionFrame::decode(&encoded, RegionChannel::Data)
            != Err(RegionDecodeError::WrongChannel)
    {
        return Err("settled was accepted on the data channel".to_owned());
    }
    if hello(RegionChannel::Control)
        .encode(RegionChannel::Data)
        .is_ok()
    {
        return Err("HELLO channel mismatch was accepted".to_owned());
    }
    Ok(())
}

#[test]
fn control_hello_is_not_legal_after_handshake() {
    assert!(
        !RegionFrameType::Hello.is_legal_after_hello_on(RegionChannel::Control),
        "HELLO is only legal as the first frame on a control channel"
    );
}

fn capped_snapshot(extra_wide_generations: usize) -> RegionFrame {
    let mut presence_entries = Vec::new();
    for index in 0..35 {
        presence_entries.push(RegionPresence {
            slot: [0x10; 16],
            network_id: [0x20; 32],
            identity: [0x30; 32],
            generation: if index < 31 + extra_wide_generations {
                24
            } else {
                23
            },
            incarnation: u64::MAX,
            carrier: RegionCarrier::Udp,
            boot_epoch: u64::MAX,
            revision: u64::MAX,
        });
    }
    RegionFrame::Snapshot(RegionSnapshot {
        snapshot_id: u64::MAX,
        base_revision: u64::MAX,
        marks_revision: u64::MAX,
        chunk_index: u32::MAX,
        presence_entries,
        mark_entries: Vec::new(),
        more: false,
    })
}

#[test]
fn exact_frame_and_datagram_limits_are_enforced() -> Result<(), String> {
    let at_frame_limit = capped_snapshot(0);
    let encoded = at_frame_limit
        .encode(RegionChannel::Control)
        .map_err(|error| format!("{error:?}"))?;
    if encoded.len() != MAX_REGION_FRAME_BYTES + 4 {
        return Err("frame did not reach the exact size cap".to_owned());
    }
    if capped_snapshot(1).encode(RegionChannel::Control) != Err(RegionEncodeError::FrameTooLarge) {
        return Err("one-byte-over frame was accepted".to_owned());
    }
    let at_datagram_limit = RegionFrame::Forward(RegionForward {
        forward_id: 1,
        source_owner: RegionOwner {
            network_id: [0x20; 32],
            identity: [0x30; 32],
        },
        datagram: vec![0; MAX_REGION_FORWARD_DATAGRAM_BYTES],
    });
    let _ = round_trip(&at_datagram_limit, RegionChannel::Data)?;
    let over_datagram_limit = RegionFrame::Forward(RegionForward {
        forward_id: 1,
        source_owner: RegionOwner {
            network_id: [0x20; 32],
            identity: [0x30; 32],
        },
        datagram: vec![0; MAX_REGION_FORWARD_DATAGRAM_BYTES + 1],
    });
    if over_datagram_limit.encode(RegionChannel::Data) != Err(RegionEncodeError::InvalidFrame) {
        return Err("one-byte-over datagram was accepted".to_owned());
    }
    Ok(())
}

#[test]
fn snapshot_entry_limit_is_checked_before_the_size_limit() -> Result<(), String> {
    let at_entry_limit = RegionFrame::Snapshot(RegionSnapshot {
        snapshot_id: 1,
        base_revision: 2,
        marks_revision: 3,
        chunk_index: 4,
        presence_entries: vec![presence(RegionCarrier::Udp); MAX_REGION_SNAPSHOT_ENTRIES],
        mark_entries: Vec::new(),
        more: false,
    });
    if at_entry_limit.encode(RegionChannel::Control) != Err(RegionEncodeError::FrameTooLarge) {
        return Err("the 256-entry snapshot was not constrained by frame size".to_owned());
    }
    let one_over_entry_limit = RegionFrame::Snapshot(RegionSnapshot {
        snapshot_id: 1,
        base_revision: 2,
        marks_revision: 3,
        chunk_index: 4,
        presence_entries: vec![presence(RegionCarrier::Udp); MAX_REGION_SNAPSHOT_ENTRIES + 1],
        mark_entries: Vec::new(),
        more: false,
    });
    if one_over_entry_limit.encode(RegionChannel::Control) != Err(RegionEncodeError::InvalidFrame) {
        return Err("the 257-entry snapshot was accepted".to_owned());
    }
    Ok(())
}

#[test]
fn invalid_carried_node_datagram_is_not_a_mesh_framing_failure() -> Result<(), String> {
    let frame = RegionFrame::Forward(RegionForward {
        forward_id: 1,
        source_owner: RegionOwner {
            network_id: [0x20; 32],
            identity: [0x30; 32],
        },
        datagram: vec![0; 37],
    });
    let encoded = round_trip(&frame, RegionChannel::Data)?;
    let decoded =
        RegionFrame::decode(&encoded, RegionChannel::Data).map_err(|error| format!("{error:?}"))?;
    let RegionFrame::Forward(forward) = decoded else {
        return Err("forward frame decoded as another type".to_owned());
    };
    if RelayHeader::decode(&forward.datagram).is_ok() {
        return Err("invalid carried node datagram was accepted by the node parser".to_owned());
    }
    Ok(())
}

#[test]
fn sealed_region_frame_vectors_match_the_declared_cases() -> Result<(), String> {
    let text = fs::read_to_string(fixture_root().join("region_frames.vec"))
        .map_err(|error| error.to_string())?;
    let vectors = blocks(&text)?;
    let expected = REGION_FRAME_CASES
        .split(',')
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    let mut actual = BTreeSet::new();
    for vector in vectors {
        let case = field(&vector, "case")?.to_owned();
        if !actual.insert(case.clone()) {
            return Err(format!("duplicate sealed region frame case: {case}"));
        }
        let channel = channel(field(&vector, "channel")?)?;
        match field(&vector, "outcome")? {
            "accept" => {
                let encoded = hex_bytes(field(&vector, "frame")?)?;
                let decoded = RegionFrame::decode(&encoded, channel)
                    .map_err(|error| format!("{case}: {error:?}"))?;
                if frame_type_name(decoded.frame_type()) != field(&vector, "type")? {
                    return Err(format!("sealed region frame type mismatch: {case}"));
                }
            }
            "reject" => {
                let encoded = hex_bytes(field(&vector, "frame")?)?;
                assert_rejected(&encoded, channel, &case)?;
            }
            "generated" => assert_generated_fixture_case(&case, &vector)?,
            _ => return Err(format!("invalid sealed region frame outcome: {case}")),
        }
    }
    if actual != expected {
        return Err("sealed region frame cases differ from the declared inventory".to_owned());
    }
    Ok(())
}
