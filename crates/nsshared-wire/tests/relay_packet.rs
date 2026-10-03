//! Relay packet header and bodies: quick-v2 §8.1-§8.2, §8.4-§8.5 and §12.1.

#![allow(clippy::unwrap_used, reason = "test fixture helpers")]

use ed25519_dalek::SigningKey;
use nsshared_wire::{
    CborError, DataRejection, MAX_RELAY_CONTROL_BYTES, MAX_RELAY_DATA_BODY_BYTES,
    MAX_RELAY_PACKET_BYTES, NodeId, NodeRecord, NodeRecordFields, ObservedAddr, Presence,
    RELAY_SLOT, RELAY_WSS_PATH, RELAY_WSS_SUBPROTOCOL, Reflect, Reflected, Register, Registered,
    RelayBody, RelayHeader, RelayId, RelayPacket, RelayPacketError, RelayType, Revoke,
    RevokeReason, SignerMismatch, Status, StatusCode, accept_relayed_data, is_handshake_initiation,
};
use proptest::prelude::*;
use sha2::{Digest, Sha256};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const NODE: NodeId = NodeId::from_bytes([7; 12]);
const PEER: NodeId = NodeId::from_bytes([9; 12]);

fn signer(label: &[u8]) -> SigningKey {
    SigningKey::from_bytes(&Sha256::digest(label).into())
}

fn relay_id() -> RelayId {
    RelayId::parse("hkg-a1.relay.ns.io:51822").unwrap()
}

fn record(signer: &SigningKey) -> NodeRecord {
    NodeRecord::sign(
        signer,
        NodeRecordFields {
            wg_key: [5; 32],
            generation: 3,
            issued_at: 1_767_225_600,
            expires: 1_767_830_400,
            relays: vec![relay_id()],
        },
    )
    .unwrap()
}

/// `NSR2 ‖ type ‖ src ‖ dst ‖ body`, built without the library.
fn raw(packet_type: u8, src: NodeId, dst: NodeId, body: &[u8]) -> Vec<u8> {
    let mut output = b"NSR2".to_vec();
    output.push(packet_type);
    output.extend_from_slice(src.as_bytes());
    output.extend_from_slice(dst.as_bytes());
    output.extend_from_slice(body);
    output
}

fn decode_err(packet: &[u8]) -> RelayPacketError {
    RelayPacket::decode(packet).unwrap_err()
}

fn presence() -> RelayPacket {
    RelayPacket {
        src: NODE,
        dst: RELAY_SLOT,
        body: RelayBody::Presence(Presence {
            incarnation: 7,
            seq: 1,
            mac: [3; 32],
        }),
    }
}

fn reflected(port: u16) -> RelayPacket {
    RelayPacket {
        src: RELAY_SLOT,
        dst: NODE,
        body: RelayBody::Reflected(Reflected {
            incarnation: 1,
            seq: 1,
            nonce: [4; 16],
            observed_addr: ObservedAddr {
                ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
                port,
            },
            mac: [0; 32],
        }),
    }
}

fn registered(ttl: u32, ack_seq: u64, capabilities: &[&str]) -> RelayPacket {
    RelayPacket {
        src: RELAY_SLOT,
        dst: NODE,
        body: RelayBody::Registered(Registered {
            incarnation: 1,
            relay_ephemeral: [8; 32],
            presence_ttl_s: ttl,
            observed_addr: None,
            ack_seq,
            capabilities: capabilities.iter().map(|text| (*text).to_owned()).collect(),
            mac: [0; 32],
        }),
    }
}

/// `[incarnation, seq, mac]` for a PRESENCE body with a one-byte incarnation and seq.
fn presence_body() -> Vec<u8> {
    let mut body = vec![0x83, 0x07, 0x01, 0x58, 0x20];
    body.extend_from_slice(&[3; 32]);
    body
}

#[test]
fn presence_encodes_to_the_spec_layout() {
    let encoded = presence().encode().unwrap();
    assert_eq!(encoded, raw(3, NODE, RELAY_SLOT, &presence_body()));
    assert_eq!(RelayPacket::decode(&encoded).unwrap(), presence());
    assert_eq!(
        RelayHeader::parse(&encoded).unwrap(),
        RelayHeader {
            packet_type: RelayType::Presence,
            src: NODE,
            dst: RELAY_SLOT
        }
    );
}

#[test]
fn transport_constants_match_the_spec() {
    assert_eq!(RELAY_WSS_PATH, "/ns/v2");
    assert_eq!(RELAY_WSS_SUBPROTOCOL, "ns-relay-v2");
}

#[test]
fn size_limits_accept_their_edges() {
    let data = RelayPacket {
        src: NODE,
        dst: PEER,
        body: RelayBody::Data(vec![1; MAX_RELAY_DATA_BODY_BYTES]),
    };
    let encoded = data.encode().unwrap();
    assert_eq!(encoded.len(), MAX_RELAY_PACKET_BYTES);
    assert_eq!(RelayPacket::decode(&encoded).unwrap(), data);
    let one = RelayPacket {
        body: RelayBody::Data(vec![4]),
        ..data
    };
    assert_eq!(RelayPacket::decode(&one.encode().unwrap()).unwrap(), one);
}

#[test]
fn handshake_initiation_is_judged_by_the_first_byte() {
    assert!(is_handshake_initiation(&[1, 0, 0, 0]));
    assert!(is_handshake_initiation(&[1]));
    assert!(!is_handshake_initiation(&[2, 0, 0, 0]));
    assert!(!is_handshake_initiation(&[4]));
    assert!(!is_handshake_initiation(&[]));
}

#[test]
fn relayed_data_is_accepted_for_own_destination_and_installed_source() {
    let packet = RelayPacket {
        src: PEER,
        dst: NODE,
        body: RelayBody::Data(vec![4, 0, 0, 0, 9]),
    };
    let data = accept_relayed_data(&packet, &NODE, |src| *src == PEER).unwrap();
    assert_eq!(data, [4, 0, 0, 0, 9]);
}

#[test]
fn refutation_relayed_data_checks() {
    let packet = RelayPacket {
        src: PEER,
        dst: NODE,
        body: RelayBody::Data(vec![4]),
    };
    assert_eq!(
        accept_relayed_data(&packet, &PEER, |_| true),
        Err(DataRejection::Destination(NODE))
    );
    assert_eq!(
        accept_relayed_data(&packet, &NODE, |_| false),
        Err(DataRejection::Source(PEER))
    );
    assert_eq!(
        accept_relayed_data(&presence(), &RELAY_SLOT, |_| true),
        Err(DataRejection::NotData(RelayType::Presence))
    );
}

#[test]
fn refutation_short_packet() {
    assert_eq!(decode_err(&[]), RelayPacketError::TooShort(0));
    let header = raw(3, NODE, RELAY_SLOT, &[]);
    assert_eq!(decode_err(&header[..28]), RelayPacketError::TooShort(28));
    assert_eq!(
        RelayHeader::parse(&header[..4]),
        Err(RelayPacketError::TooShort(4))
    );
}

#[test]
fn refutation_bad_magic() {
    let mut packet = presence().encode().unwrap();
    packet[3] = b'1';
    assert_eq!(decode_err(&packet), RelayPacketError::BadMagic);
}

#[test]
fn refutation_unknown_type() {
    for packet_type in [0, 9, 10, 255] {
        let packet = raw(packet_type, NODE, RELAY_SLOT, &presence_body());
        assert_eq!(
            decode_err(&packet),
            RelayPacketError::UnknownType(packet_type)
        );
    }
}

#[test]
fn refutation_direction_to_relay() {
    for packet_type in [1, 3, 4, 8] {
        let expected = RelayPacketError::Direction(RelayType::from_u8(packet_type).unwrap());
        for (src, dst) in [(RELAY_SLOT, RELAY_SLOT), (NODE, PEER), (RELAY_SLOT, NODE)] {
            let packet = raw(packet_type, src, dst, &presence_body());
            assert_eq!(decode_err(&packet), expected);
        }
    }
    let mut packet = presence();
    packet.dst = PEER;
    assert_eq!(
        packet.encode(),
        Err(RelayPacketError::Direction(RelayType::Presence))
    );
}

#[test]
fn refutation_direction_from_relay() {
    for packet_type in [2, 5, 7] {
        let expected = RelayPacketError::Direction(RelayType::from_u8(packet_type).unwrap());
        for (src, dst) in [(RELAY_SLOT, RELAY_SLOT), (NODE, PEER), (NODE, RELAY_SLOT)] {
            let packet = raw(packet_type, src, dst, &[0x80]);
            assert_eq!(decode_err(&packet), expected);
        }
    }
    let mut packet = reflected(1);
    packet.src = PEER;
    assert_eq!(
        packet.encode(),
        Err(RelayPacketError::Direction(RelayType::Reflected))
    );
}

#[test]
fn refutation_direction_data() {
    for (src, dst) in [
        (RELAY_SLOT, RELAY_SLOT),
        (NODE, RELAY_SLOT),
        (RELAY_SLOT, NODE),
    ] {
        let packet = raw(6, src, dst, &[1]);
        assert_eq!(
            decode_err(&packet),
            RelayPacketError::Direction(RelayType::Data)
        );
        let header = RelayHeader {
            packet_type: RelayType::Data,
            src,
            dst,
        };
        assert_eq!(
            header.encode(),
            Err(RelayPacketError::Direction(RelayType::Data))
        );
    }
}

#[test]
fn refutation_oversize_packet() {
    let data = raw(6, NODE, PEER, &[1; MAX_RELAY_DATA_BODY_BYTES + 1]);
    assert_eq!(
        decode_err(&data),
        RelayPacketError::TooLarge {
            length: 2049,
            maximum: 2048
        }
    );
    let control = raw(3, NODE, RELAY_SLOT, &[0; MAX_RELAY_CONTROL_BYTES - 28]);
    assert_eq!(
        decode_err(&control),
        RelayPacketError::TooLarge {
            length: 1201,
            maximum: 1200
        }
    );
    let mut registered = registered(90, 0, &[]);
    if let RelayBody::Registered(body) = &mut registered.body {
        body.capabilities = vec!["c".repeat(1200)];
    }
    assert!(matches!(
        registered.encode(),
        Err(RelayPacketError::TooLarge { maximum: 1200, .. })
    ));
}

#[test]
fn refutation_data_length() {
    assert_eq!(
        decode_err(&raw(6, NODE, PEER, &[])),
        RelayPacketError::DataLength(0)
    );
    for length in [0, MAX_RELAY_DATA_BODY_BYTES + 1] {
        let packet = RelayPacket {
            src: NODE,
            dst: PEER,
            body: RelayBody::Data(vec![1; length]),
        };
        assert_eq!(packet.encode(), Err(RelayPacketError::DataLength(length)));
    }
}

#[test]
fn refutation_non_canonical_body() {
    let mut body = presence_body();
    body.splice(1..2, [0x18, 0x07]);
    assert_eq!(
        decode_err(&raw(3, NODE, RELAY_SLOT, &body)),
        RelayPacketError::Body(CborError::NonShortest)
    );
    let mut body = presence_body();
    body[0] = 0x9f;
    assert_eq!(
        decode_err(&raw(3, NODE, RELAY_SLOT, &body)),
        RelayPacketError::Body(CborError::IndefiniteLength)
    );
    let mut body = presence_body();
    body[0] = 0xa3;
    assert_eq!(
        decode_err(&raw(3, NODE, RELAY_SLOT, &body)),
        RelayPacketError::Body(CborError::Map)
    );
    let mut body = presence_body();
    body.splice(1..2, [0xc0, 0x07]);
    assert_eq!(
        decode_err(&raw(3, NODE, RELAY_SLOT, &body)),
        RelayPacketError::Body(CborError::Tag)
    );
}

#[test]
fn refutation_wrong_arity() {
    let mut body = presence_body();
    body[0] = 0x84;
    body.push(0x00);
    assert_eq!(
        decode_err(&raw(3, NODE, RELAY_SLOT, &body)),
        RelayPacketError::Body(CborError::ArrayLength {
            expected: 3,
            actual: 4
        })
    );
    let mut body = presence_body();
    body[0] = 0x82;
    assert_eq!(
        decode_err(&raw(3, NODE, RELAY_SLOT, &body)),
        RelayPacketError::Body(CborError::ArrayLength {
            expected: 3,
            actual: 2
        })
    );
}

#[test]
fn refutation_trailing_bytes() {
    let mut packet = presence().encode().unwrap();
    packet.push(0x00);
    assert_eq!(
        decode_err(&packet),
        RelayPacketError::Body(CborError::TrailingBytes)
    );
}

#[test]
fn refutation_wrong_width() {
    // REFLECT nonce of 15 bytes.
    let mut body = vec![0x84, 0x01, 0x01, 0x4f];
    body.extend_from_slice(&[0; 15]);
    body.extend_from_slice(&[0x58, 0x20]);
    body.extend_from_slice(&[0; 32]);
    assert_eq!(
        decode_err(&raw(4, NODE, RELAY_SLOT, &body)),
        RelayPacketError::Body(CborError::StringLength {
            expected: 16,
            actual: 15
        })
    );
    // PRESENCE mac of 31 bytes.
    let mut body = vec![0x83, 0x07, 0x01, 0x58, 0x1f];
    body.extend_from_slice(&[0; 31]);
    assert_eq!(
        decode_err(&raw(3, NODE, RELAY_SLOT, &body)),
        RelayPacketError::Body(CborError::StringLength {
            expected: 32,
            actual: 31
        })
    );
    // STATUS type_in above u8 and a text destination.
    let mut body = vec![0x83, 0x19, 0x01, 0x00, 0x4c];
    body.extend_from_slice(&[7; 12]);
    body.push(0x01);
    assert_eq!(
        decode_err(&raw(7, RELAY_SLOT, NODE, &body)),
        RelayPacketError::TypeIn(256)
    );
    let mut body = vec![0x83, 0x03, 0x6c];
    body.extend_from_slice(&[b'a'; 12]);
    body.push(0x01);
    assert_eq!(
        decode_err(&raw(7, RELAY_SLOT, NODE, &body)),
        RelayPacketError::Body(CborError::UnexpectedType)
    );
}

#[test]
fn refutation_presence_ttl() {
    for ttl in [0, 29, 3601, u32::MAX] {
        assert_eq!(
            registered(ttl, 0, &[]).encode(),
            Err(RelayPacketError::PresenceTtl(u64::from(ttl)))
        );
    }
    for ttl in [30, 3600] {
        let packet = registered(ttl, 0, &[]);
        assert_eq!(
            RelayPacket::decode(&packet.encode().unwrap()).unwrap(),
            packet
        );
    }
    // presence_ttl_s 29 and 2^32 on the wire.
    let encoded = registered(30, 0, &[]).encode().unwrap();
    let position = encoded.iter().position(|byte| *byte == 0x18).unwrap();
    let mut low = encoded.clone();
    low[position + 1] = 29;
    assert_eq!(decode_err(&low), RelayPacketError::PresenceTtl(29));
    let mut low = encoded.clone();
    low.splice(position..position + 2, [0x17]);
    assert_eq!(decode_err(&low), RelayPacketError::PresenceTtl(23));
    let mut high = encoded;
    high.splice(position..position + 2, [0x1b, 0, 0, 0, 1, 0, 0, 0, 0]);
    assert_eq!(decode_err(&high), RelayPacketError::PresenceTtl(1 << 32));
}

#[test]
fn refutation_capabilities_with_ack_seq() {
    let provisional = registered(90, 0, &["relay-v2"]);
    let encoded = provisional.encode().unwrap();
    assert_eq!(RelayPacket::decode(&encoded).unwrap(), provisional);
    assert_eq!(
        registered(90, 5, &["relay-v2"]).encode(),
        Err(RelayPacketError::CapabilitiesNotProvisional(5))
    );
    // Same body with ack_seq 0 rewritten to 5 on the wire.
    let plain = registered(90, 0, &[]).encode().unwrap();
    let mut wire = encoded;
    let position = plain.len() - 36;
    assert_eq!(wire[position], 0x00);
    wire[position] = 0x05;
    assert_eq!(
        decode_err(&wire),
        RelayPacketError::CapabilitiesNotProvisional(5)
    );
}

#[test]
fn refutation_status_code() {
    for (code, valid) in [(0, false), (1, true), (6, true), (7, false), (255, false)] {
        let mut body = vec![0x83, 0x03, 0x4c];
        body.extend_from_slice(&[7; 12]);
        body.extend_from_slice(&if code < 24 {
            vec![code]
        } else {
            vec![0x18, code]
        });
        let result = RelayPacket::decode(&raw(7, RELAY_SLOT, NODE, &body));
        if valid {
            assert!(result.is_ok());
        } else {
            assert_eq!(result, Err(RelayPacketError::StatusCode(u64::from(code))));
        }
    }
}

#[test]
fn refutation_revoke_reason() {
    for reason in [2, 23] {
        let mut body = vec![0x84, 0x01, 0x01, reason, 0x58, 0x20];
        body.extend_from_slice(&[0; 32]);
        assert_eq!(
            decode_err(&raw(8, NODE, RELAY_SLOT, &body)),
            RelayPacketError::RevokeReason(u64::from(reason))
        );
    }
}

#[test]
fn refutation_observed_port() {
    assert_eq!(
        reflected(0).encode(),
        Err(RelayPacketError::ObservedPort(0))
    );
    let encoded = reflected(9).encode().unwrap();
    let position = encoded.iter().rposition(|byte| *byte == 0x09).unwrap();
    let mut zero = encoded.clone();
    zero[position] = 0x00;
    assert_eq!(decode_err(&zero), RelayPacketError::ObservedPort(0));
    let mut large = encoded;
    large.splice(position..=position, [0x1a, 0, 1, 0, 0]);
    assert_eq!(decode_err(&large), RelayPacketError::ObservedPort(65_536));
}

#[test]
fn refutation_observed_ip_length() {
    let encoded = reflected(9).encode().unwrap();
    let position = encoded.iter().position(|byte| *byte == 0x44).unwrap();
    let mut five = encoded;
    five.splice(position..=position, [0x45, 0]);
    assert_eq!(decode_err(&five), RelayPacketError::ObservedIp(5));
}

#[test]
fn refutation_reflected_observed_addr_required() {
    let encoded = reflected(9).encode().unwrap();
    let start = encoded.iter().position(|byte| *byte == 0x82).unwrap();
    let mut wire = encoded;
    wire.splice(start..start + 7, [0xf6]);
    assert_eq!(
        decode_err(&wire),
        RelayPacketError::Body(CborError::UnexpectedType)
    );
}

#[test]
fn refutation_zero_seq() {
    let mut body = presence_body();
    body[2] = 0x00;
    assert_eq!(
        decode_err(&raw(3, NODE, RELAY_SLOT, &body)),
        RelayPacketError::ZeroSeq
    );
    let packet = RelayPacket {
        src: NODE,
        dst: RELAY_SLOT,
        body: RelayBody::Revoke(Revoke {
            incarnation: 1,
            seq: 0,
            reason: RevokeReason::Close,
            mac: [0; 32],
        }),
    };
    assert_eq!(packet.encode(), Err(RelayPacketError::ZeroSeq));
}

#[test]
fn refutation_register_relay_name_length() {
    let record = record(&signer(b"node"));
    for name in [String::new(), "a".repeat(256)] {
        assert_eq!(
            Register::from_parts(record.as_bytes(), 1, 1, [0; 32], &name, [0; 64]),
            Err(RelayPacketError::RelayNameLength(name.len()))
        );
    }
}

#[test]
fn refutation_register_record_shape() {
    let record = record(&signer(b"node"));
    let mut version = record.as_bytes().to_vec();
    version[1] = 0x01;
    assert_eq!(
        Register::from_parts(&version, 1, 1, [0; 32], "r:1", [0; 64]),
        Err(RelayPacketError::RecordVersion(1))
    );
    let mut wrapped = vec![0x58, u8::try_from(record.as_bytes().len()).unwrap()];
    wrapped.extend_from_slice(record.as_bytes());
    assert_eq!(
        Register::from_parts(&wrapped, 1, 1, [0; 32], "r:1", [0; 64]),
        Err(RelayPacketError::Body(CborError::UnexpectedType))
    );
    let mut trailing = record.as_bytes().to_vec();
    trailing.push(0);
    assert_eq!(
        Register::from_parts(&trailing, 1, 1, [0; 32], "r:1", [0; 64]),
        Err(RelayPacketError::Body(CborError::TrailingBytes))
    );
}

#[test]
fn refutation_register_signer_mismatch() {
    let record = record(&signer(b"node"));
    assert_eq!(
        Register::sign(&signer(b"other"), &record, 1, 1, [0; 32], &relay_id()),
        Err(SignerMismatch)
    );
}

fn nonzero_slot() -> impl Strategy<Value = NodeId> {
    any::<[u8; 12]>()
        .prop_filter("non-zero slot", |bytes| bytes.iter().any(|byte| *byte != 0))
        .prop_map(NodeId::from_bytes)
}

fn arb_observed() -> impl Strategy<Value = ObservedAddr> {
    let ip = prop_oneof![
        any::<[u8; 4]>().prop_map(|octets| IpAddr::V4(Ipv4Addr::from(octets))),
        any::<[u8; 16]>().prop_map(|octets| IpAddr::V6(Ipv6Addr::from(octets))),
    ];
    (ip, 1..=u16::MAX).prop_map(|(ip, port)| ObservedAddr { ip, port })
}

fn arb_registered() -> impl Strategy<Value = Registered> {
    (
        any::<u64>(),
        any::<[u8; 32]>(),
        30..=3600_u32,
        proptest::option::of(arb_observed()),
        prop_oneof![Just(0_u64), any::<u64>()],
        prop::collection::vec("[a-z0-9-]{0,12}", 0..4),
        any::<[u8; 32]>(),
    )
        .prop_map(
            |(incarnation, relay_ephemeral, ttl, observed_addr, ack_seq, capabilities, mac)| {
                Registered {
                    incarnation,
                    relay_ephemeral,
                    presence_ttl_s: ttl,
                    observed_addr,
                    ack_seq,
                    capabilities: if ack_seq == 0 {
                        capabilities
                    } else {
                        Vec::new()
                    },
                    mac,
                }
            },
        )
}

fn arb_status() -> impl Strategy<Value = Status> {
    (any::<u8>(), any::<[u8; 12]>(), 1..=6_u64).prop_map(|(type_in, destination, status)| Status {
        type_in,
        destination: NodeId::from_bytes(destination),
        status: StatusCode::from_u64(status).unwrap(),
    })
}

fn arb_register() -> impl Strategy<Value = Register> {
    (
        any::<u64>(),
        any::<u64>(),
        any::<[u8; 32]>(),
        prop_oneof![
            Just("hkg-a1.relay.ns.io:51822"),
            Just("203.0.113.7:443"),
            Just("[2001:db8::1]:51822"),
        ],
    )
        .prop_map(|(incarnation, ts, node_ephemeral, name)| {
            let signer = signer(b"node");
            let record = record(&signer);
            let name = RelayId::parse(name).unwrap();
            Register::sign(&signer, &record, incarnation, ts, node_ephemeral, &name).unwrap()
        })
}

fn arb_body() -> impl Strategy<Value = RelayBody> {
    prop_oneof![
        arb_register().prop_map(RelayBody::Register),
        arb_registered().prop_map(RelayBody::Registered),
        (any::<u64>(), 1..=u64::MAX, any::<[u8; 32]>()).prop_map(|(incarnation, seq, mac)| {
            RelayBody::Presence(Presence {
                incarnation,
                seq,
                mac,
            })
        }),
        (
            any::<u64>(),
            1..=u64::MAX,
            any::<[u8; 16]>(),
            any::<[u8; 32]>()
        )
            .prop_map(
                |(incarnation, seq, nonce, mac)| RelayBody::Reflect(Reflect {
                    incarnation,
                    seq,
                    nonce,
                    mac,
                })
            ),
        (
            any::<u64>(),
            1..=u64::MAX,
            any::<[u8; 16]>(),
            arb_observed(),
            any::<[u8; 32]>()
        )
            .prop_map(|(incarnation, seq, nonce, observed_addr, mac)| {
                RelayBody::Reflected(Reflected {
                    incarnation,
                    seq,
                    nonce,
                    observed_addr,
                    mac,
                })
            }),
        prop::collection::vec(any::<u8>(), 1..=MAX_RELAY_DATA_BODY_BYTES).prop_map(RelayBody::Data),
        arb_status().prop_map(RelayBody::Status),
        (any::<u64>(), 1..=u64::MAX, any::<bool>(), any::<[u8; 32]>()).prop_map(
            |(incarnation, seq, close, mac)| RelayBody::Revoke(Revoke {
                incarnation,
                seq,
                reason: if close {
                    RevokeReason::Close
                } else {
                    RevokeReason::Rotation
                },
                mac,
            })
        ),
    ]
}

fn arb_packet() -> impl Strategy<Value = RelayPacket> {
    (arb_body(), nonzero_slot(), nonzero_slot()).prop_map(|(body, node, peer)| {
        let (src, dst) = match body.packet_type() {
            RelayType::Registered | RelayType::Reflected | RelayType::Status => (RELAY_SLOT, node),
            RelayType::Data => (node, peer),
            RelayType::Register => match &body {
                RelayBody::Register(register) => (register.node_id(), RELAY_SLOT),
                _ => (node, RELAY_SLOT),
            },
            RelayType::Presence | RelayType::Reflect | RelayType::Revoke => (node, RELAY_SLOT),
        };
        RelayPacket { src, dst, body }
    })
}

fn arb_header() -> impl Strategy<Value = RelayHeader> {
    (1..=8_u8, nonzero_slot(), nonzero_slot()).prop_map(|(packet_type, node, peer)| {
        let packet_type = RelayType::from_u8(packet_type).unwrap();
        let (src, dst) = match packet_type.direction() {
            nsshared_wire::RelayDirection::ToRelay => (node, RELAY_SLOT),
            nsshared_wire::RelayDirection::FromRelay => (RELAY_SLOT, node),
            nsshared_wire::RelayDirection::NodeToNode => (node, peer),
        };
        RelayHeader {
            packet_type,
            src,
            dst,
        }
    })
}

proptest! {
    #[test]
    fn header_round_trips(header in arb_header()) {
        let encoded = header.encode().unwrap();
        prop_assert_eq!(&encoded[..4], b"NSR2");
        prop_assert_eq!(encoded[4], header.packet_type.as_u8());
        prop_assert_eq!(RelayHeader::parse(&encoded).unwrap(), header);
    }

    #[test]
    fn packets_round_trip(packet in arb_packet()) {
        let encoded = packet.encode().unwrap();
        prop_assert!(encoded.len() <= packet.body.packet_type().max_packet_bytes());
        prop_assert_eq!(RelayHeader::parse(&encoded).unwrap(), packet.header());
        prop_assert_eq!(RelayPacket::decode(&encoded).unwrap(), packet);
    }

    #[test]
    fn decode_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..1300)) {
        let _ = RelayPacket::decode(&bytes);
    }

    #[test]
    fn truncated_packets_are_rejected(packet in arb_packet(), cut in 1_usize..64) {
        let encoded = packet.encode().unwrap();
        if !matches!(packet.body, RelayBody::Data(_)) {
            let length = encoded.len().saturating_sub(cut);
            prop_assert!(RelayPacket::decode(&encoded[..length]).is_err());
        }
    }
}
