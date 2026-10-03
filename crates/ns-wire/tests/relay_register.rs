//! REGISTER signing, §8.3 rule 1, session key and relay MACs: quick-v2 §8.3 and §12.2.

#![allow(clippy::unwrap_used, reason = "test fixture helpers")]

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use ns_wire::{
    BadRegisterSignature, NodeId, NodeRecord, NodeRecordError, NodeRecordFields, ObservedAddr,
    Presence, RELAY_SLOT, RecordDecision, RecordExpired, RecordMarks, Reflect, Reflected, Register,
    RegisterCandidate, RegisterRejection, Registered, RelayBody, RelayId, RelayMacError,
    RelayPacket, RelayPacketError, RelayType, Revoke, RevokeReason, SessionKey, Status, StatusCode,
    ZeroSharedSecret, check_register, derive_session_key, ephemeral_public,
};
use sha2::{Digest, Sha256};
use std::net::{IpAddr, Ipv6Addr};
use x25519_dalek::{PublicKey, StaticSecret};

const NOW: u64 = 1_767_225_700;
const ISSUED_AT: u64 = 1_767_225_600;
const EXPIRES: u64 = 1_767_830_400;
const INCARNATION: u64 = 7;

fn sha256(label: &[u8]) -> [u8; 32] {
    Sha256::digest(label).into()
}

/// The §2.3 demo identity: seed `SHA-256("ns-demo-node-v2")`.
fn demo_signer() -> SigningKey {
    SigningKey::from_bytes(&sha256(b"ns-demo-node-v2"))
}

fn node_secret() -> [u8; 32] {
    sha256(b"ns-test-node-ephemeral")
}

fn relay_secret() -> [u8; 32] {
    sha256(b"ns-test-relay-ephemeral")
}

fn x25519_public(secret: [u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(secret)).to_bytes()
}

fn relay_id() -> RelayId {
    RelayId::parse("hkg-a1.relay.ns.io:51822").unwrap()
}

fn record_with(signer: &SigningKey, generation: u64, key: u8, issued_at: u64) -> NodeRecord {
    NodeRecord::sign(
        signer,
        NodeRecordFields {
            wg_key: [key; 32],
            generation,
            issued_at,
            // Keep the seven-day service period of the demo record (quick-v2 §3.2).
            expires: issued_at + (EXPIRES - ISSUED_AT),
            relays: vec![relay_id()],
        },
    )
    .unwrap()
}

fn demo_record() -> NodeRecord {
    record_with(&demo_signer(), 3, 5, ISSUED_AT)
}

fn register_at(record: &NodeRecord, ts: u64) -> Register {
    Register::sign(
        &demo_signer(),
        record,
        INCARNATION,
        ts,
        x25519_public(node_secret()),
        &relay_id(),
    )
    .unwrap()
}

fn packet_of(register: Register) -> Vec<u8> {
    RelayPacket {
        src: register.node_id(),
        dst: RELAY_SLOT,
        body: RelayBody::Register(register),
    }
    .encode()
    .unwrap()
}

fn demo_packet() -> Vec<u8> {
    packet_of(register_at(&demo_record(), NOW))
}

fn fresh_marks() -> RecordMarks {
    RecordMarks::new(demo_signer().verifying_key().to_bytes())
}

fn rejection(packet: &[u8]) -> RegisterRejection {
    check_register(packet, &relay_id(), NOW, &fresh_marks()).unwrap_err()
}

/// Flips a bit in the trailing REGISTER signature.
fn with_bad_signature(mut packet: Vec<u8>) -> Vec<u8> {
    let last = packet.len() - 1;
    packet[last] ^= 1;
    packet
}

// Minimal canonical CBOR writer, independent of the library.
fn head(major: u8, value: u64) -> Vec<u8> {
    let major = major << 5;
    match value {
        0..=23 => vec![major | value as u8],
        24..=0xff => vec![major | 24, value as u8],
        0x100..=0xffff => [&[major | 25][..], &(value as u16).to_be_bytes()].concat(),
        0x1_0000..=0xffff_ffff => [&[major | 26][..], &(value as u32).to_be_bytes()].concat(),
        _ => [&[major | 27][..], &value.to_be_bytes()].concat(),
    }
}

fn uint(value: u64) -> Vec<u8> {
    head(0, value)
}

fn bytes(value: &[u8]) -> Vec<u8> {
    [head(2, value.len() as u64), value.to_vec()].concat()
}

fn text(value: &str) -> Vec<u8> {
    [head(3, value.len() as u64), value.as_bytes().to_vec()].concat()
}

/// The five unsigned REGISTER fields with the record nested as an array.
fn unsigned_register(record: &[u8], ts: u64, name: &str) -> Vec<u8> {
    [
        vec![0x85],
        record.to_vec(),
        uint(INCARNATION),
        uint(ts),
        bytes(&x25519_public(node_secret())),
        text(name),
    ]
    .concat()
}

/// A REGISTER over arbitrary record bytes, signed by the demo identity in the test.
fn hand_signed_packet(record: &[u8], ts: u64) -> Vec<u8> {
    let unsigned = unsigned_register(record, ts, relay_id().as_str());
    let message = [b"ns/relay-register/v2".to_vec(), unsigned].concat();
    let signature = demo_signer().sign(&message).to_bytes();
    let register = Register::from_parts(
        record,
        INCARNATION,
        ts,
        x25519_public(node_secret()),
        relay_id().as_str(),
        signature,
    )
    .unwrap();
    packet_of(register)
}

fn hmac(key: &[u8; 32], message: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).unwrap();
    mac.update(message);
    mac.finalize().into_bytes().into()
}

#[test]
fn known_answer_register_session_key_and_presence_mac() {
    let signer = demo_signer();
    let identity = signer.verifying_key().to_bytes();
    let record = demo_record();
    let node_ephemeral = x25519_public(node_secret());
    let relay_ephemeral = x25519_public(relay_secret());
    assert_eq!(ephemeral_public(&node_secret()), node_ephemeral);
    let register = register_at(&record, NOW);
    let src = NodeId::derive(&identity);
    assert_eq!(src.to_string(), "5kemem6slxrgyd63rcqa");

    // REGISTER layout and signature, from the spec formula.
    let unsigned = unsigned_register(record.as_bytes(), NOW, "hkg-a1.relay.ns.io:51822");
    let message = [b"ns/relay-register/v2".to_vec(), unsigned.clone()].concat();
    let signature = Signature::from_bytes(register.signature());
    VerifyingKey::from_bytes(&identity)
        .unwrap()
        .verify_strict(&message, &signature)
        .unwrap();
    let mut body = unsigned;
    body[0] = 0x86;
    body.extend_from_slice(&bytes(register.signature()));
    assert_eq!(register.encode(), body);
    let reg_hash = sha256(&body);
    assert_eq!(register.reg_hash(), reg_hash);

    // Rule 1 accepts it and reports the same reg_hash.
    let packet = packet_of(register.clone());
    assert_eq!(packet[..5], *b"NSR2\x01");
    assert_eq!(packet[5..17], *src.as_bytes());
    assert_eq!(packet[17..29], [0; 12]);
    assert_eq!(packet[29..], body);
    let verified = check_register(&packet, &relay_id(), NOW, &fresh_marks()).unwrap();
    assert_eq!(verified.reg_hash(), &reg_hash);
    assert_eq!(verified.src(), src);
    assert_eq!(verified.record(), &record);
    assert_eq!(verified.register(), &register);
    assert_eq!(verified.decision(), RecordDecision::Advanced);

    // sk = HKDF-SHA256(no salt, X25519, info), from the spec formula.
    let shared =
        StaticSecret::from(node_secret()).diffie_hellman(&PublicKey::from(relay_ephemeral));
    let info = [
        b"ns/relay-session/v2".as_slice(),
        src.as_bytes(),
        &INCARNATION.to_be_bytes(),
        &node_ephemeral,
        &relay_ephemeral,
        &reg_hash,
    ]
    .concat();
    let mut expected_sk = [0; 32];
    Hkdf::<Sha256>::new(None, shared.as_bytes())
        .expand(&info, &mut expected_sk)
        .unwrap();
    let node_sk = register
        .node_session_key(&node_secret(), &relay_ephemeral)
        .unwrap();
    let relay_sk = verified.relay_session_key(&relay_secret()).unwrap();
    assert_eq!(node_sk.as_bytes(), &expected_sk);
    assert_eq!(relay_sk, node_sk);

    // PRESENCE MAC = HMAC-SHA256(sk, "ns/relay-ctl/v2" ‖ CBOR([magic, 3, src, dst, [inc, seq]])).
    let transcript = [
        vec![0x85],
        bytes(b"NSR2"),
        uint(3),
        bytes(src.as_bytes()),
        bytes(&[0; 12]),
        vec![0x82],
        uint(INCARNATION),
        uint(1),
    ]
    .concat();
    let expected_mac = hmac(
        &expected_sk,
        &[b"ns/relay-ctl/v2".to_vec(), transcript].concat(),
    );
    let mut presence = RelayPacket {
        src,
        dst: RELAY_SLOT,
        body: RelayBody::Presence(Presence {
            incarnation: INCARNATION,
            seq: 1,
            mac: [0; 32],
        }),
    };
    presence.seal(&node_sk).unwrap();
    assert_eq!(
        presence.body,
        RelayBody::Presence(Presence {
            incarnation: INCARNATION,
            seq: 1,
            mac: expected_mac,
        })
    );
    let decoded = RelayPacket::decode(&presence.encode().unwrap()).unwrap();
    assert_eq!(decoded.verify_mac(&relay_sk), Ok(()));
}

#[test]
fn registered_mac_uses_the_reply_context() {
    let src = NodeId::derive(&demo_signer().verifying_key().to_bytes());
    let key = SessionKey::from_bytes(sha256(b"ns-test-sk"));
    let relay_ephemeral = x25519_public(relay_secret());
    let mut packet = RelayPacket {
        src: RELAY_SLOT,
        dst: src,
        body: RelayBody::Registered(Registered {
            incarnation: INCARNATION,
            relay_ephemeral,
            presence_ttl_s: 90,
            observed_addr: None,
            ack_seq: 0,
            capabilities: vec!["relay".to_owned()],
            mac: [0; 32],
        }),
    };
    packet.seal(&key).unwrap();
    let transcript = [
        vec![0x85],
        bytes(b"NSR2"),
        uint(2),
        bytes(&[0; 12]),
        bytes(src.as_bytes()),
        vec![0x86],
        uint(INCARNATION),
        bytes(&relay_ephemeral),
        uint(90),
        vec![0xf6],
        uint(0),
        vec![0x81],
        text("relay"),
    ]
    .concat();
    let expected = hmac(
        key.as_bytes(),
        &[b"ns/relay-reply/v2".to_vec(), transcript].concat(),
    );
    let RelayBody::Registered(body) = &packet.body else {
        unreachable!()
    };
    assert_eq!(body.mac, expected);
    assert_eq!(packet.verify_mac(&key), Ok(()));
}

fn mac_packets(src: NodeId) -> Vec<RelayPacket> {
    let observed = ObservedAddr {
        ip: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        port: 51_820,
    };
    vec![
        RelayPacket {
            src: RELAY_SLOT,
            dst: src,
            body: RelayBody::Registered(Registered {
                incarnation: 1,
                relay_ephemeral: [2; 32],
                presence_ttl_s: 90,
                observed_addr: Some(observed),
                ack_seq: 4,
                capabilities: Vec::new(),
                mac: [0; 32],
            }),
        },
        RelayPacket {
            src,
            dst: RELAY_SLOT,
            body: RelayBody::Presence(Presence {
                incarnation: 1,
                seq: 4,
                mac: [0; 32],
            }),
        },
        RelayPacket {
            src,
            dst: RELAY_SLOT,
            body: RelayBody::Reflect(Reflect {
                incarnation: 1,
                seq: 5,
                nonce: [6; 16],
                mac: [0; 32],
            }),
        },
        RelayPacket {
            src: RELAY_SLOT,
            dst: src,
            body: RelayBody::Reflected(Reflected {
                incarnation: 1,
                seq: 5,
                nonce: [6; 16],
                observed_addr: observed,
                mac: [0; 32],
            }),
        },
        RelayPacket {
            src,
            dst: RELAY_SLOT,
            body: RelayBody::Revoke(Revoke {
                incarnation: 1,
                seq: 6,
                reason: RevokeReason::Rotation,
                mac: [0; 32],
            }),
        },
    ]
}

#[test]
fn refutation_bad_mac_on_each_mac_carrying_type() {
    let src = NodeId::from_bytes([7; 12]);
    let key = SessionKey::from_bytes([1; 32]);
    let other_key = SessionKey::from_bytes([2; 32]);
    for mut packet in mac_packets(src) {
        let packet_type = packet.body.packet_type();
        packet.seal(&key).unwrap();
        let mut wire = packet.encode().unwrap();
        let decoded = RelayPacket::decode(&wire).unwrap();
        assert_eq!(decoded.verify_mac(&key), Ok(()), "{packet_type:?}");
        assert_eq!(
            decoded.verify_mac(&other_key),
            Err(RelayMacError::BadMac),
            "{packet_type:?}"
        );
        // A flipped MAC bit.
        let last = wire.len() - 1;
        wire[last] ^= 0x80;
        assert_eq!(
            RelayPacket::decode(&wire).unwrap().verify_mac(&key),
            Err(RelayMacError::BadMac),
            "{packet_type:?}"
        );
        // A different node slot in the header is covered by the MAC.
        let mut moved = decoded;
        if moved.src.is_zero() {
            moved.dst = NodeId::from_bytes([8; 12]);
        } else {
            moved.src = NodeId::from_bytes([8; 12]);
        }
        assert_eq!(
            moved.verify_mac(&key),
            Err(RelayMacError::BadMac),
            "{packet_type:?}"
        );
    }
}

#[test]
fn refutation_mac_on_types_without_mac() {
    let key = SessionKey::from_bytes([1; 32]);
    let mut data = RelayPacket {
        src: NodeId::from_bytes([7; 12]),
        dst: NodeId::from_bytes([9; 12]),
        body: RelayBody::Data(vec![4]),
    };
    assert_eq!(data.seal(&key), Err(RelayMacError::NoMac(RelayType::Data)));
    assert_eq!(
        data.verify_mac(&key),
        Err(RelayMacError::NoMac(RelayType::Data))
    );
    let status = RelayPacket {
        src: RELAY_SLOT,
        dst: NodeId::from_bytes([7; 12]),
        body: RelayBody::Status(Status {
            type_in: 9,
            destination: RELAY_SLOT,
            status: StatusCode::UnsupportedType,
        }),
    };
    assert_eq!(
        status.mac_input(),
        Err(RelayMacError::NoMac(RelayType::Status))
    );
    let register = RelayPacket::decode(&demo_packet()).unwrap();
    assert_eq!(
        register.verify_mac(&key),
        Err(RelayMacError::NoMac(RelayType::Register))
    );
}

#[test]
fn refutation_zero_shared_secret() {
    let register = register_at(&demo_record(), NOW);
    for low_order in [[0; 32], {
        let mut one = [0; 32];
        one[0] = 1;
        one
    }] {
        assert_eq!(
            register.node_session_key(&node_secret(), &low_order),
            Err(ZeroSharedSecret)
        );
        assert_eq!(
            derive_session_key(
                &relay_secret(),
                &low_order,
                &register.node_id(),
                INCARNATION,
                &low_order,
                &x25519_public(relay_secret()),
                &register.reg_hash(),
            ),
            Err(ZeroSharedSecret)
        );
    }
    let verified = check_register(
        &packet_of(
            Register::sign(
                &demo_signer(),
                &demo_record(),
                INCARNATION,
                NOW,
                [0; 32],
                &relay_id(),
            )
            .unwrap(),
        ),
        &relay_id(),
        NOW,
        &fresh_marks(),
    )
    .unwrap();
    assert_eq!(
        verified.relay_session_key(&relay_secret()),
        Err(ZeroSharedSecret)
    );
}

#[test]
fn refutation_rule1_packet_checks() {
    assert_eq!(
        rejection(&demo_packet()[..28]),
        RegisterRejection::Packet(RelayPacketError::TooShort(28))
    );
    let mut magic = demo_packet();
    magic[0] = b'K';
    assert_eq!(
        rejection(&magic),
        RegisterRejection::Packet(RelayPacketError::BadMagic)
    );
    let mut zero_src = demo_packet();
    zero_src[5..17].fill(0);
    assert_eq!(
        rejection(&zero_src),
        RegisterRejection::Packet(RelayPacketError::Direction(RelayType::Register))
    );
    let mut trailing = demo_packet();
    trailing.push(0);
    assert_eq!(
        rejection(&trailing),
        RegisterRejection::Packet(RelayPacketError::Body(ns_wire::CborError::TrailingBytes))
    );
    let mut oversize = demo_packet();
    oversize.resize(1201, 0);
    assert_eq!(
        rejection(&oversize),
        RegisterRejection::Packet(RelayPacketError::TooLarge {
            length: 1201,
            maximum: 1200
        })
    );
}

#[test]
fn refutation_rule1_not_register() {
    let presence = RelayPacket {
        src: NodeId::from_bytes([7; 12]),
        dst: RELAY_SLOT,
        body: RelayBody::Presence(Presence {
            incarnation: 1,
            seq: 1,
            mac: [0; 32],
        }),
    };
    assert_eq!(
        rejection(&presence.encode().unwrap()),
        RegisterRejection::NotRegister(RelayType::Presence)
    );
}

#[test]
fn refutation_rule1_source_mismatch() {
    let expected = NodeId::derive(&demo_signer().verifying_key().to_bytes());
    let mut packet = with_bad_signature(demo_packet());
    packet[5..17].fill(9);
    assert_eq!(
        rejection(&packet),
        RegisterRejection::SourceMismatch {
            src: NodeId::from_bytes([9; 12]),
            expected
        }
    );
}

#[test]
fn refutation_rule1_relay_name() {
    let other = RelayId::parse("hkg-a2.relay.ns.io:51822").unwrap();
    for packet in [demo_packet(), with_bad_signature(demo_packet())] {
        assert_eq!(
            check_register(&packet, &other, NOW, &fresh_marks()).unwrap_err(),
            RegisterRejection::RelayName
        );
    }
}

#[test]
fn refutation_rule1_timestamp_window() {
    let record = demo_record();
    for ts in [NOW - 120, NOW + 120] {
        let packet = packet_of(register_at(&record, ts));
        assert!(check_register(&packet, &relay_id(), NOW, &fresh_marks()).is_ok());
    }
    for ts in [NOW - 121, NOW + 121, 0, u64::MAX] {
        let packet = with_bad_signature(packet_of(register_at(&record, ts)));
        assert_eq!(
            rejection(&packet),
            RegisterRejection::Timestamp { ts, now: NOW }
        );
    }
    let packet = packet_of(register_at(&record, u64::MAX));
    assert_eq!(
        check_register(&packet, &relay_id(), 0, &fresh_marks()).unwrap_err(),
        RegisterRejection::Timestamp {
            ts: u64::MAX,
            now: 0
        }
    );
}

#[test]
fn refutation_rule1_pre_crypto_failure_wins_over_bad_record() {
    let mut record = demo_record().as_bytes().to_vec();
    let last = record.len() - 1;
    record[last] ^= 1;
    let packet = with_bad_signature(hand_signed_packet(&record, NOW - 121));
    assert_eq!(
        rejection(&packet),
        RegisterRejection::Timestamp {
            ts: NOW - 121,
            now: NOW
        }
    );
    assert!(
        RegisterCandidate::precheck(&hand_signed_packet(&record, NOW), &relay_id(), NOW).is_ok()
    );
}

#[test]
fn refutation_rule1_invalid_record() {
    let mut record = demo_record().as_bytes().to_vec();
    let last = record.len() - 1;
    record[last] ^= 1;
    assert_eq!(
        rejection(&hand_signed_packet(&record, NOW)),
        RegisterRejection::Record(NodeRecordError::BadSignature)
    );
    // gen = 0 is structurally fine but not a valid record.
    let mut zero_gen = demo_record().as_bytes().to_vec();
    let gen_position = 1 + 1 + 34 + 34;
    assert_eq!(zero_gen[gen_position], 0x03);
    zero_gen[gen_position] = 0x00;
    assert_eq!(
        rejection(&with_bad_signature(hand_signed_packet(&zero_gen, NOW))),
        RegisterRejection::Record(NodeRecordError::ZeroGeneration)
    );
}

#[test]
fn refutation_rule1_expired_record() {
    let packet = packet_of(register_at(&demo_record(), EXPIRES));
    assert_eq!(
        check_register(&packet, &relay_id(), EXPIRES, &fresh_marks()).unwrap_err(),
        RegisterRejection::RecordExpired(RecordExpired {
            expires: EXPIRES,
            now: EXPIRES
        })
    );
    let packet = packet_of(register_at(&demo_record(), EXPIRES - 1));
    assert!(check_register(&packet, &relay_id(), EXPIRES - 1, &fresh_marks()).is_ok());
}

#[test]
fn refutation_rule1_register_signature() {
    assert_eq!(
        rejection(&with_bad_signature(demo_packet())),
        RegisterRejection::Signature(BadRegisterSignature)
    );
    // A REGISTER signed under another context.
    let unsigned = unsigned_register(demo_record().as_bytes(), NOW, relay_id().as_str());
    let message = [b"ns/relay-register/v1".to_vec(), unsigned].concat();
    let register = Register::from_parts(
        demo_record().as_bytes(),
        INCARNATION,
        NOW,
        x25519_public(node_secret()),
        relay_id().as_str(),
        demo_signer().sign(&message).to_bytes(),
    )
    .unwrap();
    assert_eq!(
        rejection(&packet_of(register)),
        RegisterRejection::Signature(BadRegisterSignature)
    );
}

fn marks_with(records: &[NodeRecord]) -> RecordMarks {
    let mut marks = fresh_marks();
    for record in records {
        marks.apply(record).unwrap();
    }
    marks
}

#[test]
fn refutation_rule1_marks() {
    let signer = demo_signer();
    let packet = demo_packet();
    let check = |marks: &RecordMarks| check_register(&packet, &relay_id(), NOW, marks);

    let higher = record_with(&signer, 4, 5, ISSUED_AT);
    assert_eq!(
        check(&marks_with(&[higher])).unwrap_err(),
        RegisterRejection::StaleGeneration {
            generation: 3,
            committed: 4
        }
    );

    let other_key = record_with(&signer, 3, 6, ISSUED_AT);
    assert_eq!(
        check(&marks_with(std::slice::from_ref(&other_key))).unwrap_err(),
        RegisterRejection::Conflict(3)
    );

    let mut latched = marks_with(&[other_key]);
    assert_eq!(latched.apply(&demo_record()), Ok(RecordDecision::Conflict));
    assert!(latched.is_conflicted());
    assert_eq!(
        check(&latched).unwrap_err(),
        RegisterRejection::ConflictLatched(3)
    );

    let stranger = RecordMarks::new(SigningKey::from_bytes(&[1; 32]).verifying_key().to_bytes());
    assert_eq!(
        check(&stranger).unwrap_err(),
        RegisterRejection::MarksIdentity
    );
}

#[test]
fn rule1_reports_how_marks_would_advance() {
    let signer = demo_signer();
    let packet = demo_packet();
    let decision = |marks: &RecordMarks| {
        check_register(&packet, &relay_id(), NOW, marks)
            .unwrap()
            .decision()
    };
    assert_eq!(decision(&fresh_marks()), RecordDecision::Advanced);
    assert_eq!(
        decision(&marks_with(&[record_with(&signer, 2, 6, ISSUED_AT)])),
        RecordDecision::Advanced
    );
    assert_eq!(
        decision(&marks_with(&[demo_record()])),
        RecordDecision::Unchanged
    );
    assert_eq!(
        decision(&marks_with(&[record_with(&signer, 3, 5, ISSUED_AT - 10)])),
        RecordDecision::Refreshed
    );
    // A higher generation clears a latched conflict.
    let mut latched = marks_with(&[record_with(&signer, 2, 6, ISSUED_AT)]);
    latched
        .apply(&record_with(&signer, 2, 7, ISSUED_AT))
        .unwrap();
    assert!(latched.is_conflicted());
    assert_eq!(decision(&latched), RecordDecision::Advanced);
}

#[test]
fn precheck_then_verify_matches_check_register() {
    let packet = demo_packet();
    let candidate = RegisterCandidate::precheck(&packet, &relay_id(), NOW).unwrap();
    assert_eq!(candidate.register().ts(), NOW);
    assert_eq!(
        candidate.verify(&fresh_marks()),
        check_register(&packet, &relay_id(), NOW, &fresh_marks())
    );
}
