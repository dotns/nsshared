//! Generated relay packet vectors: packets, REGISTER signature, session key and MACs
//! (quick-v2 §8.1-§8.3, §12.1-§12.3).

#![allow(clippy::unwrap_used, clippy::panic, reason = "test fixture helpers")]

mod support;

use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use nsshared_proto::{
    NodeId, NodeRecord, RelayId, record::RecordMarks, relay::ObservedAddr, relay::Presence,
    relay::Reflect, relay::Reflected, relay::Register, relay::RegisterRejection, relay::Registered,
    relay::RelayBody, relay::RelayMacError, relay::RelayPacket, relay::RelayPacketError,
    relay::RelayType, relay::Revoke, relay::RevokeReason, relay::SessionKey, relay::Status,
    relay::StatusCode, relay::ZeroSharedSecret, relay::check_register, relay::derive_session_key,
    relay::ephemeral_public,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use support::vectors::{Vector, load};

fn node_id(v: &Vector, key: &str) -> NodeId {
    NodeId::from_bytes(v.hex_array(key))
}

fn int<T: TryFrom<u64>>(v: &Vector, key: &str) -> T {
    T::try_from(v.u64(key)).unwrap_or_else(|_| panic!("{}: `{key}` out of range", v.name()))
}

fn observed(v: &Vector) -> Option<ObservedAddr> {
    let ip = v.opt("observed_ip")?;
    let ip = match support::vectors::decode_hex(ip).unwrap().as_slice() {
        &[a, b, c, d] => IpAddr::V4(Ipv4Addr::new(a, b, c, d)),
        bytes => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(bytes).unwrap())),
    };
    Some(ObservedAddr {
        ip,
        port: int(v, "observed_port"),
    })
}

/// Builds the typed body of a positive packet vector with a zero MAC.
fn body(v: &Vector) -> RelayBody {
    let mac = [0; 32];
    match RelayType::from_u8(int(v, "type")).unwrap() {
        RelayType::Registered => {
            let capabilities: Vec<String> = v
                .all("capability")
                .iter()
                .map(|c| (*c).to_owned())
                .collect();
            assert_eq!(capabilities.len(), int::<usize>(v, "capability_count"));
            RelayBody::Registered(Registered {
                incarnation: v.u64("incarnation"),
                relay_ephemeral: v.hex_array("relay_ephemeral"),
                presence_ttl_s: int(v, "presence_ttl_s"),
                observed_addr: observed(v),
                ack_seq: v.u64("ack_seq"),
                capabilities,
                mac,
            })
        }
        RelayType::Presence => RelayBody::Presence(Presence {
            incarnation: v.u64("incarnation"),
            seq: v.u64("seq"),
            mac,
        }),
        RelayType::Reflect => RelayBody::Reflect(Reflect {
            incarnation: v.u64("incarnation"),
            seq: v.u64("seq"),
            nonce: v.hex_array("nonce"),
            mac,
        }),
        RelayType::Reflected => RelayBody::Reflected(Reflected {
            incarnation: v.u64("incarnation"),
            seq: v.u64("seq"),
            nonce: v.hex_array("nonce"),
            observed_addr: observed(v).unwrap(),
            mac,
        }),
        RelayType::Data => RelayBody::Data(v.hex("data")),
        RelayType::Status => RelayBody::Status(Status {
            type_in: int(v, "type_in"),
            destination: node_id(v, "destination"),
            status: StatusCode::from_u64(v.u64("status")).unwrap(),
        }),
        RelayType::Revoke => RelayBody::Revoke(Revoke {
            incarnation: v.u64("incarnation"),
            seq: v.u64("seq"),
            reason: match v.u64("reason") {
                0 => RevokeReason::Rotation,
                1 => RevokeReason::Close,
                other => panic!("{}: reason {other}", v.name()),
            },
            mac,
        }),
        RelayType::Register => panic!("{}: REGISTER has its own vector kind", v.name()),
    }
}

fn of_kind<'a>(vectors: &'a [Vector], kind: &str, reject: bool) -> Vec<&'a Vector> {
    vectors
        .iter()
        .filter(|v| v.get("kind") == kind && v.is_reject() == reject)
        .collect()
}

#[test]
fn register_matches_vector() {
    let vectors = load("relay_packets");
    let [v] = of_kind(&vectors, "register", false)[..] else {
        panic!("expected one REGISTER vector");
    };
    let signer = SigningKey::from_bytes(&v.hex_array("seed"));
    assert_eq!(
        signer.verifying_key().to_bytes(),
        v.hex_array::<32>("identity")
    );
    let record = NodeRecord::decode(&v.hex("record")).unwrap();
    let relay_name = RelayId::parse(v.get("relay_name")).unwrap();
    let node_ephemeral = v.hex_array("node_ephemeral");
    assert_eq!(
        ephemeral_public(&v.hex_array("node_ephemeral_secret")),
        node_ephemeral
    );

    // Encode equals the fixture, and the fixture signature covers the fixture message.
    let register = Register::sign(
        &signer,
        &record,
        v.u64("incarnation"),
        v.u64("ts"),
        node_ephemeral,
        &relay_name,
    )
    .unwrap();
    assert_eq!(register.signature(), &v.hex_array::<64>("signature"));
    VerifyingKey::from_bytes(&v.hex_array("identity"))
        .unwrap()
        .verify_strict(
            &v.hex("signed_message"),
            &Signature::from_bytes(register.signature()),
        )
        .unwrap();
    assert_eq!(register.encode(), v.hex("body"));
    assert_eq!(register.reg_hash(), v.hex_array::<32>("reg_hash"));
    assert_eq!(register.node_id(), node_id(v, "src"));
    let packet = RelayPacket {
        src: node_id(v, "src"),
        dst: node_id(v, "dst"),
        body: RelayBody::Register(register.clone()),
    };
    let encoded = v.hex("packet");
    assert_eq!(encoded.len(), int::<usize>(v, "packet_len"));
    assert_eq!(packet.encode().unwrap(), encoded);

    // Decode then re-encode equals the fixture, and the relay admits it.
    let decoded = RelayPacket::decode(&encoded).unwrap();
    assert_eq!(decoded, packet);
    assert_eq!(decoded.encode().unwrap(), encoded);
    let verified = check_register(
        &encoded,
        &relay_name,
        v.u64("now"),
        &RecordMarks::new(*record.identity()),
    )
    .unwrap();
    assert_eq!(verified.reg_hash(), &v.hex_array::<32>("reg_hash"));
    assert_eq!(verified.register(), &register);
}

fn session_register(v: &Vector) -> Register {
    match RelayPacket::decode(&v.hex("register")).unwrap().body {
        RelayBody::Register(register) => register,
        other => panic!("{}: not a REGISTER: {other:?}", v.name()),
    }
}

#[test]
fn session_key_matches_vector() {
    let vectors = load("relay_packets");
    let [v] = of_kind(&vectors, "session", false)[..] else {
        panic!("expected one session vector");
    };
    let node_secret = v.hex_array("node_ephemeral_secret");
    let relay_secret = v.hex_array("relay_ephemeral_secret");
    let node_ephemeral = v.hex_array("node_ephemeral");
    let relay_ephemeral = v.hex_array("relay_ephemeral");
    assert_eq!(ephemeral_public(&node_secret), node_ephemeral);
    assert_eq!(ephemeral_public(&relay_secret), relay_ephemeral);
    let expected = SessionKey::from_bytes(v.hex_array("sk"));
    let src = node_id(v, "src");
    let reg_hash = v.hex_array("reg_hash");

    // Both sides' Diffie-Hellman agree on sk.
    for (own, peer) in [
        (&node_secret, &relay_ephemeral),
        (&relay_secret, &node_ephemeral),
    ] {
        let key = derive_session_key(
            own,
            peer,
            &src,
            v.u64("incarnation"),
            &node_ephemeral,
            &relay_ephemeral,
            &reg_hash,
        )
        .unwrap();
        assert_eq!(key, expected);
    }
    let register = session_register(v);
    assert_eq!(register.reg_hash(), reg_hash);
    assert_eq!(
        register
            .node_session_key(&node_secret, &relay_ephemeral)
            .unwrap(),
        expected
    );
    let record = NodeRecord::decode(register.record()).unwrap();
    let verified = check_register(
        &v.hex("register"),
        &RelayId::parse(register.relay_name()).unwrap(),
        register.ts(),
        &RecordMarks::new(*record.identity()),
    )
    .unwrap();
    assert_eq!(verified.relay_session_key(&relay_secret).unwrap(), expected);
}

#[test]
fn packets_match_vectors() {
    let vectors = load("relay_packets");
    let positives = of_kind(&vectors, "packet", false);
    for v in &positives {
        let name = v.name();
        let mut packet = RelayPacket {
            src: node_id(v, "src"),
            dst: node_id(v, "dst"),
            body: body(v),
        };
        if v.opt("sk").is_some() {
            let key = SessionKey::from_bytes(v.hex_array("sk"));
            assert_eq!(packet.mac_input().unwrap(), v.hex("mac_input"), "{name}");
            packet.seal(&key).unwrap();
            packet.verify_mac(&key).unwrap();
            let context = match packet.body.packet_type() {
                RelayType::Registered | RelayType::Reflected => "ns/relay-reply/v2",
                _ => "ns/relay-ctl/v2",
            };
            assert_eq!(v.get("mac_context"), context, "{name}");
            assert!(v.hex("mac_input").starts_with(context.as_bytes()), "{name}");
            assert!(v.hex("packet").ends_with(&v.hex("mac")), "{name}");
        } else {
            assert_eq!(
                packet.mac_input(),
                Err(RelayMacError::NoMac(packet.body.packet_type()))
            );
        }
        let encoded = v.hex("packet");
        assert_eq!(encoded.len(), int::<usize>(v, "packet_len"), "{name}");
        assert_eq!(packet.encode().unwrap(), encoded, "{name}");
        assert!(encoded.ends_with(&v.hex("body")), "{name}");
        let decoded = RelayPacket::decode(&encoded).unwrap();
        assert_eq!(decoded, packet, "{name}");
        assert_eq!(decoded.encode().unwrap(), encoded, "{name}");
    }
    let types: std::collections::BTreeSet<u64> = positives.iter().map(|v| v.u64("type")).collect();
    assert_eq!(types.into_iter().collect::<Vec<_>>(), [2, 3, 4, 5, 6, 7, 8]);
}

fn packet_error_matches(reason: &str, error: &RelayPacketError) -> bool {
    use nsshared_proto::encoding::CborError;
    match reason {
        "too_large" => matches!(error, RelayPacketError::TooLarge { .. }),
        "too_short" => matches!(error, RelayPacketError::TooShort(_)),
        "bad_magic" => *error == RelayPacketError::BadMagic,
        "unknown_type" => matches!(error, RelayPacketError::UnknownType(_)),
        "direction" => matches!(error, RelayPacketError::Direction(_)),
        "data_length" => matches!(error, RelayPacketError::DataLength(_)),
        "trailing_bytes" => *error == RelayPacketError::Body(CborError::TrailingBytes),
        "non_canonical" | "schema" => matches!(error, RelayPacketError::Body(_)),
        "record_version" => matches!(error, RelayPacketError::RecordVersion(_)),
        "relay_name_length" => matches!(error, RelayPacketError::RelayNameLength(_)),
        "type_in" => matches!(error, RelayPacketError::TypeIn(_)),
        "presence_ttl" => matches!(error, RelayPacketError::PresenceTtl(_)),
        "capabilities_not_provisional" => {
            matches!(error, RelayPacketError::CapabilitiesNotProvisional(_))
        }
        "zero_seq" => *error == RelayPacketError::ZeroSeq,
        "status_code" => matches!(error, RelayPacketError::StatusCode(_)),
        "revoke_reason" => matches!(error, RelayPacketError::RevokeReason(_)),
        "observed_ip" => matches!(error, RelayPacketError::ObservedIp(_)),
        "observed_port" => matches!(error, RelayPacketError::ObservedPort(_)),
        other => panic!("unknown reason {other}"),
    }
}

#[test]
fn rejected_packets_match_vectors() {
    let vectors = load("relay_packets");
    let negatives = of_kind(&vectors, "packet", true);
    for v in &negatives {
        let error = RelayPacket::decode(&v.hex("packet")).unwrap_err();
        assert!(
            packet_error_matches(v.reason(), &error),
            "{}: {error:?}",
            v.name()
        );
    }
    assert!(negatives.len() >= 30);
}

#[test]
fn rejected_macs_match_vectors() {
    let vectors = load("relay_packets");
    let negatives = of_kind(&vectors, "mac", true);
    for v in &negatives {
        assert_eq!(v.reason(), "bad_mac");
        let key = SessionKey::from_bytes(v.hex_array("sk"));
        let packet = RelayPacket::decode(&v.hex("packet")).unwrap();
        assert_eq!(
            packet.verify_mac(&key),
            Err(RelayMacError::BadMac),
            "{}",
            v.name()
        );
    }
    assert!(negatives.len() >= 4);
}

#[test]
fn zero_shared_secrets_are_rejected() {
    let vectors = load("relay_packets");
    let negatives = of_kind(&vectors, "session", true);
    for v in &negatives {
        assert_eq!(v.reason(), "zero_shared_secret");
        let register = session_register(v);
        let node_secret = v.hex_array("node_ephemeral_secret");
        let relay_ephemeral = v.hex_array("relay_ephemeral");
        assert_eq!(
            register.node_session_key(&node_secret, &relay_ephemeral),
            Err(ZeroSharedSecret),
            "{}",
            v.name()
        );
    }
    assert_eq!(negatives.len(), 2);
}

#[test]
fn rejected_registers_match_vectors() {
    let vectors = load("relay_packets");
    let negatives = of_kind(&vectors, "register", true);
    for v in &negatives {
        let packet = v.hex("packet");
        let RelayBody::Register(register) = RelayPacket::decode(&packet).unwrap().body else {
            panic!("{}: not a REGISTER", v.name());
        };
        let marks = RecordMarks::new(*register.identity());
        let relay_name = RelayId::parse(v.get("relay_name")).unwrap();
        let error = check_register(&packet, &relay_name, v.u64("now"), &marks).unwrap_err();
        let matched = match v.reason() {
            "source_mismatch" => matches!(error, RegisterRejection::SourceMismatch { .. }),
            "relay_name" => error == RegisterRejection::RelayName,
            "timestamp" => matches!(error, RegisterRejection::Timestamp { .. }),
            "bad_signature" => matches!(error, RegisterRejection::Signature(_)),
            other => panic!("{}: unknown reason {other}", v.name()),
        };
        assert!(matched, "{}: {error:?}", v.name());
    }
    assert!(negatives.len() >= 5);
}
