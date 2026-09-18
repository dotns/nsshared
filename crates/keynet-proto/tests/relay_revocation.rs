use ed25519_dalek::SigningKey;
use keynet_proto::{
    KeyBindingScope, ObservedAddr, Presence, Reflect, RegisterInputError, RegisterValidationError,
    Registered, RelayBody, RelayCryptoError, RelayDatagram, RelayDecodeError, RelayEncodeError,
    RelayHeader, RelayMacError, RelayType, Revocation, RevocationDecision, RevocationDecisionError,
    RevocationDecodeError, RevocationInputError, RevocationSignatureError, RevocationState, Revoke,
    RevokeReason, Status, StatusCode, derive_relay_session_key, derive_relay_shared_secret,
    derive_slot_id,
};
use std::collections::BTreeMap;

const VECTORS: &str = include_str!("fixtures/keynet-v1/relay_revocation.vec");

fn hex_bytes(input: &str) -> Vec<u8> {
    assert_eq!(input.len() % 2, 0);
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).expect("fixture hex is ASCII");
            u8::from_str_radix(text, 16).expect("fixture hex is valid")
        })
        .collect()
}

fn vectors() -> BTreeMap<&'static str, Vec<u8>> {
    VECTORS
        .lines()
        .map(|line| {
            let (name, value) = line.split_once('|').expect("fixture line has separator");
            (name, hex_bytes(value))
        })
        .collect()
}

fn fixed<const N: usize>(name: &str) -> [u8; N] {
    vectors()[name]
        .clone()
        .try_into()
        .expect("fixture field has fixed width")
}

fn datagram(name: &str) -> RelayDatagram {
    RelayDatagram::decode(&vectors()[name]).expect("literal datagram decodes")
}

#[test]
fn every_relay_datagram_has_a_fixed_literal_and_round_trips() {
    let cases = [
        ("register_datagram", RelayType::Register),
        ("registered_datagram", RelayType::Registered),
        ("presence_datagram", RelayType::Presence),
        ("reflect_datagram", RelayType::Reflect),
        ("reflected_datagram", RelayType::Reflected),
        ("intro_datagram", RelayType::Intro),
        ("intro_ack_datagram", RelayType::IntroAck),
        ("data_datagram", RelayType::Data),
        ("status_datagram", RelayType::Status),
        ("revoke_datagram", RelayType::Revoke),
    ];
    let values = vectors();
    for (name, message_type) in cases {
        let decoded = RelayDatagram::decode(&values[name]).expect("literal datagram decodes");
        assert_eq!(decoded.header.message_type, message_type);
        assert_eq!(decoded.body.message_type(), message_type);
        assert_eq!(decoded.encode(), Ok(values[name].clone()));
    }
    let RelayBody::Registered(registered) = datagram("registered_datagram").body else {
        panic!("expected REGISTERED body");
    };
    assert_eq!(
        registered.observed_addr,
        Some(ObservedAddr::V4([192, 0, 2, 7], 65_535))
    );
    let RelayBody::Reflected(reflected) = datagram("reflected_datagram").body else {
        panic!("expected REFLECTED body");
    };
    assert_eq!(
        reflected.observed_addr,
        ObservedAddr::V6([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], 1)
    );
}

#[test]
fn header_boundaries_magic_types_directions_and_slots_are_exact() {
    let header = RelayHeader::new(RelayType::Data, [1; 16], [2; 16]).expect("valid header");
    let encoded = header.encode().expect("header encodes");
    assert_eq!(encoded.len(), 37);
    assert_eq!(
        RelayHeader::decode(&encoded[..36]),
        Err(RelayDecodeError::InvalidLength)
    );
    assert_eq!(RelayHeader::decode(&encoded), Ok(header));
    let mut changed = encoded;
    changed[0] = b'X';
    assert_eq!(
        RelayHeader::decode(&changed),
        Err(RelayDecodeError::InvalidMagic)
    );
    changed = encoded;
    changed[4] = 0;
    assert_eq!(
        RelayHeader::decode(&changed),
        Err(RelayDecodeError::UnsupportedType)
    );
    changed[4] = 11;
    assert_eq!(
        RelayHeader::decode(&changed),
        Err(RelayDecodeError::UnsupportedType)
    );

    for typ in [
        RelayType::Register,
        RelayType::Presence,
        RelayType::Reflect,
        RelayType::Revoke,
    ] {
        assert!(RelayHeader::new(typ, [1; 16], [0; 16]).is_ok());
        assert_eq!(
            RelayHeader::new(typ, [0; 16], [0; 16]),
            Err(RelayEncodeError::InvalidDirection)
        );
    }
    for typ in [
        RelayType::Registered,
        RelayType::Reflected,
        RelayType::Status,
    ] {
        assert!(RelayHeader::new(typ, [0; 16], [1; 16]).is_ok());
        assert_eq!(
            RelayHeader::new(typ, [0; 16], [0; 16]),
            Err(RelayEncodeError::InvalidDirection)
        );
    }
    for typ in [RelayType::Intro, RelayType::IntroAck, RelayType::Data] {
        assert!(RelayHeader::new(typ, [1; 16], [2; 16]).is_ok());
        assert_eq!(
            RelayHeader::new(typ, [1; 16], [0; 16]),
            Err(RelayEncodeError::InvalidDirection)
        );
    }
}

#[test]
fn datagram_and_data_bounds_are_enforced_before_body_parsing() {
    let header = RelayHeader::new(RelayType::Data, [1; 16], [2; 16]).expect("valid header");
    for length in [1, 2011] {
        let value = RelayDatagram {
            header,
            body: RelayBody::Data(vec![7; length]),
        };
        let encoded = value.encode().expect("bounded DATA encodes");
        assert_eq!(RelayDatagram::decode(&encoded), Ok(value));
    }
    assert_eq!(
        RelayDatagram {
            header,
            body: RelayBody::Data(Vec::new())
        }
        .encode(),
        Err(RelayEncodeError::InvalidDataLength)
    );
    assert_eq!(
        RelayDatagram {
            header,
            body: RelayBody::Data(vec![0; 2012])
        }
        .encode(),
        Err(RelayEncodeError::InvalidDataLength)
    );
    let mut over = header.encode().expect("header encodes").to_vec();
    over.extend_from_slice(&vec![0; 2012]);
    assert_eq!(over.len(), 2049);
    assert_eq!(
        RelayDatagram::decode(&over),
        Err(RelayDecodeError::DatagramTooLarge)
    );
    let mut control = vectors()["presence_datagram"].clone();
    control.resize(1200, 0);
    assert_eq!(
        RelayDatagram::decode(&control),
        Err(RelayDecodeError::InvalidBody)
    );
    control.push(0);
    assert_eq!(
        RelayDatagram::decode(&control),
        Err(RelayDecodeError::DatagramTooLarge)
    );
}

#[test]
fn relay_wire_preserves_legacy_bytes_until_strict_admission() {
    let RelayBody::Register(base) = datagram("register_datagram").body else {
        panic!("expected REGISTER body");
    };
    assert_eq!(base.relay_name, "Relay.EXAMPLE:443/Path");
    for length in [1, 255] {
        let mut value = base.clone();
        value.relay_name = "x".repeat(length);
        assert!(
            RelayDatagram {
                header: datagram("register_datagram").header,
                body: RelayBody::Register(value)
            }
            .encode()
            .is_ok()
        );
    }
    for length in [0, 256] {
        let mut value = base.clone();
        value.relay_name = "x".repeat(length);
        assert!(
            RelayDatagram {
                header: datagram("register_datagram").header,
                body: RelayBody::Register(value)
            }
            .encode()
            .is_err()
        );
    }
    let mut invalid = vectors()["register_datagram"].clone();
    let position = invalid
        .windows(22)
        .position(|window| window == b"Relay.EXAMPLE:443/Path")
        .expect("literal name");
    invalid[position] = 0xff;
    assert_eq!(
        RelayDatagram::decode(&invalid),
        Err(RelayDecodeError::InvalidBody)
    );
}

#[test]
fn observed_addresses_ttl_ports_and_null_are_strict() {
    let header = RelayHeader::new(RelayType::Registered, [0; 16], [1; 16]).expect("header");
    let base = Registered {
        incarnation: 0,
        relay_ephemeral: [2; 32],
        presence_ttl_s: 30,
        observed_addr: None,
        ack_seq: 0,
        mac: [0; 32],
    };
    for ttl in [30, 3600] {
        let value = Registered {
            presence_ttl_s: ttl,
            ..base
        };
        assert!(
            RelayDatagram {
                header,
                body: RelayBody::Registered(value)
            }
            .encode()
            .is_ok()
        );
    }
    for ttl in [29, 3601] {
        let value = Registered {
            presence_ttl_s: ttl,
            ..base
        };
        assert!(
            RelayDatagram {
                header,
                body: RelayBody::Registered(value)
            }
            .encode()
            .is_err()
        );
    }
    for observed_addr in [
        Some(ObservedAddr::V4([127, 0, 0, 1], 1)),
        Some(ObservedAddr::V6([3; 16], 65_535)),
        None,
    ] {
        let value = Registered {
            observed_addr,
            ..base
        };
        let encoded = RelayDatagram {
            header,
            body: RelayBody::Registered(value),
        }
        .encode()
        .expect("valid observation");
        assert_eq!(
            RelayDatagram::decode(&encoded).expect("decodes").body,
            RelayBody::Registered(value)
        );
    }
    for observed_addr in [ObservedAddr::V4([1; 4], 0), ObservedAddr::V6([1; 16], 0)] {
        let value = Registered {
            observed_addr: Some(observed_addr),
            ..base
        };
        assert!(
            RelayDatagram {
                header,
                body: RelayBody::Registered(value)
            }
            .encode()
            .is_err()
        );
    }
}

#[test]
fn canonical_cbor_counts_widths_types_and_trailing_bytes_are_rejected() {
    let original = vectors()["presence_datagram"].clone();
    let body = 37;
    let mut cases = Vec::new();
    let mut value = original.clone();
    value[body] = 0x9f;
    cases.push(value);
    let mut value = original.clone();
    value[body] = 0x82;
    cases.push(value);
    let mut value = original.clone();
    value[body + 1] = 0x49;
    cases.push(value);
    let mut value = original.clone();
    value.splice(body + 2..body + 3, [0x18, 0x01]);
    cases.push(value);
    let mut value = original;
    value.push(0);
    cases.push(value);
    for malformed in cases {
        assert_eq!(
            RelayDatagram::decode(&malformed),
            Err(RelayDecodeError::InvalidBody)
        );
    }
}

#[test]
fn register_signature_slot_shared_secret_hkdf_and_validation_match_literals() {
    let values = vectors();
    let RelayDatagram {
        header,
        body: RelayBody::Register(register),
    } = datagram("register_datagram")
    else {
        panic!("expected REGISTER");
    };
    assert_eq!(
        derive_slot_id(&fixed("network"), &fixed("identity")),
        Ok(fixed("slot"))
    );
    assert_eq!(
        register.unsigned_bytes(),
        Ok(values["register_unsigned"].clone())
    );
    assert_eq!(register.signature, fixed("register_signature"));
    assert_eq!(register.reg_hash(), Ok(fixed("reg_hash")));
    assert_eq!(
        register.validate(header, "Relay.EXAMPLE:443/Path", 1500),
        Err(RegisterValidationError::RelayNameMismatch)
    );
    assert_eq!(
        RelayDatagram::decode_and_validate_register(
            &values["register_datagram"],
            "Relay.EXAMPLE:443/Path",
            1500,
        ),
        Err(RegisterInputError::Validation(
            RegisterValidationError::RelayNameMismatch
        ))
    );
    let mut invalid_signature = values["register_datagram"].clone();
    *invalid_signature.last_mut().expect("signature byte") ^= 1;
    assert_eq!(
        RelayDatagram::decode_and_validate_register(
            &invalid_signature,
            "Relay.EXAMPLE:443/Path",
            1500,
        ),
        Err(RegisterInputError::Validation(
            RegisterValidationError::RelayNameMismatch
        ))
    );
    let signer = SigningKey::from_bytes(&std::array::from_fn(|index| (index + 1) as u8));
    let mut canonical = register.clone();
    canonical.relay_name = "relay.example:443".to_owned();
    canonical.sign(&signer).expect("canonical REGISTER signs");
    assert!(
        canonical
            .validate(header, &canonical.relay_name, 1500)
            .is_ok()
    );
    let mut site_local = canonical.clone();
    site_local.relay_name = "[fec0::1]:443".to_owned();
    site_local.sign(&signer).expect("site-local REGISTER signs");
    assert_eq!(
        site_local.validate(header, &site_local.relay_name, 1500),
        Err(RegisterValidationError::RelayNameMismatch)
    );
    let mut malformed = values["register_datagram"].clone();
    malformed[37] = 0x9f;
    assert_eq!(
        RelayDatagram::decode_and_validate_register(&malformed, "Relay.EXAMPLE:443/Path", 1500,),
        Err(RegisterInputError::Decode(RelayDecodeError::InvalidBody))
    );
    assert!(
        register
            .validate(header, "relay.example:443/path", 1500)
            .is_err()
    );
    assert!(
        canonical
            .validate(header, &canonical.relay_name, 1380)
            .is_ok()
    );
    assert!(
        canonical
            .validate(header, &canonical.relay_name, 1620)
            .is_ok()
    );
    assert_eq!(
        canonical.validate(header, &canonical.relay_name, 1379),
        Err(RegisterValidationError::TimestampOutsideWindow)
    );
    assert_eq!(
        derive_relay_shared_secret(&fixed("node_private"), &fixed("relay_ephemeral")),
        Ok(fixed("shared_secret"))
    );
    assert_eq!(
        derive_relay_shared_secret(&fixed("node_private"), &[0; 32]),
        Err(RelayCryptoError::AllZeroSharedSecret)
    );
    assert_eq!(
        derive_relay_session_key(
            &fixed("shared_secret"),
            &fixed("slot"),
            9,
            &fixed("node_ephemeral"),
            &fixed("relay_ephemeral"),
            &fixed("reg_hash")
        ),
        Ok(fixed("session_key"))
    );
    assert_eq!(
        derive_relay_session_key(
            &[0; 32],
            &fixed("slot"),
            9,
            &fixed("node_ephemeral"),
            &fixed("relay_ephemeral"),
            &fixed("reg_hash")
        ),
        Err(RelayCryptoError::AllZeroSharedSecret)
    );
    assert_eq!(
        derive_relay_session_key(
            &fixed("shared_secret"),
            &[0; 16],
            9,
            &fixed("node_ephemeral"),
            &fixed("relay_ephemeral"),
            &fixed("reg_hash")
        ),
        Err(RelayCryptoError::ReservedSlot)
    );

    let mut tampered = canonical.clone();
    tampered.node_ephemeral[0] ^= 1;
    assert_eq!(
        tampered.validate(header, &tampered.relay_name, 1500),
        Err(RegisterValidationError::InvalidSignature)
    );
    let wrong_header = RelayHeader {
        src: [9; 16],
        ..header
    };
    assert_eq!(
        canonical.validate(wrong_header, &canonical.relay_name, 1500),
        Err(RegisterValidationError::SourceSlotMismatch)
    );
    let mut stale = canonical;
    stale.binding.not_after = 1500;
    stale.binding.sign(&signer).expect("binding resigns");
    stale.sign(&signer).expect("REGISTER resigns");
    assert_eq!(
        stale.validate(header, &stale.relay_name, 1500),
        Err(RegisterValidationError::BindingNotCurrent)
    );
}

#[test]
fn control_and_reply_macs_cover_context_type_header_and_body() {
    let key = fixed("session_key");
    for (datagram_name, mac_name) in [
        ("registered_datagram", "registered_mac"),
        ("presence_datagram", "presence_mac"),
        ("reflect_datagram", "reflect_mac"),
        ("reflected_datagram", "reflected_mac"),
        ("revoke_datagram", "revoke_mac"),
    ] {
        let value = datagram(datagram_name);
        let mac = match &value.body {
            RelayBody::Registered(body) => {
                body.verify_mac(&key, value.header).expect("reply MAC");
                body.mac
            }
            RelayBody::Presence(body) => {
                body.verify_mac(&key, value.header).expect("control MAC");
                body.mac
            }
            RelayBody::Reflect(body) => {
                body.verify_mac(&key, value.header).expect("control MAC");
                body.mac
            }
            RelayBody::Reflected(body) => {
                body.verify_mac(&key, value.header).expect("reply MAC");
                body.mac
            }
            RelayBody::Revoke(body) => {
                body.verify_mac(&key, value.header).expect("control MAC");
                body.mac
            }
            _ => panic!("expected authenticated body"),
        };
        assert_eq!(mac, fixed(mac_name));
    }
    let RelayDatagram {
        header,
        body: RelayBody::Presence(mut presence),
    } = datagram("presence_datagram")
    else {
        panic!("expected PRESENCE");
    };
    presence.seq += 1;
    assert_eq!(
        presence.verify_mac(&key, header),
        Err(RelayMacError::InvalidMac)
    );
    assert_eq!(
        presence.verify_mac(
            &key,
            RelayHeader {
                src: [8; 16],
                ..header
            }
        ),
        Err(RelayMacError::InvalidMac)
    );
    assert_eq!(
        presence.verify_mac(
            &key,
            RelayHeader {
                message_type: RelayType::Reflect,
                ..header
            }
        ),
        Err(RelayMacError::TypeMismatch)
    );
    presence.seq -= 1;
    presence.mac[0] ^= 1;
    assert_eq!(
        presence.verify_mac(&key, header),
        Err(RelayMacError::InvalidMac)
    );
}

#[test]
fn status_and_revoke_values_and_echo_semantics_are_exact() {
    let input = RelayHeader::new(RelayType::Data, [1; 16], [2; 16]).expect("input");
    for code in [
        StatusCode::NoDestination,
        StatusCode::RateLimited,
        StatusCode::TooLarge,
        StatusCode::StaleGenerationOrIncarnation,
        StatusCode::UnsupportedType,
        StatusCode::SenderUnregisteredOrSourceMismatch,
    ] {
        let (header, status) = Status::for_input(input, code).expect("STATUS");
        assert!(status.matches_input(header, input));
    }
    let register = RelayHeader::new(RelayType::Register, [1; 16], [0; 16]).expect("header");
    assert!(Status::for_input(register, StatusCode::UnsupportedType).is_err());
    let invalid_input = RelayHeader {
        message_type: RelayType::Data,
        src: [0; 16],
        dst: [2; 16],
    };
    assert_eq!(
        Status::for_input(invalid_input, StatusCode::UnsupportedType),
        Err(RelayEncodeError::InvalidDirection)
    );
    let mut invalid_status = vectors()["status_datagram"].clone();
    *invalid_status.last_mut().expect("status") = 7;
    assert_eq!(
        RelayDatagram::decode(&invalid_status),
        Err(RelayDecodeError::InvalidBody)
    );
    let mut invalid_reason = vectors()["revoke_datagram"].clone();
    let reason = invalid_reason.len() - 35;
    invalid_reason[reason] = 2;
    assert_eq!(
        RelayDatagram::decode(&invalid_reason),
        Err(RelayDecodeError::InvalidBody)
    );
    let header = RelayHeader::new(RelayType::Revoke, [1; 16], [0; 16]).expect("header");
    for reason in [RevokeReason::Rotation, RevokeReason::Shutdown] {
        assert!(
            RelayDatagram {
                header,
                body: RelayBody::Revoke(Revoke {
                    incarnation: 0,
                    seq: 1,
                    reason,
                    mac: [0; 32]
                })
            }
            .encode()
            .is_ok()
        );
    }
}

#[test]
fn revocation_literal_signature_scope_and_high_water_are_strict() {
    let values = vectors();
    let record = Revocation::decode(&values["revocation"]).expect("Revocation decodes");
    assert!(Revocation::decode_and_verify(&values["revocation"]).is_ok());
    assert_eq!(record.unsigned_bytes(), values["revocation_unsigned"]);
    assert_eq!(record.signature, fixed("revocation_signature"));
    let verified = record.verify().expect("signature verifies");
    let state = RevocationState {
        scope: KeyBindingScope {
            network_id: record.network_id,
            identity: record.identity,
        },
        revoked_through: Some(3),
    };
    assert_eq!(
        verified.high_water_decision(&state),
        Ok(RevocationDecision::Raise(RevocationState {
            revoked_through: Some(5),
            ..state
        }))
    );
    assert_eq!(
        verified.high_water_decision(&RevocationState {
            revoked_through: Some(5),
            ..state
        }),
        Ok(RevocationDecision::Idempotent)
    );
    assert_eq!(
        verified.high_water_decision(&RevocationState {
            revoked_through: Some(7),
            ..state
        }),
        Ok(RevocationDecision::Idempotent)
    );
    let wrong_scope = RevocationState {
        scope: KeyBindingScope {
            network_id: [0; 32],
            identity: record.identity,
        },
        revoked_through: None,
    };
    assert_eq!(
        verified.high_water_decision(&wrong_scope),
        Err(RevocationDecisionError::ScopeMismatch)
    );
    let mut tampered = values["revocation"].clone();
    tampered[40] ^= 1;
    assert_eq!(
        Revocation::decode(&tampered).expect("canonical").verify(),
        Err(RevocationSignatureError::InvalidSignature)
    );
    let mut version = values["revocation"].clone();
    version[1] = 2;
    assert_eq!(
        Revocation::decode(&version),
        Err(RevocationDecodeError::UnsupportedVersion)
    );
    let mut trailing = values["revocation"].clone();
    trailing.push(0);
    assert_eq!(
        Revocation::decode(&trailing),
        Err(RevocationDecodeError::InvalidEncoding)
    );
    let mut noncanonical = values["revocation"].clone();
    noncanonical.splice(1..2, [0x18, 0x01]);
    assert_eq!(
        Revocation::decode(&noncanonical),
        Err(RevocationDecodeError::InvalidEncoding)
    );
    assert_eq!(
        Revocation::decode_and_verify(&noncanonical),
        Err(RevocationInputError::Decode(
            RevocationDecodeError::InvalidEncoding
        ))
    );
}

#[test]
fn zero_counters_and_header_body_mismatch_are_rejected() {
    let header = RelayHeader::new(RelayType::Presence, [1; 16], [0; 16]).expect("header");
    let presence = Presence {
        incarnation: 0,
        seq: 0,
        mac: [0; 32],
    };
    assert_eq!(
        RelayDatagram {
            header,
            body: RelayBody::Presence(presence)
        }
        .encode(),
        Err(RelayEncodeError::InvalidBody)
    );
    let reflect = Reflect {
        incarnation: 0,
        seq: 0,
        nonce: [0; 16],
        mac: [0; 32],
    };
    assert!(
        RelayDatagram {
            header: RelayHeader::new(RelayType::Reflect, [1; 16], [0; 16]).expect("header"),
            body: RelayBody::Reflect(reflect)
        }
        .encode()
        .is_err()
    );
    assert_eq!(
        RelayDatagram {
            header,
            body: RelayBody::Data(vec![1])
        }
        .encode(),
        Err(RelayEncodeError::TypeMismatch)
    );
}
