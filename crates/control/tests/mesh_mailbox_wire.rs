use control::envelope::{ControlEnvelope, DOMAIN_REQUEST};
use control::mesh::*;
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};

fn envelope(api: &str, ts: u64, payload: Vec<u8>, key: &SigningKey) -> ControlEnvelope {
    let mut input = DOMAIN_REQUEST.to_vec();
    input.push(1);
    input.extend_from_slice(&u32::try_from(api.len()).unwrap().to_be_bytes());
    input.extend_from_slice(api.as_bytes());
    input.extend_from_slice(&ts.to_be_bytes());
    input.extend_from_slice(&[7; 16]);
    input.push(0);
    input.extend_from_slice(&key.verifying_key().to_bytes());
    input.extend_from_slice(&Sha256::digest(&payload));
    ControlEnvelope {
        v: 1,
        api: api.into(),
        ts,
        nonce: [7; 16],
        machine_id: None,
        machine_key_pub: key.verifying_key().to_bytes(),
        payload: payload.into(),
        signature: key.sign(&input).to_bytes(),
    }
}

fn control_budget(name: &str, raw: &[u8]) {
    let udp = encode_udp(raw).unwrap();
    let wss = encode_wss(WssFrame::Control(raw), 0).unwrap();
    assert!(udp.len() <= MAX_CONTROL_FRAME, "{name}");
    assert!(wss.len() <= MAX_CONTROL_FRAME, "{name}");
    assert_eq!(decode_udp(&udp).unwrap(), raw);
    assert!(matches!(decode_wss(&wss, 0).unwrap(), WssFrame::Control(bytes) if bytes == raw));
    eprintln!("maximum {name}: UDP={}, WSS={}", udp.len(), wss.len());
}

fn addresses() -> OverlayAddresses {
    OverlayAddresses {
        v4: [100, 64, 1, 2],
        v4_salt: 0,
        v6: [0xfd; 16],
    }
}

fn accept() -> Accept {
    Accept {
        network_pub: SigningKey::from_bytes(&[1; 32]).verifying_key().to_bytes(),
        network_name: "home".into(),
        relay_origin: "udp://relay.example:51821".into(),
        approver_wg: [2; 32],
        joiner_id: member_id(&SigningKey::from_bytes(&[3; 32]).verifying_key().to_bytes()),
        joiner_pub: SigningKey::from_bytes(&[3; 32]).verifying_key().to_bytes(),
        joiner_wg: [4; 32],
        request_id: [5; 16],
        member_incarnation: 1,
        capabilities: CAPABILITY_EXIT,
        joiner_addrs: addresses(),
        approver_addrs: addresses(),
        added_at: 100,
        expires_at: 160,
        network_sig: [0; 64],
    }
}

fn signed_accept() -> (Accept, ControlEnvelope) {
    let mut value = accept();
    value.network_sig = SigningKey::from_bytes(&[1; 32])
        .sign(&value.network_signing_input().unwrap())
        .to_bytes();
    let envelope = envelope(
        Accept::API,
        100,
        value.encode().unwrap(),
        &SigningKey::from_bytes(&[9; 32]),
    );
    (value, envelope)
}

#[test]
fn mesh_accept_preserves_dual_signatures_and_join_binding() {
    let (value, original) = signed_accept();
    assert_eq!(Accept::verify_historical(&original).unwrap(), value);
    let mut binding = JoinBinding {
        network_pub: value.network_pub,
        joiner_id: value.joiner_id,
        joiner_pub: value.joiner_pub,
        joiner_wg: value.joiner_wg,
        request_id: value.request_id,
        deadline: 160,
    };
    value.verify_join(&binding, 159).unwrap();
    assert!(value.verify_join(&binding, 160).is_err());
    binding.request_id[0] ^= 1;
    assert!(value.verify_join(&binding, 110).is_err());
    binding.request_id = value.request_id;
    binding.network_pub[0] ^= 1;
    assert!(value.verify_join(&binding, 110).is_err());
    for field in 0..15 {
        let mut invalid = value.clone();
        match field {
            0 => invalid.network_pub[0] ^= 1,
            1 => invalid.network_name.push('x'),
            2 => invalid.relay_origin = "udp://other.example:51821".into(),
            3 => invalid.approver_wg[0] ^= 1,
            4 => invalid.joiner_id[0] ^= 1,
            5 => invalid.joiner_wg[0] ^= 1,
            6 => invalid.request_id[0] ^= 1,
            7 => invalid.member_incarnation += 1,
            8 => invalid.capabilities = 0,
            9 => invalid.joiner_addrs.v4_salt += 1,
            10 => invalid.approver_addrs.v6[0] ^= 1,
            11 => invalid.added_at += 1,
            12 => invalid.expires_at -= 1,
            13 => invalid.network_sig[0] ^= 1,
            _ => invalid.joiner_pub[0] ^= 1,
        }
        assert!(invalid.verify_network_signature().is_err());
    }
    let retimed = envelope(
        Accept::API,
        101,
        value.encode().unwrap(),
        &SigningKey::from_bytes(&[9; 32]),
    );
    assert!(Accept::verify_historical(&retimed).is_err());
    let mut forged = original;
    forged.signature[0] ^= 1;
    assert!(Accept::verify_historical(&forged).is_err());
}

#[test]
fn mesh_network_proof_and_vouch_bind_registration_nonce() {
    let key = SigningKey::from_bytes(&[1; 32]);
    let mut registration = Register {
        network_pub: key.verifying_key().to_bytes(),
        wg_pub: [2; 32],
        member_incarnation: 1,
        allocate_pin: None,
        network_proof: None,
        vouch: None,
    };
    registration.network_proof = Some(
        key.sign(
            &registration
                .network_proof_input(&[3; 16], &[4; 32])
                .unwrap(),
        )
        .to_bytes(),
    );
    registration
        .verify_network_proof(&[3; 16], &[4; 32])
        .unwrap();
    assert!(
        registration
            .verify_network_proof(&[5; 16], &[4; 32])
            .is_err()
    );
    assert!(
        registration
            .verify_network_proof(&[3; 16], &[5; 32])
            .is_err()
    );
    let mut value = Vouch {
        network_pub: [1; 32],
        member_id: [2; 20],
        member_wg: [3; 32],
        incarnation: 1,
        register_nonce: [4; 16],
        issued_at: 100,
        expires_at: 160,
        signature: [0; 64],
    };
    value.signature = key.sign(&value.signing_input().unwrap()).to_bytes();
    let original = envelope(Vouch::API, 100, value.encode().unwrap(), &key);
    assert_eq!(Vouch::verify_historical(&original).unwrap(), value);
    value.register_nonce[0] ^= 1;
    let modified = envelope(Vouch::API, 100, value.encode().unwrap(), &key);
    assert!(Vouch::verify_historical(&modified).is_err());
}

fn admins() -> Vec<u8> {
    (0..32).flat_map(|n| [n; 20]).collect()
}

#[test]
fn mesh_management_originals_are_authenticated_and_bounded() {
    let key = SigningKey::from_bytes(&[5; 32]);
    for (kind, body) in [
        (
            SignedManagementRecord::ADMINS,
            Admins {
                admins: admins(),
                admins_revision: u64::MAX,
            }
            .encode()
            .unwrap(),
        ),
        (
            SignedManagementRecord::EVICT,
            Eviction {
                member_id: [3; 20],
                incarnation: u64::MAX,
                reason: "r".repeat(128),
                member_pub: [4; 32],
            }
            .encode()
            .unwrap(),
        ),
    ] {
        let mut record = SignedManagementRecord {
            kind,
            network_pub: [1; 32],
            op_id: [2; 16],
            author_pub: key.verifying_key().to_bytes(),
            issued_at: u64::MAX - 60,
            expires_at: u64::MAX,
            body,
            signature: [0; 64],
        };
        record.signature = key.sign(&record.signing_input().unwrap()).to_bytes();
        record.verify().unwrap();
        let encoded = record.encode().unwrap();
        let wrapped = envelope(
            if kind == 0 {
                Eviction::API
            } else {
                Admins::API
            },
            u64::MAX,
            encoded.clone(),
            &key,
        )
        .to_cbor()
        .unwrap();
        control_budget(
            if kind == 0 {
                Eviction::API
            } else {
                Admins::API
            },
            &wrapped,
        );
        let sequenced = Sequenced {
            network_pub: [1; 32],
            seq: u64::MAX,
            record: encoded,
        };
        let sequenced = envelope(Sequenced::API, u64::MAX, sequenced.encode().unwrap(), &key)
            .to_cbor()
            .unwrap();
        control_budget(
            if kind == 0 {
                "sequenced-eviction"
            } else {
                "sequenced-admins"
            },
            &sequenced,
        );
        record.op_id[0] ^= 1;
        assert!(record.verify().is_err());
    }
    assert!(
        Admins {
            admins: vec![0; 640],
            admins_revision: 1
        }
        .encode()
        .is_err()
    );
    assert!(
        Admins {
            admins: vec![0; 641],
            admins_revision: 1
        }
        .encode()
        .is_err()
    );
    assert!(
        Admins {
            admins: vec![],
            admins_revision: 1
        }
        .encode()
        .is_ok()
    );
}

#[test]
fn mesh_mailbox_vectors_and_registration_budget() {
    let cookie = Cookie {
        nonce: [1; 16],
        cookie: [2; 16],
    };
    let expected = hex::decode(format!(
        "a300010150{}0250{}",
        "01".repeat(16),
        "02".repeat(16)
    ))
    .unwrap();
    assert_eq!(cookie.encode().unwrap(), expected);
    assert_eq!(Cookie::decode(&expected).unwrap(), cookie);
    let key = SigningKey::from_bytes(&[5; 32]);
    let mut value = accept();
    value.network_name = "n".repeat(64);
    value.relay_origin = format!(
        "https://{}.{}.{}.{}:9443",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(50)
    );
    value.member_incarnation = u64::MAX;
    value.joiner_addrs.v4_salt = u64::from(u32::MAX);
    value.approver_addrs.v4_salt = u64::from(u32::MAX);
    value.added_at = u64::MAX - 60;
    value.expires_at = u64::MAX;
    let original = envelope(Accept::API, value.added_at, value.encode().unwrap(), &key)
        .to_cbor()
        .unwrap();
    control_budget(Accept::API, &original);
    let registration = Register {
        network_pub: [1; 32],
        wg_pub: [2; 32],
        member_incarnation: u64::MAX,
        allocate_pin: Some(PinRequest { ttl_secs: u64::MAX }),
        network_proof: None,
        vouch: Some(original),
    };
    let registered = Registered {
        nonce: [1; 16],
        status: Registered::REGISTERED,
        network_pub: [1; 32],
        pin: Some(PinInfo {
            value: "KX-83920174".into(),
            expires_in_secs: 3600,
        }),
        admins: admins(),
        admins_revision: u64::MAX,
        latest_seq: u64::MAX,
        observed_addr: ObservedEndpoint {
            ip: vec![1; 16],
            port: 65535,
        },
        relay_key: [4; 32],
        ttl_secs: u64::MAX,
        slot_status: Registered::SLOT_BOUND,
        anchor: None,
        creation_receipt: None,
    };
    let join = Join {
        pin: "KX-83920174".into(),
        joiner_wg: [1; 32],
        capabilities: 1,
        expires_at: u64::MAX,
        cookie: Some([2; 16]),
        request_id: [3; 16],
    };
    let deny = Deny {
        request_id: [1; 16],
        joiner_id: [2; 20],
        reason: "r".repeat(128),
    };
    let resolved = Resolved {
        network_pub: [1; 32],
        request_id: [2; 16],
        joiner_id: [3; 20],
        approver_id: [4; 20],
        seq: u64::MAX,
    };
    let unbind = Unbind {
        network_pub: [1; 32],
    };
    for (api, bytes) in [
        (Register::API, registration.encode().unwrap()),
        (Registered::API, registered.encode().unwrap()),
        (Join::API, join.encode().unwrap()),
        (Deny::API, deny.encode().unwrap()),
        (Resolved::API, resolved.encode().unwrap()),
        (Unbind::API, unbind.encode().unwrap()),
    ] {
        let encoded = envelope(api, u64::MAX, bytes, &key).to_cbor().unwrap();
        control_budget(api, &encoded);
    }
    assert_eq!(
        Register::decode(&registration.encode().unwrap()).unwrap(),
        registration
    );
    assert_eq!(
        Registered::decode(&registered.encode().unwrap()).unwrap(),
        registered
    );
    assert_eq!(Join::decode(&join.encode().unwrap()).unwrap(), join);
    assert_eq!(Deny::decode(&deny.encode().unwrap()).unwrap(), deny);
    assert_eq!(
        Resolved::decode(&resolved.encode().unwrap()).unwrap(),
        resolved
    );
    assert_eq!(Unbind::decode(&unbind.encode().unwrap()).unwrap(), unbind);
}

#[test]
fn mesh_registered_optional_genesis_and_recovery_frames_fit_both_carriers() {
    let key = SigningKey::from_bytes(&[5; 32]);
    let mut receipt = CommitReceipt {
        network_pub: [1; 32],
        op_id: [2; 16],
        author_pub: [3; 32],
        seq: 0,
        record_digest: [4; 32],
        signature: [0; 64],
    };
    receipt.signature = key.sign(&receipt.signing_input()).to_bytes();
    receipt.verify(&key.verifying_key().to_bytes()).unwrap();
    let mut value = Registered {
        nonce: [2; 16],
        status: Registered::REGISTERED,
        network_pub: receipt.network_pub,
        pin: Some(PinInfo {
            value: "KX-83920174".into(),
            expires_in_secs: 3600,
        }),
        admins: Vec::new(),
        admins_revision: 0,
        latest_seq: 0,
        observed_addr: ObservedEndpoint {
            ip: vec![1; 16],
            port: 65535,
        },
        relay_key: key.verifying_key().to_bytes(),
        ttl_secs: u64::MAX,
        slot_status: Registered::SLOT_BOUND,
        anchor: None,
        creation_receipt: Some(receipt.encode().unwrap()),
    };
    for name in ["registered-genesis", "registered-recovery"] {
        let payload = value.encode().unwrap();
        assert_eq!(Registered::decode(&payload).unwrap(), value);
        let raw = envelope(Registered::API, u64::MAX, payload, &key)
            .to_cbor()
            .unwrap();
        control_budget(name, &raw);
        value.status = Registered::RECOVERING;
        value.pin = None;
        value.creation_receipt = None;
        value.anchor = Some(AnchorChallenge {
            anchor_seq: u64::MAX,
            state_digest: [4; 32],
            format_version: 1,
        });
    }
}

#[test]
fn mesh_origin_and_pin_reject_ambiguous_inputs() {
    for valid in [
        "udp://relay.example:51821",
        "udp://127.0.0.1:51821",
        "wss://[::1]:443",
        "https://relay.example:443",
    ] {
        validate_relay_origin(valid).unwrap();
    }
    for invalid in [
        "udp://relay.example",
        "udp://user@relay.example:51821",
        "wss://relay.example:443/path",
        "wss://relay.example:443?x=1",
        "udp://relay.example:51821#key",
        "https://RELAY.example:443",
        "http://relay.example:80",
    ] {
        assert!(validate_relay_origin(invalid).is_err(), "{invalid}");
    }
    for pin in [
        "",
        "IX-83920174",
        "KX-8392017",
        "KX-8392017a",
        "kx-83920174",
    ] {
        assert!(
            Join {
                pin: pin.into(),
                joiner_wg: [1; 32],
                capabilities: 0,
                expires_at: 1,
                cookie: None,
                request_id: [2; 16]
            }
            .encode()
            .is_err()
        );
    }
}
