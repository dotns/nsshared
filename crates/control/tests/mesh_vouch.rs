use std::collections::{BTreeMap, BTreeSet};

use control::envelope::ControlEnvelope;
use control::mesh::*;
use ed25519_dalek::{Signer as _, SigningKey};
use sha2::{Digest as _, Sha256};

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}
fn public(seed: u8) -> [u8; 32] {
    key(seed).verifying_key().to_bytes()
}
fn state() -> CompactState {
    CompactState {
        network_pub: public(12),
        seq: 9,
        members: BTreeMap::from([
            (
                public(11),
                CompactMember {
                    wg_pub: [4; 32],
                    incarnation: 1,
                },
            ),
            (
                public(14),
                CompactMember {
                    wg_pub: [6; 32],
                    incarnation: 3,
                },
            ),
        ]),
        admins_revision: 2,
        admins: BTreeSet::from([public(11)]),
        evicted_through: BTreeMap::from([(public(14), 2)]),
    }
}

// Independent request-domain construction, without the production signing helper.
fn resign(envelope: &mut ControlEnvelope, author: u8) {
    let mut input = b"nsio-ctrl-v1\0".to_vec();
    input.push(envelope.v);
    input.extend_from_slice(&u32::try_from(envelope.api.len()).unwrap().to_be_bytes());
    input.extend_from_slice(envelope.api.as_bytes());
    input.extend_from_slice(&envelope.ts.to_be_bytes());
    input.extend_from_slice(&envelope.nonce);
    input.push(0);
    input.extend_from_slice(&envelope.machine_key_pub);
    input.extend_from_slice(&Sha256::digest(&envelope.payload));
    envelope.signature = key(author).sign(&input).to_bytes();
}
fn envelope(api: &str, author: u8, payload: Vec<u8>) -> ControlEnvelope {
    let mut result = ControlEnvelope {
        v: 1,
        api: api.into(),
        ts: 1000,
        nonce: [2; 16],
        machine_id: None,
        machine_key_pub: public(author),
        payload: payload.into(),
        signature: [0; 64],
    };
    resign(&mut result, author);
    result
}
fn vouch() -> Vouch {
    Vouch {
        network_pub: public(12),
        member_id: member_id(&public(14)),
        member_wg: [6; 32],
        incarnation: 3,
        register_nonce: [2; 16],
        issued_at: 1000,
        expires_at: 1060,
        signature: [0; 64],
    }
}
fn registration(mut vouch: Vouch, author: u8) -> ControlEnvelope {
    vouch.signature = key(author).sign(&vouch.signing_input().unwrap()).to_bytes();
    let credential = envelope(Vouch::API, author, vouch.encode().unwrap());
    with_credential(credential.to_cbor().unwrap())
}
fn with_credential(raw: Vec<u8>) -> ControlEnvelope {
    envelope(
        Register::API,
        14,
        Register {
            network_pub: public(12),
            wg_pub: [6; 32],
            member_incarnation: 3,
            allocate_pin: None,
            network_proof: None,
            vouch: Some(raw),
            recovery_intent: None,
        }
        .encode()
        .unwrap(),
    )
}

#[test]
fn mesh_vouch_maximum_registration_preserves_proofs_and_transport_budgets() {
    let now = u64::MAX - 60;
    let mut current = state();
    current.seq = u64::MAX;
    current.admins_revision = u64::MAX;
    current.members.get_mut(&public(14)).unwrap().incarnation = u64::MAX;
    current.evicted_through.insert(public(14), u64::MAX - 1);
    let canonical = current.encode().unwrap();
    let mut credential = vouch();
    credential.incarnation = u64::MAX;
    credential.issued_at = now;
    credential.expires_at = u64::MAX;
    credential.signature = key(11)
        .sign(&credential.signing_input().unwrap())
        .to_bytes();
    let mut signed = envelope(Vouch::API, 11, credential.encode().unwrap());
    signed.ts = now;
    resign(&mut signed, 11);
    for proof in [false, true] {
        for allocate_pin in [false, true] {
            let mut request = with_credential(signed.to_cbor().unwrap());
            request.ts = now;
            let mut payload = Register::decode(&request.payload).unwrap();
            payload.member_incarnation = u64::MAX;
            payload.allocate_pin = allocate_pin.then_some(PinRequest { ttl_secs: u64::MAX });
            if proof {
                payload.network_proof = Some(
                    key(12)
                        .sign(
                            &payload
                                .network_proof_input(&request.nonce, &request.machine_key_pub)
                                .unwrap(),
                        )
                        .to_bytes(),
                );
                payload
                    .verify_network_proof(&request.nonce, &request.machine_key_pub)
                    .unwrap();
            }
            request.payload = payload.encode().unwrap().into();
            resign(&mut request, 14);
            current.verify_registration_vouch(&request, now).unwrap();
            let raw = request.to_cbor().unwrap();
            let udp = encode_udp(&raw).unwrap();
            let wss = encode_wss(WssFrame::Control(&raw), 0).unwrap();
            assert!(udp.len() <= MAX_CONTROL_FRAME);
            assert!(wss.len() <= MAX_CONTROL_FRAME);
            assert_eq!(decode_udp(&udp).unwrap(), raw);
            assert!(matches!(
                decode_wss(&wss, 0).unwrap(),
                WssFrame::Control(bytes) if bytes == raw
            ));
            let received = ControlEnvelope::from_cbor(decode_udp(&udp).unwrap()).unwrap();
            current.verify_registration_vouch(&received, now).unwrap();
            assert_eq!(current.encode().unwrap(), canonical);
            eprintln!(
                "maximum vouch registration: proof={proof}, pin={allocate_pin}, UDP={}, WSS={}",
                udp.len(),
                wss.len()
            );
        }
    }
}

#[test]
fn mesh_vouch_matches_independent_openssl_registration_and_canonical_state_vector() {
    let vector: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/mesh-vouch-v1/vectors.json")).unwrap();
    let bytes = |name: &str| hex::decode(vector[name].as_str().unwrap()).unwrap();
    let current = state();
    assert_eq!(current.encode().unwrap(), bytes("canonical_hex"));
    assert_eq!(
        current.digest().unwrap().as_slice(),
        bytes("state_digest_hex")
    );
    let raw = bytes("register_hex");
    let request = ControlEnvelope::from_cbor(&raw).unwrap();
    current.verify_registration_vouch(&request, 1000).unwrap();
    assert_eq!(encode_udp(&raw).unwrap(), bytes("udp_hex"));
    assert_eq!(
        encode_wss(WssFrame::Control(&raw), 0).unwrap(),
        bytes("wss_hex")
    );
    for end in 0..raw.len() {
        assert!(ControlEnvelope::from_cbor(&raw[..end]).is_err());
    }
}

#[test]
fn mesh_vouch_attests_rejoined_member_without_reducing_saved_watermark_or_sequence() {
    let mut state = state();
    let request = registration(vouch(), 11);
    for admins in [BTreeSet::from([public(11)]), BTreeSet::new()] {
        state.admins = admins;
        let canonical = state.encode().unwrap();
        let digest = state.digest().unwrap();
        for now in [940, 1000, 1059] {
            state.verify_registration_vouch(&request, now).unwrap();
        }
        assert_eq!(state.encode().unwrap(), canonical);
        assert_eq!(state.digest().unwrap(), digest);
        assert_eq!(state.seq, 9);
        assert_eq!(state.evicted_through[&public(14)], 2);
    }
    let raw = request.to_cbor().unwrap();
    assert!(encode_udp(&raw).unwrap().len() <= 1200);
    assert!(encode_wss(WssFrame::Control(&raw), 0).unwrap().len() <= 1200);
}

#[test]
fn mesh_vouch_cannot_restore_absent_evicted_or_different_incarnation_targets() {
    let request = registration(vouch(), 11);
    for variant in 0..5 {
        let mut current = state();
        match variant {
            0 => {
                current.members.remove(&public(14));
            }
            1 => {
                current.members.remove(&public(14));
                current.evicted_through.insert(public(14), 3);
            }
            2 => {
                current.members.get_mut(&public(14)).unwrap().incarnation = 4;
            }
            3 => {
                current.members.get_mut(&public(14)).unwrap().wg_pub = [7; 32];
            }
            4 => {
                current.evicted_through.insert(public(14), 3);
            }
            _ => unreachable!(),
        }
        let before = current.clone();
        assert!(
            current.verify_registration_vouch(&request, 1000).is_err(),
            "variant {variant}"
        );
        assert_eq!(current, before);
    }
}

#[test]
fn mesh_vouch_requires_current_authority_and_exact_live_registration_binding() {
    let current = state();
    for author in [14, 15] {
        assert!(
            current
                .verify_registration_vouch(&registration(vouch(), author), 1000)
                .is_err()
        );
    }
    for variant in 0..7 {
        let mut value = vouch();
        match variant {
            0 => value.network_pub[0] ^= 1,
            1 => value.member_id[0] ^= 1,
            2 => value.member_wg[0] ^= 1,
            3 => value.incarnation = 4,
            4 => value.register_nonce[0] ^= 1,
            5 => {
                value.issued_at = 1001;
                value.expires_at = 1061;
            }
            6 => {
                value.issued_at = 940;
                value.expires_at = 1000;
            }
            _ => unreachable!(),
        }
        assert!(
            current
                .verify_registration_vouch(&registration(value, 11), 1000)
                .is_err()
        );
    }
    let request = registration(vouch(), 11);
    for now in [939, 1060, 1061] {
        assert!(current.verify_registration_vouch(&request, now).is_err());
    }
    let mut replay = request.clone();
    replay.nonce[0] ^= 1;
    resign(&mut replay, 14);
    assert!(current.verify_registration_vouch(&replay, 1000).is_err());
}

#[test]
fn mesh_vouch_rejects_each_signature_layer_and_does_not_treat_old_add_as_a_vouch() {
    let current = state();
    let request = registration(vouch(), 11);
    let mut bad = request.clone();
    bad.signature[0] ^= 1;
    assert!(current.verify_registration_vouch(&bad, 1000).is_err());
    let register = Register::decode(&request.payload).unwrap();
    let credential = ControlEnvelope::from_cbor(register.vouch.as_ref().unwrap()).unwrap();
    let mut bad = credential.clone();
    bad.signature[0] ^= 1;
    assert!(
        current
            .verify_registration_vouch(&with_credential(bad.to_cbor().unwrap()), 1000)
            .is_err()
    );
    let mut bad = credential;
    let mut inner = Vouch::decode(&bad.payload).unwrap();
    inner.signature[0] ^= 1;
    bad.payload = inner.encode().unwrap().into();
    resign(&mut bad, 11);
    assert!(
        current
            .verify_registration_vouch(&with_credential(bad.to_cbor().unwrap()), 1000)
            .is_err()
    );
    let suite: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/mesh-v1/vectors.json")).unwrap();
    for vector in suite["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|v| v["api"] == Accept::API)
    {
        let raw = hex::decode(vector["envelope_hex"].as_str().unwrap()).unwrap();
        assert!(
            current
                .verify_registration_vouch(&with_credential(raw), 1000)
                .is_err()
        );
    }
    assert!(
        current
            .verify_registration_vouch(&with_credential(vec![0]), 1000)
            .is_err()
    );
}
