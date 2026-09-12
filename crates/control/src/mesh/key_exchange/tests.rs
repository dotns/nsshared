use ed25519_dalek::{Signer as _, SigningKey};
use secrecy::ExposeSecret as _;

use super::*;
use crate::envelope::ControlEnvelope;
use crate::mesh::{SyncFrame, SyncMessage};

#[path = "../../../tests/fixtures/mesh-key-v1/oracle.rs"]
mod oracle;

fn public(seed: u8) -> [u8; 32] {
    SigningKey::from_bytes(&[seed; 32])
        .verifying_key()
        .to_bytes()
}
fn request() -> KeyRequest {
    KeyRequest {
        network_pub: public(12),
        requester: KeyPeerBinding {
            signing_pub: public(11),
            wg_pub: [4; 32],
            incarnation: 2,
        },
        grantor: KeyPeerBinding {
            signing_pub: public(13),
            wg_pub: [6; 32],
            incarnation: 1,
        },
        version: SyncVersion {
            history_seq: 7,
            history_digest: [3; 32],
            owners_digest: [5; 32],
        },
    }
}
fn fixtures() -> serde_json::Value {
    serde_json::from_str(include_str!(
        "../../../tests/fixtures/mesh-key-v1/vectors.json"
    ))
    .unwrap()
}
pub(super) fn bytes(index: usize, field: &str) -> Vec<u8> {
    hex::decode(fixtures()["vectors"][index][field].as_str().unwrap()).unwrap()
}
pub(super) fn envelope(index: usize) -> ControlEnvelope {
    ControlEnvelope::from_cbor(&bytes(index, "envelope_hex")).unwrap()
}
fn key_frame(bytes: &[u8]) -> KeyEnvelope {
    match decode_wg_peer_frame(bytes).unwrap() {
        WgPeerFrame::Key(envelope) => envelope,
        WgPeerFrame::Sync(_) => panic!("key fixture decoded as history"),
    }
}
fn encode(value: &Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(value, &mut bytes).unwrap();
    bytes
}
fn frame(value: &Value) -> Vec<u8> {
    let bytes = encode(value);
    [(bytes.len() as u32).to_be_bytes().as_slice(), &bytes].concat()
}

#[test]
fn mesh_key_independent_vectors_cover_full_envelopes_prefix_and_signature_domains() {
    assert_eq!(oracle::vectors(), fixtures());
    let request = request();
    assert_eq!(request.encode().unwrap(), bytes(0, "payload_hex"));
    assert_eq!(
        KeyRequest::decode(&bytes(0, "payload_hex")).unwrap(),
        request
    );
    let grant =
        KeyGrant::new(request.clone(), [2; 16], SecretBox::new(Box::new([12; 32]))).unwrap();
    assert_eq!(
        grant.encode().unwrap().expose_secret(),
        &bytes(1, "payload_hex")
    );
    let request_frame = key_frame(&bytes(0, "frame_hex"));
    assert_eq!(
        request_frame
            .verify_request(&request.grantor, 1000)
            .unwrap(),
        request
    );
    let grant_frame = key_frame(&bytes(1, "frame_hex"));
    let decoded = grant_frame.verify_grant(&request, &[2; 16], 1001).unwrap();
    assert_eq!(decoded.network_secret().expose_secret(), &[12; 32]);
    for (index, decoded) in [request_frame, grant_frame].iter().enumerate() {
        assert_eq!(
            decoded.encode().unwrap().expose_secret(),
            &bytes(index, "frame_hex")
        );
    }
    assert!(envelope(0).verify_response(1000, &public(11)).is_err());
    assert!(envelope(1).verify_request(1001).is_err());
    assert!(envelope(1).verify_response(1001, &public(14)).is_err());
}

#[test]
fn mesh_key_grants_bind_full_peers_version_nonce_network_and_secret() {
    let key = key_frame(&bytes(1, "frame_hex"));
    for case in 0..10 {
        let mut expected = request();
        match case {
            0 => expected.network_pub = public(14),
            1 => expected.requester.signing_pub = public(14),
            2 => expected.requester.wg_pub = [14; 32],
            3 => expected.requester.incarnation += 1,
            4 => expected.grantor.signing_pub = public(14),
            5 => expected.grantor.wg_pub = [14; 32],
            6 => expected.grantor.incarnation += 1,
            7 => expected.version.history_seq += 1,
            8 => expected.version.history_digest = [14; 32],
            _ => expected.version.owners_digest = [14; 32],
        }
        assert!(key.verify_grant(&expected, &[2; 16], 1001).is_err());
    }
    assert!(key.verify_grant(&request(), &[3; 16], 1001).is_err());
    assert!(key.verify_grant(&request(), &[2; 16], 1062).is_err());
    assert!(KeyGrant::new(request(), [2; 16], SecretBox::new(Box::new([14; 32]))).is_err());
    let mut wrong_author = envelope(0);
    wrong_author.machine_key_pub = public(14);
    assert!(
        KeyEnvelope::from_envelope(wrong_author)
            .unwrap()
            .verify_request(&request().grantor, 1000)
            .is_err()
    );
    let outsider = SigningKey::from_bytes(&[14; 32]);
    let signed = ControlEnvelope::sign_request(
        KeyRequest::API,
        None,
        public(14),
        request().encode().unwrap(),
        |input| outsider.sign(input).to_bytes(),
    )
    .unwrap();
    let now = signed.ts;
    signed.verify_request(now).unwrap();
    assert!(
        KeyEnvelope::from_envelope(signed)
            .unwrap()
            .verify_request(&request().grantor, now)
            .is_err()
    );
    let mut forged = envelope(1);
    forged.signature[0] ^= 1;
    assert!(
        KeyEnvelope::from_envelope(forged)
            .unwrap()
            .verify_grant(&request(), &[2; 16], 1001)
            .is_err()
    );
}

#[test]
fn mesh_key_payloads_reject_bad_shapes_and_keep_optional_field_policy() {
    let mut same = request();
    same.grantor = same.requester;
    assert!(same.encode().is_err());
    let mut zero = request();
    zero.requester.incarnation = 0;
    assert!(zero.encode().is_err());
    for index in 0..2 {
        let original: Value =
            ciborium::de::from_reader(bytes(index, "payload_hex").as_slice()).unwrap();
        for case in 0..5 {
            let mut value = original.clone();
            let Value::Map(fields) = &mut value else {
                panic!("map")
            };
            match case {
                0 => fields[0].1 = 2_u64.to_value(),
                1 => fields.push(fields[0].clone()),
                2 => {
                    fields.remove(1);
                }
                3 => fields[1].1 = vec![1_u8; 31].to_value(),
                _ => fields.push((99_u64.to_value(), Value::Float(1.0))),
            }
            let malformed = encode(&value);
            if index == 0 {
                assert!(KeyRequest::decode(&malformed).is_err());
            } else {
                assert!(KeyGrant::decode(&malformed).is_err());
            }
        }
        let Value::Map(mut fields) = original else {
            panic!("map")
        };
        fields.push((99_u64.to_value(), Value::Bool(true)));
        let extended = encode(&Value::Map(fields));
        if index == 0 {
            assert_eq!(KeyRequest::decode(&extended).unwrap(), request());
        } else {
            assert_eq!(KeyGrant::decode(&extended).unwrap().request(), &request());
        }
        let mut trailing = bytes(index, "payload_hex");
        trailing.push(0);
        if index == 0 {
            assert!(KeyRequest::decode(&trailing).is_err());
        } else {
            assert!(KeyGrant::decode(&trailing).is_err());
        }
    }
    let mut seed_width: Value =
        ciborium::de::from_reader(bytes(1, "payload_hex").as_slice()).unwrap();
    let Value::Map(fields) = &mut seed_width else {
        panic!("map")
    };
    fields[3].1 = Value::Bytes(vec![12; 31]);
    assert!(KeyGrant::decode(&encode(&seed_width)).is_err());
}

#[test]
fn mesh_key_wg_framing_is_disjoint_bounded_and_never_falls_back() {
    let sync = SyncFrame {
        network_pub: public(12),
        version: request().version,
        message: SyncMessage::Digest { owner_count: 0 },
    };
    assert!(matches!(
        decode_wg_peer_frame(&sync.encode().unwrap()).unwrap(),
        WgPeerFrame::Sync(_)
    ));
    for index in 0..2 {
        let valid = bytes(index, "frame_hex");
        for size in [0, 3, valid.len() - 1] {
            assert!(decode_wg_peer_frame(&valid[..size]).is_err());
        }
        assert!(decode_wg_peer_frame(&[valid.clone(), vec![0]].concat()).is_err());
        let original: Value = ciborium::de::from_reader(&valid[4..]).unwrap();
        for case in 0..5 {
            let mut value = original.clone();
            let Value::Map(fields) = &mut value else {
                panic!("map")
            };
            match case {
                0 => fields.push((0_u64.to_value(), 1_u64.to_value())),
                1 => fields.push(fields[0].clone()),
                2 => fields[1].1 = Value::Text("mesh.register".into()),
                3 => fields[4].1 = Value::Text("managed".into()),
                _ => fields.push((Value::Text("optional".into()), Value::Float(1.0))),
            }
            assert!(decode_wg_peer_frame(&frame(&value)).is_err());
        }
        let Value::Map(mut fields) = original else {
            panic!("map")
        };
        fields.push((
            Value::Text("optional".into()),
            Value::Bytes(vec![0; MAX_KEY_FRAME]),
        ));
        assert!(decode_wg_peer_frame(&frame(&Value::Map(fields))).is_err());
    }
    assert!(decode_wg_peer_frame(&65533_u32.to_be_bytes()).is_err());
    assert!(decode_wg_peer_frame(&0_u32.to_be_bytes()).is_err());
}

#[test]
fn mesh_key_exact_total_limit_and_nonminimal_encodings_are_rejected_before_use() {
    for index in 0..2 {
        let original: Value =
            ciborium::de::from_reader(bytes(index, "envelope_hex").as_slice()).unwrap();
        let Value::Map(mut fields) = original else {
            panic!("map")
        };
        fields.push((Value::Text("optional".into()), Value::Bytes(Vec::new())));
        let mut found = false;
        for length in 0..MAX_KEY_FRAME {
            fields.last_mut().unwrap().1 = Value::Bytes(vec![0; length]);
            let encoded = frame(&Value::Map(fields.clone()));
            if encoded.len() == MAX_KEY_FRAME {
                assert!(decode_wg_peer_frame(&encoded).is_ok());
                fields.last_mut().unwrap().1 = Value::Bytes(vec![0; length + 1]);
                let overflow = frame(&Value::Map(fields.clone()));
                assert_eq!(overflow.len(), MAX_KEY_FRAME + 1);
                assert!(decode_wg_peer_frame(&overflow).is_err());
                found = true;
                break;
            }
        }
        assert!(found);
        let payload = bytes(index, "payload_hex");
        let mut nonminimal = payload.clone();
        nonminimal.splice(2..3, [0x18, 0x01]);
        let mut indefinite = payload.clone();
        indefinite[0] = 0xbf;
        indefinite.push(0xff);
        for malformed in [nonminimal, indefinite] {
            if index == 0 {
                assert!(KeyRequest::decode(&malformed).is_err());
            } else {
                assert!(KeyGrant::decode(&malformed).is_err());
            }
        }
        let mut indefinite = bytes(index, "envelope_hex");
        indefinite[0] = 0xbf;
        indefinite.push(0xff);
        let framed = [
            (indefinite.len() as u32).to_be_bytes().as_slice(),
            &indefinite,
        ]
        .concat();
        assert!(decode_wg_peer_frame(&framed).is_err());
    }
}

#[test]
fn mesh_key_secret_debug_is_redacted_and_encoding_stays_explicit() {
    let grant = KeyGrant::decode(&bytes(1, "payload_hex")).unwrap();
    let debug = format!("{grant:?}");
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains(&format!("{:?}", [12; 32])));
    let envelope = key_frame(&bytes(1, "frame_hex"));
    let debug = format!("{envelope:?}");
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains(&hex::encode(bytes(1, "payload_hex"))));
    let key = SigningKey::from_bytes(&[13; 32]);
    let signed = KeyEnvelope::sign_grant(&grant, |input| key.sign(input).to_bytes()).unwrap();
    assert!(signed.encode().is_ok());
}

#[test]
fn mesh_key_guarded_grant_uses_fresh_nonce_and_live_response_domain() {
    let grant = KeyGrant::decode(&bytes(1, "payload_hex")).unwrap();
    let key = SigningKey::from_bytes(&[13; 32]);
    let first = KeyEnvelope::sign_grant(&grant, |input| key.sign(input).to_bytes()).unwrap();
    let second = KeyEnvelope::sign_grant(&grant, |input| key.sign(input).to_bytes()).unwrap();
    assert_ne!(first.nonce(), second.nonce());
    assert_ne!(first.nonce(), grant.request_nonce());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let encoded = first.encode().unwrap();
    let decoded = key_frame(encoded.expose_secret());
    let verified = decoded
        .verify_grant(grant.request(), grant.request_nonce(), now)
        .unwrap();
    assert_eq!(
        verified.network_secret().expose_secret(),
        grant.network_secret().expose_secret()
    );
    assert!(
        decoded
            .verify_request(&grant.request().grantor, now)
            .is_err()
    );
    let envelope = ControlEnvelope::from_cbor(&encoded.expose_secret()[4..]).unwrap();
    assert_eq!(envelope.machine_id, None);
    assert_eq!(envelope.v, 1);
    assert!(envelope.verify_response(now, &public(14)).is_err());
}
