use ciborium::value::Value;
use control::envelope::ControlEnvelope;
use control::mesh::{self, RestoreResult, WssFrame};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use sha2::{Digest as _, Sha256};

fn vectors() -> serde_json::Value {
    serde_json::from_str(include_str!("fixtures/mesh-restore-v1/vectors.json")).unwrap()
}
fn bytes(v: &serde_json::Value, field: &str) -> Vec<u8> {
    hex::decode(v[field].as_str().unwrap()).unwrap()
}
fn value(phase: u64, status: u64) -> RestoreResult {
    RestoreResult {
        network_pub: [1; 32],
        request_id: [2; 16],
        uploader_pub: [3; 32],
        anchor_seq: u64::MAX,
        state_digest: [4; 32],
        phase,
        chunk_index: (phase == 1).then_some(2047),
        status,
    }
}
fn encoded(v: &Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(v, &mut bytes).unwrap();
    bytes
}

#[test]
fn mesh_restore_result_matches_independent_complete_signed_vectors() {
    let key = SigningKey::from_bytes(&[13; 32]);
    let suite = vectors();
    assert_eq!(suite["vectors"].as_array().unwrap().len(), 9);
    for v in suite["vectors"].as_array().unwrap() {
        let result = value(v["phase"].as_u64().unwrap(), v["status"].as_u64().unwrap());
        let payload = bytes(v, "payload_hex");
        assert_eq!(result.encode().unwrap(), payload);
        assert_eq!(RestoreResult::decode(&payload).unwrap(), result);
        let raw = bytes(v, "envelope_hex");
        let envelope = ControlEnvelope::from_cbor(&raw).unwrap();
        assert_eq!(envelope.to_cbor().unwrap(), raw);
        assert_eq!(envelope.api, "mesh.restore.result");
        assert_eq!(envelope.payload.as_ref(), payload);
        assert_eq!(envelope.nonce, [5; 16]);
        assert_eq!(envelope.ts, 1000);
        assert_eq!(envelope.machine_id, None);
        // Independent reconstruction of the response signature input, not a production helper.
        let api = b"mesh.restore.result";
        let mut input = b"nsio-ctrl-v1-resp\0".to_vec();
        input.push(1);
        input.extend_from_slice(&u32::try_from(api.len()).unwrap().to_be_bytes());
        input.extend_from_slice(api);
        input.extend_from_slice(&1000_u64.to_be_bytes());
        input.extend_from_slice(&[5; 16]);
        input.push(0);
        input.extend_from_slice(&key.verifying_key().to_bytes());
        input.extend_from_slice(&Sha256::digest(&payload));
        assert_eq!(input, bytes(v, "signing_input_hex"));
        assert_eq!(key.sign(&input).to_bytes(), envelope.signature);
        VerifyingKey::from_bytes(&envelope.machine_key_pub)
            .unwrap()
            .verify_strict(&input, &Signature::from_bytes(&envelope.signature))
            .unwrap();
        mesh::verify_response(&envelope, 1000, &key.verifying_key().to_bytes()).unwrap();
        assert!(mesh::verify_request(&envelope, 1000).is_err());
        assert_eq!(mesh::encode_udp(&raw).unwrap(), bytes(v, "udp_hex"));
        assert_eq!(
            mesh::encode_wss(WssFrame::Control(&raw), 0).unwrap(),
            bytes(v, "wss_hex")
        );
        assert!(bytes(v, "udp_hex").len() <= 1200);
    }
}

#[test]
fn mesh_restore_result_rejects_every_illegal_phase_status_and_index_combination() {
    for phase in [0, 1, 2, 3, u64::MAX] {
        for status in [0, 1, 2, 3, 4, 5, u64::MAX] {
            for index in [None, Some(0), Some(2047), Some(2048), Some(u64::MAX)] {
                let mut result = value(phase, status);
                result.chunk_index = index;
                let valid = match phase {
                    0 => index.is_none() && [0, 3, 4].contains(&status),
                    1 => index.is_some_and(|i| i < 2048) && [0, 3].contains(&status),
                    2 => index.is_none() && [1, 2, 3, 4].contains(&status),
                    _ => false,
                };
                assert_eq!(result.encode().is_ok(), valid);
                let mut fields: Value =
                    ciborium::de::from_reader(value(0, 0).encode().unwrap().as_slice()).unwrap();
                let Value::Map(ref mut map) = fields else {
                    unreachable!()
                };
                map[6].1 = Value::Integer(phase.into());
                map[7].1 = index.map_or(Value::Null, |i| Value::Integer(i.into()));
                map[8].1 = Value::Integer(status.into());
                assert_eq!(RestoreResult::decode(&encoded(&fields)).is_ok(), valid);
            }
        }
    }
}

#[test]
fn mesh_restore_result_signature_binds_candidate_phase_index_status_and_request_nonce() {
    let key = SigningKey::from_bytes(&[13; 32]);
    let result = value(1, 0);
    let envelope = result
        .sign_response([9; 16], key.verifying_key().to_bytes(), |b| {
            key.sign(b).to_bytes()
        })
        .unwrap();
    assert_eq!(envelope.nonce, [9; 16]);
    mesh::verify_response(&envelope, envelope.ts, &key.verifying_key().to_bytes()).unwrap();
    for field in 0..8 {
        let mut wrong = result.clone();
        match field {
            0 => wrong.network_pub[0] ^= 1,
            1 => wrong.request_id[0] ^= 1,
            2 => wrong.uploader_pub[0] ^= 1,
            3 => wrong.anchor_seq -= 1,
            4 => wrong.state_digest[0] ^= 1,
            5 => {
                wrong.phase = 0;
                wrong.chunk_index = None;
            }
            6 => wrong.chunk_index = Some(0),
            _ => wrong.status = 3,
        }
        let mut altered = envelope.clone();
        altered.payload = wrong.encode().unwrap().into();
        assert!(
            mesh::verify_response(&altered, altered.ts, &key.verifying_key().to_bytes()).is_err()
        );
    }
    let mut altered = envelope.clone();
    altered.nonce[0] ^= 1;
    assert!(mesh::verify_response(&altered, altered.ts, &key.verifying_key().to_bytes()).is_err());
    assert!(
        mesh::verify_response(
            &envelope,
            envelope.ts,
            &SigningKey::from_bytes(&[14; 32]).verifying_key().to_bytes()
        )
        .is_err()
    );
}

#[test]
fn mesh_restore_result_rejects_ambiguous_truncated_missing_and_wrong_width_fields() {
    let wire = value(0, 0).encode().unwrap();
    for len in 0..wire.len() {
        assert!(RestoreResult::decode(&wire[..len]).is_err());
    }
    let fields: Value = ciborium::de::from_reader(wire.as_slice()).unwrap();
    let Value::Map(map) = fields else {
        unreachable!()
    };
    for i in 0..map.len() {
        let mut missing = map.clone();
        missing.remove(i);
        assert!(RestoreResult::decode(&encoded(&Value::Map(missing))).is_err());
        let mut duplicate = map.clone();
        duplicate.push(map[i].clone());
        assert!(RestoreResult::decode(&encoded(&Value::Map(duplicate))).is_err());
    }
    for i in [1, 2, 3, 5] {
        let mut bad = map.clone();
        bad[i].1 = Value::Bytes(vec![0; 31]);
        assert!(RestoreResult::decode(&encoded(&Value::Map(bad))).is_err());
    }
    let mut bad = wire.clone();
    bad[2] = 2;
    assert!(RestoreResult::decode(&bad).is_err());
    let mut bad = wire.clone();
    bad.push(0);
    assert!(RestoreResult::decode(&bad).is_err());
    let mut bad = wire.clone();
    bad[0] = 0xbf;
    bad.push(0xff);
    assert!(RestoreResult::decode(&bad).is_err());
    let mut bad = wire;
    bad.splice(2..3, [0x18, 1]);
    assert!(RestoreResult::decode(&bad).is_err());
}
