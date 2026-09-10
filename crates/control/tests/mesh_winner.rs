use ciborium::value::Value;
use control::envelope::ControlEnvelope;
use control::mesh::{self, WinnerQuery, WinnerResult, WssFrame};
use ed25519_dalek::{Signer as _, SigningKey};
use sha2::{Digest as _, Sha256};

fn query() -> WinnerQuery {
    WinnerQuery {
        network_pub: [1; 32],
        request_id: [2; 16],
        joiner_pub: [3; 32],
        joiner_wg: [4; 32],
    }
}
fn result(found: bool) -> WinnerResult {
    WinnerResult {
        network_pub: [1; 32],
        request_id: [2; 16],
        joiner_pub: [3; 32],
        joiner_wg: [4; 32],
        status: u64::from(!found),
        author_pub: found.then_some([6; 32]),
        seq: found.then_some(u64::MAX),
        record_digest: found.then_some([8; 32]),
    }
}
fn encoded(value: &Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(value, &mut bytes).unwrap();
    bytes
}

#[test]
fn mesh_winner_matches_independent_signed_request_and_results() {
    let suite: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/mesh-winner-v1/vectors.json")).unwrap();
    let key = SigningKey::from_bytes(&[13; 32]);
    for vector in suite["vectors"].as_array().unwrap() {
        let bytes = |field: &str| hex::decode(vector[field].as_str().unwrap()).unwrap();
        let is_query = vector["name"] == "query";
        let payload = if is_query {
            query().encode().unwrap()
        } else {
            result(vector["name"] == "found").encode().unwrap()
        };
        assert_eq!(payload, bytes("payload_hex"));
        if is_query {
            assert_eq!(WinnerQuery::decode(&payload).unwrap(), query());
        } else {
            assert_eq!(
                WinnerResult::decode(&payload).unwrap(),
                result(vector["name"] == "found")
            );
        }
        let raw = bytes("envelope_hex");
        let envelope = ControlEnvelope::from_cbor(&raw).unwrap();
        assert_eq!(envelope.to_cbor().unwrap(), raw);
        assert_eq!(envelope.payload.as_ref(), payload);
        assert_eq!(envelope.nonce, [5; 16]);
        assert_eq!(envelope.ts, 1000);
        assert_eq!(envelope.machine_id, None);
        let api = if is_query {
            WinnerQuery::API
        } else {
            WinnerResult::API
        };
        assert_eq!(envelope.api, api);
        let mut input = if is_query {
            b"nsio-ctrl-v1\0".to_vec()
        } else {
            b"nsio-ctrl-v1-resp\0".to_vec()
        };
        input.push(1);
        input.extend_from_slice(&u32::try_from(api.len()).unwrap().to_be_bytes());
        input.extend_from_slice(api.as_bytes());
        input.extend_from_slice(&1000_u64.to_be_bytes());
        input.extend_from_slice(&[5; 16]);
        input.push(0);
        input.extend_from_slice(&key.verifying_key().to_bytes());
        input.extend_from_slice(&Sha256::digest(&payload));
        assert_eq!(input, bytes("signing_input_hex"));
        assert_eq!(key.sign(&input).to_bytes(), envelope.signature);
        assert_eq!(mesh::verify_request(&envelope, 1000).is_ok(), is_query);
        assert_eq!(
            mesh::verify_response(&envelope, 1000, &key.verifying_key().to_bytes()).is_ok(),
            !is_query
        );
        assert_eq!(mesh::encode_udp(&raw).unwrap(), bytes("udp_hex"));
        assert_eq!(
            mesh::encode_wss(WssFrame::Control(&raw), 0).unwrap(),
            bytes("wss_hex")
        );
        assert!(raw.len() + 8 <= 1200);
    }
}

#[test]
fn mesh_winner_rejects_inconsistent_metadata_on_encode_and_decode() {
    for status in [0, 1, 2, u64::MAX] {
        for author in [None, Some([6; 32])] {
            for seq in [None, Some(0), Some(1), Some(u64::MAX)] {
                for digest in [None, Some([8; 32])] {
                    let mut value = result(true);
                    value.status = status;
                    value.author_pub = author;
                    value.seq = seq;
                    value.record_digest = digest;
                    let valid = (status == 0
                        && author.is_some()
                        && seq.is_some_and(|s| s > 0)
                        && digest.is_some())
                        || (status == 1 && author.is_none() && seq.is_none() && digest.is_none());
                    assert_eq!(value.encode().is_ok(), valid);
                    let Value::Map(mut map) =
                        ciborium::de::from_reader(result(true).encode().unwrap().as_slice())
                            .unwrap()
                    else {
                        unreachable!()
                    };
                    map[5].1 = Value::Integer(status.into());
                    map[6].1 = author.map_or(Value::Null, |v| Value::Bytes(v.to_vec()));
                    map[7].1 = seq.map_or(Value::Null, |v| Value::Integer(v.into()));
                    map[8].1 = digest.map_or(Value::Null, |v| Value::Bytes(v.to_vec()));
                    assert_eq!(
                        WinnerResult::decode(&encoded(&Value::Map(map))).is_ok(),
                        valid
                    );
                }
            }
        }
    }
}

#[test]
fn mesh_winner_rejects_missing_duplicate_truncated_and_noncanonical_fields() {
    for is_query in [true, false] {
        let wire = if is_query {
            query().encode().unwrap()
        } else {
            result(true).encode().unwrap()
        };
        let valid = |bytes: &[u8]| {
            if is_query {
                WinnerQuery::decode(bytes).is_ok()
            } else {
                WinnerResult::decode(bytes).is_ok()
            }
        };
        for len in 0..wire.len() {
            assert!(!valid(&wire[..len]));
        }
        let Value::Map(map) = ciborium::de::from_reader(wire.as_slice()).unwrap() else {
            unreachable!()
        };
        for i in 0..map.len() {
            let mut missing = map.clone();
            missing.remove(i);
            assert!(!valid(&encoded(&Value::Map(missing))));
            let mut duplicate = map.clone();
            duplicate.push(map[i].clone());
            assert!(!valid(&encoded(&Value::Map(duplicate))));
            if let Value::Bytes(b) = &map[i].1 {
                let mut wrong = map.clone();
                wrong[i].1 = Value::Bytes(vec![0; b.len() - 1]);
                assert!(!valid(&encoded(&Value::Map(wrong))));
            }
        }
        let mut bad = wire.clone();
        bad[2] = 2;
        assert!(!valid(&bad));
        let mut bad = wire.clone();
        bad.push(0);
        assert!(!valid(&bad));
        let mut bad = wire.clone();
        bad[0] = 0xbf;
        bad.push(0xff);
        assert!(!valid(&bad));
        let mut bad = wire;
        bad.splice(2..3, [0x18, 1]);
        assert!(!valid(&bad));
    }
}

#[test]
fn mesh_winner_response_binds_each_field_and_request_nonce() {
    let key = SigningKey::from_bytes(&[13; 32]);
    let original = result(true);
    let envelope = original
        .sign_response([9; 16], key.verifying_key().to_bytes(), |b| {
            key.sign(b).to_bytes()
        })
        .unwrap();
    assert_eq!(envelope.nonce, [9; 16]);
    mesh::verify_response(&envelope, envelope.ts, &key.verifying_key().to_bytes()).unwrap();
    let Value::Map(map) = ciborium::de::from_reader(envelope.payload.as_ref()).unwrap() else {
        unreachable!()
    };
    for i in 1..map.len() {
        let mut wrong = map.clone();
        match &mut wrong[i].1 {
            Value::Bytes(b) => b[0] ^= 1,
            Value::Integer(n) => *n = u64::try_from(*n).unwrap().wrapping_add(1).into(),
            _ => unreachable!(),
        }
        let mut altered = envelope.clone();
        altered.payload = encoded(&Value::Map(wrong)).into();
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
