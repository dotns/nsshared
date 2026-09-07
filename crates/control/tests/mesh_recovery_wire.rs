use control::envelope::ControlEnvelope;
use control::mesh::*;
use ed25519_dalek::{Signer, SigningKey};

fn query() -> CommitQuery {
    CommitQuery {
        network_pub: [1; 32],
        op_id: [2; 16],
        record_digest: [3; 32],
    }
}

#[test]
fn mesh_query_matches_independent_integer_map_vector() {
    let expected = hex::decode(format!(
        "a40001015820{}0250{}035820{}",
        "01".repeat(32),
        "02".repeat(16),
        "03".repeat(32)
    ))
    .unwrap();
    assert_eq!(query().encode().unwrap(), expected);
    assert_eq!(CommitQuery::decode(&expected).unwrap(), query());
    let mut extended = expected.clone();
    extended[0] = 0xa5;
    extended.extend_from_slice(&[0x18, 0x64, 0xf6]);
    assert_eq!(CommitQuery::decode(&extended).unwrap(), query());
}

#[test]
fn mesh_payload_rejects_ambiguous_and_unbounded_encodings() {
    let good = query().encode().unwrap();
    let mut duplicate = good.clone();
    duplicate[0] = 0xa5;
    duplicate.extend_from_slice(&[0, 1]);
    let mut indefinite = good.clone();
    indefinite[0] = 0xbf;
    indefinite.push(0xff);
    let mut version = good.clone();
    version[2] = 2;
    let mut trailing = good.clone();
    trailing.push(0);
    let mut width = good.clone();
    width[5] = 31;
    width.remove(6);
    let mut nonminimal = good.clone();
    nonminimal.splice(2..3, [0x18, 1]);
    for invalid in [
        duplicate,
        indefinite,
        version,
        trailing,
        width,
        nonminimal,
        vec![0; 1201],
    ] {
        assert!(CommitQuery::decode(&invalid).is_err());
    }
    assert!(CommitQuery::decode(&good[..good.len() - 1]).is_err());
}

fn receipt() -> CommitReceipt {
    CommitReceipt {
        network_pub: [1; 32],
        op_id: [2; 16],
        author_pub: [3; 32],
        seq: 7,
        record_digest: [4; 32],
        signature: [0; 64],
    }
}

#[test]
fn mesh_receipt_binds_every_result_field_and_relay_key() {
    let key = SigningKey::from_bytes(&[5; 32]);
    let mut signed = receipt();
    let mut input = b"nsmesh-receipt-v1\0".to_vec();
    input.extend_from_slice(&[1; 32]);
    input.extend_from_slice(&[2; 16]);
    input.extend_from_slice(&[3; 32]);
    input.extend_from_slice(&7_u64.to_be_bytes());
    input.extend_from_slice(&[4; 32]);
    assert_eq!(signed.signing_input(), input);
    signed.signature = key.sign(&input).to_bytes();
    signed.verify(&key.verifying_key().to_bytes()).unwrap();
    assert!(
        signed
            .verify(&SigningKey::from_bytes(&[6; 32]).verifying_key().to_bytes())
            .is_err()
    );
    for field in 0..6 {
        let mut invalid = signed.clone();
        match field {
            0 => invalid.network_pub[0] ^= 1,
            1 => invalid.op_id[0] ^= 1,
            2 => invalid.author_pub[0] ^= 1,
            3 => invalid.seq += 1,
            4 => invalid.record_digest[0] ^= 1,
            _ => invalid.signature[0] ^= 1,
        }
        assert!(invalid.verify(&key.verifying_key().to_bytes()).is_err());
    }
    let mut result = CommitResult {
        network_pub: signed.network_pub,
        op_id: signed.op_id,
        author_pub: signed.author_pub,
        status: CommitResult::COMMITTED,
        seq: Some(signed.seq),
        record_digest: signed.record_digest,
        receipt: Some(signed),
    };
    assert_eq!(
        CommitResult::decode(&result.encode().unwrap()).unwrap(),
        result
    );
    result.seq = Some(8);
    assert!(result.encode().is_err());
    result.seq = None;
    result.receipt = None;
    result.status = CommitResult::RESULT_UNAVAILABLE;
    assert_eq!(
        CommitResult::decode(&result.encode().unwrap()).unwrap(),
        result
    );
    result.status = 3;
    assert!(result.encode().is_err());
}

fn begin() -> RestoreBegin {
    RestoreBegin {
        network_pub: SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes(),
        request_id: [2; 16],
        anchor_seq: 3,
        state_digest: [4; 32],
        format_version: 1,
        total_bytes: 1024,
        chunk_count: 2,
        network_proof: [0; 64],
    }
}

#[test]
fn mesh_restore_proof_binds_upload_identity_and_dimensions() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let mut value = begin();
    let mut expected = b"nsmesh-restore-v1\0".to_vec();
    expected.extend_from_slice(&key.verifying_key().to_bytes());
    expected.extend_from_slice(&[2; 16]);
    expected.extend_from_slice(&3_u64.to_be_bytes());
    expected.extend_from_slice(&[4; 32]);
    for field in [1_u64, 1024, 2] {
        expected.extend_from_slice(&field.to_be_bytes());
    }
    expected.extend_from_slice(&[8; 32]);
    expected.extend_from_slice(&[9; 32]);
    assert_eq!(value.proof_input(&[8; 32], &[9; 32]).unwrap(), expected);
    value.network_proof = key.sign(&expected).to_bytes();
    value.verify_proof(&[8; 32], &[9; 32]).unwrap();
    assert!(value.verify_proof(&[9; 32], &[9; 32]).is_err());
    assert!(value.verify_proof(&[8; 32], &[8; 32]).is_err());
    for field in 0..7 {
        let mut invalid = value.clone();
        match field {
            0 => invalid.network_pub[0] ^= 1,
            1 => invalid.request_id[0] ^= 1,
            2 => invalid.anchor_seq += 1,
            3 => invalid.state_digest[0] ^= 1,
            4 => invalid.format_version += 1,
            5 => invalid.total_bytes -= 1,
            _ => invalid.chunk_count += 1,
        }
        assert!(invalid.verify_proof(&[8; 32], &[9; 32]).is_err());
    }
}

fn wrapped(api: &str, payload: Vec<u8>) -> Vec<u8> {
    let key = SigningKey::from_bytes(&[10; 32]);
    ControlEnvelope::sign_request(
        api,
        None,
        key.verifying_key().to_bytes(),
        payload,
        |bytes| key.sign(bytes).to_bytes(),
    )
    .unwrap()
    .to_cbor()
    .unwrap()
}

#[test]
fn mesh_recovery_messages_fit_real_envelopes_and_enforce_limits() {
    let ack = CommitAck {
        network_pub: [1; 32],
        op_id: [2; 16],
        record_digest: [3; 32],
        seq: u64::MAX,
    };
    let finish = RestoreFinish {
        network_pub: [1; 32],
        request_id: [2; 16],
        anchor_seq: u64::MAX,
        state_digest: [3; 32],
    };
    let chunk = RestoreChunk {
        network_pub: [1; 32],
        request_id: [2; 16],
        anchor_seq: u64::MAX,
        state_digest: [3; 32],
        index: 2047,
        bytes: vec![4; 512],
    };
    let mut begin = begin();
    begin.anchor_seq = u64::MAX;
    begin.total_bytes = 1_048_576;
    begin.chunk_count = 2048;
    for (api, payload) in [
        (CommitQuery::API, query().encode().unwrap()),
        (CommitAck::API, ack.encode().unwrap()),
        (RestoreBegin::API, begin.encode().unwrap()),
        (RestoreChunk::API, chunk.encode().unwrap()),
        (RestoreFinish::API, finish.encode().unwrap()),
    ] {
        let envelope = wrapped(api, payload);
        assert!(encode_udp(&envelope).unwrap().len() <= 1200);
        assert!(
            encode_wss(WssFrame::Control(&envelope), 1500)
                .unwrap()
                .len()
                <= 1200
        );
    }
    assert_eq!(CommitAck::decode(&ack.encode().unwrap()).unwrap(), ack);
    assert_eq!(
        RestoreBegin::decode(&begin.encode().unwrap()).unwrap(),
        begin
    );
    assert_eq!(
        RestoreFinish::decode(&finish.encode().unwrap()).unwrap(),
        finish
    );
    assert_eq!(
        RestoreChunk::decode(&chunk.encode().unwrap()).unwrap(),
        chunk
    );
    begin.total_bytes = u64::MAX;
    assert!(begin.encode().is_err());
    let mut oversized = chunk;
    oversized.bytes.push(0);
    assert!(oversized.encode().is_err());
    oversized.bytes.clear();
    assert!(oversized.encode().is_err());
}
