use control::envelope::ControlEnvelope;
use control::mesh::*;
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn signed_receipt(raw: &[u8], network: [u8; 32], author: [u8; 32], op: [u8; 16]) -> CommitReceipt {
    let mut receipt = CommitReceipt {
        network_pub: network,
        author_pub: author,
        op_id: op,
        seq: 7,
        record_digest: Sha256::digest(raw).into(),
        signature: [0; 64],
    };
    resign_receipt(&mut receipt);
    receipt
}

fn resign_receipt(receipt: &mut CommitReceipt) {
    receipt.signature = key(13).sign(&receipt.signing_input()).to_bytes();
}

fn verify<'a>(
    kind: ManagementKind,
    raw: &'a [u8],
    receipt: &CommitReceipt,
) -> Result<AuthenticatedRecord<'a>, Error> {
    AuthenticatedRecord::verify(
        kind,
        raw,
        receipt,
        &key(13).verifying_key().to_bytes(),
        &key(12).verifying_key().to_bytes(),
        6,
    )
}

fn management(kind: ManagementKind) -> SignedManagementRecord {
    let target = key(14).verifying_key().to_bytes();
    let (kind, body) = match kind {
        ManagementKind::Evict => (
            SignedManagementRecord::EVICT,
            Eviction {
                member_id: member_id(&target),
                member_pub: target,
                incarnation: 2,
                reason: "test".into(),
            }
            .encode()
            .unwrap(),
        ),
        ManagementKind::Admins => (
            SignedManagementRecord::ADMINS,
            Admins {
                admins: member_id(&target).to_vec(),
                admins_revision: 1,
            }
            .encode()
            .unwrap(),
        ),
        ManagementKind::Add => unreachable!(),
    };
    let mut record = SignedManagementRecord {
        kind,
        network_pub: key(12).verifying_key().to_bytes(),
        op_id: [2; 16],
        author_pub: key(11).verifying_key().to_bytes(),
        issued_at: 1000,
        expires_at: 1060,
        body,
        signature: [0; 64],
    };
    record.signature = key(11).sign(&record.signing_input().unwrap()).to_bytes();
    record
}

fn add() -> (Vec<u8>, CommitReceipt) {
    let suite: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/mesh-v1/vectors.json")).unwrap();
    let vector = suite["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["api"] == "mesh.accept")
        .unwrap();
    let raw = hex::decode(vector["envelope_hex"].as_str().unwrap()).unwrap();
    let envelope = ControlEnvelope::from_cbor(&raw).unwrap();
    let accept = Accept::verify_historical(&envelope).unwrap();
    let receipt = signed_receipt(
        &raw,
        accept.network_pub,
        envelope.machine_key_pub,
        accept.request_id,
    );
    (raw, receipt)
}

#[test]
fn mesh_history_preserves_original_add_and_authenticates_expired_records() {
    let (raw, receipt) = add();
    let record = verify(ManagementKind::Add, &raw, &receipt).unwrap();
    assert_eq!(record.original(), raw);
    assert_eq!(record.original().as_ptr(), raw.as_ptr());
    assert_eq!(record.receipt(), &receipt);
    assert_eq!((record.issued_at(), record.expires_at()), (1000, 1060));
    assert!(matches!(record.contents(), ManagementContents::Add(_)));
    assert!(validate_live_credential(record.issued_at(), record.expires_at(), 2000, 1060).is_err());
    for kind in [ManagementKind::Evict, ManagementKind::Admins] {
        let original = management(kind);
        let raw = original.encode().unwrap();
        let receipt = signed_receipt(
            &raw,
            original.network_pub,
            original.author_pub,
            original.op_id,
        );
        let record = verify(kind, &raw, &receipt).unwrap();
        assert_eq!(record.original(), raw);
        assert_eq!((record.issued_at(), record.expires_at()), (1000, 1060));
        assert!(matches!(
            (kind, record.contents()),
            (ManagementKind::Evict, ManagementContents::Evict(_))
                | (ManagementKind::Admins, ManagementContents::Admins(_))
        ));
    }
}

#[test]
fn mesh_history_rejects_receipt_aliases_gaps_overflow_and_wrong_relay() {
    let (raw, receipt) = add();
    for field in 0..6 {
        let mut wrong = receipt.clone();
        match field {
            0 => wrong.network_pub[0] ^= 1,
            1 => wrong.author_pub[0] ^= 1,
            2 => wrong.op_id[0] ^= 1,
            3 => wrong.seq += 1,
            4 => wrong.record_digest[0] ^= 1,
            _ => wrong.seq -= 1,
        }
        resign_receipt(&mut wrong);
        assert!(
            verify(ManagementKind::Add, &raw, &wrong).is_err(),
            "field {field}"
        );
    }
    let mut forged = receipt.clone();
    forged.signature[0] ^= 1;
    assert!(verify(ManagementKind::Add, &raw, &forged).is_err());
    for previous in [0, 7, u64::MAX] {
        assert!(
            AuthenticatedRecord::verify(
                ManagementKind::Add,
                &raw,
                &receipt,
                &key(13).verifying_key().to_bytes(),
                &receipt.network_pub,
                previous
            )
            .is_err()
        );
    }
    assert!(
        AuthenticatedRecord::verify(
            ManagementKind::Add,
            &raw,
            &receipt,
            &key(14).verifying_key().to_bytes(),
            &receipt.network_pub,
            6
        )
        .is_err()
    );
}

#[test]
fn mesh_history_rejects_forged_originals_and_kind_confusion() {
    let (raw, receipt) = add();
    for kind in [ManagementKind::Evict, ManagementKind::Admins] {
        assert!(verify(kind, &raw, &receipt).is_err());
    }
    let mut envelope = ControlEnvelope::from_cbor(&raw).unwrap();
    envelope.signature[0] ^= 1;
    let raw = envelope.to_cbor().unwrap();
    let receipt = signed_receipt(&raw, receipt.network_pub, receipt.author_pub, receipt.op_id);
    assert!(verify(ManagementKind::Add, &raw, &receipt).is_err());
    for kind in [ManagementKind::Evict, ManagementKind::Admins] {
        let mut original = management(kind);
        let raw = original.encode().unwrap();
        let receipt = signed_receipt(
            &raw,
            original.network_pub,
            original.author_pub,
            original.op_id,
        );
        let other = if kind == ManagementKind::Evict {
            ManagementKind::Admins
        } else {
            ManagementKind::Evict
        };
        assert!(verify(other, &raw, &receipt).is_err());
        original.signature[0] ^= 1;
        let raw = original.encode().unwrap();
        let receipt = signed_receipt(
            &raw,
            original.network_pub,
            original.author_pub,
            original.op_id,
        );
        assert!(verify(kind, &raw, &receipt).is_err());
    }
    let mut original = management(ManagementKind::Evict);
    let mut body = Eviction::decode(&original.body).unwrap();
    body.member_id[0] ^= 1;
    original.body = body.encode().unwrap();
    original.signature = key(11).sign(&original.signing_input().unwrap()).to_bytes();
    let raw = original.encode().unwrap();
    let receipt = signed_receipt(
        &raw,
        original.network_pub,
        original.author_pub,
        original.op_id,
    );
    assert!(verify(ManagementKind::Evict, &raw, &receipt).is_err());
}

#[test]
fn mesh_history_bounds_originals_and_rejects_trailing_envelope_data() {
    let (raw, receipt) = add();
    let mut envelope: ciborium::Value = ciborium::de::from_reader(raw.as_slice()).unwrap();
    let mut nested = ciborium::Value::Null;
    for _ in 0..32 {
        nested = ciborium::Value::Array(vec![nested]);
    }
    envelope
        .as_map_mut()
        .unwrap()
        .push((ciborium::Value::Text("extra".into()), nested));
    let mut deep = Vec::new();
    ciborium::ser::into_writer(&envelope, &mut deep).unwrap();
    assert!(deep.len() <= 1200);
    let deep_receipt = signed_receipt(
        &deep,
        receipt.network_pub,
        receipt.author_pub,
        receipt.op_id,
    );
    assert!(verify(ManagementKind::Add, &deep, &deep_receipt).is_err());
    for length in [0, 1, raw.len() - 1] {
        let raw = &raw[..length];
        let receipt = signed_receipt(raw, receipt.network_pub, receipt.author_pub, receipt.op_id);
        assert!(verify(ManagementKind::Add, raw, &receipt).is_err());
    }
    for raw in [vec![0; 1201], [raw, vec![0]].concat()] {
        let receipt = signed_receipt(&raw, receipt.network_pub, receipt.author_pub, receipt.op_id);
        assert!(verify(ManagementKind::Add, &raw, &receipt).is_err());
    }
}
