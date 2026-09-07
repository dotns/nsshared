use ciborium::value::Value;
use control::envelope::ControlEnvelope;
use control::mesh::*;
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};

const INITIAL_DIGEST: &str = "f46f185668f38c77e11c1b4569fe0405fd0ce3fa71370d6bac16112cc2df5425";

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}
fn public(seed: u8) -> [u8; 32] {
    key(seed).verifying_key().to_bytes()
}

fn fixture(name: &str) -> Vec<u8> {
    let suite: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/mesh-v1/vectors.json")).unwrap();
    let vector = suite["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == name)
        .unwrap();
    hex::decode(vector["envelope_hex"].as_str().unwrap()).unwrap()
}

fn receipt() -> CommitReceipt {
    let mut receipt = CommitReceipt {
        network_pub: public(12),
        op_id: [2; 16],
        author_pub: public(11),
        seq: 0,
        record_digest: hex::decode(INITIAL_DIGEST).unwrap().try_into().unwrap(),
        signature: [0; 64],
    };
    sign_receipt(&mut receipt);
    receipt
}

fn sign_receipt(receipt: &mut CommitReceipt) {
    receipt.signature = key(13).sign(&receipt.signing_input()).to_bytes();
}

fn resign(envelope: &mut ControlEnvelope, seed: u8) {
    assert!(envelope.machine_id.is_none());
    envelope.machine_key_pub = public(seed);
    let mut input = b"nsio-ctrl-v1\0".to_vec();
    input.push(envelope.v);
    input.extend_from_slice(&u32::try_from(envelope.api.len()).unwrap().to_be_bytes());
    input.extend_from_slice(envelope.api.as_bytes());
    input.extend_from_slice(&envelope.ts.to_be_bytes());
    input.extend_from_slice(&envelope.nonce);
    input.push(0);
    input.extend_from_slice(&envelope.machine_key_pub);
    input.extend_from_slice(&Sha256::digest(&envelope.payload));
    envelope.signature = key(seed).sign(&input).to_bytes();
}

#[test]
fn mesh_genesis_recomputes_independent_initial_state_and_historical_receipt() {
    let raw = fixture("register-create");
    let genesis = Genesis::from_register(&raw, &public(12)).unwrap();
    assert_eq!(genesis.original().as_ptr(), raw.as_ptr());
    assert_eq!(genesis.creator(), &public(11));
    assert_eq!(genesis.creation_id(), &[2; 16]);
    let state = genesis.state();
    assert_eq!(state.network_pub, public(12));
    assert_eq!(state.seq, 0);
    assert_eq!(state.members.len(), 1);
    assert_eq!(
        state.members[&public(11)],
        CompactMember {
            wg_pub: [4; 32],
            incarnation: 1
        }
    );
    assert_eq!(state.admins_revision, 0);
    assert!(state.admins.is_empty());
    assert!(state.evicted_through.is_empty());
    let mut expected = vec![0, 1];
    expected.extend_from_slice(&public(12));
    expected.extend_from_slice(&0_u64.to_be_bytes());
    expected.extend_from_slice(&1_u32.to_be_bytes());
    expected.extend_from_slice(&public(11));
    expected.extend_from_slice(&[4; 32]);
    expected.extend_from_slice(&1_u64.to_be_bytes());
    expected.extend_from_slice(&[0; 16]);
    assert_eq!(expected.len(), 134);
    assert_eq!(state.encode().unwrap(), expected);
    // Independently hashed explicit fields using Perl Digest::SHA, not CompactState::encode.
    assert_eq!(hex::encode(state.digest().unwrap()), INITIAL_DIGEST);
    genesis.verify_receipt(&receipt(), &public(13)).unwrap();
    let envelope = ControlEnvelope::from_cbor(&raw).unwrap();
    assert!(envelope.verify_request(2000).is_err());
    let mut later = envelope.clone();
    later.ts = u64::MAX;
    resign(&mut later, 11);
    let later_raw = later.to_cbor().unwrap();
    let later_genesis = Genesis::from_register(&later_raw, &public(12)).unwrap();
    assert_eq!(later_genesis.state(), state);
    later_genesis
        .verify_receipt(&receipt(), &public(13))
        .unwrap();
}

#[test]
fn mesh_genesis_rejects_resigned_receipt_aliases_and_wrong_relay() {
    let raw = fixture("register-create");
    let genesis = Genesis::from_register(&raw, &public(12)).unwrap();
    for field in 0..6 {
        let mut wrong = receipt();
        match field {
            0 => wrong.network_pub = public(14),
            1 => wrong.op_id[0] ^= 1,
            2 => wrong.author_pub = public(14),
            3 => wrong.seq = 1,
            4 => wrong.record_digest[0] ^= 1,
            _ => wrong.record_digest = Sha256::digest(&raw).into(),
        }
        sign_receipt(&mut wrong);
        assert!(genesis.verify_receipt(&wrong, &public(13)).is_err());
    }
    let mut forged = receipt();
    forged.signature[0] ^= 1;
    assert!(genesis.verify_receipt(&forged, &public(13)).is_err());
    assert!(genesis.verify_receipt(&receipt(), &public(14)).is_err());
}

#[test]
fn mesh_genesis_requires_member_signature_and_bound_network_proof() {
    let raw = fixture("register-create");
    let original = ControlEnvelope::from_cbor(&raw).unwrap();
    assert!(Genesis::from_register(&raw, &public(14)).is_err());
    assert!(Genesis::from_register(&fixture("register-refresh"), &public(12)).is_err());
    for field in 0..8 {
        let mut envelope = original.clone();
        let mut register = Register::decode(&envelope.payload).unwrap();
        match field {
            0 => register.network_pub = public(14),
            1 => register.wg_pub[0] ^= 1,
            2 => register.member_incarnation = 2,
            3 => register.network_proof.as_mut().unwrap()[0] ^= 1,
            4 => register.network_proof = None,
            5 => envelope.nonce[0] ^= 1,
            6 => envelope.api = "mesh.join".into(),
            _ => {}
        }
        envelope.payload = register.encode().unwrap().into();
        resign(&mut envelope, if field == 7 { 14 } else { 11 });
        assert!(Genesis::from_register(&envelope.to_cbor().unwrap(), &public(12)).is_err());
    }
    // Even a completely valid proof for a higher incarnation is not initial creation.
    let mut envelope = original.clone();
    let mut register = Register::decode(&envelope.payload).unwrap();
    register.member_incarnation = u64::MAX;
    register.network_proof = Some(
        key(12)
            .sign(
                &register
                    .network_proof_input(&envelope.nonce, &public(11))
                    .unwrap(),
            )
            .to_bytes(),
    );
    envelope.payload = register.encode().unwrap().into();
    resign(&mut envelope, 11);
    assert!(Genesis::from_register(&envelope.to_cbor().unwrap(), &public(12)).is_err());
    for field in 0..3 {
        let mut forged = original.clone();
        match field {
            0 => forged.signature[0] ^= 1,
            1 => forged.machine_id = Some("managed".into()),
            _ => forged.v = 2,
        }
        assert!(Genesis::from_register(&forged.to_cbor().unwrap(), &public(12)).is_err());
    }
}

#[test]
fn mesh_genesis_rejects_truncated_trailing_and_excessive_input() {
    let raw = fixture("register-create");
    for end in 0..raw.len() {
        assert!(Genesis::from_register(&raw[..end], &public(12)).is_err());
    }
    let mut trailing = raw.clone();
    trailing.push(0);
    assert!(Genesis::from_register(&trailing, &public(12)).is_err());
    assert!(Genesis::from_register(&vec![0; 1201], &public(12)).is_err());
    let mut outer: Value = ciborium::de::from_reader(raw.as_slice()).unwrap();
    let mut nested = Value::Null;
    for _ in 0..32 {
        nested = Value::Array(vec![nested]);
    }
    let Value::Map(ref mut fields) = outer else {
        unreachable!()
    };
    fields.push((Value::Text("future".into()), nested));
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&outer, &mut bytes).unwrap();
    assert!(Genesis::from_register(&bytes, &public(12)).is_err());
}
