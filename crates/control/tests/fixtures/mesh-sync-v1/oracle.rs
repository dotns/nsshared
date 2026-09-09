//! Independent CBOR/hash oracle. No production control types or encoders are imported.
use ciborium::value::Value;
use ed25519_dalek::{Signer as _, SigningKey};
use sha2::{Digest as _, Sha256};

#[path = "../mesh-v1/oracle.rs"]
mod legacy;

fn n(value: u64) -> Value {
    Value::Integer(value.into())
}
fn b(bytes: &[u8]) -> Value {
    Value::Bytes(bytes.to_vec())
}
fn map(values: Vec<Value>) -> Value {
    Value::Map(
        std::iter::once((n(0), n(1)))
            .chain(
                values
                    .into_iter()
                    .enumerate()
                    .map(|(index, value)| (n(index as u64 + 1), value)),
            )
            .collect(),
    )
}
fn cbor(value: &Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(value, &mut bytes).unwrap();
    bytes
}
fn hash(parts: &[&[u8]]) -> [u8; 32] {
    let mut hash = Sha256::new();
    for part in parts {
        hash.update(part);
    }
    hash.finalize().into()
}
fn public(seed: u8) -> [u8; 32] {
    SigningKey::from_bytes(&[seed; 32])
        .verifying_key()
        .to_bytes()
}
fn receipt(network: &[u8; 32], seq: u64, digest: &[u8; 32]) -> Vec<u8> {
    let mut input = b"nsmesh-receipt-v1\0".to_vec();
    input.extend_from_slice(network);
    input.extend_from_slice(&[2; 16]);
    input.extend_from_slice(&public(11));
    input.extend_from_slice(&seq.to_be_bytes());
    input.extend_from_slice(digest);
    let signature = SigningKey::from_bytes(&[13; 32]).sign(&input).to_bytes();
    cbor(&map(vec![
        b(network),
        b(&[2; 16]),
        b(&public(11)),
        n(seq),
        b(digest),
        b(&signature),
    ]))
}

pub(super) fn vectors() -> serde_json::Value {
    let legacy = legacy::vectors();
    let field = |name: &str, field: &str| {
        hex::decode(
            legacy["vectors"]
                .as_array()
                .unwrap()
                .iter()
                .find(|vector| vector["name"] == name)
                .unwrap()[field]
                .as_str()
                .unwrap(),
        )
        .unwrap()
    };
    let network = public(12);
    let creation = field("register-create", "envelope_hex");
    let original = field("mesh.admins", "payload_hex");
    let owners = [
        field("owner-address", "envelope_hex"),
        field("owner-capability", "envelope_hex"),
    ];
    let mut state = Vec::new();
    state.extend_from_slice(&1_u16.to_be_bytes());
    state.extend_from_slice(&network);
    state.extend_from_slice(&0_u64.to_be_bytes());
    state.extend_from_slice(&1_u32.to_be_bytes());
    state.extend_from_slice(&public(11));
    state.extend_from_slice(&[4; 32]);
    state.extend_from_slice(&1_u64.to_be_bytes());
    state.extend_from_slice(&0_u64.to_be_bytes());
    state.extend_from_slice(&0_u32.to_be_bytes());
    state.extend_from_slice(&0_u32.to_be_bytes());
    let creation_receipt = receipt(
        &network,
        0,
        &hash(&[b"nsmesh-membership-state-v1\0", &state]),
    );
    let management_receipt = receipt(&network, 1, &hash(&[&original]));
    let h0 = hash(&[
        b"nsmesh-history-genesis-v1\0",
        &network,
        &hash(&[&creation]),
        &hash(&[&creation_receipt]),
    ]);
    let h1 = hash(&[
        b"nsmesh-history-record-v1\0",
        &h0,
        &1_u64.to_be_bytes(),
        &hash(&[&original]),
        &hash(&[&management_receipt]),
    ]);
    let empty = hash(&[
        b"nsmesh-owner-snapshot-v1\0",
        &network,
        &0_u32.to_be_bytes(),
    ]);
    let mut owner_input = b"nsmesh-owner-snapshot-v1\0".to_vec();
    owner_input.extend_from_slice(&network);
    owner_input.extend_from_slice(&2_u32.to_be_bytes());
    for (kind, owner) in owners.iter().enumerate() {
        owner_input.extend_from_slice(&public(11));
        owner_input.extend_from_slice(&[4; 32]);
        owner_input.extend_from_slice(&1_u64.to_be_bytes());
        owner_input.push(kind as u8);
        owner_input.extend_from_slice(&1000_u64.to_be_bytes());
        owner_input.extend_from_slice(&hash(&[owner]));
    }
    let owner_digest = hash(&[&owner_input]);
    let version = map(vec![n(1), b(&h1), b(&owner_digest)]);
    let empty_version = map(vec![n(0), b(&h0), b(&empty)]);
    let frames = vec![
        (
            "digest-empty",
            map(vec![n(0), b(&network), empty_version, n(0)]),
        ),
        (
            "digest",
            map(vec![n(0), b(&network), version.clone(), n(2)]),
        ),
        (
            "pull-genesis",
            map(vec![
                n(1),
                b(&network),
                version.clone(),
                n(1),
                n(0),
                n(0),
                n(24),
                Value::Null,
            ]),
        ),
        (
            "pull-gap",
            map(vec![
                n(1),
                b(&network),
                version.clone(),
                n(2),
                n(0),
                n(1),
                n(24),
                b(&h0),
            ]),
        ),
        (
            "pull-owners",
            map(vec![
                n(1),
                b(&network),
                version.clone(),
                n(3),
                n(1),
                n(0),
                n(24),
                Value::Null,
            ]),
        ),
        (
            "records-history",
            map(vec![
                n(2),
                b(&network),
                version.clone(),
                n(1),
                n(0),
                n(0),
                Value::Array(vec![
                    Value::Array(vec![b(&creation), b(&creation_receipt)]),
                    Value::Array(vec![b(&original), b(&management_receipt)]),
                ]),
                Value::Bool(false),
            ]),
        ),
        (
            "records-owner-first",
            map(vec![
                n(2),
                b(&network),
                version.clone(),
                n(3),
                n(1),
                n(0),
                Value::Array(vec![b(&owners[0])]),
                Value::Bool(true),
            ]),
        ),
        (
            "records-owner-last",
            map(vec![
                n(2),
                b(&network),
                version.clone(),
                n(4),
                n(1),
                n(1),
                Value::Array(vec![b(&owners[1])]),
                Value::Bool(false),
            ]),
        ),
        (
            "done",
            map(vec![n(3), b(&network), version.clone(), b(&[9; 16])]),
        ),
        (
            "done-ack",
            map(vec![n(4), b(&network), version, b(&[9; 16])]),
        ),
    ];
    let vectors: Vec<_> = frames
        .into_iter()
        .map(|(name, value)| {
            let body = cbor(&value);
            let mut frame = (body.len() as u32).to_be_bytes().to_vec();
            frame.extend_from_slice(&body);
            serde_json::json!({"name":name,"frame_hex":hex::encode(frame)})
        })
        .collect();
    serde_json::json!({
        "version":1,"network_pub_hex":hex::encode(network),"relay_key_hex":hex::encode(public(13)),
        "creation_hex":hex::encode(creation),"creation_receipt_hex":hex::encode(creation_receipt),
        "record_hex":hex::encode(original),"record_receipt_hex":hex::encode(management_receipt),
        "owners_hex":owners.iter().map(hex::encode).collect::<Vec<_>>(),
        "history_0_hex":hex::encode(h0),"history_1_hex":hex::encode(h1),
        "owners_empty_hex":hex::encode(empty),"owners_2_hex":hex::encode(owner_digest),"vectors":vectors,
    })
}
