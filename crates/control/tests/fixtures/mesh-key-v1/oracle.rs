//! Independent, fixed test seeds only. No production control encoders are imported.
use ciborium::value::Value;
use ed25519_dalek::{Signer as _, SigningKey};
use sha2::{Digest as _, Sha256};

fn n(value: u64) -> Value {
    Value::Integer(value.into())
}
fn b(value: &[u8]) -> Value {
    Value::Bytes(value.to_vec())
}
fn s(value: &str) -> Value {
    Value::Text(value.into())
}
fn public(seed: u8) -> [u8; 32] {
    SigningKey::from_bytes(&[seed; 32])
        .verifying_key()
        .to_bytes()
}
fn map(values: Vec<Value>) -> Value {
    Value::Map(
        std::iter::once((n(0), n(1)))
            .chain(
                values
                    .into_iter()
                    .enumerate()
                    .map(|(i, v)| (n(i as u64 + 1), v)),
            )
            .collect(),
    )
}
fn cbor(value: &Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(value, &mut bytes).unwrap();
    bytes
}
fn lp(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
}

pub(super) fn vectors() -> serde_json::Value {
    let request = map(vec![
        b(&public(12)),
        map(vec![b(&public(11)), b(&[4; 32]), n(2)]),
        map(vec![b(&public(13)), b(&[6; 32]), n(1)]),
        map(vec![n(7), b(&[3; 32]), b(&[5; 32])]),
    ]);
    let grant = map(vec![request.clone(), b(&[2; 16]), b(&[12; 32])]);
    let mut vectors = Vec::new();
    for (api, payload, seed, nonce, ts, domain) in [
        (
            "mesh.key.request",
            request,
            11,
            2,
            1000_u64,
            b"nsio-ctrl-v1\0".as_slice(),
        ),
        (
            "mesh.key.grant",
            grant,
            13,
            7,
            1001_u64,
            b"nsio-ctrl-v1-resp\0".as_slice(),
        ),
    ] {
        let payload = cbor(&payload);
        let signer = public(seed);
        let mut input = domain.to_vec();
        input.push(1);
        lp(&mut input, api.as_bytes());
        input.extend_from_slice(&ts.to_be_bytes());
        input.extend_from_slice(&[nonce; 16]);
        input.push(0);
        input.extend_from_slice(&signer);
        input.extend_from_slice(&Sha256::digest(&payload));
        let signature = SigningKey::from_bytes(&[seed; 32]).sign(&input).to_bytes();
        let envelope = cbor(&Value::Map(vec![
            (s("v"), n(1)),
            (s("api"), s(api)),
            (s("ts"), n(ts)),
            (s("nonce"), b(&[nonce; 16])),
            (s("machine_id"), Value::Null),
            (s("machine_key_pub"), b(&signer)),
            (s("payload"), b(&payload)),
            (s("signature"), b(&signature)),
        ]));
        let mut frame = (envelope.len() as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(&envelope);
        vectors.push(serde_json::json!({
            "api": api, "payload_hex": hex::encode(payload),
            "signing_input_hex": hex::encode(input),
            "envelope_hex": hex::encode(envelope), "frame_hex": hex::encode(frame),
        }));
    }
    serde_json::json!({"schema": "mesh-key-v1", "vectors": vectors})
}
