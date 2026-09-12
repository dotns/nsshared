//! Independent fixed test seeds; no production control codec or signing input.
use ciborium::value::Value;
use ed25519_dalek::{Signer as _, SigningKey};

pub(super) fn vectors() -> serde_json::Value {
    let mut vectors = Vec::new();
    for (seed, origin, wg) in [
        (11, "wss://relay.example:9443", [4; 32]),
        (12, "wss://[2001:db8::1]:443", [5; 32]),
    ] {
        let key = SigningKey::from_bytes(&[seed; 32]);
        let signer = key.verifying_key().to_bytes();
        let mut challenge: Vec<u8> = (0..32).collect();
        if seed == 12 {
            challenge[0] = 1;
        }
        let mut input = b"nsmesh-wss-v1\0".to_vec();
        input.extend_from_slice(&challenge);
        input.extend_from_slice(&u32::try_from(origin.len()).unwrap().to_be_bytes());
        input.extend_from_slice(origin.as_bytes());
        input.extend_from_slice(&signer);
        input.extend_from_slice(&wg);
        let signature = key.sign(&input).to_bytes();
        let values = [
            Value::Integer(1.into()),
            Value::Bytes(challenge.clone()),
            Value::Text(origin.into()),
            Value::Bytes(signer.to_vec()),
            Value::Bytes(wg.to_vec()),
            Value::Bytes(signature.to_vec()),
        ];
        let map = Value::Map(
            values
                .into_iter()
                .enumerate()
                .map(|(i, v)| (Value::Integer(u64::try_from(i).unwrap().into()), v))
                .collect(),
        );
        let mut hello = Vec::new();
        ciborium::ser::into_writer(&map, &mut hello).unwrap();
        vectors.push(serde_json::json!({
            "origin": origin, "challenge_hex": hex::encode(challenge),
            "signer_hex": hex::encode(signer), "wg_hex": hex::encode(wg),
            "signing_input_hex": hex::encode(input), "hello_hex": hex::encode(hello),
        }));
    }
    serde_json::json!({"schema": "mesh-wss-v1", "vectors": vectors})
}
