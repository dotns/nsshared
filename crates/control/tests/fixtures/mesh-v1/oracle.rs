//! Independent fixture oracle: only CBOR/cryptographic primitives, never control codecs.
//! Fixed seeds are synthetic test material, not deployment identities.
use ciborium::value::Value;
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};

fn n(v: u64) -> Value {
    Value::Integer(v.into())
}
fn b(v: &[u8]) -> Value {
    Value::Bytes(v.to_vec())
}
fn s(v: &str) -> Value {
    Value::Text(v.into())
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
    let mut out = Vec::new();
    ciborium::ser::into_writer(value, &mut out).unwrap();
    out
}
fn lp(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
}
fn ints(out: &mut Vec<u8>, values: &[u64]) {
    for v in values {
        out.extend_from_slice(&v.to_be_bytes());
    }
}
fn sig(seed: u8, input: &[u8]) -> Value {
    b(&SigningKey::from_bytes(&[seed; 32]).sign(input).to_bytes())
}
fn addr() -> Value {
    map(vec![b(&[10, 1, 2, 3]), n(0), b(&[0xfd; 16])])
}
fn addr_input(out: &mut Vec<u8>) {
    out.extend_from_slice(&[10, 1, 2, 3]);
    ints(out, &[0]);
    out.extend_from_slice(&[0xfd; 16]);
}
fn envelope(api: &str, kind: &str, payload: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut input = Vec::new();
    if matches!(kind, "unsigned" | "hello") {
        return (input, Vec::new());
    }
    input.extend_from_slice(if kind == "response" {
        b"nsio-ctrl-v1-resp\0"
    } else {
        b"nsio-ctrl-v1\0"
    });
    input.push(1);
    lp(&mut input, api.as_bytes());
    ints(&mut input, &[1000]);
    input.extend_from_slice(&[2; 16]);
    input.push(0);
    let seed = if kind == "response" { 13 } else { 11 };
    let signer = SigningKey::from_bytes(&[seed; 32])
        .verifying_key()
        .to_bytes();
    input.extend_from_slice(&signer);
    input.extend_from_slice(&Sha256::digest(payload));
    let bytes = cbor(&Value::Map(vec![
        (s("v"), n(1)),
        (s("api"), s(api)),
        (s("ts"), n(1000)),
        (s("nonce"), b(&[2; 16])),
        (s("machine_id"), Value::Null),
        (s("machine_key_pub"), b(&signer)),
        (s("payload"), b(payload)),
        (s("signature"), sig(seed, &input)),
    ]));
    (input, bytes)
}
pub(super) fn vectors() -> serde_json::Value {
    let joiner = SigningKey::from_bytes(&[14; 32]).verifying_key().to_bytes();
    let joiner_id = blake2::Blake2s::<blake2::digest::consts::U20>::digest(joiner);
    let member = SigningKey::from_bytes(&[11; 32]).verifying_key().to_bytes();
    let network = SigningKey::from_bytes(&[12; 32]).verifying_key().to_bytes();
    let relay = SigningKey::from_bytes(&[13; 32]).verifying_key().to_bytes();
    let mut cases: Vec<(&str, &str, &str, Value)> = Vec::new();
    let mut proof = b"nsmesh-network-proof-v1\0".to_vec();
    proof.extend_from_slice(&network);
    proof.extend_from_slice(&[2; 16]);
    proof.extend_from_slice(&[4; 32]);
    ints(&mut proof, &[1]);
    proof.extend_from_slice(&member);
    cases.push((
        "register-create",
        "mesh.register",
        "request",
        map(vec![
            b(&network),
            b(&[4; 32]),
            n(1),
            map(vec![n(600)]),
            sig(12, &proof),
            Value::Null,
        ]),
    ));
    cases.push((
        "register-refresh",
        "mesh.register",
        "request",
        map(vec![
            b(&network),
            b(&[4; 32]),
            n(1),
            Value::Null,
            Value::Null,
            Value::Null,
        ]),
    ));
    let mut receipt_input = b"nsmesh-receipt-v1\0".to_vec();
    receipt_input.extend_from_slice(&network);
    receipt_input.extend_from_slice(&[2; 16]);
    receipt_input.extend_from_slice(&member);
    ints(&mut receipt_input, &[7]);
    receipt_input.extend_from_slice(&[3; 32]);
    let receipt = map(vec![
        b(&network),
        b(&[2; 16]),
        b(&member),
        n(7),
        b(&[3; 32]),
        sig(13, &receipt_input),
    ]);
    let registered = |pin, status, anchor| {
        map(vec![
            b(&[2; 16]),
            n(status),
            b(&network),
            pin,
            b(&[5; 20]),
            n(1),
            n(7),
            map(vec![b(&[192, 0, 2, 1]), n(51900)]),
            b(&relay),
            n(90),
            n(0),
            anchor,
            Value::Null,
        ])
    };
    cases.push((
        "registered-pin",
        "mesh.registered",
        "response",
        registered(map(vec![s("KX-83920174"), n(600)]), 0, Value::Null),
    ));
    cases.push((
        "registered-recovery",
        "mesh.registered",
        "response",
        registered(Value::Null, 3, map(vec![n(7), b(&[3; 32]), n(1)])),
    ));
    cases.push((
        "cookie",
        "mesh.cookie",
        "unsigned",
        map(vec![b(&[2; 16]), b(&[6; 16])]),
    ));
    let join = |cookie| {
        map(vec![
            s("KX-83920174"),
            b(&[4; 32]),
            n(1),
            n(1120),
            cookie,
            b(&[2; 16]),
        ])
    };
    cases.push(("join-first", "mesh.join", "request", join(Value::Null)));
    cases.push(("join-cookie", "mesh.join", "request", join(b(&[6; 16]))));
    let mut ai = b"nsmesh-accept-v1\0".to_vec();
    ai.extend_from_slice(&network);
    lp(&mut ai, b"home");
    lp(&mut ai, b"wss://relay.example:9443");
    ai.extend_from_slice(&[4; 32]);
    ai.extend_from_slice(&joiner_id);
    ai.extend_from_slice(&[6; 32]);
    ai.extend_from_slice(&[2; 16]);
    ints(&mut ai, &[1, 1]);
    addr_input(&mut ai);
    addr_input(&mut ai);
    ints(&mut ai, &[1000, 1060]);
    ai.extend_from_slice(&joiner);
    cases.push((
        "accept",
        "mesh.accept",
        "request",
        map(vec![
            b(&network),
            s("home"),
            s("wss://relay.example:9443"),
            b(&[4; 32]),
            b(&joiner_id),
            b(&[6; 32]),
            b(&[2; 16]),
            n(1),
            n(1),
            addr(),
            addr(),
            n(1000),
            n(1060),
            sig(12, &ai),
            b(&joiner),
        ]),
    ));
    cases.push((
        "resolved",
        "mesh.resolved",
        "response",
        map(vec![
            b(&network),
            b(&[2; 16]),
            b(&[5; 20]),
            b(&[7; 20]),
            n(7),
        ]),
    ));
    cases.push((
        "deny",
        "mesh.deny",
        "request",
        map(vec![b(&[2; 16]), b(&[5; 20]), s("declined")]),
    ));
    let mut vi = b"nsmesh-vouch-v1\0".to_vec();
    vi.extend_from_slice(&network);
    vi.extend_from_slice(&[5; 20]);
    vi.extend_from_slice(&[6; 32]);
    ints(&mut vi, &[1]);
    vi.extend_from_slice(&[2; 16]);
    ints(&mut vi, &[1000, 1060]);
    cases.push((
        "vouch",
        "mesh.vouch",
        "request",
        map(vec![
            b(&network),
            b(&[5; 20]),
            b(&[6; 32]),
            n(1),
            b(&[2; 16]),
            n(1000),
            n(1060),
            sig(11, &vi),
        ]),
    ));
    cases.push(("unbind", "mesh.unbind", "request", map(vec![b(&network)])));
    for (kind, api, body) in [
        (
            0,
            "mesh.evict",
            map(vec![b(&[5; 20]), n(1), s("removed"), b(&[6; 32])]),
        ),
        (1, "mesh.admins", map(vec![b(&[5; 20]), n(2)])),
    ] {
        let body = cbor(&body);
        let mut input = b"nsmesh-record-v1\0".to_vec();
        ints(&mut input, &[kind]);
        input.extend_from_slice(&network);
        input.extend_from_slice(&[2; 16]);
        input.extend_from_slice(&member);
        ints(&mut input, &[1000, 1060]);
        lp(&mut input, &body);
        let record = map(vec![
            n(kind),
            b(&network),
            b(&[2; 16]),
            b(&member),
            n(1000),
            n(1060),
            b(&body),
            sig(11, &input),
        ]);
        if kind == 0 {
            cases.push((
                "sequenced",
                "mesh.sequenced",
                "response",
                map(vec![b(&network), n(7), b(&cbor(&record))]),
            ));
        }
        cases.push((api, api, "request", record));
    }
    cases.push((
        "commit-query",
        "mesh.commit.query",
        "request",
        map(vec![b(&network), b(&[2; 16]), b(&[3; 32])]),
    ));
    cases.push((
        "commit-ack",
        "mesh.commit.ack",
        "request",
        map(vec![b(&network), b(&[2; 16]), b(&[3; 32]), n(7)]),
    ));
    cases.push((
        "commit-result",
        "mesh.commit.result",
        "response",
        map(vec![
            b(&network),
            b(&[2; 16]),
            b(&member),
            n(0),
            n(7),
            b(&[3; 32]),
            receipt,
        ]),
    ));
    for (status, name) in [(1, "commit-unavailable"), (2, "commit-conflict")] {
        cases.push((
            name,
            "mesh.commit.result",
            "response",
            map(vec![
                b(&network),
                b(&[2; 16]),
                b(&member),
                n(status),
                Value::Null,
                b(&[3; 32]),
                Value::Null,
            ]),
        ));
    }
    let mut ri = b"nsmesh-restore-v1\0".to_vec();
    ri.extend_from_slice(&network);
    ri.extend_from_slice(&[2; 16]);
    ints(&mut ri, &[7]);
    ri.extend_from_slice(&[3; 32]);
    ints(&mut ri, &[1, 512, 1]);
    ri.extend_from_slice(&member);
    ri.extend_from_slice(&[4; 32]);
    cases.push((
        "restore-begin",
        "mesh.restore.begin",
        "request",
        map(vec![
            b(&network),
            b(&[2; 16]),
            n(7),
            b(&[3; 32]),
            n(1),
            n(512),
            n(1),
            sig(12, &ri),
        ]),
    ));
    cases.push((
        "restore-chunk",
        "mesh.restore.chunk",
        "request",
        map(vec![
            b(&network),
            b(&[2; 16]),
            n(7),
            b(&[3; 32]),
            n(0),
            b(&[8; 512]),
        ]),
    ));
    cases.push((
        "restore-finish",
        "mesh.restore.finish",
        "request",
        map(vec![b(&network), b(&[2; 16]), n(7), b(&[3; 32])]),
    ));
    let mut hi = b"nsmesh-wss-v1\0".to_vec();
    hi.extend_from_slice(&[2; 32]);
    lp(&mut hi, b"wss://relay.example:9443");
    hi.extend_from_slice(&member);
    hi.extend_from_slice(&[4; 32]);
    cases.push((
        "wss-hello",
        "",
        "hello",
        map(vec![
            b(&[2; 32]),
            s("wss://relay.example:9443"),
            b(&member),
            b(&[4; 32]),
            sig(11, &hi),
        ]),
    ));
    cases.push(("managed-envelope", "info.get", "managed", map(vec![])));
    let vouch_payload = cbor(&cases.iter().find(|c| c.0 == "vouch").unwrap().3);
    let (_, vouch_envelope) = envelope("mesh.vouch", "request", &vouch_payload);
    cases.push((
        "register-vouch",
        "mesh.register",
        "request",
        map(vec![
            b(&network),
            b(&[6; 32]),
            n(1),
            Value::Null,
            Value::Null,
            b(&vouch_envelope),
        ]),
    ));
    let mut genesis_input = b"nsmesh-receipt-v1\0".to_vec();
    genesis_input.extend_from_slice(&network);
    genesis_input.extend_from_slice(&[2; 16]);
    genesis_input.extend_from_slice(&member);
    ints(&mut genesis_input, &[0]);
    genesis_input.extend_from_slice(&[3; 32]);
    let genesis = cbor(&map(vec![
        b(&network),
        b(&[2; 16]),
        b(&member),
        n(0),
        b(&[3; 32]),
        sig(13, &genesis_input),
    ]));
    cases.push((
        "registered-genesis",
        "mesh.registered",
        "response",
        map(vec![
            b(&[2; 16]),
            n(0),
            b(&network),
            Value::Null,
            b(&[]),
            n(0),
            n(0),
            map(vec![b(&[192, 0, 2, 1]), n(51900)]),
            b(&relay),
            n(90),
            n(0),
            Value::Null,
            b(&genesis),
        ]),
    ));
    cases.push((
        "owner-address",
        "mesh.addr",
        "request",
        map(vec![b(&network), n(1), n(7)]),
    ));
    cases.push((
        "owner-capability",
        "mesh.capability",
        "request",
        map(vec![b(&network), n(1), n(1)]),
    ));
    let vectors: Vec<_> = cases.into_iter().map(|(name,api,kind,payload)| {
        let payload = cbor(&payload);
        let (input, envelope) = envelope(api, kind, &payload);
        serde_json::json!({"name":name,"api":api,"kind":kind,"payload_hex":hex::encode(payload),"envelope_hex":hex::encode(envelope),"signing_input_hex":hex::encode(input)})
    }).collect();
    serde_json::json!({"version":1,"vectors":vectors})
}
