#![allow(clippy::unwrap_used, clippy::panic)]

use ed25519_dalek::{Signer as _, SigningKey};
use nsshared_codec::cbor::value::{Value, decode_canonical, encode_canonical};
use nsshared_control::{
    account::control::{
        BootstrapEnvelope, EnvelopeDirection, EnvelopeExpectation, EnvelopePins,
        MAX_RUNTIME_DECLARATION_BYTES, MembershipScope, NODE_RUNTIME_DECLARE, NodeReportContext,
        NodeRuntimeFence, RegistrationCondition, RuntimeDeclarationAccepted,
        RuntimeDeclarationRequest, runtime_declaration_digest,
    },
    account::node::{MembershipIdentityVersion, NodeBinding, RecordGeneration},
    account::publication::SignedSourceBinding,
};
use nsshared_identity::keys::IdentityKey;
use nsshared_testkit::hex::unhex;

// Produced independently with the Python canonical CBOR and Ed25519 vector primitives.
const REQUEST: &str = concat!(
    "88018250030303030303030303030303030303035003030303030303030303030303030303840158208a88e3dd7409f1",
    "95fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c5820050505050505050505050505050505050505050505",
    "050505050505050505050502835006060606060606060606060606060606500707070707070707070707070707070750",
    "0808080808080808080808080808080858fc8258b78a0158208139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37",
    "a25df60f5b8fc9b39458208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c781a303330",
    "4331473630523330433147363052333043314736305233656e6f64657378186578706c696369742d676174657761792d",
    "70726f66696c6558208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c500a0a0a0a0a0a",
    "0a0a0a0a0a0a0a0a0a0a0b0c58406e9057a3813602f75f427ea416e0d88a58ae3464d4f8a114d755a3b773ae05b87315",
    "eaa44d328e4a2a7aa226c0999598bbc69cb4d1f96200f20dc3643203c907835009090909090909090909090909090909",
    "0d0e0f846e6e6f64655f6c335f61636c2e76316f6e6f64655f6c335f6563686f2e7631706f70617175652e6675747572",
    "652d763272736572766963655f636f6e74726f6c2e7631",
);
const SOURCE: &str = concat!(
    "8258b78a0158208139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b39458208a88e3dd7409f1",
    "95fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c781a303330433147363052333043314736305233304331",
    "4736305233656e6f64657378186578706c696369742d676174657761792d70726f66696c6558208a88e3dd7409f195fd",
    "52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c500a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0b0c58406e9057a3",
    "813602f75f427ea416e0d88a58ae3464d4f8a114d755a3b773ae05b87315eaa44d328e4a2a7aa226c0999598bbc69cb4",
    "d1f96200f20dc3643203c907",
);
const ACCEPTED: &str =
    concat!("83010f5820d0cc47b7534adc13a42f802a70eb9c993347e0c21dd6fcaed87af4c8e85914da",);
const DIGEST: &str = concat!("d0cc47b7534adc13a42f802a70eb9c993347e0c21dd6fcaed87af4c8e85914da",);

fn identity(seed: u8) -> IdentityKey {
    IdentityKey::from_bytes(
        &SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes(),
    )
    .unwrap()
}

fn request() -> RuntimeDeclarationRequest {
    RuntimeDeclarationRequest {
        scope: MembershipScope {
            nsd_id: [3; 16],
            network_id: [3; 16],
        },
        binding: NodeBinding {
            identity_version: MembershipIdentityVersion(1),
            identity: identity(1),
            wg_key: [5; 32],
            generation: RecordGeneration(2),
        },
        registration: RegistrationCondition {
            node_id: [6; 16],
            credential_incarnation: [7; 16],
            activation_generation: [8; 16],
        },
        signed_source: SignedSourceBinding::decode(&unhex(SOURCE)).unwrap(),
        fence: NodeRuntimeFence {
            runtime_id: [9; 16],
            runtime_generation: 13,
            authority_epoch: 14,
        },
        declaration_seq: 15,
        capabilities: [
            "node_l3_acl.v1",
            "node_l3_echo.v1",
            "opaque.future-v2",
            "service_control.v1",
        ]
        .map(str::to_owned)
        .to_vec(),
    }
}

fn context() -> NodeReportContext {
    NodeReportContext {
        scope: request().scope,
        subject: identity(1),
        authority: identity(2),
    }
}

fn parts(value: &mut Value) -> &mut Vec<Value> {
    let Value::Array(parts) = value else {
        panic!("expected fixture array")
    };
    parts
}
fn bytes(value: &mut Value) -> &mut Vec<u8> {
    let Value::Bytes(bytes) = value else {
        panic!("expected fixture byte string")
    };
    bytes
}
fn changed(edit: impl FnOnce(&mut Vec<Value>)) -> Vec<u8> {
    let mut value = decode_canonical(&unhex(REQUEST)).unwrap();
    edit(parts(&mut value));
    encode_canonical(&value).unwrap()
}
fn changed_source(edit: impl FnOnce(&mut Vec<Value>)) -> Vec<u8> {
    changed(|request| {
        let mut signed = decode_canonical(bytes(&mut request[4])).unwrap();
        let mut source = decode_canonical(bytes(&mut parts(&mut signed)[0])).unwrap();
        edit(parts(&mut source));
        parts(&mut signed)[0] = Value::Bytes(encode_canonical(&source).unwrap());
        request[4] = Value::Bytes(encode_canonical(&signed).unwrap());
    })
}

fn pins(key: IdentityKey) -> EnvelopePins {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use sha2::{Digest as _, Sha256};
    let x = URL_SAFE_NO_PAD.encode(key.as_bytes());
    let jwk = format!("{{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"{x}\"}}");
    EnvelopePins::intersect(
        &[URL_SAFE_NO_PAD.encode(Sha256::digest(jwk.as_bytes()))],
        &[],
    )
    .unwrap()
}
fn sign(envelope: &mut BootstrapEnvelope, seed: u8) {
    envelope.signer = identity(seed);
    envelope.signature = SigningKey::from_bytes(&[seed; 32])
        .sign(&envelope.signing_input().unwrap())
        .to_bytes();
}
fn envelope(response: bool) -> BootstrapEnvelope {
    let mut envelope = BootstrapEnvelope {
        direction: if response {
            EnvelopeDirection::Response
        } else {
            EnvelopeDirection::Request
        },
        signer: identity(if response { 2 } else { 1 }),
        recipient: Some(identity(if response { 1 } else { 2 })),
        kind: NODE_RUNTIME_DECLARE.into(),
        unix_seconds: 100,
        nonce: [16; 16],
        payload: unhex(if response { ACCEPTED } else { REQUEST }),
        signature: [0; 64],
    };
    sign(&mut envelope, if response { 2 } else { 1 });
    envelope
}
fn validate(envelope: &BootstrapEnvelope, response: bool, now: u64, seen: Option<u64>) -> bool {
    let pins = pins(identity(if response { 2 } else { 1 }));
    let expected = EnvelopeExpectation {
        pins: &pins,
        direction: if response {
            EnvelopeDirection::Response
        } else {
            EnvelopeDirection::Request
        },
        recipient: identity(if response { 1 } else { 2 }),
        kind: NODE_RUNTIME_DECLARE,
        now_seconds: now,
        previous_acceptance_seconds: seen,
    };
    if response {
        RuntimeDeclarationAccepted::from_envelope(envelope, &expected, &request(), [16; 16]).is_ok()
    } else {
        RuntimeDeclarationRequest::from_envelope(envelope, &expected, &context()).is_ok()
    }
}

#[test]
fn runtime_declaration_independent_bytes_and_complete_digest() {
    let request = request();
    assert_eq!(NODE_RUNTIME_DECLARE, "node.runtime.declare.v1");
    assert_eq!(MAX_RUNTIME_DECLARATION_BYTES, 65_536);
    assert_eq!(request.canonical().unwrap(), unhex(REQUEST));
    assert_eq!(
        RuntimeDeclarationRequest::decode(&unhex(REQUEST)).unwrap(),
        request
    );
    assert_eq!(
        runtime_declaration_digest(&unhex(REQUEST)).as_slice(),
        unhex(DIGEST)
    );
    let accepted = RuntimeDeclarationAccepted::for_request(&request).unwrap();
    assert_eq!(accepted.declaration_seq, 15);
    assert_eq!(accepted.request_digest.as_slice(), unhex(DIGEST));
    assert_eq!(accepted.canonical().unwrap(), unhex(ACCEPTED));
    assert_eq!(
        RuntimeDeclarationAccepted::decode(&unhex(ACCEPTED)).unwrap(),
        accepted
    );
    accepted.validate_for(&request).unwrap();
    for path in [
        (1, 0),
        (1, 1),
        (2, 0),
        (2, 1),
        (2, 2),
        (2, 3),
        (3, 0),
        (3, 1),
        (3, 2),
        (5, 0),
        (5, 1),
        (5, 2),
    ] {
        let altered = changed(|v| {
            let field = &mut parts(&mut v[path.0])[path.1];
            match field {
                Value::UInt(n) => *n += 1,
                Value::Bytes(b) => b[0] ^= 1,
                _ => panic!("field"),
            }
        });
        assert_ne!(
            runtime_declaration_digest(&altered).as_slice(),
            unhex(DIGEST),
            "{path:?}"
        );
    }
    for field in 0..8 {
        let mut changed = request.clone();
        match field {
            0 => changed.registration.node_id[0] ^= 1,
            1 => changed.registration.credential_incarnation[0] ^= 1,
            2 => changed.registration.activation_generation[0] ^= 1,
            3 => changed.signed_source.binding.contribution[0] ^= 1,
            4 => changed.signed_source.binding.source_epoch += 1,
            5 => changed.signed_source.binding.source_generation += 1,
            6 => changed.signed_source.signature[0] ^= 1,
            _ => changed.capabilities.push("z.opaque".into()),
        }
        assert!(accepted.validate_for(&changed).is_err(), "field {field}");
    }
    let mut changed = request.clone();
    changed.declaration_seq += 1;
    assert!(accepted.validate_for(&changed).is_err());
}

#[test]
fn runtime_declaration_strict_arities_versions_and_consumption() {
    for index in [1, 2, 3, 5] {
        for extra in [false, true] {
            let altered = changed(|v| {
                if extra {
                    parts(&mut v[index]).push(Value::UInt(0));
                } else {
                    parts(&mut v[index]).pop();
                }
            });
            assert!(
                RuntimeDeclarationRequest::decode(&altered).is_err(),
                "nested {index}/{extra}"
            );
        }
        let altered = changed(|v| v[index] = Value::Bytes(encode_canonical(&v[index]).unwrap()));
        assert!(RuntimeDeclarationRequest::decode(&altered).is_err());
    }
    for altered in [
        changed(|v| {
            v.pop();
        }),
        changed(|v| v.push(Value::UInt(0))),
        changed(|v| v[0] = Value::UInt(2)),
        changed(|v| v[3] = Value::Null),
    ] {
        assert!(RuntimeDeclarationRequest::decode(&altered).is_err());
    }
    let raw = unhex(REQUEST);
    for cut in 0..raw.len() {
        assert!(
            RuntimeDeclarationRequest::decode(&raw[..cut]).is_err(),
            "cut {cut}"
        );
    }
    for malformed in [vec![0x98, 8], vec![0x9f], vec![0x88, 0x18, 1]] {
        let start = if malformed.len() == 3 { 2 } else { 1 };
        let mut altered = malformed;
        altered.extend_from_slice(&raw[start..]);
        assert!(RuntimeDeclarationRequest::decode(&altered).is_err());
    }
    let mut trailing = raw;
    trailing.push(0);
    assert!(RuntimeDeclarationRequest::decode(&trailing).is_err());
    for boundary in 0..3 {
        let altered = changed(|v| {
            if boundary == 0 {
                bytes(&mut v[4]).push(0);
                return;
            }
            let mut signed = decode_canonical(bytes(&mut v[4])).unwrap();
            if boundary == 1 {
                bytes(&mut parts(&mut signed)[0]).push(0);
            } else {
                parts(&mut signed).push(Value::UInt(0));
            }
            v[4] = Value::Bytes(encode_canonical(&signed).unwrap());
        });
        assert!(
            RuntimeDeclarationRequest::decode(&altered).is_err(),
            "source {boundary}"
        );
    }
    for response in [
        vec![0x82, 1, 15],
        vec![0x83, 2, 15],
        vec![0x83, 0x18, 1, 15],
        vec![0x84, 1, 15],
    ] {
        let mut malformed = response;
        malformed.extend_from_slice(&unhex(ACCEPTED)[3..]);
        assert!(RuntimeDeclarationAccepted::decode(&malformed).is_err());
    }
    let mut trailing = unhex(ACCEPTED);
    trailing.push(0);
    assert!(RuntimeDeclarationAccepted::decode(&trailing).is_err());
    for cut in 0..unhex(ACCEPTED).len() {
        assert!(RuntimeDeclarationAccepted::decode(&unhex(ACCEPTED)[..cut]).is_err());
    }
}

#[test]
fn runtime_declaration_nonzero_binding_and_source_constraints() {
    for (outer, inner, width) in [
        (1, 0, 16),
        (1, 1, 16),
        (2, 2, 32),
        (3, 0, 16),
        (3, 1, 16),
        (3, 2, 16),
        (5, 0, 16),
    ] {
        for len in [0, width - 1, width, width + 1] {
            let altered = changed(|v| parts(&mut v[outer])[inner] = Value::Bytes(vec![0; len]));
            assert!(
                RuntimeDeclarationRequest::decode(&altered).is_err(),
                "{outer}/{inner}/{len}"
            );
        }
    }
    for (outer, inner) in [(2, 0), (2, 3), (5, 1), (5, 2)] {
        let altered = changed(|v| parts(&mut v[outer])[inner] = Value::UInt(0));
        assert!(RuntimeDeclarationRequest::decode(&altered).is_err());
    }
    for altered in [
        changed(|v| v[6] = Value::UInt(0)),
        changed(|v| v[6] = Value::Null),
        changed(|v| parts(&mut v[2])[1] = Value::Bytes(vec![0; 31])),
    ] {
        assert!(RuntimeDeclarationRequest::decode(&altered).is_err());
    }
    for (field, value) in [
        (3, Value::Text("030c1g60r30c1g60r30c1g60r3".into())),
        (3, Value::Text("00000000000000000000000000".into())),
        (4, Value::Text("egress".into())),
        (5, Value::Text("other-profile".into())),
        (7, Value::Bytes(vec![0; 16])),
        (8, Value::UInt(0)),
        (9, Value::UInt(0)),
    ] {
        assert!(
            RuntimeDeclarationRequest::decode(&changed_source(|v| v[field] = value)).is_err(),
            "source field {field}"
        );
    }
    for field in [2, 6] {
        assert!(
            RuntimeDeclarationRequest::decode(&changed_source(
                |v| v[field] = Value::Bytes(identity(3).as_bytes().to_vec())
            ))
            .is_err()
        );
    }
    let mut request = request();
    request.declaration_seq = u64::MAX;
    assert_eq!(
        RuntimeDeclarationRequest::decode(&request.canonical().unwrap())
            .unwrap()
            .declaration_seq,
        u64::MAX
    );
    let mut accepted = RuntimeDeclarationAccepted::for_request(&request).unwrap();
    accepted.declaration_seq = 0;
    assert!(accepted.canonical().is_err());
    let malformed = encode_canonical(&Value::Array(vec![
        Value::UInt(1),
        Value::UInt(0),
        Value::Bytes(vec![0; 32]),
    ]))
    .unwrap();
    assert!(RuntimeDeclarationAccepted::decode(&malformed).is_err());
}

#[test]
fn runtime_declaration_capability_set_and_byte_bounds() {
    for capabilities in [
        vec![],
        vec!["node_l3_echo.v2".into()],
        vec!["a".repeat(64)],
        (0..64).map(|n| format!("cap.{n:02}")).collect(),
    ] {
        let mut request = request();
        request.capabilities = capabilities.clone();
        let decoded = RuntimeDeclarationRequest::decode(&request.canonical().unwrap()).unwrap();
        assert_eq!(decoded.capabilities, capabilities);
    }
    for capabilities in [
        vec!["".into()],
        vec!["a".repeat(65)],
        vec!["A".into()],
        vec!["a b".into()],
        vec!["a/b".into()],
        vec!["a\n".into()],
        vec!["é".into()],
        vec!["a".into(), "a".into()],
        vec!["b".into(), "a".into()],
        (0..65).map(|n| format!("cap.{n:02}")).collect(),
    ] {
        let altered = changed(|v| {
            v[7] = Value::Array(capabilities.iter().cloned().map(Value::Text).collect())
        });
        assert!(
            RuntimeDeclarationRequest::decode(&altered).is_err(),
            "{capabilities:?}"
        );
        let mut request = request();
        request.capabilities = capabilities;
        assert!(request.canonical().is_err());
    }
    assert!(RuntimeDeclarationRequest::decode(&changed(|v| v[7] = Value::Null)).is_err());
    for size in [16_384, 16_385, 65_536, 65_537] {
        let altered = changed(|v| v[4] = Value::Bytes(vec![0; size]));
        assert!(
            RuntimeDeclarationRequest::decode(&altered).is_err(),
            "size {size}"
        );
    }
    assert!(RuntimeDeclarationRequest::decode(&vec![0; 65_537]).is_err());
}

#[test]
fn runtime_declaration_independent_membership_and_source_trust() {
    let request = request();
    request.validate_context(&context()).unwrap();
    for field in 0..4 {
        let mut context = context();
        match field {
            0 => context.scope.nsd_id[0] ^= 1,
            1 => context.scope.network_id[0] ^= 1,
            2 => context.subject = identity(3),
            _ => context.authority = identity(3),
        }
        assert!(
            request.validate_context(&context).is_err(),
            "context {field}"
        );
    }
    let mut corrupt = request.clone();
    corrupt.signed_source.signature[0] ^= 1;
    assert!(corrupt.canonical().is_ok());
    assert!(corrupt.validate_context(&context()).is_err());
    let mut forged = request.clone();
    forged.signed_source.binding.nsd = identity(3);
    forged.signed_source.signature = SigningKey::from_bytes(&[3; 32])
        .sign(&forged.signed_source.signing_input().unwrap())
        .to_bytes();
    assert!(forged.canonical().is_ok());
    assert!(forged.validate_context(&context()).is_err());
}

#[test]
fn runtime_declaration_signed_envelope_authentication_and_correlation() {
    for response in [false, true] {
        let original = envelope(response);
        assert!(validate(&original, response, 100, None));
        assert!(validate(&original, response, 160, None));
        assert!(!validate(&original, response, 161, None));
        assert!(!validate(&original, response, 100, Some(100)));
        for field in 0..8 {
            let mut altered = original.clone();
            match field {
                0 => {
                    altered.direction = if response {
                        EnvelopeDirection::Request
                    } else {
                        EnvelopeDirection::Response
                    }
                }
                1 => altered.kind = "machine.auth".into(),
                2 => altered.recipient = None,
                3 => altered.recipient = Some(identity(3)),
                4 => altered.nonce = [0; 16],
                5 => {
                    sign(&mut altered, 3);
                    assert!(!validate(&altered, response, 100, None));
                    continue;
                }
                6 => {
                    altered.signature[0] ^= 1;
                    assert!(!validate(&altered, response, 100, None));
                    continue;
                }
                _ => altered.payload[1] ^= 1,
            }
            sign(&mut altered, if response { 2 } else { 1 });
            assert!(
                !validate(&altered, response, 100, None),
                "{response}/{field}"
            );
        }
        // A caller's self-consistent expectations cannot change operation-specific facts.
        for field in 0..4 {
            let mut altered = original.clone();
            match field {
                0 => altered.kind = "other".into(),
                1 => {
                    altered.direction = if response {
                        EnvelopeDirection::Request
                    } else {
                        EnvelopeDirection::Response
                    }
                }
                2 => altered.recipient = None,
                _ => sign(&mut altered, 3),
            }
            let seed = if field == 3 {
                3
            } else if response {
                2
            } else {
                1
            };
            sign(&mut altered, seed);
            let pins = pins(altered.signer);
            let expected = EnvelopeExpectation {
                pins: &pins,
                direction: altered.direction,
                recipient: altered.recipient.unwrap_or(identity(3)),
                kind: &altered.kind,
                now_seconds: 100,
                previous_acceptance_seconds: None,
            };
            altered.verify(&expected).unwrap();
            let ok = if response {
                RuntimeDeclarationAccepted::from_envelope(&altered, &expected, &request(), [16; 16])
                    .is_ok()
            } else {
                RuntimeDeclarationRequest::from_envelope(&altered, &expected, &context()).is_ok()
            };
            assert!(!ok, "self-presented {response}/{field}");
        }
    }
    let mut response = envelope(true);
    response.nonce = [17; 16];
    sign(&mut response, 2);
    assert!(!validate(&response, true, 100, None));
    for field in 0..2 {
        let mut accepted = RuntimeDeclarationAccepted::decode(&unhex(ACCEPTED)).unwrap();
        if field == 0 {
            accepted.declaration_seq += 1;
        } else {
            accepted.request_digest[0] ^= 1;
        }
        let mut response = envelope(true);
        response.payload = accepted.canonical().unwrap();
        sign(&mut response, 2);
        assert!(!validate(&response, true, 100, None));
    }
    let mut source = envelope(false);
    let mut corrupted = request();
    corrupted.signed_source.signature[0] ^= 1;
    source.payload = corrupted.canonical().unwrap();
    sign(&mut source, 1);
    assert!(!validate(&source, false, 100, None));
}
