#![allow(clippy::unwrap_used, clippy::panic)]

use ed25519_dalek::{Signer as _, SigningKey};
use nsshared_codec::cbor::value::{Value, decode_canonical, encode_canonical};
use nsshared_control::account::control::{
    BootstrapEnvelope, EnvelopeDirection, EnvelopeExpectation, EnvelopePins,
    MAX_NODE_RECORD_REPORT_BYTES, MembershipScope, NODE_RECORD_REPORT, NodeRecordReportAccepted,
    NodeRecordReportRequest, NodeReportContext, node_record_report_digest,
};
use nsshared_identity::{
    keys::IdentityKey,
    record::{NodeRecord, NodeRecordFields},
};
use nsshared_testkit::hex::unhex;

// Independent Python canonical CBOR and Ed25519 fixture with fixed keys and time.
const REQUEST: &str = concat!(
    "87018250030303030303030303030303030303035003030303030303030303030303030303840158208a88e3dd7409f1",
    "95fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c5820050505050505050505050505050505050505050505",
    "050505050505050505050502835006060606060606060606060606060606500707070707070707070707070707070750",
    "0808080808080808080808080808080858fc8258b78a0158208139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37",
    "a25df60f5b8fc9b39458208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c781a303330",
    "4331473630523330433147363052333043314736305233656e6f64657378186578706c696369742d676174657761792d",
    "70726f66696c6558208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c500a0a0a0a0a0a",
    "0a0a0a0a0a0a0a0a0a0a0b0c58406e9057a3813602f75f427ea416e0d88a58ae3464d4f8a114d755a3b773ae05b87315",
    "eaa44d328e4a2a7aa226c0999598bbc69cb4d1f96200f20dc3643203c907835009090909090909090909090909090909",
    "0d0e5891880258208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c5820050505050505",
    "05050505050505050505050505050505050505050505050505050218641a000151e480584090ef711b8e9277f194b67f",
    "0d5070521b1574ba78e118cda9892ed3a3f1dc53bed25e6b56b410ee4f911d7514bdee3042666b0e61dc4a39738d8073",
    "64a9e9e90b",
);
const DIGEST: &str = "66d8ad8acf00fbe57ef363706b6d38de5315a0cf69e7cc641d83b097f7c08f10";
const ACCEPTED: &str = "8201582066d8ad8acf00fbe57ef363706b6d38de5315a0cf69e7cc641d83b097f7c08f10";

fn identity(seed: u8) -> IdentityKey {
    IdentityKey::from_bytes(
        &SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes(),
    )
    .unwrap()
}
fn request() -> NodeRecordReportRequest {
    NodeRecordReportRequest::decode(&unhex(REQUEST)).unwrap()
}
fn context() -> NodeReportContext {
    NodeReportContext {
        scope: request().scope,
        subject: identity(1),
        authority: identity(2),
    }
}
fn record(seed: u8, key: [u8; 32], generation: u64, issued_at: u64) -> NodeRecord {
    NodeRecord::sign(
        &SigningKey::from_bytes(&[seed; 32]),
        NodeRecordFields {
            wg_key: key,
            generation,
            issued_at,
            expires: issued_at + 86_400,
            relays: vec![],
        },
    )
    .unwrap()
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
fn sign(value: &mut BootstrapEnvelope, seed: u8) {
    value.signer = identity(seed);
    value.signature = SigningKey::from_bytes(&[seed; 32])
        .sign(&value.signing_input().unwrap())
        .to_bytes();
}
fn envelope(response: bool) -> BootstrapEnvelope {
    let mut value = BootstrapEnvelope {
        direction: if response {
            EnvelopeDirection::Response
        } else {
            EnvelopeDirection::Request
        },
        signer: identity(if response { 2 } else { 1 }),
        recipient: Some(identity(if response { 1 } else { 2 })),
        kind: NODE_RECORD_REPORT.into(),
        unix_seconds: 100,
        nonce: [16; 16],
        payload: unhex(if response { ACCEPTED } else { REQUEST }),
        signature: [0; 64],
    };
    sign(&mut value, if response { 2 } else { 1 });
    value
}
fn admitted(value: &BootstrapEnvelope, response: bool, now: u64, seen: Option<u64>) -> bool {
    let pins = pins(identity(if response { 2 } else { 1 }));
    let expected = EnvelopeExpectation {
        pins: &pins,
        direction: if response {
            EnvelopeDirection::Response
        } else {
            EnvelopeDirection::Request
        },
        recipient: identity(if response { 1 } else { 2 }),
        kind: NODE_RECORD_REPORT,
        now_seconds: now,
        previous_acceptance_seconds: seen,
    };
    if response {
        NodeRecordReportAccepted::from_envelope(value, &expected, &request(), [16; 16]).is_ok()
    } else {
        NodeRecordReportRequest::from_envelope(value, &expected, &context()).is_ok()
    }
}
fn parts(value: &mut Value) -> &mut Vec<Value> {
    let Value::Array(parts) = value else {
        panic!("array fixture")
    };
    parts
}
fn changed(edit: impl FnOnce(&mut Vec<Value>)) -> Vec<u8> {
    let mut value = decode_canonical(&unhex(REQUEST)).unwrap();
    edit(parts(&mut value));
    encode_canonical(&value).unwrap()
}

#[test]
fn private_record_report_matches_independent_bytes_and_digest() {
    let request = request();
    assert_eq!(NODE_RECORD_REPORT, "node.record.report.v1");
    assert_eq!(MAX_NODE_RECORD_REPORT_BYTES, 65_536);
    assert_eq!(request.canonical().unwrap(), unhex(REQUEST));
    assert_eq!(request.record, record(1, [5; 32], 2, 100));
    request.validate_context(&context()).unwrap();
    assert_eq!(
        node_record_report_digest(&unhex(REQUEST)).as_slice(),
        unhex(DIGEST)
    );
    let accepted = NodeRecordReportAccepted::for_request(&request).unwrap();
    assert_eq!(accepted.request_digest.as_slice(), unhex(DIGEST));
    assert_eq!(accepted.canonical(), unhex(ACCEPTED));
    assert_eq!(
        NodeRecordReportAccepted::decode(&unhex(ACCEPTED)).unwrap(),
        accepted
    );
    accepted.validate_for(&request).unwrap();
    assert!(admitted(&envelope(false), false, 100, None));
    assert!(admitted(&envelope(true), true, 100, None));
}

#[test]
fn private_record_report_rejects_framing_and_nested_record_corruption() {
    for malformed in [
        vec![0x86, 1],
        vec![0x87, 2],
        vec![0x87, 0x18, 1],
        vec![0; MAX_NODE_RECORD_REPORT_BYTES + 1],
    ] {
        assert!(NodeRecordReportRequest::decode(&malformed).is_err());
    }
    let mut trailing = unhex(REQUEST);
    trailing.push(0);
    assert!(NodeRecordReportRequest::decode(&trailing).is_err());
    for index in [1, 2, 3, 5] {
        let bytes = changed(|v| {
            parts(&mut v[index]).push(Value::UInt(1));
        });
        assert!(NodeRecordReportRequest::decode(&bytes).is_err());
    }
    let bytes = changed(|v| {
        let Value::Bytes(record) = &mut v[6] else {
            panic!("record fixture")
        };
        *record.last_mut().unwrap() ^= 1;
    });
    assert!(NodeRecordReportRequest::decode(&bytes).is_err());
    let bytes = changed(|v| {
        v[6] = Value::Bytes(vec![0; 601]);
    });
    assert!(NodeRecordReportRequest::decode(&bytes).is_err());
}

#[test]
fn private_record_report_requires_exact_root_binding_and_source() {
    let original = request();
    for altered in [
        record(3, [5; 32], 2, 100),
        record(1, [6; 32], 2, 100),
        record(1, [5; 32], 3, 100),
    ] {
        let mut value = original.clone();
        value.record = altered;
        assert!(value.canonical().is_err());
    }
    let mut value = original.clone();
    value.signed_source.binding.scope = "egress".into();
    assert!(value.canonical().is_err());
    let mut value = original.clone();
    value.signed_source.binding.recipient = identity(3);
    assert!(value.canonical().is_err());
    let mut value = original.clone();
    value.signed_source.binding.source_node = identity(3);
    assert!(value.canonical().is_err());
    let mut value = original.clone();
    value.scope.network_id = [4; 16];
    assert!(value.canonical().is_err());
    let mut value = original;
    value.signed_source.signature[0] ^= 1;
    assert!(value.validate_context(&context()).is_err());
    let mut wrong = context();
    wrong.scope = MembershipScope {
        nsd_id: [4; 16],
        network_id: [3; 16],
    };
    assert!(request().validate_context(&wrong).is_err());
    let mut wrong = context();
    wrong.subject = identity(3);
    assert!(request().validate_context(&wrong).is_err());
    let mut wrong = context();
    wrong.authority = identity(3);
    assert!(request().validate_context(&wrong).is_err());
}

#[test]
fn private_record_report_carrier_refuses_substitution_and_replay() {
    for response in [false, true] {
        let seed = if response { 2 } else { 1 };
        for change in 0..5 {
            let mut value = envelope(response);
            match change {
                0 => value.recipient = Some(identity(3)),
                1 => value.kind = "node.heartbeat".into(),
                2 => value.nonce = [0; 16],
                3 => {
                    value.direction = if response {
                        EnvelopeDirection::Request
                    } else {
                        EnvelopeDirection::Response
                    }
                }
                _ => value.signer = identity(3),
            }
            let signer = if change == 4 { 3 } else { seed };
            sign(&mut value, signer);
            assert!(
                !admitted(&value, response, 100, None),
                "response={response}, change={change}"
            );
        }
        assert!(!admitted(&envelope(response), response, 1000, None));
        assert!(!admitted(&envelope(response), response, 100, Some(100)));
        let mut value = envelope(response);
        value.signature[0] ^= 1;
        assert!(!admitted(&value, response, 100, None));
    }
    let mut value = envelope(true);
    value.nonce = [17; 16];
    sign(&mut value, 2);
    assert!(!admitted(&value, true, 100, None));
}

#[test]
fn private_record_report_receipt_binds_every_current_request_field() {
    let original = request();
    let accepted = NodeRecordReportAccepted::for_request(&original).unwrap();
    for change in 0..10 {
        let mut value = original.clone();
        match change {
            0 => value.registration.node_id[0] ^= 1,
            1 => value.registration.credential_incarnation[0] ^= 1,
            2 => value.registration.activation_generation[0] ^= 1,
            3 => value.signed_source.binding.contribution[0] ^= 1,
            4 => value.signed_source.binding.source_epoch += 1,
            5 => value.signed_source.binding.source_generation += 1,
            6 => value.fence.runtime_id[0] ^= 1,
            7 => value.fence.runtime_generation += 1,
            8 => value.fence.authority_epoch += 1,
            _ => value.record = record(1, [5; 32], 2, 101),
        }
        assert_ne!(
            node_record_report_digest(&value.canonical().unwrap()),
            accepted.request_digest
        );
        assert!(accepted.validate_for(&value).is_err(), "change={change}");
    }
    let mut bad = accepted;
    bad.request_digest[0] ^= 1;
    assert!(bad.validate_for(&original).is_err());
    let mut malformed = unhex(ACCEPTED);
    malformed.push(0);
    assert!(NodeRecordReportAccepted::decode(&malformed).is_err());
}

#[test]
fn private_record_report_does_not_advertise_relays_or_accept_zero_fences() {
    let mut value = request();
    value.record = NodeRecord::sign(
        &SigningKey::from_bytes(&[1; 32]),
        NodeRecordFields {
            wg_key: [5; 32],
            generation: 2,
            issued_at: 100,
            expires: 86_500,
            relays: vec!["relay.example.test:443".parse().unwrap()],
        },
    )
    .unwrap();
    assert!(value.canonical().is_err());
    for field in 0..6 {
        let mut value = request();
        match field {
            0 => value.scope.nsd_id = [0; 16],
            1 => value.scope.network_id = [0; 16],
            2 => value.registration.node_id = [0; 16],
            3 => value.fence.runtime_id = [0; 16],
            4 => value.fence.runtime_generation = 0,
            _ => value.fence.authority_epoch = 0,
        }
        assert!(value.canonical().is_err(), "field={field}");
    }
}
