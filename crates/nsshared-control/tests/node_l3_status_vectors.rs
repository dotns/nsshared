#![allow(clippy::unwrap_used, clippy::panic)]

#[path = "support/vectors.rs"]
mod vectors;
use nsshared_control::{
    account::control::BootstrapEnvelope, account::control::EnvelopeDirection,
    account::control::EnvelopeExpectation, account::control::EnvelopePins,
    account::control::NODE_L3_STATUS, account::control::NodeL3Status,
    account::control::NodeL3StatusContext, account::control::NodeL3StatusRequest,
    account::control::NodeL3StatusResponse, account::control::node_l3_event_digest,
    account::publication::PublicationChannel, account::publication::PublicationDecision,
    account::publication::PublicationEvent, account::publication::PublicationExpectation,
    account::publication::PublicationScope, account::publication::SourceBinding,
    account::publication::decide_publication,
};
use nsshared_identity::keys::IdentityKey;

fn pins(identity: IdentityKey) -> EnvelopePins {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use sha2::{Digest as _, Sha256};
    let x = URL_SAFE_NO_PAD.encode(identity.as_bytes());
    let jwk = format!("{{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"{x}\"}}");
    EnvelopePins::intersect(
        &[URL_SAFE_NO_PAD.encode(Sha256::digest(jwk.as_bytes()))],
        &[],
    )
    .unwrap()
}

#[test]
fn node_l3_applied_status() {
    let cases = vectors::parse(include_str!("fixtures/vectors/node-l3-status.vec"));
    assert_eq!(cases.len(), 29);
    let initial = NodeL3StatusRequest::decode(&cases[0].hex("bytes")).unwrap();
    for case in &cases {
        let bytes = case.hex("bytes");
        let decoded = NodeL3StatusRequest::decode(&bytes);
        if case.get("decision") == "refuse" {
            assert!(decoded.is_err(), "{}", case.name());
            assert!(
                NodeL3StatusResponse::decode(&case.hex("response")).is_err(),
                "{}",
                case.name()
            );
            continue;
        }
        let report = decoded.unwrap();
        assert_eq!(report.canonical().unwrap(), bytes, "{}", case.name());
        let event_bytes = case.hex("event");
        let event = PublicationEvent::decode(&event_bytes).unwrap();
        assert_eq!(node_l3_event_digest(&event), case.hex_array::<32>("digest"));
        let current = SourceBinding::decode(&case.hex("source")).unwrap();
        let context = NodeL3StatusContext {
            event: &event,
            source_binding: &current,
        };
        let expected = case.get("decision") == "accept";
        assert_eq!(
            report.validate_issuance(context).is_ok(),
            expected,
            "{}",
            case.name()
        );
        assert_eq!(
            report.validate_application(context).is_ok(),
            expected,
            "{}",
            case.name()
        );
        let receipt = NodeL3StatusResponse::decode(&case.hex("response")).unwrap();
        assert_eq!(receipt.canonical().unwrap(), case.hex("response"));
        receipt.validate_for(&report).unwrap();
        let mut changed = report.clone();
        changed.request_id[0] ^= 1;
        assert!(receipt.validate_for(&changed).is_err());
        changed = report.clone();
        changed.status = match report.status {
            NodeL3Status::Applied => NodeL3Status::Rejected("not installed".into()),
            _ => NodeL3Status::Applied,
        };
        assert!(receipt.validate_for(&changed).is_err());
        let source_pins = pins(initial.key.recipient);
        let request_expected = EnvelopeExpectation {
            pins: &source_pins,
            direction: EnvelopeDirection::Request,
            recipient: initial.key.issuer,
            kind: NODE_L3_STATUS,
            now_seconds: 150,
            previous_acceptance_seconds: None,
        };
        let envelope = BootstrapEnvelope::decode(&case.hex("request-envelope")).unwrap();
        assert_eq!(
            NodeL3StatusRequest::from_envelope(&envelope, &request_expected).unwrap(),
            report
        );
        let nsd_pins = pins(initial.key.issuer);
        let response_expected = EnvelopeExpectation {
            pins: &nsd_pins,
            direction: EnvelopeDirection::Response,
            recipient: initial.key.recipient,
            kind: NODE_L3_STATUS,
            now_seconds: 150,
            previous_acceptance_seconds: None,
        };
        let envelope = BootstrapEnvelope::decode(&case.hex("response-envelope")).unwrap();
        assert_eq!(
            NodeL3StatusResponse::from_envelope(&envelope, &response_expected, &report, [8; 16])
                .unwrap(),
            receipt
        );
        assert!(
            NodeL3StatusResponse::from_envelope(&envelope, &response_expected, &report, [9; 16])
                .is_err()
        );
        assert!(
            NodeL3StatusResponse::from_envelope(&envelope, &response_expected, &changed, [8; 16])
                .is_err()
        );
        if expected {
            let scopes = [PublicationScope {
                served_realm: current.served_realm,
                scope: &current.scope,
            }];
            let expectation = PublicationExpectation {
                issuer: initial.key.issuer,
                recipient: initial.key.recipient,
                scopes: &scopes,
                channel: PublicationChannel::Snapshot,
                now_seconds: 150,
            };
            let decision = decide_publication(&[], Some(&event_bytes), &expectation);
            match case.name() {
                "fetch-failed-denied" => {
                    assert!(matches!(decision, PublicationDecision::FetchFailed(_)))
                }
                "empty-withdrawal" => assert!(matches!(decision, PublicationDecision::Withdraw(_))),
                _ => assert!(matches!(decision, PublicationDecision::Replace(_))),
            }
        }
    }
}

#[test]
fn node_l3_status_compares_every_current_source_field() {
    let cases = vectors::parse(include_str!("fixtures/vectors/node-l3-status.vec"));
    let report = NodeL3StatusRequest::decode(&cases[0].hex("bytes")).unwrap();
    let event_bytes = cases[0].hex("event");
    let event = PublicationEvent::decode(&event_bytes).unwrap();
    for field in 0..8 {
        let mut current = report.source_binding.clone();
        match field {
            0 => current.nsd = report.key.recipient,
            1 => current.recipient = report.key.issuer,
            2 => current.served_realm = nsshared_identity::realm::RealmId::from_bytes([9; 16]),
            3 => current.scope = "egress".into(),
            4 => current.source_node = report.key.issuer,
            5 => current.contribution = [11; 16],
            6 => current.source_epoch += 1,
            _ => current.source_generation += 1,
        }
        let context = NodeL3StatusContext {
            event: &event,
            source_binding: &current,
        };
        assert!(report.validate_issuance(context).is_err(), "field {field}");
        assert!(
            report.validate_application(context).is_err(),
            "field {field}"
        );
    }
    // Every signed byte, including the signature, belongs to the digest.
    let digest = node_l3_event_digest(&event);
    let mut changed = event_bytes.clone();
    let index = changed.len() - 1;
    changed[index] ^= 1;
    let changed = PublicationEvent::decode(&changed).unwrap();
    assert_ne!(digest, node_l3_event_digest(&changed));
}

#[test]
fn node_l3_receipt_refuses_extended_and_noncanonical_bytes() {
    use nsshared_codec::cbor::CborWriter;
    let cases = vectors::parse(include_str!("fixtures/vectors/node-l3-status.vec"));
    let raw = cases[0].hex("bytes");
    let mut extended = CborWriter::default();
    extended.array(3).uint(1).bytes(&raw).uint(0);
    assert!(NodeL3StatusResponse::decode(&extended.into_bytes()).is_err());
    let mut schema = CborWriter::default();
    schema.array(2).uint(2).bytes(&raw);
    assert!(NodeL3StatusResponse::decode(&schema.into_bytes()).is_err());
    let response = cases[0].hex("response");
    let mut nonminimal = vec![0x82, 0x18, 0x01];
    nonminimal.extend_from_slice(&response[2..]);
    assert!(NodeL3StatusResponse::decode(&nonminimal).is_err());
    let mut trailing = response;
    trailing.push(0);
    assert!(NodeL3StatusResponse::decode(&trailing).is_err());
}

#[test]
fn node_l3_status_enforces_envelope_operation_direction_and_identity() {
    use ed25519_dalek::{Signer as _, SigningKey};
    let cases = vectors::parse(include_str!("fixtures/vectors/node-l3-status.vec"));
    let report = NodeL3StatusRequest::decode(&cases[0].hex("bytes")).unwrap();
    for field in 0..4 {
        let mut envelope = BootstrapEnvelope::decode(&cases[0].hex("request-envelope")).unwrap();
        let mut seed = [1; 32];
        match field {
            0 => envelope.kind = "other.operation".into(),
            1 => envelope.direction = EnvelopeDirection::Response,
            2 => {
                envelope.signer = report.key.issuer;
                seed = [2; 32];
            }
            _ => envelope.recipient = Some(report.key.recipient),
        }
        let key = SigningKey::from_bytes(&seed);
        envelope.signature = key.sign(&envelope.signing_input().unwrap()).to_bytes();
        let pins = pins(envelope.signer);
        // Authenticate these modified carriers first: the operation-specific checks must refuse them.
        let expected = EnvelopeExpectation {
            pins: &pins,
            direction: envelope.direction,
            recipient: envelope.recipient.unwrap(),
            kind: &envelope.kind,
            now_seconds: 150,
            previous_acceptance_seconds: None,
        };
        envelope.verify(&expected).unwrap();
        assert!(NodeL3StatusRequest::from_envelope(&envelope, &expected).is_err());
    }
    for field in 0..4 {
        let mut envelope = BootstrapEnvelope::decode(&cases[0].hex("response-envelope")).unwrap();
        let mut seed = [2; 32];
        match field {
            0 => envelope.kind = "other.operation".into(),
            1 => envelope.direction = EnvelopeDirection::Request,
            2 => {
                envelope.signer = report.key.recipient;
                seed = [1; 32];
            }
            _ => envelope.recipient = Some(report.key.issuer),
        }
        let key = SigningKey::from_bytes(&seed);
        envelope.signature = key.sign(&envelope.signing_input().unwrap()).to_bytes();
        let pins = pins(envelope.signer);
        let expected = EnvelopeExpectation {
            pins: &pins,
            direction: envelope.direction,
            recipient: envelope.recipient.unwrap(),
            kind: &envelope.kind,
            now_seconds: 150,
            previous_acceptance_seconds: None,
        };
        envelope.verify(&expected).unwrap();
        assert!(
            NodeL3StatusResponse::from_envelope(&envelope, &expected, &report, [8; 16]).is_err()
        );
    }
}
