#![allow(clippy::unwrap_used)]
use nsshared_control::service::{FloorContent, ReportContent};

#[test]
fn empty_floor_preserves_legacy_report_bytes() {
    let report = ReportContent {
        publisher_identity: [3; 32],
        nsd_id: [1; 16],
        network_id: [2; 16],
        strict_mode: false,
        declarations: vec![],
    };
    let floor = FloorContent {
        report: report.clone(),
        metadata: vec![],
        exit_profiles: vec![],
    };
    assert_eq!(floor.canonical().unwrap(), report.canonical().unwrap());
    assert_eq!(
        FloorContent::decode(&report.canonical().unwrap().0).unwrap(),
        floor
    );
}

use nsshared_control::service::{
    ContractError, ExitSelection, FloorExitProfile, FloorReportMessage, Message, MessageBody,
    ReportAccepted,
};
use nsshared_testkit::hex::{decode as unhex, encode as hex};
use serde_json::Value as Json;

fn vectors() -> Json {
    serde_json::from_str(include_str!("../vectors/service/floor.json")).unwrap()
}
fn vector_bytes(key: &str) -> Vec<u8> {
    unhex(vectors()[key].as_str().unwrap()).unwrap()
}
fn sample() -> FloorContent {
    FloorContent::decode(&vector_bytes("floor_cbor")).unwrap()
}

#[test]
fn independent_whole_floor_round_trip_and_digest() {
    let input = vector_bytes("floor_cbor");
    let floor = sample();
    assert_eq!(floor.report.declarations.len(), 1);
    assert_eq!(floor.metadata[0].reference, "alpha");
    assert_eq!(floor.exit_profiles[0].reference, "office");
    let (bytes, digest) = floor.canonical().unwrap();
    assert_eq!(bytes, input);
    assert_eq!(hex(&digest), vectors()["floor_sha256"].as_str().unwrap());
    assert!(ReportContent::decode(&input).is_err());
    let wire = vector_bytes("message_cbor");
    let message = FloorReportMessage::decode(&wire).unwrap();
    assert_eq!(&message.report().report, &floor);
    assert_eq!(message.encode().unwrap(), wire);
    assert!(Message::decode(&wire).is_err());
    let constructed = message
        .context()
        .clone()
        .with_floor(floor.metadata, floor.exit_profiles)
        .unwrap();
    assert_eq!(constructed, message);
}

#[test]
fn independent_default_floor_round_trip_and_digest() {
    let mut floor = sample();
    floor.exit_profiles[0].selection = ExitSelection::Default;
    let input = vector_bytes("default_floor_cbor");
    let (bytes, digest) = floor.canonical().unwrap();
    assert_eq!(bytes, input);
    assert_eq!(FloorContent::decode(&input).unwrap(), floor);
    assert_eq!(hex(&digest), vectors()["default_floor_sha256"]);
    assert_ne!(digest, sample().canonical().unwrap().1);
    let wire = vector_bytes("default_message_cbor");
    let message = FloorReportMessage::decode(&wire).unwrap();
    assert_eq!(message.report().report, floor);
    assert_eq!(message.encode().unwrap(), wire);
    assert_eq!(
        message
            .context()
            .clone()
            .with_floor(floor.metadata, floor.exit_profiles)
            .unwrap(),
        message
    );
    assert!(ReportContent::decode(&input).is_err());
    assert!(Message::decode(&wire).is_err());
    assert!(matches!(
        message.context().body,
        MessageBody::ReportReplace(_)
    ));
}

#[test]
fn default_and_explicit_profiles_share_complete_floor_validation() {
    let mut floor = sample();
    let mut default = floor.exit_profiles[0].clone();
    default.reference = "internet".into();
    default.selection = ExitSelection::Default;
    default.enabled = false;
    floor.exit_profiles.insert(0, default);
    let bytes = floor.canonical().unwrap().0;
    assert_eq!(FloorContent::decode(&bytes).unwrap(), floor);
    floor.exit_profiles.swap(0, 1);
    assert_eq!(floor.canonical(), Err(ContractError::InvalidFloorOrder));
    floor.exit_profiles.swap(0, 1);
    floor.exit_profiles[1].reference = "internet".into();
    assert_eq!(floor.canonical(), Err(ContractError::InvalidFloorOrder));
}

#[test]
fn independent_invalid_floor_vectors_are_refused() {
    for (name, value) in vectors()["invalid"].as_object().unwrap() {
        let result = FloorContent::decode(&unhex(value.as_str().unwrap()).unwrap());
        let expected = match name.as_str() {
            "invalid_cidr"
            | "invalid_prefix_length"
            | "noncanonical_ipv6"
            | "empty_cidrs"
            | "overlapping_cidrs"
            | "empty_selection"
            | "unknown_selection"
            | "unknown_selection_payload"
            | "default_payload"
            | "default_cidrs"
            | "default_extra"
            | "explicit_missing_cidrs"
            | "selection_boolean"
            | "selection_text" => ContractError::InvalidFloorCidr,
            "selection_not_array" => ContractError::InvalidField,
            "dangling_metadata" => ContractError::InvalidFloorBinding,
            "oversize_cidrs" | "oversize_text" => ContractError::FloorLimit,
            "unknown_version" => ContractError::UnsupportedVersion,
            "unknown_field" => ContractError::UnsupportedField,
            _ => ContractError::InvalidFloorOrder,
        };
        assert_eq!(result, Err(expected), "{name}");
    }
    assert!(FloorContent::decode(&vec![0; 65_537]).is_err());
}

#[test]
fn entire_floor_changes_the_digest_and_acknowledgement() {
    for key in ["message_cbor", "default_message_cbor"] {
        check_floor_acknowledgement(key);
    }
}

fn check_floor_acknowledgement(key: &str) {
    let message = FloorReportMessage::decode(&vector_bytes(key)).unwrap();
    let mut reply = message.context().clone();
    reply.body = MessageBody::ReportAccepted(ReportAccepted {
        accepted_revision: 3,
        report_digest: Some(message.report().report.canonical().unwrap().1),
        bindings: vec![],
    });
    message.validate_accepted(&reply).unwrap();
    for change in 0..10 {
        let mut changed = message.report().report.clone();
        match change {
            0 => changed.metadata[0].capabilities = vec!["tcp".into()],
            1 => changed.metadata[0].policy_labels[0].1 = "database".into(),
            2 => changed.exit_profiles[0].reference = "remote".into(),
            3 => changed.exit_profiles[0].enabled = false,
            4 => {
                changed.exit_profiles[0].selection =
                    ExitSelection::Explicit(vec!["192.0.2.0/24".into()])
            }
            5 => changed.exit_profiles[0].capabilities = vec!["tcp".into()],
            6 => changed.exit_profiles[0].policy_labels[0].1 = "remote".into(),
            7 => changed.metadata.clear(),
            8 => changed.exit_profiles.clear(),
            _ => {
                changed.exit_profiles[0].selection = match changed.exit_profiles[0].selection {
                    ExitSelection::Default => sample().exit_profiles[0].selection.clone(),
                    ExitSelection::Explicit(_) => ExitSelection::Default,
                };
            }
        }
        let request = message
            .context()
            .clone()
            .with_floor(changed.metadata, changed.exit_profiles)
            .unwrap();
        assert_eq!(
            request.validate_accepted(&reply),
            Err(ContractError::DigestConflict)
        );
    }
    for change in 0..8 {
        let mut changed = reply.clone();
        match change {
            0 => changed.nsd_id[0] ^= 1,
            1 => changed.network_id[0] ^= 1,
            2 => changed.subject_identity[0] ^= 1,
            3 => changed.runtime_id = Some([9; 16]),
            4 => changed.runtime_generation = Some(2),
            5 => changed.authority_epoch = Some(3),
            6 => changed.request_id[0] ^= 1,
            _ => {
                if let MessageBody::ReportAccepted(body) = &mut changed.body {
                    body.accepted_revision += 1;
                }
            }
        }
        assert!(message.validate_accepted(&changed).is_err());
    }
}

#[test]
fn invalid_programmatic_floor_is_refused() {
    let mut floor = sample();
    for selection in [
        ExitSelection::Default,
        ExitSelection::Explicit(vec!["0.0.0.0/0".into()]),
    ] {
        floor.exit_profiles = vec![FloorExitProfile {
            reference: "".into(),
            selection,
            enabled: true,
            capabilities: vec![],
            policy_labels: vec![],
        }];
        assert_eq!(floor.canonical(), Err(ContractError::InvalidField));
    }
    floor = sample();
    floor.exit_profiles[0].selection = ExitSelection::Default;
    floor.exit_profiles[0].capabilities = vec!["udp".into(), "tcp".into()];
    assert_eq!(floor.canonical(), Err(ContractError::InvalidFloorOrder));
    floor.exit_profiles[0].capabilities.clear();
    floor.metadata[0].reference = "absent".into();
    assert_eq!(floor.canonical(), Err(ContractError::InvalidFloorBinding));
}

#[cfg(feature = "unstable-account")]
#[test]
fn authenticated_pending_floor_correlates_complete_digest() {
    for key in ["signed", "signed_default"] {
        check_authenticated_pending_floor(key);
    }
}

#[cfg(feature = "unstable-account")]
fn check_authenticated_pending_floor(key: &str) {
    use nsshared_control::account::control::{
        BootstrapEnvelope, EnvelopeDirection, EnvelopeExpectation, EnvelopePins, PendingRequest,
        SERVICE_CONTROL, UnaryReply, validate_unary_reply, validate_unary_request,
    };
    let vectors = vectors();
    let data = &vectors[key];
    let request =
        BootstrapEnvelope::decode(&unhex(data["request"].as_str().unwrap()).unwrap()).unwrap();
    let node_pins =
        EnvelopePins::intersect(&[data["node_pin"].as_str().unwrap().into()], &[]).unwrap();
    let authority_pins =
        EnvelopePins::intersect(&[data["authority_pin"].as_str().unwrap().into()], &[]).unwrap();
    let expected = EnvelopeExpectation {
        pins: &node_pins,
        direction: EnvelopeDirection::Request,
        recipient: request.recipient.unwrap(),
        kind: SERVICE_CONTROL,
        now_seconds: 100,
        previous_acceptance_seconds: None,
    };
    assert!(validate_unary_request(&request, &expected).is_err());
    let authenticated = FloorReportMessage::from_envelope(&request, &expected).unwrap();
    assert_eq!(authenticated.encode().unwrap(), request.payload);
    let mut tampered = request.clone();
    tampered.signature[0] ^= 1;
    assert!(FloorReportMessage::from_envelope(&tampered, &expected).is_err());
    let pending = PendingRequest::from_envelope(&request, &expected).unwrap();
    assert_eq!(
        pending.floor_report().unwrap().encode().unwrap(),
        request.payload
    );
    let expected = EnvelopeExpectation {
        pins: &authority_pins,
        direction: EnvelopeDirection::Response,
        recipient: request.signer,
        kind: SERVICE_CONTROL,
        now_seconds: 100,
        previous_acceptance_seconds: None,
    };
    for name in [
        "accepted",
        "legacy_digest",
        "stale_runtime",
        "wrong_revision",
        "wrong_nonce",
    ] {
        let reply =
            BootstrapEnvelope::decode(&unhex(data[name].as_str().unwrap()).unwrap()).unwrap();
        let result = validate_unary_reply(&reply, &expected, &pending);
        if name == "accepted" {
            assert!(matches!(result, Ok(UnaryReply::Message(_))));
        } else {
            assert!(result.is_err(), "{name}");
        }
    }
}

#[test]
fn floor_report_rejects_tampered_digest_scope_and_runtime() {
    for key in ["message_cbor", "default_message_cbor"] {
        check_tampered_floor(key);
    }
}

fn check_tampered_floor(key: &str) {
    use nsshared_codec::cbor::value::{Value, decode_canonical, encode_canonical};
    let wire = vector_bytes(key);
    for (name, replacement) in [
        ("network_id", Value::Bytes(vec![9; 16])),
        ("subject_identity", Value::Bytes(vec![9; 32])),
        ("runtime_generation", Value::UInt(0)),
        ("runtime_id", Value::Null),
        ("authority_epoch", Value::UInt(0)),
        ("request_id", Value::Bytes(vec![0; 16])),
    ] {
        let Value::Map(mut fields) = decode_canonical(&wire).unwrap() else {
            unreachable!()
        };
        fields.iter_mut().find(|(k, _)| k == name).unwrap().1 = replacement;
        assert!(
            FloorReportMessage::decode(&encode_canonical(&Value::Map(fields)).unwrap()).is_err(),
            "{name}"
        );
    }
    let Value::Map(mut fields) = decode_canonical(&wire).unwrap() else {
        unreachable!()
    };
    let Value::Map(body) = &mut fields.iter_mut().find(|(k, _)| k == "body").unwrap().1 else {
        unreachable!()
    };
    body.iter_mut()
        .find(|(k, _)| k == "report_digest")
        .unwrap()
        .1 = Value::Bytes(vec![0; 32]);
    assert_eq!(
        FloorReportMessage::decode(&encode_canonical(&Value::Map(fields)).unwrap()),
        Err(ContractError::DigestConflict)
    );
}

#[test]
fn cidr_boundaries_and_collection_limits_are_checked() {
    let mut floor = sample();
    for cidrs in [
        vec!["0.0.0.0/0", "::/0"],
        vec!["192.0.2.1/32", "2001:db8::1/128"],
    ] {
        floor.exit_profiles[0].selection =
            ExitSelection::Explicit(cidrs.into_iter().map(str::to_owned).collect());
        let bytes = floor.canonical().unwrap().0;
        assert_eq!(FloorContent::decode(&bytes).unwrap(), floor);
    }
    floor.exit_profiles[0].selection =
        ExitSelection::Explicit(vec!["2001:db8::/32".into(), "2001:db8::/64".into()]);
    assert_eq!(floor.canonical(), Err(ContractError::InvalidFloorCidr));
    floor = sample();
    floor.metadata = vec![floor.metadata[0].clone(); 257];
    assert_eq!(floor.canonical(), Err(ContractError::FloorLimit));
    floor = sample();
    floor.exit_profiles = vec![floor.exit_profiles[0].clone(); 257];
    assert_eq!(floor.canonical(), Err(ContractError::FloorLimit));
    floor = sample();
    floor.exit_profiles[0].policy_labels = vec![("a".into(), "b".into()); 257];
    assert_eq!(floor.canonical(), Err(ContractError::FloorLimit));
}

#[test]
fn typed_floor_errors_have_valid_wire_codes() {
    let request = FloorReportMessage::decode(&vector_bytes("message_cbor")).unwrap();
    for error in [
        ContractError::InvalidFloorCidr,
        ContractError::InvalidFloorBinding,
        ContractError::InvalidFloorOrder,
        ContractError::DefaultExitUnsupported,
        ContractError::FloorLimit,
    ] {
        let mut reply = request.context().clone();
        reply.body = MessageBody::Error(error.code().into());
        let encoded = reply.encode().unwrap();
        assert_eq!(Message::decode(&encoded).unwrap(), reply);
    }
}
