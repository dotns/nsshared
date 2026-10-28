use nsshared_control::account::{AccountError, control::*};
use nsshared_identity::keys::IdentityKey;

#[test]
fn fenced_gateway_vectors_and_correlated_receipts() {
    let vectors = nsshared_testkit::vectors!("account/control/fenced-gateway");
    let request = FencedGatewayReportRequest::decode(
        &vectors
            .iter()
            .find(|v| v.name() == "full")
            .unwrap()
            .hex("bytes"),
    )
    .unwrap();
    assert!(!request.report.draining);
    assert_eq!(request.report.request_id, [8; 16]);
    for vector in &vectors {
        if vector.get("error") == "envelope" {
            continue;
        }
        let bytes = vector.hex("bytes");
        let direction = if vector.get("direction") == "0" {
            EnvelopeDirection::Request
        } else {
            EnvelopeDirection::Response
        };
        let roundtrip = |raw: &[u8]| match direction {
            EnvelopeDirection::Request => FencedGatewayReportRequest::decode(raw)?.canonical(),
            EnvelopeDirection::Response => FencedGatewayReportResponse::decode(raw)?.canonical(),
        };
        let result: Result<Vec<u8>, AccountError> = roundtrip(&bytes);
        match vector.get("error") {
            "none" | "correlation" => {
                assert_eq!(result.unwrap(), bytes, "{}", vector.name());
                ControlReportOperation::Gateway
                    .validate_payload(direction, &bytes)
                    .unwrap();
                if direction == EnvelopeDirection::Response {
                    let receipt = FencedGatewayReportResponse::decode(&bytes).unwrap();
                    if vector.get("error") == "correlation" {
                        assert!(
                            matches!(receipt.validate_for(&request), Err(AccountError::Field)),
                            "{}",
                            vector.name()
                        );
                    } else {
                        receipt.validate_for(&request).unwrap();
                    }
                }
                let mut trailing = bytes.clone();
                trailing.push(0);
                assert!(matches!(roundtrip(&trailing), Err(AccountError::Cbor(_))));
                let mut noncanonical = bytes.clone();
                noncanonical.splice(1..2, [0x18, 1]);
                assert!(matches!(
                    roundtrip(&noncanonical),
                    Err(AccountError::Cbor(_))
                ));
                let mut noncanonical = bytes.clone();
                noncanonical.splice(0..1, [0x98, bytes[0] & 0x1f]);
                assert!(matches!(
                    roundtrip(&noncanonical),
                    Err(AccountError::Cbor(_))
                ));
            }
            "field" => assert!(
                matches!(result, Err(AccountError::Field)),
                "{}: {result:?}",
                vector.name()
            ),
            "cbor" => assert!(
                matches!(result, Err(AccountError::Cbor(_))),
                "{}: {result:?}",
                vector.name()
            ),
            _ => panic!("unknown refusal"),
        }
    }
}

#[test]
fn fenced_gateway_requires_persisted_membership_and_endpoints() {
    for vector in &nsshared_testkit::vectors!("account/control/fenced-gateway") {
        if vector.get("error") != "envelope" {
            continue;
        }
        let envelope = BootstrapEnvelope::decode(&vector.hex("bytes")).unwrap();
        let operation = ControlReportOperation::Gateway;
        let context = NodeReportContext {
            scope: MembershipScope {
                nsd_id: [3; 16],
                network_id: [4; 16],
            },
            subject: IdentityKey::from_bytes(&vector.hex_array("subject")).unwrap(),
            authority: IdentityKey::from_bytes(&vector.hex_array("authority")).unwrap(),
        };
        let pins = EnvelopePins::intersect(&[vector.get("pin").into()], &[]).unwrap();
        let expected = EnvelopeExpectation {
            pins: &pins,
            direction: EnvelopeDirection::Request,
            recipient: context.authority,
            kind: operation.as_str(),
            now_seconds: 100,
            previous_acceptance_seconds: None,
        };
        context
            .validate_envelope(operation, &envelope, &expected)
            .unwrap();
        assert!(matches!(
            operation.validate_envelope(&envelope, &expected),
            Err(ExchangeError::Scope)
        ));
        let mut changed = context.clone();
        changed.scope.nsd_id[0] ^= 1;
        assert!(matches!(
            changed.validate_envelope(operation, &envelope, &expected),
            Err(NodeReportError::Scope)
        ));
        changed = context.clone();
        changed.scope.network_id[0] ^= 1;
        assert!(matches!(
            changed.validate_envelope(operation, &envelope, &expected),
            Err(NodeReportError::Scope)
        ));
        changed = context.clone();
        changed.subject = context.authority;
        assert!(matches!(
            changed.validate_envelope(operation, &envelope, &expected),
            Err(NodeReportError::Subject)
        ));
        changed = context.clone();
        changed.authority = context.subject;
        assert!(matches!(
            changed.validate_envelope(operation, &envelope, &expected),
            Err(NodeReportError::Authority)
        ));
        let mut invalid = envelope.clone();
        invalid.signature[0] ^= 1;
        assert!(matches!(
            context.validate_envelope(operation, &invalid, &expected),
            Err(NodeReportError::Envelope(_))
        ));
        assert!(matches!(
            context.validate_envelope(ControlReportOperation::Heartbeat, &envelope, &expected),
            Err(NodeReportError::Operation)
        ));
    }
}

#[test]
fn fenced_gateway_operation_accepts_scoped_payload() {
    let vectors = nsshared_testkit::vectors!("account/control/fenced-gateway");
    let bytes = vectors
        .iter()
        .find(|v| v.name() == "full")
        .unwrap()
        .hex("bytes");
    ControlReportOperation::Gateway
        .validate_payload(EnvelopeDirection::Request, &bytes)
        .unwrap();
}

#[test]
fn fenced_gateway_preserves_observations_and_validates_in_memory_context() {
    let vectors = nsshared_testkit::vectors!("account/control/fenced-gateway");
    let request = FencedGatewayReportRequest::decode(
        &vectors
            .iter()
            .find(|v| v.name() == "full")
            .unwrap()
            .hex("bytes"),
    )
    .unwrap();
    let receipt = FencedGatewayReportResponse::decode(
        &vectors
            .iter()
            .find(|v| v.name() == "receipt")
            .unwrap()
            .hex("bytes"),
    )
    .unwrap();
    let drain = FencedGatewayReportRequest::decode(
        &vectors
            .iter()
            .find(|v| v.name() == "drain")
            .unwrap()
            .hex("bytes"),
    )
    .unwrap();
    assert!(drain.report.draining);
    let mut expected = request.clone();
    expected.report.draining = true;
    assert_eq!(expected, drain);
    assert_eq!(
        GatewayReport::decode(&request.report.canonical().unwrap()).unwrap(),
        request.report
    );
    assert_eq!(
        GatewayReportResponse::decode(&receipt.response.canonical()).unwrap(),
        receipt.response
    );
    for index in 0..3 {
        let mut invalid_request = request.clone();
        let mut invalid_receipt = receipt.clone();
        for fence in [&mut invalid_request.fence, &mut invalid_receipt.fence] {
            match index {
                0 => fence.runtime_id = [0; 16],
                1 => fence.runtime_generation = 0,
                _ => fence.authority_epoch = 0,
            }
        }
        assert!(matches!(
            invalid_request.canonical(),
            Err(AccountError::Field)
        ));
        assert!(matches!(
            invalid_receipt.canonical(),
            Err(AccountError::Field)
        ));
        assert!(matches!(
            receipt.validate_for(&invalid_request),
            Err(AccountError::Field)
        ));
        assert!(matches!(
            invalid_receipt.validate_for(&request),
            Err(AccountError::Field)
        ));
    }
    let mut invalid = request;
    invalid.report.public_http_port = Some(0);
    assert!(matches!(invalid.canonical(), Err(AccountError::Field)));
    assert!(matches!(
        receipt.validate_for(&invalid),
        Err(AccountError::Field)
    ));
}
