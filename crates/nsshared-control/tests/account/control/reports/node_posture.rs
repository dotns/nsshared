use nsshared_control::account::{AccountError, control::*};
use nsshared_identity::keys::IdentityKey;

#[test]
fn node_posture_vectors_and_correlated_receipts() {
    let vectors = nsshared_testkit::vectors!("account/control/node-posture");
    let request = NodePostureRequest::decode(
        &vectors
            .iter()
            .find(|v| v.name() == "full")
            .unwrap()
            .hex("bytes"),
    )
    .unwrap();
    assert_eq!(request.snapshot.os, "linux");
    assert_eq!(request.snapshot.os_version, "Ubuntu 24.04");
    assert_eq!(request.snapshot.arch, "x86_64");
    assert_eq!(request.snapshot.client_version, "1.2.3");
    assert_eq!(request.snapshot.hostname, "node-one");
    assert_eq!(
        request.snapshot.disk_encryption,
        DiskEncryptionStatus::Encrypted
    );
    assert_eq!(request.snapshot.uptime_seconds, 123);
    assert_eq!(request.snapshot.local_ips, ["192.0.2.1", "2001:db8::1"]);
    assert_eq!(
        ControlReportOperation::parse(NODE_POSTURE).unwrap(),
        ControlReportOperation::NodePosture
    );
    assert_eq!(ControlReportOperation::NodePosture.as_str(), "node.posture");
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
            EnvelopeDirection::Request => NodePostureRequest::decode(raw)?.canonical(),
            EnvelopeDirection::Response => NodePostureResponse::decode(raw)?.canonical(),
        };
        let result: Result<Vec<u8>, AccountError> = roundtrip(&bytes);
        match vector.get("error") {
            "none" | "correlation" => {
                assert_eq!(result.unwrap(), bytes, "{}", vector.name());
                ControlReportOperation::NodePosture
                    .validate_payload(direction, &bytes)
                    .unwrap();
                if direction == EnvelopeDirection::Response {
                    let receipt = NodePostureResponse::decode(&bytes).unwrap();
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
fn node_posture_in_memory_bounds_and_invalid_pending_request() {
    let vectors = nsshared_testkit::vectors!("account/control/node-posture");
    let request = NodePostureRequest::decode(
        &vectors
            .iter()
            .find(|v| v.name() == "full")
            .unwrap()
            .hex("bytes"),
    )
    .unwrap();
    let receipt = NodePostureResponse::decode(
        &vectors
            .iter()
            .find(|v| v.name() == "receipt")
            .unwrap()
            .hex("bytes"),
    )
    .unwrap();
    for field in 0..7 {
        let mut changed = request.clone();
        let snapshot = &mut changed.snapshot;
        match field {
            0 => snapshot.os = "x".repeat(MAX_NODE_POSTURE_TEXT_BYTES + 1),
            1 => snapshot.os_version = "x".repeat(MAX_NODE_POSTURE_TEXT_BYTES + 1),
            2 => snapshot.arch = "x".repeat(MAX_NODE_POSTURE_TEXT_BYTES + 1),
            3 => snapshot.client_version = "x".repeat(MAX_NODE_POSTURE_TEXT_BYTES + 1),
            4 => snapshot.hostname = "x".repeat(MAX_NODE_POSTURE_TEXT_BYTES + 1),
            5 => snapshot.local_ips = vec!["192.0.2.1".into(); MAX_NODE_POSTURE_IPS + 1],
            _ => snapshot.local_ips = vec!["x".repeat(MAX_NODE_POSTURE_IP_BYTES + 1)],
        }
        assert!(matches!(changed.canonical(), Err(AccountError::Bounds)));
        assert!(matches!(
            receipt.validate_for(&changed),
            Err(AccountError::Bounds)
        ));
    }
    let mut changed = request;
    changed.snapshot.local_ips = vec!["not-an-ip".into()];
    assert!(matches!(changed.canonical(), Err(AccountError::Field)));
    assert!(matches!(
        receipt.validate_for(&changed),
        Err(AccountError::Field)
    ));
}

#[test]
fn node_posture_requires_persisted_membership_and_endpoints() {
    for vector in &nsshared_testkit::vectors!("account/control/node-posture") {
        if vector.get("error") != "envelope" {
            continue;
        }
        let envelope = BootstrapEnvelope::decode(&vector.hex("bytes")).unwrap();
        let operation = ControlReportOperation::NodePosture;
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
