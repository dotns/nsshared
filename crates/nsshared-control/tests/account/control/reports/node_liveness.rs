use nsshared_control::account::{AccountError, control::*};
use nsshared_identity::keys::IdentityKey;

fn roundtrip(
    operation: ControlReportOperation,
    direction: EnvelopeDirection,
    bytes: &[u8],
) -> Result<Vec<u8>, AccountError> {
    match (operation, direction) {
        (ControlReportOperation::NodeHeartbeat, EnvelopeDirection::Request) => {
            NodeHeartbeatRequest::decode(bytes)?.canonical()
        }
        (ControlReportOperation::NodeHeartbeat, EnvelopeDirection::Response) => {
            NodeHeartbeatResponse::decode(bytes)?.canonical()
        }
        (ControlReportOperation::NodeDisconnect, EnvelopeDirection::Request) => {
            NodeDisconnectRequest::decode(bytes)?.canonical()
        }
        (ControlReportOperation::NodeDisconnect, EnvelopeDirection::Response) => {
            NodeDisconnectResponse::decode(bytes)?.canonical()
        }
        _ => panic!("unexpected operation"),
    }
}

#[test]
fn node_liveness_vectors_and_bounded_refusals() {
    for vector in &nsshared_testkit::vectors!("account/control/node-liveness") {
        if vector.get("error") == "envelope" {
            continue;
        }
        let raw = vector.hex("bytes");
        let operation = ControlReportOperation::parse(vector.get("operation")).unwrap();
        assert_eq!(operation.as_str(), vector.get("operation"));
        let direction = if vector.get("direction") == "0" {
            EnvelopeDirection::Request
        } else {
            EnvelopeDirection::Response
        };
        let result = roundtrip(operation, direction, &raw);
        match vector.get("error") {
            "none" => {
                assert_eq!(result.unwrap(), raw, "{}", vector.name());
                operation.validate_payload(direction, &raw).unwrap();
                if operation == ControlReportOperation::NodeHeartbeat {
                    match direction {
                        EnvelopeDirection::Request => {
                            assert!(HeartbeatRequest::decode(&raw).is_err())
                        }
                        EnvelopeDirection::Response => {
                            assert!(HeartbeatResponse::decode(&raw).is_err())
                        }
                    }
                }
                let mut trailing = raw.clone();
                trailing.push(0);
                assert!(roundtrip(operation, direction, &trailing).is_err());
                let mut noncanonical = raw;
                noncanonical.splice(1..2, [0x18, 1]);
                assert!(roundtrip(operation, direction, &noncanonical).is_err());
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
fn node_liveness_requires_persisted_membership_and_endpoints() {
    for vector in &nsshared_testkit::vectors!("account/control/node-liveness") {
        if vector.get("error") != "envelope" {
            continue;
        }
        let envelope = BootstrapEnvelope::decode(&vector.hex("bytes")).unwrap();
        let operation = ControlReportOperation::parse(vector.get("operation")).unwrap();
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
fn node_liveness_receipts_match_exact_requests() {
    let vectors = nsshared_testkit::vectors!("account/control/node-liveness");
    let raw = |name| {
        vectors
            .iter()
            .find(|v| v.name() == name)
            .unwrap()
            .hex("bytes")
    };
    let request = NodeHeartbeatRequest::decode(&raw("node.heartbeat-0")).unwrap();
    let response = NodeHeartbeatResponse::decode(&raw("node.heartbeat-1")).unwrap();
    assert_eq!(request.heartbeat.uptime_seconds, 123);
    assert_eq!(request.heartbeat.local_ips, ["192.0.2.1", "2001:db8::1"]);
    assert_eq!(request.heartbeat.policy_version, Some(9));
    response.validate_for(&request).unwrap();
    for field in 0..6 {
        let mut changed = request.clone();
        match field {
            0 => changed.scope.nsd_id[0] ^= 1,
            1 => changed.scope.network_id[0] ^= 1,
            2 => changed.fence.runtime_id[0] ^= 1,
            3 => changed.fence.runtime_generation += 1,
            4 => changed.fence.authority_epoch += 1,
            _ => changed.heartbeat.request_id[0] ^= 1,
        }
        assert!(response.validate_for(&changed).is_err());
    }
    let request = NodeDisconnectRequest::decode(&raw("machine.disconnect-0")).unwrap();
    let response = NodeDisconnectResponse::decode(&raw("machine.disconnect-1")).unwrap();
    response.validate_for(&request).unwrap();
    for field in 0..6 {
        let mut changed = request.clone();
        match field {
            0 => changed.scope.nsd_id[0] ^= 1,
            1 => changed.scope.network_id[0] ^= 1,
            2 => changed.fence.runtime_id[0] ^= 1,
            3 => changed.fence.runtime_generation += 1,
            4 => changed.fence.authority_epoch += 1,
            _ => changed.request_id[0] ^= 1,
        }
        assert!(response.validate_for(&changed).is_err());
    }
}
