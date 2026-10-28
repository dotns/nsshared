#![allow(clippy::unwrap_used, clippy::panic)]
use nsshared_control::account::{control::*, edge::*, subnet::*, usage::*};
use nsshared_identity::keys::IdentityKey;

#[test]
fn control_report_contract_vectors() {
    let vectors = nsshared_testkit::vectors!("account/control/reports");
    for vector in &vectors {
        let raw = vector.hex("bytes");
        let accepted = vector.get("expect") == "accept";
        match vector.get("kind") {
            "envelope" => {
                let envelope = BootstrapEnvelope::decode(&raw).unwrap();
                assert_eq!(
                    envelope.signing_input().unwrap(),
                    vector.hex("signing_input")
                );
                assert_eq!(envelope.canonical().unwrap(), raw);
                let pins = EnvelopePins::intersect(&[vector.get("pin").into()], &[]).unwrap();
                let expected = EnvelopeExpectation {
                    pins: &pins,
                    direction: envelope.direction,
                    recipient: IdentityKey::from_bytes(&vector.hex_array("recipient")).unwrap(),
                    kind: vector.get("operation"),
                    now_seconds: 100,
                    previous_acceptance_seconds: None,
                };
                let operation = ControlReportOperation::parse(vector.get("operation")).unwrap();
                assert_eq!(
                    operation.validate_envelope(&envelope, &expected).is_ok(),
                    accepted,
                    "{}",
                    vector.name()
                );
                let mut invalid = envelope.clone();
                invalid.signature[0] ^= 1;
                assert!(operation.validate_envelope(&invalid, &expected).is_err());
                let wrong = EnvelopeExpectation {
                    direction: if envelope.direction == EnvelopeDirection::Request {
                        EnvelopeDirection::Response
                    } else {
                        EnvelopeDirection::Request
                    },
                    ..expected
                };
                assert!(operation.validate_envelope(&envelope, &wrong).is_err());
                if vector.name().ends_with("unknown-operation") {
                    assert!(ControlReportOperation::parse(&envelope.kind).is_err());
                }
            }
            "payload" => {
                let direction = if vector.get("direction") == "0" {
                    EnvelopeDirection::Request
                } else {
                    EnvelopeDirection::Response
                };
                let operation = ControlReportOperation::parse(vector.get("operation")).unwrap();
                assert_eq!(
                    operation.validate_payload(direction, &raw).is_ok(),
                    accepted,
                    "{}",
                    vector.name()
                );
                if accepted {
                    let encoded = match (operation, direction) {
                        (ControlReportOperation::NodePosture, EnvelopeDirection::Request) => {
                            NodePostureRequest::decode(&raw)
                                .unwrap()
                                .canonical()
                                .unwrap()
                        }
                        (ControlReportOperation::NodePosture, EnvelopeDirection::Response) => {
                            NodePostureResponse::decode(&raw)
                                .unwrap()
                                .canonical()
                                .unwrap()
                        }
                        (ControlReportOperation::NodeHeartbeat, EnvelopeDirection::Request) => {
                            NodeHeartbeatRequest::decode(&raw)
                                .unwrap()
                                .canonical()
                                .unwrap()
                        }
                        (ControlReportOperation::NodeHeartbeat, EnvelopeDirection::Response) => {
                            NodeHeartbeatResponse::decode(&raw)
                                .unwrap()
                                .canonical()
                                .unwrap()
                        }
                        (ControlReportOperation::NodeDisconnect, EnvelopeDirection::Request) => {
                            NodeDisconnectRequest::decode(&raw)
                                .unwrap()
                                .canonical()
                                .unwrap()
                        }
                        (ControlReportOperation::NodeDisconnect, EnvelopeDirection::Response) => {
                            NodeDisconnectResponse::decode(&raw)
                                .unwrap()
                                .canonical()
                                .unwrap()
                        }
                        (ControlReportOperation::Heartbeat, EnvelopeDirection::Request) => {
                            HeartbeatRequest::decode(&raw).unwrap().canonical().unwrap()
                        }
                        (ControlReportOperation::Heartbeat, EnvelopeDirection::Response) => {
                            HeartbeatResponse::decode(&raw)
                                .unwrap()
                                .canonical()
                                .unwrap()
                        }
                        (ControlReportOperation::Gateway, EnvelopeDirection::Request) => {
                            GatewayReport::decode(&raw).unwrap().canonical().unwrap()
                        }
                        (ControlReportOperation::Gateway, EnvelopeDirection::Response) => {
                            GatewayReportResponse::decode(&raw).unwrap().canonical()
                        }
                        (ControlReportOperation::Services, EnvelopeDirection::Request) => {
                            EdgeServiceRequest::decode(&raw)
                                .unwrap()
                                .canonical()
                                .unwrap()
                        }
                        (ControlReportOperation::Services, EnvelopeDirection::Response) => {
                            EdgeServiceResponse::decode(&raw)
                                .unwrap()
                                .canonical()
                                .unwrap()
                        }
                        (ControlReportOperation::Usage, EnvelopeDirection::Request) => {
                            UsageReport::decode(&raw).unwrap().canonical().unwrap()
                        }
                        (ControlReportOperation::Usage, EnvelopeDirection::Response) => {
                            UsageAnswer::decode(&raw).unwrap().canonical().unwrap()
                        }
                        (ControlReportOperation::MaterialStatus, EnvelopeDirection::Request) => {
                            EdgeMaterialAck::decode(&raw).unwrap().canonical().unwrap()
                        }
                        (ControlReportOperation::MaterialStatus, EnvelopeDirection::Response) => {
                            MaterialStatusResponse::decode(&raw)
                                .unwrap()
                                .canonical()
                                .unwrap()
                        }
                    };
                    assert_eq!(encoded, raw, "{}", vector.name());
                }
            }
            "material-match" => {
                let pending = EdgeMaterialAck::decode(&vector.hex("pending")).unwrap();
                let result = MaterialStatusResponse::decode(&raw).unwrap();
                assert!(result.validate_for(&pending).is_err(), "{}", vector.name());
                if result.report.installed {
                    assert!(
                        result
                            .report
                            .validate_installation(
                                pending.request_id,
                                pending.served_realm,
                                &pending.scope,
                                pending.realm,
                                &pending.material
                            )
                            .is_err()
                    );
                }
            }
            "service-unknown" => {
                assert!(UsageAnswer::decode(&raw).is_err());
                let pending = UsageReport::decode(&vector.hex("pending")).unwrap();
                let relay = nsshared_testkit::vectors!("account/usage/reports");
                let repair = relay
                    .iter()
                    .find(|v| v.name() == "unknown-mapping")
                    .unwrap();
                let mut answer = UsageAnswer::decode(&repair.hex("bytes")).unwrap();
                answer.reporter = pending.reporter;
                answer.incarnation = pending.incarnation;
                answer.profile = pending.profile;
                answer.sequence = pending.sequence;
                answer.part_index = pending.part_index;
                answer.part_digest = pending.part_digest;
                assert!(answer.validate_for(&pending).is_err());
            }
            "floor-match" => {
                let pending = EdgeServiceRequest::decode(&vector.hex("pending")).unwrap();
                let answer = EdgeServiceResponse::decode(&raw).unwrap();
                let result = answer.validate_request(&pending);
                assert_eq!(result.is_ok(), accepted, "{}: {result:?}", vector.name());
                match vector.name() {
                    "floor-missing-service" | "floor-missing-exit" => {
                        assert!(matches!(result, Err(EdgeServiceAckError::MissingReference)))
                    }
                    "floor-unknown-service"
                    | "floor-unknown-exit"
                    | "floor-wrong-kind"
                    | "floor-unknown-rejected" => {
                        assert!(matches!(result, Err(EdgeServiceAckError::UnknownReference)))
                    }
                    "floor-contradictory" => assert!(matches!(
                        result,
                        Err(EdgeServiceAckError::ContradictoryReference)
                    )),
                    "floor-empty" => assert!(answer.accepted),
                    "floor-exit-rejected" => {
                        assert!(!answer.accepted);
                        assert_eq!(answer.outcomes.unwrap().rejected[0].reason, "scope refused");
                    }
                    "floor-rejected" => {
                        assert!(!answer.accepted);
                        assert_eq!(
                            answer.outcomes.unwrap().rejected[0].reason,
                            "policy refused"
                        );
                    }
                    _ => panic!("unknown outcome vector"),
                }
            }
            _ => panic!("unknown vector kind"),
        }
    }
}

#[test]
fn report_receipts_preserve_observations_and_exact_pending_context() {
    let vectors = nsshared_testkit::vectors!("account/control/reports");
    let bytes = |name| {
        vectors
            .iter()
            .find(|v| v.name() == name)
            .unwrap()
            .hex("bytes")
    };
    let heartbeat = HeartbeatRequest::decode(&bytes("machine.heartbeat-request")).unwrap();
    assert_eq!(heartbeat.uptime_seconds, 123);
    assert_eq!(heartbeat.local_ips, ["192.0.2.1", "2001:db8::1"]);
    assert_eq!(heartbeat.policy_version, Some(9));
    let mut receipt = HeartbeatResponse::decode(&bytes("machine.heartbeat-response")).unwrap();
    assert_eq!(receipt.features, ["unknown.feature"]);
    receipt.validate_for(&heartbeat).unwrap();
    receipt.request_id[0] ^= 1;
    assert!(receipt.validate_for(&heartbeat).is_err());
    let gateway = GatewayReport::decode(&bytes("gateway.report-request")).unwrap();
    assert_eq!(gateway.software_version.as_deref(), Some("1.0"));
    assert_eq!(gateway.source_revision.as_deref(), Some("0123456789abcdef"));
    assert_eq!(gateway.connections, Some(0));
    assert_eq!(gateway.terminate_enabled, Some(false));
    assert_eq!(gateway.public_http_port, Some(443));
    assert_eq!(gateway.internal_http_port, Some(8080));
    assert!(gateway.draining);
    assert_eq!(gateway.capabilities, ["node.control"]);
    assert_eq!(gateway.public_ingress_scopes, ["edge.http"]);
    let certificate = &gateway.certificates[0];
    assert_eq!(
        (
            &*certificate.id,
            &*certificate.issuer,
            &*certificate.fingerprint
        ),
        ("cert", "issuer", "sha256:abc")
    );
    assert_eq!(certificate.hostnames, ["web.example"]);
    assert_eq!(certificate.not_after_seconds, 200);
    assert_eq!(certificate.ack_generation, Some(2));
    assert_eq!(certificate.last_error, None);
    let mut receipt = GatewayReportResponse::decode(&bytes("gateway.report-response")).unwrap();
    receipt.validate_for(&gateway).unwrap();
    receipt.request_id[0] ^= 1;
    assert!(receipt.validate_for(&gateway).is_err());
    let material = EdgeMaterialAck::decode(&bytes("gateway.material_status-request")).unwrap();
    let receipt =
        MaterialStatusResponse::decode(&bytes("gateway.material_status-response")).unwrap();
    receipt.validate_for(&material).unwrap();
    let mut rejected = material.clone();
    rejected.installed = false;
    assert!(
        rejected
            .validate_installation(
                material.request_id,
                material.served_realm,
                &material.scope,
                material.realm,
                &material.material
            )
            .is_err()
    );
    MaterialStatusResponse {
        report: rejected.clone(),
    }
    .validate_for(&rejected)
    .unwrap();
    let request = EdgeServiceRequest::decode(&bytes("gateway.services_report-request")).unwrap();
    assert_eq!(
        request.metadata[0].policy_labels,
        [("team".into(), "Platform Engineering".into())]
    );
    assert_eq!(request.exit_profiles[0].selection, SubnetSelection::Default);
    assert!(request.exit_profiles[0].enabled);
    let mut changed = request.clone();
    changed.metadata[0].policy_labels[0].1 = "other".into();
    assert_ne!(
        request.content_digest().unwrap(),
        changed.content_digest().unwrap()
    );
    let response = EdgeServiceResponse::decode(&bytes("gateway.services_report-response")).unwrap();
    assert!(response.validate_request(&changed).is_err());
}

#[test]
fn ordinary_node_report_operations_are_registered() {
    assert!(ControlReportOperation::parse("node.heartbeat").is_ok());
    assert!(ControlReportOperation::parse("machine.disconnect").is_ok());
}

mod node_liveness;

#[test]
fn ordinary_node_posture_operation_is_registered() {
    assert!(ControlReportOperation::parse("node.posture").is_ok());
}

mod node_posture;
