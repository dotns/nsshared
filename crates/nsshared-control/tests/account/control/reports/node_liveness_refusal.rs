use ed25519_dalek::Signer as _;
use nsshared_control::account::{AccountError, control::*};
use nsshared_identity::keys::{IdentityKey, IdentitySecret};

fn heartbeat() -> NodeHeartbeatRequest {
    NodeHeartbeatRequest::decode(
        &nsshared_testkit::vectors!("account/control/node-liveness")
            .iter()
            .find(|v| v.name() == "node.heartbeat-0")
            .unwrap()
            .hex("bytes"),
    )
    .unwrap()
}

fn posture() -> NodePostureRequest {
    NodePostureRequest::decode(
        &nsshared_testkit::vectors!("account/control/node-posture")
            .iter()
            .find(|v| v.name() == "full")
            .unwrap()
            .hex("bytes"),
    )
    .unwrap()
}

#[test]
fn node_liveness_refusal_independent_vectors_and_success_separation() {
    let mut accepted = 0;
    for vector in &nsshared_testkit::vectors!("account/control/node-liveness-refusal") {
        if vector.get("kind") != "payload" {
            continue;
        }
        let bytes = vector.hex("bytes");
        let decoded = NodeLivenessRefusal::decode(&bytes);
        assert_eq!(
            decoded.is_ok(),
            vector.get("expect") == "accept",
            "{}: {decoded:?}",
            vector.name()
        );
        if let Ok(refusal) = decoded {
            accepted += 1;
            assert_eq!(refusal.canonical().unwrap(), bytes);
            assert_eq!(refusal.operation.as_str(), vector.get("operation"));
            assert_eq!(refusal.code.as_str(), vector.get("code"));
            assert_eq!(refusal.reason.as_str(), vector.get("reason"));
            assert_eq!(refusal.code.http_status().to_string(), vector.get("status"));
            assert_eq!(refusal.request_id, [8; 16]);
            match refusal.operation {
                NodeLivenessOperation::Heartbeat => {
                    refusal.validate_for_heartbeat(&heartbeat()).unwrap();
                    assert!(refusal.validate_for_posture(&posture()).is_err());
                }
                NodeLivenessOperation::Posture => {
                    refusal.validate_for_posture(&posture()).unwrap();
                    assert!(refusal.validate_for_heartbeat(&heartbeat()).is_err());
                }
            }
            assert!(NodeHeartbeatResponse::decode(&bytes).is_err());
            assert!(NodePostureResponse::decode(&bytes).is_err());
            assert!(HeartbeatResponse::decode(&bytes).is_err());
            assert!(FencedGatewayReportResponse::decode(&bytes).is_err());
        }
    }
    assert_eq!(accepted, 10);
    // All pre-existing successful report forms remain separate from refusals.
    for group in [
        nsshared_testkit::vectors!("account/control/node-liveness"),
        nsshared_testkit::vectors!("account/control/node-posture"),
    ] {
        for vector in &group {
            assert!(
                NodeLivenessRefusal::decode(&vector.hex("bytes")).is_err(),
                "{}",
                vector.name()
            );
        }
    }
}

#[test]
fn node_liveness_refusal_correlates_every_pending_field() {
    let vectors = nsshared_testkit::vectors!("account/control/node-liveness-refusal");
    for operation in [
        NodeLivenessOperation::Heartbeat,
        NodeLivenessOperation::Posture,
    ] {
        let vector = vectors
            .iter()
            .find(|v| v.name() == format!("{}-lease_elapsed", operation.as_str()))
            .unwrap();
        let refusal = NodeLivenessRefusal::decode(&vector.hex("bytes")).unwrap();
        for field in 0..7 {
            let mut changed = refusal.clone();
            match field {
                0 => changed.scope.nsd_id[0] ^= 1,
                1 => changed.scope.network_id[0] ^= 1,
                2 => changed.fence.runtime_id[0] ^= 1,
                3 => changed.fence.runtime_generation += 1,
                4 => changed.fence.authority_epoch += 1,
                5 => changed.request_id[0] ^= 1,
                _ => {
                    changed.operation = if operation == NodeLivenessOperation::Heartbeat {
                        NodeLivenessOperation::Posture
                    } else {
                        NodeLivenessOperation::Heartbeat
                    }
                }
            }
            let result = match operation {
                NodeLivenessOperation::Heartbeat => changed.validate_for_heartbeat(&heartbeat()),
                NodeLivenessOperation::Posture => changed.validate_for_posture(&posture()),
            };
            assert!(
                matches!(result, Err(AccountError::Field)),
                "{operation:?} {field}"
            );
        }
        let mut invalid = refusal.clone();
        invalid.request_id = [0; 16];
        assert!(invalid.canonical().is_err());
        let mut invalid = refusal.clone();
        invalid.reason = NodeLivenessRefusalReason::AuthorityChanged;
        assert!(invalid.canonical().is_err());
        let mut invalid = refusal;
        invalid.fence.authority_epoch = 0;
        assert!(invalid.canonical().is_err());
    }
    let mut invalid = heartbeat();
    invalid.heartbeat.local_ips.push("invalid".into());
    let refusal = NodeLivenessRefusal::decode(&vectors[0].hex("bytes")).unwrap();
    assert!(refusal.validate_for_heartbeat(&invalid).is_err());
    let mut invalid = posture();
    invalid.snapshot.local_ips.push("invalid".into());
    let mut refusal = refusal;
    refusal.operation = NodeLivenessOperation::Posture;
    assert!(refusal.validate_for_posture(&invalid).is_err());
}

#[test]
fn node_liveness_refusal_accepts_full_width_fences_and_rejects_zero_pending_ids() {
    let mut refusal = NodeLivenessRefusal::decode(
        &nsshared_testkit::vectors!("account/control/node-liveness-refusal")[0].hex("bytes"),
    )
    .unwrap();
    refusal.fence.runtime_id = [255; 16];
    refusal.fence.runtime_generation = u64::MAX;
    refusal.fence.authority_epoch = u64::MAX;
    refusal.request_id = [255; 16];
    refusal.reason = NodeLivenessRefusalReason::AuthorityEpochChanged;
    let bytes = refusal.canonical().unwrap();
    assert!(bytes.len() <= MAX_NODE_LIVENESS_REFUSAL_BYTES);
    assert_eq!(NodeLivenessRefusal::decode(&bytes).unwrap(), refusal);
    let mut pending = heartbeat();
    pending.fence = refusal.fence.clone();
    pending.heartbeat.request_id = refusal.request_id;
    refusal.validate_for_heartbeat(&pending).unwrap();
    // A zero logical ID is refused even though legacy request codecs accept it.
    refusal.request_id = [0; 16];
    pending.heartbeat.request_id = [0; 16];
    assert!(refusal.validate_for_heartbeat(&pending).is_err());
    refusal.operation = NodeLivenessOperation::Posture;
    let mut pending = posture();
    pending.fence = refusal.fence.clone();
    pending.request_id = [0; 16];
    assert!(refusal.validate_for_posture(&pending).is_err());
}

fn sign(envelope: &mut BootstrapEnvelope, seed: u8) {
    envelope.signature = IdentitySecret::from_seed([seed; 32])
        .signing_key()
        .sign(&envelope.signing_input().unwrap())
        .to_bytes();
}

#[test]
fn node_liveness_refusal_requires_authenticated_correlated_carrier_and_status() {
    let mut accepted = 0;
    for vector in &nsshared_testkit::vectors!("account/control/node-liveness-refusal") {
        if vector.get("kind") != "envelope" {
            continue;
        }
        let envelope = BootstrapEnvelope::decode(&vector.hex("bytes")).unwrap();
        assert_eq!(envelope.canonical().unwrap(), vector.hex("bytes"));
        let pins = EnvelopePins::intersect(&[vector.get("pin").into()], &[]).unwrap();
        let context = NodeReportContext {
            scope: heartbeat().scope,
            subject: IdentityKey::from_bytes(&vector.hex_array("subject")).unwrap(),
            authority: IdentityKey::from_bytes(&vector.hex_array("authority")).unwrap(),
        };
        let expected = EnvelopeExpectation {
            pins: &pins,
            direction: EnvelopeDirection::Response,
            recipient: context.subject,
            kind: vector.get("operation"),
            now_seconds: 100,
            previous_acceptance_seconds: None,
        };
        let nonce = vector.hex_array("nonce");
        let status: u16 = vector.get("status").parse().unwrap();
        let refusal = context
            .validate_liveness_refusal(&envelope, &expected, nonce, status)
            .unwrap();
        match refusal.operation {
            NodeLivenessOperation::Heartbeat => {
                refusal.validate_for_heartbeat(&heartbeat()).unwrap()
            }
            NodeLivenessOperation::Posture => refusal.validate_for_posture(&posture()).unwrap(),
        }
        accepted += 1;
        for wrong_status in [200, 401, 403, 409, 503] {
            if wrong_status != status {
                assert!(
                    context
                        .validate_liveness_refusal(&envelope, &expected, nonce, wrong_status)
                        .is_err()
                );
            }
        }
        assert!(
            context
                .validate_liveness_refusal(&envelope, &expected, [8; 16], status)
                .is_err()
        );
        let stale = EnvelopeExpectation {
            now_seconds: 161,
            ..expected
        };
        assert!(
            context
                .validate_liveness_refusal(&envelope, &stale, nonce, status)
                .is_err()
        );
        let replay = EnvelopeExpectation {
            previous_acceptance_seconds: Some(99),
            ..expected
        };
        assert!(
            context
                .validate_liveness_refusal(&envelope, &replay, nonce, status)
                .is_err()
        );
        let wrong_kind = EnvelopeExpectation {
            kind: MACHINE_HEARTBEAT,
            ..expected
        };
        assert!(
            context
                .validate_liveness_refusal(&envelope, &wrong_kind, nonce, status)
                .is_err()
        );
        // Each altered semantic carrier is correctly re-signed to isolate its check.
        for field in 0..7 {
            let mut changed = envelope.clone();
            match field {
                0 => changed.recipient = None,
                1 => changed.recipient = Some(context.authority),
                2 => {
                    changed.kind = if envelope.kind == NODE_HEARTBEAT {
                        NODE_POSTURE
                    } else {
                        NODE_HEARTBEAT
                    }
                    .into();
                }
                3 => {
                    changed.direction = EnvelopeDirection::Request;
                }
                4 => changed.nonce = [8; 16],
                5 => {
                    let mut payload = refusal.clone();
                    payload.scope.network_id[0] ^= 1;
                    changed.payload = payload.canonical().unwrap();
                }
                _ => changed.signer = context.subject,
            }
            sign(&mut changed, if field == 6 { 1 } else { 2 });
            let expectation = EnvelopeExpectation {
                kind: &changed.kind,
                direction: changed.direction,
                ..expected
            };
            assert!(
                context
                    .validate_liveness_refusal(&changed, &expectation, nonce, status)
                    .is_err(),
                "{field}"
            );
        }
        let mut invalid = envelope.clone();
        invalid.signature[0] ^= 1;
        assert!(
            context
                .validate_liveness_refusal(&invalid, &expected, nonce, status)
                .is_err()
        );
        let mut wrong_context = context.clone();
        wrong_context.authority = context.subject;
        assert!(
            wrong_context
                .validate_liveness_refusal(&envelope, &expected, nonce, status)
                .is_err()
        );
        let mut wrong_context = context.clone();
        wrong_context.subject = context.authority;
        assert!(
            wrong_context
                .validate_liveness_refusal(&envelope, &expected, nonce, status)
                .is_err()
        );
    }
    assert_eq!(accepted, 10);
}
