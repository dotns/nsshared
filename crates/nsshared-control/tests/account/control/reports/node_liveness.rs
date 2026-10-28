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
                let mut noncanonical_header = raw.clone();
                let arity = noncanonical_header[0] & 0x1f;
                noncanonical_header.splice(0..1, [0x98, arity]);
                assert!(roundtrip(operation, direction, &noncanonical_header).is_err());
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

#[test]
fn node_heartbeat_observation_vectors_roundtrip() {
    let vectors = nsshared_testkit::vectors!("account/control/node-liveness");
    for name in [
        "udp-true",
        "udp-false",
        "pair-present",
        "pair-empty",
        "rtt-present",
        "rtt-empty",
        "observations-all",
    ] {
        let bytes = vectors
            .iter()
            .find(|v| v.name() == name)
            .unwrap()
            .hex("bytes");
        let decoded =
            NodeHeartbeatRequest::decode(&bytes).unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(decoded.canonical().unwrap(), bytes, "{name}");
    }
}

#[test]
fn node_heartbeat_observations_preserve_omission_and_exact_receipts() {
    let vectors = nsshared_testkit::vectors!("account/control/node-liveness");
    let raw = |name| {
        vectors
            .iter()
            .find(|v| v.name() == name)
            .unwrap()
            .hex("bytes")
    };
    let decode = |name| NodeHeartbeatRequest::decode(&raw(name)).unwrap();
    let absent = decode("node.heartbeat-0");
    assert_eq!(absent.udp_reachable, None);
    assert_eq!(absent.pair_transport, None);
    assert_eq!(absent.gateway_rtt, None);
    assert_eq!(decode("udp-true").udp_reachable, Some(true));
    assert_eq!(decode("udp-false").udp_reachable, Some(false));
    let empty = decode("pair-empty").pair_transport.unwrap();
    assert!(empty.unhealthy.is_empty());
    assert_eq!(empty.runtime_id, absent.fence.runtime_id);
    assert_eq!(empty.revision, 0);
    assert_eq!(decode("rtt-empty").gateway_rtt, Some(vec![]));
    assert_eq!(
        decode("pair-at-bound")
            .pair_transport
            .unwrap()
            .unhealthy
            .len(),
        MAX_NODE_OBSERVATIONS
    );
    let boundary_rtt = decode("rtt-at-bound").gateway_rtt.unwrap();
    assert_eq!(boundary_rtt.len(), MAX_NODE_OBSERVATIONS);
    assert!(
        boundary_rtt
            .iter()
            .all(|entry| entry.samples == 0 && entry.timeouts == u64::MAX)
    );
    let request = decode("observations-all");
    let pair = request.pair_transport.as_ref().unwrap();
    assert_eq!(pair.revision, u64::MAX);
    assert_eq!(pair.runtime_id, request.fence.runtime_id);
    assert_eq!(pair.unhealthy.len(), 3);
    let rtt = request.gateway_rtt.as_ref().unwrap();
    assert_eq!(pair.unhealthy[0].peer, rtt[0].gateway);
    assert_eq!(pair.unhealthy[0].gateway, rtt[2].gateway);
    assert_eq!(pair.unhealthy[1].peer, rtt[0].gateway);
    assert_eq!(pair.unhealthy[1].gateway, rtt[3].gateway);
    assert_eq!(pair.unhealthy[2].peer, rtt[1].gateway);
    assert_eq!(pair.unhealthy[2].gateway, rtt[2].gateway);
    assert_eq!(
        rtt.iter().map(|entry| entry.tier).collect::<Vec<_>>(),
        [
            GatewayRttTier::Lt30,
            GatewayRttTier::Lt100,
            GatewayRttTier::Ge100,
            GatewayRttTier::Unreachable,
        ]
    );
    assert!(
        rtt.iter()
            .all(|entry| entry.samples == u64::MAX && entry.timeouts == 0)
    );
    let response = NodeHeartbeatResponse::decode(&raw("endpoint-features")).unwrap();
    assert_eq!(
        response.heartbeat.features,
        [GATEWAY_RTT_FEATURE, PAIR_TRANSPORT_FALLBACK_FEATURE]
    );
    response.validate_for(&request).unwrap();
    let withdrawal = NodeHeartbeatResponse::decode(&raw("withdraw-features")).unwrap();
    assert!(withdrawal.heartbeat.features.is_empty());
    withdrawal.validate_for(&request).unwrap();
    for field in 0..6 {
        let mut changed = response.clone();
        match field {
            0 => changed.scope.nsd_id[0] ^= 1,
            1 => changed.scope.network_id[0] ^= 1,
            2 => changed.fence.runtime_id[0] ^= 1,
            3 => changed.fence.runtime_generation += 1,
            4 => changed.fence.authority_epoch += 1,
            _ => changed.heartbeat.request_id[0] ^= 1,
        }
        assert!(matches!(
            changed.validate_for(&request),
            Err(AccountError::Field)
        ));
    }
}

#[test]
fn node_heartbeat_in_memory_observation_refusals() {
    let vectors = nsshared_testkit::vectors!("account/control/node-liveness");
    let raw = vectors
        .iter()
        .find(|v| v.name() == "observations-all")
        .unwrap()
        .hex("bytes");
    let request = NodeHeartbeatRequest::decode(&raw).unwrap();
    let mut changed = request.clone();
    changed.pair_transport.as_mut().unwrap().runtime_id[0] ^= 1;
    assert!(matches!(changed.canonical(), Err(AccountError::Field)));
    for duplicate in [false, true] {
        let mut changed = request.clone();
        let entries = &mut changed.pair_transport.as_mut().unwrap().unhealthy;
        if duplicate {
            entries[1] = entries[0].clone();
        } else {
            entries.swap(0, 1);
        }
        assert!(matches!(changed.canonical(), Err(AccountError::Field)));
        let mut changed = request.clone();
        let entries = changed.gateway_rtt.as_mut().unwrap();
        if duplicate {
            entries[1].gateway = entries[0].gateway;
        } else {
            entries.swap(0, 1);
        }
        assert!(matches!(changed.canonical(), Err(AccountError::Field)));
    }
    let mut changed = request.clone();
    let entries = &mut changed.pair_transport.as_mut().unwrap().unhealthy;
    entries.resize(MAX_NODE_OBSERVATIONS + 1, entries[0].clone());
    assert!(matches!(changed.canonical(), Err(AccountError::Bounds)));
    let mut changed = request;
    let entries = changed.gateway_rtt.as_mut().unwrap();
    entries.resize(MAX_NODE_OBSERVATIONS + 1, entries[0].clone());
    assert!(matches!(changed.canonical(), Err(AccountError::Bounds)));
}
