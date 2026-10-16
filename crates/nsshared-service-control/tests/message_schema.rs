#![allow(clippy::unwrap_used)]

use nsshared_service_control::{
    BackendHost, Declaration, Grant, LeaseAcquire, LeaseResult, ListenerIntent, Message,
    MessageBody, PortMode, PortProposal, PortResult, Protocols, ReadyProof, ReportAccepted,
    ReportBinding, ReportContent, ReportReplace, Resource, Route, RuntimeBind, RuntimeFloorResult,
    ServiceLeaseRef, ServiceRef, Snapshot, SnapshotAck, SnapshotPush, Value, Withdrawal,
    decode_canonical, encode_canonical,
};

fn reference(service: u8) -> ServiceRef {
    ServiceRef {
        nsd_id: [1; 16],
        network_id: [2; 16],
        service_id: [service; 16],
    }
}

fn report() -> ReportContent {
    ReportContent {
        publisher_identity: [3; 32],
        nsd_id: [1; 16],
        network_id: [2; 16],
        strict_mode: true,
        declarations: vec![Declaration {
            declaration_key: "one".into(),
            display_name: None,
            description: None,
            enabled: true,
            protocols: Protocols {
                tcp: true,
                udp: true,
            },
            backend_host: BackendHost::Ipv4([127, 0, 0, 1]),
            backend_port: 8080,
            port_mode: PortMode::Auto,
        }],
    }
}

fn listener() -> ListenerIntent {
    ListenerIntent {
        service_ref: reference(1),
        publisher_identity: [3; 32],
        listener_revision: 1,
        port: 8080,
        protocols: Protocols {
            tcp: true,
            udp: true,
        },
        backend_host: BackendHost::Ipv4([127, 0, 0, 1]),
        backend_port: 8080,
        enforcement_policy_version: 1,
        enforcement_policy_digest: [4; 32],
    }
}

fn proposal() -> PortProposal {
    PortProposal {
        service_ref: reference(1),
        listener_revision: 1,
        intent_digest: listener().canonical().unwrap().1,
        allocation_round: 1,
        proposal_seq: 1,
        proposal_id: [5; 16],
        port: 8080,
    }
}

fn snapshot() -> Snapshot {
    Snapshot {
        target_identity: [3; 32],
        nsd_id: [1; 16],
        network_id: [2; 16],
        snapshot_revision: 1,
        resources: vec![Resource {
            service_ref: reference(1),
            service_label: "web".into(),
            publisher_identity: [3; 32],
            listener_revision: 1,
            intent_digest: listener().canonical().unwrap().1,
            port: 8080,
            protocols: Protocols {
                tcp: true,
                udp: true,
            },
            node6: [6; 16],
            vip: Some(vec![10, 0, 0, 8]),
        }],
        routes: vec![Route {
            service_ref: reference(1),
            destination_identity: [3; 32],
            destination_node6: [6; 16],
            port: 8080,
        }],
        grants: vec![Grant {
            service_ref: reference(1),
            consumer_identity: [7; 32],
            allowed_protocols: Protocols {
                tcp: true,
                udp: true,
            },
            policy_version: 1,
            policy_digest: [4; 32],
        }],
        listeners: vec![nsshared_service_control::PublisherListener {
            intent: listener(),
            proposal: Some(proposal()),
        }],
        withdrawals: vec![Withdrawal {
            service_ref: reference(2),
            listener_revision: 1,
        }],
    }
}

fn message(body: MessageBody) -> Message {
    let floor = matches!(
        body,
        MessageBody::RuntimeFloor | MessageBody::RuntimeFloorResult(_)
    );
    let bootstrap = matches!(
        body,
        MessageBody::RuntimeFloor | MessageBody::RuntimeBind(_)
    );
    let session = matches!(
        body,
        MessageBody::SessionOpen
            | MessageBody::SessionOpenResult(_)
            | MessageBody::SnapshotPush(_)
            | MessageBody::SnapshotAck(_)
            | MessageBody::ListenerReady(_)
            | MessageBody::LeaseRefresh(_)
            | MessageBody::LeaseAcquire(_)
            | MessageBody::LeaseResult(_)
            | MessageBody::PortResult(_)
            | MessageBody::PortCancel(_)
            | MessageBody::PortQuery(_)
            | MessageBody::PortQueryResult(_)
    );
    Message {
        nsd_id: [1; 16],
        network_id: [2; 16],
        subject_identity: [3; 32],
        runtime_generation: (!floor).then_some(1),
        runtime_id: (!floor).then_some([8; 16]),
        authority_epoch: (!bootstrap).then_some(1),
        request_id: [9; 16],
        session_seq: session.then_some(1),
        body,
    }
}

fn cases() -> Vec<MessageBody> {
    let proposal = proposal();
    let service = ServiceLeaseRef {
        service_ref: reference(1),
        listener_revision: 1,
        intent_digest: proposal.intent_digest,
    };
    let ready = ReadyProof {
        proposal: proposal.clone(),
        refresh_seq: 1,
        snapshot_revision: 1,
        snapshot_digest: snapshot().canonical().unwrap().1,
        enforcement_policy_digest: [4; 32],
    };
    let accepted = ReportAccepted {
        accepted_revision: 1,
        report_digest: Some(report().canonical().unwrap().1),
        bindings: vec![ReportBinding {
            declaration_key: "one".into(),
            service_ref: reference(1),
            port: Some(8080),
            proposal_state: "ready".into(),
        }],
    };
    let port_result = PortResult {
        proposal: proposal.clone(),
        result: "claimed".into(),
        terminal_floor: None,
    };
    vec![
        MessageBody::RuntimeFloor,
        MessageBody::RuntimeFloorResult(RuntimeFloorResult {
            current_generation: Some(1),
            current_runtime_id: Some([8; 16]),
            active: true,
            authority_epoch: 1,
        }),
        MessageBody::RuntimeBind(RuntimeBind {
            recovery: false,
            observed_generation: None,
            observed_runtime_id: None,
            owner_recovery: false,
        }),
        MessageBody::RuntimeBindResult(1),
        MessageBody::SessionOpen,
        MessageBody::SessionOpenResult(1),
        MessageBody::ReportHead,
        MessageBody::ReportHeadResult(accepted.clone()),
        MessageBody::ReportReplace(ReportReplace {
            report_revision: 1,
            report: report(),
        }),
        MessageBody::ReportAccepted(accepted),
        MessageBody::SnapshotPush(SnapshotPush {
            snapshot: snapshot(),
        }),
        MessageBody::SnapshotAck(SnapshotAck {
            snapshot_revision: 1,
            snapshot_digest: snapshot().canonical().unwrap().1,
            accepted: true,
            enforcement_applied: true,
            dns_applied: false,
            error: None,
        }),
        MessageBody::ListenerReady(ready.clone()),
        MessageBody::LeaseRefresh(ready),
        MessageBody::LeaseAcquire(LeaseAcquire {
            consumer_seq: 1,
            snapshot_revision: 1,
            snapshot_digest: [10; 32],
            services: vec![service.clone()],
        }),
        MessageBody::LeaseResult(LeaseResult {
            service,
            grant_id: Some([11; 16]),
            refresh_seq: Some(1),
            consumer_seq: None,
            remaining_ms: 28_000,
            result: "ok".into(),
            snapshot_revision: None,
            snapshot_digest: None,
        }),
        MessageBody::PortResult(port_result.clone()),
        MessageBody::PortCancel(proposal.clone()),
        MessageBody::PortQuery(proposal),
        MessageBody::PortQueryResult(port_result),
        MessageBody::ServiceRetryPort(reference(1)),
        MessageBody::Error("stale-runtime".into()),
    ]
}

#[test]
fn every_kind_roundtrips_and_rejects_unknown_body_field() {
    for body in cases() {
        let message = message(body);
        let bytes = message.encode().unwrap();
        assert_eq!(Message::decode(&bytes).unwrap(), message);
        let mut value = decode_canonical(&bytes).unwrap();
        if let Value::Map(ref mut envelope) = value {
            let (_, Value::Map(body)) = envelope.iter_mut().find(|(key, _)| key == "body").unwrap()
            else {
                unreachable!()
            };
            body.push(("unknown".into(), Value::Bool(true)));
        }
        assert!(
            Message::decode(&encode_canonical(&value).unwrap()).is_err(),
            "kind={:?}",
            message.body.kind()
        );
    }
}

#[test]
fn missing_fields_zero_counters_and_cross_scope_are_rejected() {
    for body in cases() {
        let message = message(body);
        let mut value = decode_canonical(&message.encode().unwrap()).unwrap();
        if let Value::Map(ref mut envelope) = value {
            let (_, Value::Map(body)) = envelope.iter_mut().find(|(key, _)| key == "body").unwrap()
            else {
                unreachable!()
            };
            if !body.is_empty() {
                body.pop();
                assert!(
                    Message::decode(&encode_canonical(&value).unwrap()).is_err(),
                    "kind={:?}",
                    message.body.kind()
                );
            }
        }
    }
    let mut ready = message(MessageBody::ListenerReady(ReadyProof {
        proposal: proposal(),
        refresh_seq: 0,
        snapshot_revision: 1,
        snapshot_digest: [1; 32],
        enforcement_policy_digest: [4; 32],
    }));
    assert!(ready.encode().is_err());
    ready.session_seq = None;
    assert!(ready.encode().is_err());
    let mut report = message(MessageBody::ReportReplace(ReportReplace {
        report_revision: 1,
        report: report(),
    }));
    report.network_id = [99; 16];
    assert!(report.encode().is_err());
}

#[test]
fn nonempty_snapshot_orders_by_resource_key_and_hides_backend_from_consumer() {
    let mut snapshot = snapshot();
    let (bytes, digest) = snapshot.canonical().unwrap();
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("../vectors/service-control-v1.json")).unwrap();
    let hex = |bytes: &[u8]| {
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    assert_eq!(
        hex(&bytes),
        vectors["snapshot_nonempty_cbor"].as_str().unwrap()
    );
    assert_eq!(
        hex(&digest),
        vectors["snapshot_nonempty_sha256"].as_str().unwrap()
    );
    assert_eq!(Snapshot::decode(&bytes).unwrap(), snapshot);
    assert_ne!(digest, [0; 32]);
    let mut second = snapshot.resources[0].clone();
    second.service_ref = reference(2);
    snapshot.resources.insert(0, second);
    assert!(snapshot.canonical().is_err());
    snapshot.resources.swap(0, 1);
    assert!(snapshot.canonical().is_ok());
    snapshot.target_identity = [7; 32];
    assert!(snapshot.canonical().is_err());
}

#[test]
fn response_echoes_and_snapshot_permissions_fail_closed() {
    let mut snapshot = snapshot();
    snapshot.resources[0].service_label = "Bad.Label".into();
    assert!(snapshot.canonical().is_err());
    snapshot.resources[0].service_label = "web".into();
    snapshot.resources[0].protocols = Protocols {
        tcp: true,
        udp: false,
    };
    assert!(snapshot.canonical().is_err());
    snapshot.resources[0].protocols = Protocols {
        tcp: true,
        udp: true,
    };
    snapshot.grants[0].allowed_protocols = Protocols {
        tcp: true,
        udp: false,
    };
    assert!(snapshot.canonical().is_ok());
    snapshot.listeners[0]
        .proposal
        .as_mut()
        .unwrap()
        .proposal_seq = 0;
    assert!(snapshot.canonical().is_err());

    let floor = message(MessageBody::RuntimeFloorResult(RuntimeFloorResult {
        current_generation: Some(1),
        current_runtime_id: None,
        active: true,
        authority_epoch: 1,
    }));
    assert!(floor.encode().is_err());
    let mut floor = message(MessageBody::RuntimeFloorResult(RuntimeFloorResult {
        current_generation: None,
        current_runtime_id: None,
        active: false,
        authority_epoch: 2,
    }));
    assert!(floor.encode().is_err());
    floor.authority_epoch = Some(2);
    assert!(floor.encode().is_ok());

    let bind = message(MessageBody::RuntimeBind(RuntimeBind {
        recovery: true,
        observed_generation: Some(7),
        observed_runtime_id: None,
        owner_recovery: false,
    }));
    assert!(bind.encode().is_err());
    let session = message(MessageBody::SessionOpenResult(2));
    assert!(session.encode().is_err());

    let service = ServiceLeaseRef {
        service_ref: reference(1),
        listener_revision: 1,
        intent_digest: listener().canonical().unwrap().1,
    };
    let refused = message(MessageBody::LeaseResult(LeaseResult {
        service: service.clone(),
        grant_id: Some([11; 16]),
        refresh_seq: Some(1),
        consumer_seq: None,
        remaining_ms: 0,
        result: "lease-expired".into(),
        snapshot_revision: None,
        snapshot_digest: None,
    }));
    assert!(refused.encode().is_err());
    let consumer = message(MessageBody::LeaseResult(LeaseResult {
        service,
        grant_id: Some([11; 16]),
        refresh_seq: None,
        consumer_seq: Some(1),
        remaining_ms: 1,
        result: "ok".into(),
        snapshot_revision: Some(0),
        snapshot_digest: Some([1; 32]),
    }));
    assert!(consumer.encode().is_err());
}

#[test]
fn service_label_allows_digit_start_but_rejects_invalid_edges() {
    let mut snapshot = snapshot();
    for label in ["1echo", "0", "a-1"] {
        snapshot.resources[0].service_label = label.into();
        let bytes = snapshot.canonical().unwrap().0;
        assert_eq!(Snapshot::decode(&bytes).unwrap(), snapshot);
    }
    for label in ["-echo", "Echo", "echo-", ""] {
        snapshot.resources[0].service_label = label.into();
        assert!(
            snapshot.canonical().is_err(),
            "unexpected valid label: {label}"
        );
    }
}
