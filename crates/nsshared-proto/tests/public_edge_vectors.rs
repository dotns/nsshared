#![allow(clippy::unwrap_used, clippy::panic)]

mod support;

use nsshared_proto::account::{
    EdgeAuth, EdgeMaterialAck, EdgeServiceRequest, EdgeServiceResponse, PublicEdge,
};

#[test]
fn public_edge_vectors() {
    let vectors = support::vectors::parse(include_str!("fixtures/vectors/public-edge.vec"));
    for vector in vectors.iter().filter(|v| v.get("kind") == "edge") {
        let raw = vector.hex("bytes");
        let result = PublicEdge::decode(&raw).and_then(|v| v.canonical());
        assert_eq!(
            result.is_ok(),
            vector.get("expect") == "accept",
            "{}: {result:?}",
            vector.get("name")
        );
        if let Ok(bytes) = result {
            assert_eq!(bytes, raw);
        }
    }
    let full = vectors
        .iter()
        .find(|v| v.get("name") == "complete")
        .unwrap();
    let edge = PublicEdge::decode(&full.hex("bytes")).unwrap();
    let routes = &edge.realms[0].routes;
    assert_eq!(routes.len(), 2);
    assert_eq!(routes[0].name, "web.example");
    assert_eq!(routes[0].aliases, ["alias.example"]);
    assert_eq!(routes[0].domains, ["web.example"]);
    assert_eq!(routes[0].virtual_port, 8080);
    assert!(routes[0].backend.is_some());
    assert!(routes[1].backend.is_none());
    assert_eq!(edge.realms.len(), 2);
    assert_eq!(edge.realms[0].auth.bindings.len(), 1);
    assert_eq!(edge.realms[0].auth.jwt_bindings.len(), 1);
    assert_eq!(edge.realms[0].auth.authorities[0].audiences, ["edge"]);
    assert_eq!(edge.realms[0].auth.jwt_bindings[0].claim_value, "visitor");
    assert_eq!(edge.realms[0].auth.bindings[0].expires_seconds, Some(200));
    assert_eq!(
        edge.realms[0]
            .auth
            .materials
            .iter()
            .map(|v| (v.reference.as_str(), v.generation))
            .collect::<Vec<_>>(),
        [("auth", 2), ("cert", 2), ("ca", 2)]
    );
    assert_eq!(routes[0].options.request_body_bytes, Some(65536));
    assert_eq!(
        routes[0].options.audit_metadata,
        [("application".into(), "web".into())]
    );
    assert!(PublicEdge::decode(&vec![0; 1_048_577]).is_err());
}

#[test]
fn material_declaration_vectors() {
    let vectors = support::vectors::parse(include_str!("fixtures/vectors/public-edge.vec"));
    for vector in &vectors {
        let raw = vector.hex("bytes");
        let result = match vector.get("kind") {
            "auth" => EdgeAuth::decode(&raw).and_then(|v| v.canonical()),
            "material-ack" => EdgeMaterialAck::decode(&raw).and_then(|v| v.canonical()),
            "request" => EdgeServiceRequest::decode(&raw).and_then(|v| v.canonical()),
            "response" => EdgeServiceResponse::decode(&raw).and_then(|v| v.canonical()),
            _ => continue,
        };
        assert_eq!(
            result.is_ok(),
            vector.get("expect") == "accept",
            "{}: {result:?}",
            vector.get("name")
        );
        if let Ok(encoded) = result {
            assert_eq!(encoded, raw);
        }
    }
}

fn identity(seed: u8) -> nsshared_proto::IdentityKey {
    nsshared_proto::IdentityKey::from_bytes(
        &ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes(),
    )
    .unwrap()
}

fn snapshot() -> nsshared_service_control::Snapshot {
    use nsshared_service_control::{Protocols, Resource, ServiceRef, Snapshot};
    Snapshot {
        target_identity: *identity(2).as_bytes(),
        nsd_id: [4; 16],
        network_id: [5; 16],
        snapshot_revision: 1,
        resources: vec![Resource {
            service_ref: ServiceRef {
                nsd_id: [4; 16],
                network_id: [5; 16],
                service_id: [6; 16],
            },
            service_label: "supplied-label".into(),
            publisher_identity: *identity(1).as_bytes(),
            listener_revision: 2,
            intent_digest: [8; 32],
            port: 8080,
            protocols: Protocols {
                tcp: true,
                udp: false,
            },
            node6: nsshared_proto::identity::AddressGroup::derive(identity(1).as_bytes())
                .n6_bytes(),
            vip: None,
        }],
        routes: vec![],
        grants: vec![],
        listeners: vec![],
        withdrawals: vec![],
    }
}

#[test]
fn public_backends_join_authenticated_m6_resources() {
    let vectors = support::vectors::parse(include_str!("fixtures/vectors/public-edge.vec"));
    let full = vectors
        .iter()
        .find(|v| v.get("name") == "complete")
        .unwrap();
    let edge = PublicEdge::decode(&full.hex("bytes")).unwrap();
    let valid_snapshot = snapshot();
    edge.validate_snapshot(identity(2), &valid_snapshot)
        .unwrap();
    assert_eq!(valid_snapshot.resources[0].service_label, "supplied-label");
    for vector in vectors.iter().filter(|v| v.get("kind") == "join") {
        let changed = PublicEdge::decode(&vector.hex("bytes")).unwrap();
        assert!(
            changed
                .validate_snapshot(identity(2), &valid_snapshot)
                .is_err(),
            "{}",
            vector.name()
        );
    }
    assert!(
        edge.validate_snapshot(identity(1), &valid_snapshot)
            .is_err()
    );
    let mut changed = valid_snapshot.clone();
    changed.resources[0].node6 = [0; 16];
    assert!(edge.validate_snapshot(identity(2), &changed).is_err());
    let mut changed = valid_snapshot.clone();
    changed.resources.clear();
    assert!(edge.validate_snapshot(identity(2), &changed).is_err());
    let mut changed = valid_snapshot.clone();
    changed.resources[0].port += 1;
    assert!(edge.validate_snapshot(identity(2), &changed).is_err());
    let mut changed = valid_snapshot;
    changed.resources[0].protocols = nsshared_service_control::Protocols {
        tcp: false,
        udp: true,
    };
    assert!(edge.validate_snapshot(identity(2), &changed).is_err());
}

#[test]
fn material_and_service_acknowledgements_require_exact_pending_context() {
    let vectors = support::vectors::parse(include_str!("fixtures/vectors/public-edge.vec"));
    let installed = vectors
        .iter()
        .find(|v| v.get("name") == "installed")
        .unwrap();
    let ack = EdgeMaterialAck::decode(&installed.hex("bytes")).unwrap();
    ack.validate_installation([7; 16], "served", "edge", [3; 16], &ack.material)
        .unwrap();
    for vector in vectors
        .iter()
        .filter(|v| v.get("kind") == "material-match" || v.get("name") == "rejected")
    {
        let result = EdgeMaterialAck::decode(&vector.hex("bytes")).unwrap();
        assert!(
            result
                .validate_installation([7; 16], "served", "edge", [3; 16], &ack.material)
                .is_err(),
            "{}",
            vector.name()
        );
    }
    for kind in 0..3 {
        let request = vectors
            .iter()
            .find(|v| v.name() == format!("request-{kind}"))
            .unwrap();
        let request = EdgeServiceRequest::decode(&request.hex("bytes")).unwrap();
        let response = vectors
            .iter()
            .find(|v| v.name() == format!("response-{kind}"))
            .unwrap();
        let response = EdgeServiceResponse::decode(&response.hex("bytes")).unwrap();
        response.validate_request(&request).unwrap();
        assert!(response.accepted);
        for vector in vectors.iter().filter(|v| v.get("kind") == "response-match") {
            let mismatched = EdgeServiceResponse::decode(&vector.hex("bytes")).unwrap();
            assert!(mismatched.validate_request(&request).is_err());
        }
        use nsshared_proto::account::EdgeServiceBody;
        let (bytes, digest) = request.body.canonical().unwrap();
        match &request.body {
            EdgeServiceBody::Declaration(value) => {
                assert_eq!(value.canonical().unwrap(), bytes);
                assert_eq!(
                    nsshared_service_control::Declaration::decode(&bytes).unwrap(),
                    *value
                );
            }
            EdgeServiceBody::Report(value) => {
                assert_eq!(value.canonical().unwrap(), (bytes, digest))
            }
            EdgeServiceBody::Listener(value) => {
                assert_eq!(value.canonical().unwrap(), (bytes, digest))
            }
        }
        let mut rejected = response;
        rejected.accepted = false;
        rejected.validate_request(&request).unwrap();
        assert!(!rejected.accepted);
    }
}

#[test]
fn dependency_installation_precedes_route_exposure() {
    let vectors = support::vectors::parse(include_str!("fixtures/vectors/public-edge.vec"));
    let full = vectors
        .iter()
        .find(|v| v.get("name") == "complete")
        .unwrap();
    let edge = PublicEdge::decode(&full.hex("bytes")).unwrap();
    let acknowledgements: Vec<_> = edge.realms[0]
        .auth
        .materials
        .iter()
        .map(|material| EdgeMaterialAck {
            request_id: [7; 16],
            served_realm: "served".into(),
            scope: "edge".into(),
            realm: [3; 16],
            material: material.clone(),
            installed: true,
        })
        .collect();
    edge.validate_materials([7; 16], &acknowledgements).unwrap();
    assert!(edge.validate_materials([7; 16], &[]).is_err());
    assert!(edge.validate_materials([8; 16], &acknowledgements).is_err());
    for index in 0..acknowledgements.len() {
        let mut changed = acknowledgements.clone();
        changed[index].material.generation += 1;
        assert!(edge.validate_materials([7; 16], &changed).is_err());
        changed[index] = acknowledgements[index].clone();
        changed[index].installed = false;
        assert!(edge.validate_materials([7; 16], &changed).is_err());
        changed[index] = acknowledgements[index].clone();
        changed[index].realm = [9; 16];
        assert!(edge.validate_materials([7; 16], &changed).is_err());
    }
}

#[test]
fn signed_public_edge_replacement_is_atomic_and_does_not_renew_invalid_data() {
    use nsshared_proto::account::{
        AcceptedPublication, PublicationChannel, PublicationDecision, PublicationExpectation,
        PublicationKey, PublicationScope, decide_publication,
    };
    let vectors = support::vectors::parse(include_str!("fixtures/vectors/public-edge.vec"));
    let inputs: Vec<_> = vectors
        .iter()
        .filter(|v| v.get("kind") == "event")
        .map(|v| v.hex("bytes"))
        .collect();
    let key = PublicationKey {
        issuer: identity(1),
        recipient: identity(2),
        served_realm: "served",
        scope: "edge",
        family: 7,
        kind: "public-edge",
    };
    let scopes = [PublicationScope {
        served_realm: "served",
        scope: "edge",
    }];
    let expected = PublicationExpectation {
        issuer: key.issuer,
        recipient: key.recipient,
        scopes: &scopes,
        channel: PublicationChannel::Stream,
        now_seconds: 150,
    };
    let mut accepted = Vec::new();
    let mut current = None;
    let mut expiry = 0;
    for (index, raw) in inputs.iter().enumerate() {
        let before = (
            current.clone(),
            expiry,
            accepted
                .first()
                .map(|v: &AcceptedPublication<'_>| v.version),
        );
        match decide_publication(&accepted, Some(raw), &expected) {
            PublicationDecision::Replace(event) => {
                if let Ok(content) = PublicEdge::decode(event.content().payload)
                    && content.validate_publication(event.content()).is_ok()
                {
                    current = Some(content);
                    accepted = vec![AcceptedPublication {
                        key,
                        version: event.content().version,
                    }];
                    expiry = event.content().expires_seconds;
                }
            }
            PublicationDecision::Withdraw(event) => {
                current = None;
                accepted = vec![AcceptedPublication {
                    key,
                    version: event.content().version,
                }];
                expiry = event.content().expires_seconds;
            }
            PublicationDecision::Refused(_) | PublicationDecision::ChannelMismatch(_) => {}
            other => panic!("unexpected decision {other:?}"),
        }
        match index {
            0 => assert_eq!(current.as_ref().unwrap().realms[0].routes.len(), 2),
            1 | 4 | 6..=8 => assert_eq!(
                (current.clone(), expiry, accepted.first().map(|v| v.version)),
                before
            ),
            2 => assert_eq!(current.as_ref().unwrap().realms[0].routes.len(), 1),
            3 => assert!(current.as_ref().unwrap().realms.is_empty()),
            5 => assert!(current.is_none()),
            _ => panic!("unexpected event"),
        }
    }
    assert_eq!(inputs.len(), 9);
    assert_eq!(accepted[0].version, 4);
    assert_eq!(expiry, 200);
}
