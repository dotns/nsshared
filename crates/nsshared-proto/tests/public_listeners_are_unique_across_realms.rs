#![allow(clippy::unwrap_used)]

mod support;

use nsshared_proto::account::{EdgeProtocol, PublicEdge};

#[test]
fn served_realms_cannot_claim_the_same_tcp_listener() {
    let vectors = support::vectors::parse(include_str!("fixtures/vectors/public-edge.vec"));
    let raw = vectors
        .iter()
        .find(|v| v.name() == "complete")
        .unwrap()
        .hex("bytes");
    let mut edge = PublicEdge::decode(&raw).unwrap();
    let mut route = edge.realms[0].routes[0].clone();
    route.protocol = EdgeProtocol::Tcp;
    route.public_port = 9443;
    route.backend = None;
    edge.realms[0].routes = vec![route.clone()];
    route.id = "other".into();
    route.name = "other.example".into();
    route.aliases.clear();
    route.domains.clear();
    route.policy.realm = edge.realms[1].realm;
    route.policy.rules.clear();
    route.policy.groups.clear();
    route.dependencies.clear();
    route.headers.enabled = false;
    route.headers.keyset_ref = None;
    edge.realms[1].routes = vec![route];
    for realm in &edge.realms {
        let mut isolated = edge.clone();
        isolated.realms = vec![realm.clone()];
        assert!(
            isolated.canonical().is_ok(),
            "each contribution is independently valid"
        );
    }
    assert!(
        edge.canonical().is_err(),
        "two served realms cannot own TCP port 9443 simultaneously"
    );
}
