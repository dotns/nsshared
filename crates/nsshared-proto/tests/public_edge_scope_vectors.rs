#![allow(clippy::unwrap_used)]

mod support;

use nsshared_proto::account::PublicEdge;

fn check_scope(prefix: &str) {
    let vectors = support::vectors::parse(include_str!("fixtures/vectors/public-edge.vec"));
    let prefix = format!("scope-{prefix}-");
    let mut isolated_count = 0;
    for vector in vectors
        .iter()
        .filter(|v| v.get("kind") == "edge-isolated" && v.name().starts_with(&prefix))
    {
        let bytes = vector.hex("bytes");
        let value = PublicEdge::decode(&bytes).unwrap();
        assert_eq!(value.realms.len(), 1);
        assert_eq!(value.canonical().unwrap(), bytes, "{}", vector.name());
        isolated_count += 1;
    }
    let mut accepted = 0;
    let mut refused = 0;
    let mut mismatches = Vec::new();
    for vector in vectors
        .iter()
        .filter(|v| v.get("kind") == "edge-cross-realm" && v.name().starts_with(&prefix))
    {
        let bytes = vector.hex("bytes");
        let result = PublicEdge::decode(&bytes);
        let expected = vector.get("expect") == "accept";
        if result.is_ok() != expected {
            mismatches.push(format!("{} decode", vector.name()));
        }
        if let Ok(value) = result {
            assert_eq!(value.realms.len(), 2);
            assert_eq!(value.canonical().unwrap(), bytes);
        }
        let mut contributions = (0..2).map(|index| {
            let name = format!("{}-isolated-{index}", vector.name());
            let isolated = vectors.iter().find(|v| v.name() == name).unwrap();
            PublicEdge::decode(&isolated.hex("bytes")).unwrap()
        });
        let mut combined = contributions.next().unwrap();
        combined.realms.extend(contributions.next().unwrap().realms);
        let encoded = combined.canonical();
        if encoded.is_ok() != expected {
            mismatches.push(format!("{} canonical", vector.name()));
        }
        if let Ok(encoded) = encoded {
            assert_eq!(encoded, bytes);
        }
        if expected {
            accepted += 1;
        } else {
            refused += 1;
        }
    }
    assert!(
        mismatches.is_empty(),
        "unexpected scope decisions: {mismatches:?}"
    );
    assert!(accepted > 0);
    assert!(refused > 0);
    assert_eq!(isolated_count, 2 * (accepted + refused));
}

#[test]
fn public_listener_ownership_is_gateway_wide() {
    check_scope("listener");
}

#[test]
fn http_hostname_port_ownership_is_gateway_wide() {
    check_scope("http");
}

#[test]
fn http_tcp_overlap_is_gateway_wide() {
    check_scope("overlap");
}

#[test]
fn backend_endpoint_ownership_is_gateway_wide() {
    check_scope("backend");
}

#[test]
fn discovery_names_and_material_refs_stay_realm_qualified() {
    let vectors = support::vectors::parse(include_str!("fixtures/vectors/public-edge.vec"));
    for index in 0..2 {
        let name = format!("scope-realm-names-materials-isolated-{index}");
        let isolated = vectors
            .iter()
            .find(|v| v.name() == name)
            .unwrap()
            .hex("bytes");
        let contribution = PublicEdge::decode(&isolated).unwrap();
        assert_eq!(contribution.realms.len(), 1);
        assert_eq!(contribution.canonical().unwrap(), isolated);
    }
    let raw = vectors
        .iter()
        .find(|v| v.name() == "scope-realm-names-materials")
        .unwrap()
        .hex("bytes");
    let value = PublicEdge::decode(&raw).unwrap();
    assert_eq!(value.canonical().unwrap(), raw);
    let first = &value.realms[0];
    let second = &value.realms[1];
    assert_ne!(first.realm, second.realm);
    assert_eq!(first.routes[0].id, second.routes[0].id);
    assert_eq!(first.routes[0].name, second.routes[0].name);
    assert_eq!(first.routes[0].aliases, second.routes[0].aliases);
    assert_eq!(first.routes[0].domains, second.routes[0].domains);
    assert_eq!(
        first.auth.materials[0].reference,
        second.auth.materials[0].reference
    );
    assert_eq!(first.auth.materials[0].generation, 2);
    assert_eq!(second.auth.materials[0].generation, 3);
    assert_eq!(first.routes[0].dependencies, first.auth.materials);
    assert_eq!(second.routes[0].dependencies, second.auth.materials);
}
