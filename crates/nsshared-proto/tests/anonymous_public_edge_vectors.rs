#![allow(clippy::unwrap_used, clippy::panic)]

mod support;

use nsshared_proto::account::{
    AdminTokenClaims, EdgeProtocol, PolicySubject, PublicEdge, SubjectBinding, SubjectPolicy,
};

#[test]
fn anonymous_public_edge_vectors() {
    let vectors =
        support::vectors::parse(include_str!("fixtures/vectors/anonymous-public-edge.vec"));
    for vector in &vectors {
        let raw = vector.hex("bytes");
        let result = match vector.get("kind") {
            "policy" | "matching" => SubjectPolicy::decode(&raw).and_then(|v| v.canonical()),
            "edge" => PublicEdge::decode(&raw).and_then(|v| v.canonical()),
            "subject" => PolicySubject::decode(&raw).and_then(|v| v.canonical()),
            "binding" => SubjectBinding::decode(&raw).and_then(|v| v.canonical()),
            "admin" => AdminTokenClaims::decode(&raw).and_then(|v| v.canonical()),
            other => panic!("unknown vector kind: {other}"),
        };
        assert_eq!(
            result.is_ok(),
            vector.get("expect") == "accept",
            "{}: {result:?}",
            vector.name()
        );
        if let Ok(encoded) = result {
            assert_eq!(encoded, raw, "{}", vector.name());
        }
        if vector.get("kind") == "edge" && vector.get("expect") == "accept" {
            let edge = PublicEdge::decode(&raw).unwrap();
            let route = &edge.realms[0].routes[0];
            assert_eq!(route.dependencies.is_empty(), !vector.bool("requires_auth"));
            assert_eq!(
                edge.realms[0].auth.materials.is_empty(),
                !vector.bool("requires_auth")
            );
            assert_eq!(
                edge.validate_materials([7; 16], &[]).is_ok(),
                !vector.bool("requires_auth")
            );
            assert_eq!(route.virtual_port, 8080);
            assert_eq!(route.policy.rules[0].destinations, ["backend.example:8080"]);
            let expected = match vector.u64("protocol") {
                0 => EdgeProtocol::Http,
                6 => EdgeProtocol::Tcp,
                17 => EdgeProtocol::Udp,
                other => panic!("unexpected protocol: {other}"),
            };
            assert_eq!(route.protocol, expected);
        }
    }
}

// A fixture consumer of the documented matching table, not a runtime evaluator.
fn fixture_matches(
    policy: &SubjectPolicy,
    principal: &str,
    subject: Option<&PolicySubject>,
) -> bool {
    use nsshared_proto::account::SubjectSelector;
    policy.rules[0].subjects.iter().any(|selector| {
        if principal == "anonymous" {
            return *selector == SubjectSelector::Anonymous;
        }
        if !principal.starts_with("verified-") {
            return false;
        }
        let Some(subject) = subject else {
            return false;
        };
        match selector {
            SubjectSelector::AnyVerified => true,
            SubjectSelector::Anonymous => false,
            SubjectSelector::Subject(expected) => {
                expected == subject
                    || policy
                        .groups
                        .iter()
                        .any(|group| group.group == *expected && group.members.contains(subject))
            }
        }
    })
}

#[test]
fn anonymous_public_edge_matching_table() {
    let vectors =
        support::vectors::parse(include_str!("fixtures/vectors/anonymous-public-edge.vec"));
    let mut count = 0;
    for vector in vectors.iter().filter(|v| v.get("kind") == "matching") {
        let policy = SubjectPolicy::decode(&vector.hex("bytes")).unwrap();
        let subject = vector
            .opt("subject")
            .map(|_| PolicySubject::decode(&vector.hex("subject")).unwrap());
        assert_eq!(
            fixture_matches(&policy, vector.get("principal"), subject.as_ref()),
            vector.bool("matches"),
            "{}",
            vector.name()
        );
        count += 1;
    }
    assert_eq!(count, 42);
}

#[test]
fn anonymous_selector_typed_encoding_and_order() {
    use nsshared_proto::account::{SubjectRule, SubjectSelector};
    let vectors =
        support::vectors::parse(include_str!("fixtures/vectors/anonymous-public-edge.vec"));
    let bytes = |name: &str| {
        vectors
            .iter()
            .find(|v| v.name() == name)
            .unwrap()
            .hex("bytes")
    };
    let anonymous = SubjectPolicy::decode(&bytes("anonymous")).unwrap();
    assert_eq!(anonymous.rules[0].subjects, [SubjectSelector::Anonymous]);
    let mut changed = anonymous.clone();
    changed.rules[0].subjects = vec![SubjectSelector::AnyVerified];
    assert_eq!(changed.canonical().unwrap(), bytes("any-verified"));
    let user = SubjectPolicy::decode(&bytes("user")).unwrap();
    let SubjectSelector::Subject(subject) = &user.rules[0].subjects[0] else {
        panic!("expected unchanged qualified subject");
    };
    for selectors in [
        vec![SubjectSelector::AnyVerified, SubjectSelector::Anonymous],
        vec![SubjectSelector::Anonymous, SubjectSelector::AnyVerified],
        vec![SubjectSelector::Anonymous, SubjectSelector::Anonymous],
        vec![
            SubjectSelector::Subject(subject.clone()),
            SubjectSelector::Anonymous,
        ],
    ] {
        changed.rules[0].subjects = selectors;
        assert!(changed.canonical().is_err());
    }
    changed.rules = vec![SubjectRule {
        subjects: vec![
            SubjectSelector::Anonymous,
            SubjectSelector::Subject(subject.clone()),
        ],
        destinations: anonymous.rules[0].destinations.clone(),
        protocol: None,
    }];
    let encoded = changed.canonical().unwrap();
    assert_eq!(SubjectPolicy::decode(&encoded).unwrap(), changed);
    changed.groups.clear();
    changed.realm = [2; 16].into();
    assert!(changed.canonical().is_err());
    for name in ["http-without-auth", "tcp-without-auth", "udp-without-auth"] {
        let edge = PublicEdge::decode(&bytes(name)).unwrap();
        assert_eq!(
            edge.realms[0].routes[0].policy.rules[0].subjects,
            [SubjectSelector::Anonymous]
        );
    }
}
