#![allow(clippy::unwrap_used, clippy::panic)]

use nsshared_control::{
    account::control::MachineClaims, account::edge::AuthConfigRequest,
    account::edge::EdgeMaterialAck, account::edge::PublicEdge,
    account::publication::PublicationEvent, account::publication::PublicationSnapshotRequest,
    account::publication::PublicationSubscriptionRequest, account::realm::RealmPeers,
};

#[test]
fn noncanonical_realms_are_refused_by_owning_decoders() {
    for vector in nsshared_testkit::vectors!("account/realm/membership") {
        let bytes = vector.hex("bytes");
        let refused = match vector.get("kind") {
            "membership" => RealmPeers::decode(&bytes).is_err(),
            "publication" => PublicationEvent::decode(&bytes).is_err(),
            "edge" => PublicEdge::decode(&bytes).is_err(),
            "ack" => EdgeMaterialAck::decode(&bytes).is_err(),
            "auth-request" => AuthConfigRequest::decode(&bytes).is_err(),
            "subscription" => PublicationSubscriptionRequest::decode(&bytes).is_err(),
            "snapshot" => PublicationSnapshotRequest::decode(&bytes).is_err(),
            "claims" => MachineClaims::decode_json(&bytes).is_err(),
            _ => continue,
        };
        assert!(refused, "{} accepted noncanonical realm", vector.name());
    }
}

#[test]
fn independent_text_and_binary_identities_agree() {
    use nsshared_identity::realm::RealmId;
    for vector in nsshared_testkit::vectors!("account/realm/membership") {
        if vector.get("kind") != "identity" {
            continue;
        }
        let realm: RealmId = vector.get("text").parse().unwrap();
        assert_eq!(
            realm.to_bytes(),
            vector.hex_array::<16>("bytes"),
            "{}",
            vector.name()
        );
        assert_eq!(realm.to_string(), vector.get("text"));
        assert_eq!(RealmId::from_bytes(vector.hex_array("bytes")), realm);
        assert_eq!(
            serde_json::from_str::<RealmId>(&serde_json::to_string(&realm).unwrap()).unwrap(),
            realm
        );
    }
}

#[test]
fn every_bit_position_and_arbitrary_values_round_trip() {
    use nsshared_identity::realm::RealmId;
    for bit in 0..128 {
        for value in [1u128 << bit, !(1u128 << bit)] {
            let realm = RealmId::from_bytes(value.to_be_bytes());
            assert_eq!(realm.to_string().parse::<RealmId>().unwrap(), realm);
        }
    }
    for text in [
        "",
        "é000000000000000000000000",
        "0000000000000000000000000\t",
    ] {
        assert!(text.parse::<RealmId>().is_err());
    }
}

proptest::proptest! {
    #[test]
    fn all_unsigned_values_have_one_canonical_spelling(value: u128, other: u128) {
        use nsshared_identity::realm::RealmId;
        let realm = RealmId::from_bytes(value.to_be_bytes());
        let text = realm.to_string();
        proptest::prop_assert_eq!(text.len(), 26);
        proptest::prop_assert_eq!(text.parse::<RealmId>().unwrap(), realm);
        proptest::prop_assert_eq!(text.cmp(&RealmId::from_bytes(other.to_be_bytes()).to_string()), value.cmp(&other));
    }
}

#[test]
fn realm_identity_membership() {
    use nsshared_control::{
        account::publication::AcceptedPublication, account::publication::PublicationChannel,
        account::publication::PublicationDecision, account::publication::PublicationExpectation,
        account::publication::PublicationScope, account::publication::decide_publication,
    };
    use nsshared_identity::realm::RealmId;
    let vectors = nsshared_testkit::vectors!("account/realm/membership");
    let raw = |name| {
        vectors
            .iter()
            .find(|v| v.name() == name)
            .unwrap()
            .hex("bytes")
    };
    let a = RealmId::from_bytes(
        vectors
            .iter()
            .find(|v| v.name() == "A")
            .unwrap()
            .hex_array("bytes"),
    );
    let b = RealmId::from_bytes(
        vectors
            .iter()
            .find(|v| v.name() == "B")
            .unwrap()
            .hex_array("bytes"),
    );
    let identity = |seed| {
        nsshared_identity::keys::IdentityKey::from_bytes(
            ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
                .verifying_key()
                .as_bytes(),
        )
        .unwrap()
    };
    let scopes = [PublicationScope {
        served_realm: a,
        scope: "collection",
    }];
    let mut expected = PublicationExpectation {
        issuer: identity(1),
        recipient: identity(2),
        scopes: &scopes,
        channel: PublicationChannel::Snapshot,
        now_seconds: 150,
    };
    let initial = raw("membership-A");
    let PublicationDecision::Replace(initial_event) =
        decide_publication(&[], Some(&initial), &expected)
    else {
        panic!("membership not authenticated")
    };
    let membership = RealmPeers::decode(initial_event.content().payload).unwrap();
    membership.validate_at(150).unwrap();
    assert_eq!(membership.realms.len(), 1);
    assert_eq!(membership.realms[0].realm, a);
    let edge_raw = raw("routes-A-B");
    expected.channel = PublicationChannel::Stream;
    let PublicationDecision::Replace(edge_event) =
        decide_publication(&[], Some(&edge_raw), &expected)
    else {
        panic!("routes not authenticated")
    };
    let edge = PublicEdge::decode(edge_event.content().payload).unwrap();
    edge.validate_publication(edge_event.content()).unwrap();
    assert_eq!(
        edge.realms.iter().map(|r| r.realm).collect::<Vec<_>>(),
        [a, b]
    );
    let before = vectors
        .iter()
        .find(|v| v.name() == "before-removal")
        .unwrap();
    for realm in &edge.realms {
        assert!(!realm.routes.is_empty());
        assert!(
            realm
                .routes
                .iter()
                .all(|route| route.policy.realm == realm.realm)
        );
        let member = membership
            .realms
            .iter()
            .any(|member| member.realm == realm.realm);
        assert_eq!(
            member,
            realm.realm.to_bytes() == before.hex_array::<16>("admitted")
        );
        assert_eq!(
            !member,
            realm.realm.to_bytes() == before.hex_array::<16>("refused")
        );
    }
    expected.channel = PublicationChannel::Snapshot;
    let last = [AcceptedPublication {
        key: initial_event.content().key,
        version: initial_event.content().version,
    }];
    let removal = raw("membership-removed");
    let PublicationDecision::Replace(removed_event) =
        decide_publication(&last, Some(&removal), &expected)
    else {
        panic!("removal not authenticated")
    };
    let removed = RealmPeers::decode(removed_event.content().payload).unwrap();
    assert!(removed.realms.is_empty());
    let refused = RealmId::from_bytes(
        vectors
            .iter()
            .find(|v| v.name() == "after-removal")
            .unwrap()
            .hex_array("refused"),
    );
    assert!(edge.realms.iter().any(|route| route.realm == refused));
    assert!(!removed.realms.iter().any(|member| member.realm == refused));
    // Membership replacement does not invalidate or withdraw the route publication.
    expected.channel = PublicationChannel::Stream;
    assert!(matches!(
        decide_publication(&[], Some(&edge_raw), &expected),
        PublicationDecision::Replace(_)
    ));
    edge.validate_publication(edge_event.content()).unwrap();
}
