#![allow(clippy::unwrap_used, clippy::panic)]

use std::collections::BTreeMap;

use nsshared_control::{
    account::control::MembershipScope, account::publication::AcceptedPublication,
    account::publication::DeliveryContext, account::publication::FamilyRegistry,
    account::publication::PublicationChannel, account::publication::PublicationDecision,
    account::publication::PublicationExpectation, account::publication::PublicationScope,
    account::publication::SignedSourceBinding, account::publication::SourcePublication,
    account::publication::decide_source_publication,
};
use nsshared_identity::keys::IdentityKey;

fn bytes(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn identity(value: &str) -> IdentityKey {
    IdentityKey::from_bytes(&bytes(value).try_into().unwrap()).unwrap()
}

#[test]
fn subnet_publication_views() {
    let fixtures: Vec<BTreeMap<_, _>> =
        include_str!("fixtures/vectors/subnet-publication-views.vec")
            .split("\n\n")
            .map(|block| {
                block
                    .lines()
                    .filter_map(|line| line.split_once(" = "))
                    .collect()
            })
            .filter(|fields: &BTreeMap<_, _>| fields.contains_key("bytes"))
            .collect();
    assert_eq!(fixtures.len(), 23);
    assert_eq!(
        FamilyRegistry
            .replacement(4, "subnet-routes")
            .unwrap()
            .clears,
        "routes,exclusions,bypasses,selection"
    );
    assert!(FamilyRegistry.replacement(3, "subnet-routes").is_none());
    assert_eq!(
        FamilyRegistry
            .replacement(4, "exit-grants")
            .unwrap()
            .publication,
        "exit-grants"
    );

    // The fixture state records only validated exact-key collection replacements.
    let mut states = Vec::new();
    let mut collections = BTreeMap::new();
    let wires: Vec<_> = fixtures
        .iter()
        .map(|fields| bytes(fields["bytes"]))
        .collect();
    let mut accepted = 0;
    for (fields, raw) in fixtures.iter().zip(&wires) {
        let current = SignedSourceBinding::decode(&bytes(fields["source"]))
            .unwrap()
            .binding;
        let pending = DeliveryContext::decode(&bytes(fields["pending"])).unwrap();
        let membership = MembershipScope {
            nsd_id: bytes(fields["nsd"]).try_into().unwrap(),
            network_id: bytes(fields["network"]).try_into().unwrap(),
        };
        let scopes = [PublicationScope {
            served_realm: current.served_realm,
            scope: &current.scope,
        }];
        let expected = PublicationExpectation {
            issuer: identity(fields["issuer"]),
            recipient: identity(fields["recipient"]),
            scopes: &scopes,
            channel: PublicationChannel::Snapshot,
            now_seconds: 150,
        };
        let decision = decide_source_publication(&states, Some(raw), &current, &pending, &expected);
        let result = match &decision {
            Ok(PublicationDecision::Replace(event) | PublicationDecision::Withdraw(event)) => event
                .validate_routing_context(expected.recipient, &membership)
                .is_ok(),
            _ => false,
        };
        assert_eq!(
            result,
            fields["decision"] == "accept",
            "{}: {decision:?}",
            fields["name"]
        );
        if !result {
            continue;
        }
        let source = SourcePublication::decode(raw).unwrap();
        let event = source.event().unwrap();
        let content = event.content();
        let key = content.key;
        let resources = if let Some(grants) = event.decode_grant_payload().unwrap() {
            assert!(event.decode_subnet_payload().unwrap().is_none());
            assert_eq!(grants.canonical().unwrap(), content.payload);
            grants
                .grants
                .into_iter()
                .map(|grant| grant.resource)
                .collect::<Vec<_>>()
        } else {
            let routes = event.decode_subnet_payload().unwrap().unwrap();
            assert_eq!(routes.canonical().unwrap(), content.payload);
            routes
                .routes
                .into_iter()
                .map(|route| route.resource)
                .collect()
        };
        collections.insert(key, resources);
        // Retain the version tombstone even for an empty typed collection.
        accepted += 1;
        states.retain(|state: &AcceptedPublication<'_>| state.key != content.key);
        states.push(AcceptedPublication {
            key: content.key,
            version: content.version,
        });
        let p = identity(fixtures[0]["recipient"]);
        let q = identity(fixtures[1]["recipient"]);
        let client = identity(fixtures[2]["recipient"]);
        let view = |node, kind: &str| {
            collections
                .iter()
                .find(|(key, _)| key.recipient == node && key.kind == kind)
                .map(|(_, resources)| resources)
        };
        let count = |node, kind: &str| view(node, kind).map(Vec::len);
        match fields["name"] {
            "client-both" => {
                assert_eq!(count(p, "exit-grants"), Some(1));
                assert_eq!(count(q, "exit-grants"), Some(1));
                assert_eq!(count(client, "subnet-routes"), Some(2));
            }
            "provider-p-empty" => {
                assert_eq!(count(p, "exit-grants"), Some(0));
                assert_eq!(count(q, "exit-grants"), Some(1));
                assert_eq!(count(client, "subnet-routes"), Some(2));
            }
            "client-q-only" => {
                assert_eq!(count(client, "subnet-routes"), Some(1));
                assert_eq!(view(client, "subnet-routes"), view(q, "exit-grants"));
            }
            "client-empty" => {
                assert_eq!(count(client, "subnet-routes"), Some(0));
                assert_eq!(count(q, "exit-grants"), Some(1));
            }
            _ => {}
        }
    }
    assert_eq!(accepted, 7);
}
