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
use nsshared_testkit::fixture::identity_hex as identity;
use nsshared_testkit::hex::unhex as bytes;

#[test]
fn provider_mapping_replacement() {
    let fixtures: Vec<BTreeMap<_, _>> = nsshared_testkit::vector_fields!("account/subnet/mapping")
        .into_iter()
        .filter(|fields| fields.contains_key("bytes"))
        .collect();
    assert_eq!(fixtures.len(), 28);
    assert_eq!(
        FamilyRegistry
            .replacement(4, "provider-mappings")
            .unwrap()
            .clears,
        "mappings"
    );
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
        if fields["name"] != "wrong-network" {
            assert_eq!(
                matches!(
                    &decision,
                    Ok(PublicationDecision::Replace(_) | PublicationDecision::Withdraw(_))
                ),
                fields["decision"] == "accept",
                "{}: unexpected direct decision: {decision:?}",
                fields["name"]
            );
        }
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
        let inventory = event.decode_provider_mapping_payload().unwrap();
        if let Some(ref inventory) = inventory {
            assert_eq!(inventory.canonical().unwrap(), content.payload);
        }
        if key.kind == "provider-mappings" {
            let mappings = inventory.map_or_else(Vec::new, |value| value.mappings);
            match fields["name"] {
                "populated" | "other-provider" => {
                    assert_eq!(
                        mappings.iter().map(|m| m.subnet_id).collect::<Vec<_>>(),
                        [1, 7]
                    );
                    assert_eq!(mappings[0].real_cidr.address.to_string(), "10.0.0.0");
                    assert_eq!(mappings[0].real_cidr.length, 8);
                    assert_eq!(mappings[1].real_cidr.address.to_string(), "2001:db8::");
                    assert_eq!(mappings[1].real_cidr.length, 32);
                }
                "replacement" => {
                    assert_eq!(mappings.len(), 1);
                    assert_eq!(mappings[0].subnet_id, 7);
                    assert_eq!(mappings[0].real_cidr.address.to_string(), "2001:db8:1::");
                    assert_eq!(mappings[0].real_cidr.length, 48);
                }
                "typed-empty" | "withdrawal" => assert!(mappings.is_empty()),
                _ => unreachable!(),
            }
            collections.insert(key, mappings.len());
        } else {
            let count = if let Some(grants) = event.decode_grant_payload().unwrap() {
                grants.grants.len()
            } else {
                event.decode_subnet_payload().unwrap().unwrap().routes.len()
            };
            collections.insert(key, count);
        }
        // Retain the version tombstone even for an empty typed collection.
        accepted += 1;
        states.retain(|state: &AcceptedPublication<'_>| state.key != content.key);
        states.push(AcceptedPublication {
            key: content.key,
            version: content.version,
        });
        if matches!(fields["name"], "replacement" | "typed-empty" | "withdrawal") {
            let p = identity(fixtures[0]["recipient"]);
            let q = identity(fixtures[1]["recipient"]);
            let client = identity(fixtures[2]["recipient"]);
            let count = |node, kind: &str| {
                collections
                    .iter()
                    .find(|(key, _)| key.recipient == node && key.kind == kind)
                    .map(|(_, count)| *count)
            };
            assert_eq!(count(p, "exit-grants"), Some(1));
            assert_eq!(count(q, "exit-grants"), Some(1));
            assert_eq!(count(client, "subnet-routes"), Some(2));
            assert_eq!(count(q, "provider-mappings"), Some(2));
            assert_eq!(
                count(p, "provider-mappings"),
                Some(usize::from(fields["name"] == "replacement"))
            );
        }
    }
    assert_eq!(accepted, 8);
}

#[test]
fn provider_mapping_codec_bounds() {
    use nsshared_control::{
        account::subnet::ProviderMapping, account::subnet::ProviderMappings,
        account::subnet::SubnetPrefix,
    };
    let entry = ProviderMapping {
        subnet_id: u32::MAX,
        real_cidr: SubnetPrefix {
            address: "::".parse().unwrap(),
            length: 0,
        },
    };
    let valid = ProviderMappings {
        mappings: vec![entry.clone()],
    };
    assert_eq!(
        ProviderMappings::decode(&valid.canonical().unwrap()).unwrap(),
        valid
    );
    let mut invalid = valid.clone();
    invalid.mappings[0].subnet_id = 0;
    assert!(invalid.canonical().is_err());
    invalid.mappings = vec![entry.clone(), entry.clone()];
    assert!(invalid.canonical().is_err());
    invalid.mappings = (1..=256)
        .map(|subnet_id| ProviderMapping {
            subnet_id,
            ..entry.clone()
        })
        .collect();
    assert!(invalid.canonical().is_ok());
    invalid.mappings.push(entry);
    assert!(invalid.canonical().is_err());
    assert!(ProviderMappings::decode(&vec![0; 1_048_577]).is_err());
}
