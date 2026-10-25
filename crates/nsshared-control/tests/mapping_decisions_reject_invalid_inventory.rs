#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;

use nsshared_codec::cbor::CborWriter;
use nsshared_control::{
    account::publication::DeliveryContext, account::publication::PublicationChannel,
    account::publication::PublicationDecision, account::publication::PublicationExpectation,
    account::publication::PublicationScope, account::publication::SignedSourceBinding,
    account::publication::decide_source_publication, account::publication::decide_source_snapshot,
};
use nsshared_identity::keys::IdentityKey;

fn hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn mapping_actions_require_a_well_formed_inventory() {
    let fixtures: Vec<BTreeMap<_, _>> = include_str!("fixtures/vectors/provider-mapping.vec")
        .split("\n\n")
        .map(|block| {
            block
                .lines()
                .filter_map(|line| line.split_once(" = "))
                .collect()
        })
        .filter(|fields: &BTreeMap<_, _>| fields.contains_key("bytes"))
        .collect();
    for name in [
        "populated",
        "zero-id",
        "duplicate-id",
        "descending-id",
        "invalid-cidr",
        "noncanonical",
    ] {
        let fields = fixtures
            .iter()
            .find(|fields| fields["name"] == name)
            .unwrap();
        let raw = hex(fields["bytes"]);
        let current = SignedSourceBinding::decode(&hex(fields["source"]))
            .unwrap()
            .binding;
        let pending = DeliveryContext::decode(&hex(fields["pending"])).unwrap();
        let scopes = [PublicationScope {
            served_realm: current.served_realm,
            scope: &current.scope,
        }];
        let expected = PublicationExpectation {
            issuer: IdentityKey::from_bytes(&hex(fields["issuer"]).try_into().unwrap()).unwrap(),
            recipient: current.recipient,
            scopes: &scopes,
            channel: PublicationChannel::Snapshot,
            now_seconds: 150,
        };
        let decision =
            decide_source_publication(&[], Some(&raw), &current, &pending, &expected).unwrap();
        let mut container = CborWriter::default();
        container.array(2).uint(1).array(1).bytes(&raw);
        let container = container.into_bytes();
        let snapshot = decide_source_snapshot(&[], &container, &current, &pending, &expected);
        if name == "populated" {
            assert!(matches!(decision, PublicationDecision::Replace(_)));
            assert!(snapshot.is_ok());
        } else {
            assert!(
                matches!(decision, PublicationDecision::Refused(_)) && snapshot.is_err(),
                "{name}: malformed inventory exposed as an action: {decision:?}; snapshot: {snapshot:?}"
            );
        }
    }
}
