#![allow(clippy::unwrap_used, clippy::panic)]

use nsshared_proto::{
    IdentitySecret,
    account::{
        BatchLossWindow, FamilyRegistry, Lifecycle, NodeL3, Roster, ServiceUsage, SignedRoster,
        validate_snapshot,
    },
};
use std::collections::BTreeMap;

fn fixtures() -> Vec<BTreeMap<&'static str, &'static str>> {
    include_str!("fixtures/vectors/account.vec")
        .split("\n\n")
        .filter_map(|block| {
            let fields: BTreeMap<_, _> = block
                .lines()
                .filter_map(|line| line.split_once(" = "))
                .collect();
            fields.contains_key("name").then_some(fields)
        })
        .collect()
}

fn bytes(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn candidate_contract_vectors() {
    let mut counts = BTreeMap::new();
    for vector in fixtures() {
        let kind = vector["kind"];
        if matches!(
            kind,
            "snapshot"
                | "signed-roster"
                | "enrollment"
                | "participant-roster"
                | "bootstrap-discovery"
                | "bootstrap-envelope"
                | "bootstrap-boundary"
                | "subnet-selection"
        ) {
            continue;
        }
        let input = bytes(vector["bytes"]);
        if vector.get("expect") == Some(&"reject") {
            let result = match kind {
                "registry" => FamilyRegistry::decode(&input).map(|_| ()),
                "lifecycle" => Lifecycle::decode(&input).map(|_| ()),
                "l3" => NodeL3::decode(&input).map(|_| ()),
                "usage" => ServiceUsage::decode(&input).map(|_| ()),
                _ => panic!("unknown vector kind: {kind}"),
            };
            assert!(result.is_err(), "{}", vector["name"]);
            continue;
        }
        *counts.entry(kind).or_insert(0) += 1;
        match kind {
            "registry" => {
                let registry = FamilyRegistry::decode(&input).unwrap();
                assert_eq!(registry, FamilyRegistry);
                assert_eq!(registry.canonical(), input);
            }
            "lifecycle" => {
                let lifecycle = Lifecycle::decode(&input).unwrap();
                assert_eq!(lifecycle.canonical().unwrap(), input);
                assert_ne!(lifecycle.before.wg_key, lifecycle.after.wg_key);
                if vector["name"] == "identity-replacement" {
                    assert_ne!(
                        lifecycle.before.identity.node_id(),
                        lifecycle.after.identity.node_id()
                    );
                    assert_ne!(
                        lifecycle.before.identity.node6(),
                        lifecycle.after.identity.node6()
                    );
                    assert_ne!(
                        lifecycle.before.identity.node4(),
                        lifecycle.after.identity.node4()
                    );
                } else {
                    assert_eq!(lifecycle.before.identity, lifecycle.after.identity);
                    assert_eq!(
                        lifecycle.before.identity.node_id(),
                        lifecycle.after.identity.node_id()
                    );
                    assert_eq!(
                        lifecycle.before.identity.node6(),
                        lifecycle.after.identity.node6()
                    );
                    assert_eq!(
                        lifecycle.before.identity.node4(),
                        lifecycle.after.identity.node4()
                    );
                }
            }
            "l3" => assert_eq!(NodeL3::decode(&input).unwrap().canonical().unwrap(), input),
            "usage" => {
                let usage = ServiceUsage::decode(&input).unwrap();
                assert_eq!(usage.canonical(), input);
                assert_eq!(
                    usage.batch_loss_window,
                    if vector["name"] == "usage-unset" {
                        BatchLossWindow::Unset
                    } else {
                        BatchLossWindow::Measured { duration_ms: 0 }
                    }
                );
            }
            _ => panic!("unknown vector kind: {kind}"),
        }
    }
    assert_eq!(
        counts,
        BTreeMap::from([("registry", 1), ("lifecycle", 2), ("l3", 2), ("usage", 2)])
    );
}

#[test]
fn strict_local_roster_vectors() {
    let mut cases = 0;
    for vector in fixtures().into_iter().filter(|v| v["kind"] == "snapshot") {
        cases += 1;
        let mut input = bytes(vector["bytes"]);
        if let Some(length) = vector.get("pad_to") {
            input.resize(length.parse().unwrap(), b' ');
        }
        let result = validate_snapshot(&input, 1000, 100);
        assert_eq!(
            result.is_ok(),
            vector["expect"] == "accept",
            "{}: {result:?}",
            vector["name"]
        );
        if let Ok(snapshot) = result {
            assert_eq!(snapshot.roster_version.0, 7);
            assert_eq!(
                snapshot.identities.len(),
                vector["count"].parse::<usize>().unwrap()
            );
        }
    }
    assert!(cases >= 12);
}

#[test]
fn independently_signed_participant_roster_vectors() {
    let vectors = fixtures();
    let valid = vectors
        .iter()
        .find(|v| v["name"] == "signed-roster")
        .unwrap();
    let roster = SignedRoster::decode(&bytes(valid["bytes"])).unwrap();
    assert_eq!(roster.canonical().unwrap(), bytes(valid["bytes"]));
    let issuer = roster.content.issuer;
    let recipient = roster.content.recipient;
    roster.verify(issuer, recipient, 6, 1000).unwrap();
    assert!(roster.verify(issuer, recipient, 7, 1000).is_err());
    assert!(roster.verify(issuer, recipient, 6, 999).is_err());
    assert!(roster.verify(issuer, recipient, 6, 86_401_000).is_err());
    assert!(roster.verify(recipient, recipient, 6, 1000).is_err());
    assert!(roster.verify(issuer, issuer, 6, 1000).is_err());
    for vector in vectors
        .iter()
        .filter(|v| v["kind"] == "signed-roster" && v["expect"] == "reject")
    {
        let result = SignedRoster::decode(&bytes(vector["bytes"]))
            .and_then(|r| r.verify(issuer, recipient, 6, 1000));
        assert!(result.is_err(), "{}", vector["name"]);
    }
    let content = Roster::decode(&roster.content.canonical().unwrap()).unwrap();
    assert_eq!(content, roster.content);
}

#[test]
fn roster_freshness_and_empty_replacement() {
    let issuer = IdentitySecret::from_seed([1; 32]).public();
    let snapshot =
        r#"{"schema_version":2,"issued_at_unix_ms":900,"roster_version":7,"identities":[]}"#;
    assert!(
        validate_snapshot(snapshot.as_bytes(), 1000, 100)
            .unwrap()
            .identities
            .is_empty()
    );
    assert!(validate_snapshot(snapshot.as_bytes(), 1001, 100).is_err());
    let mut roster = Roster {
        issuer,
        recipient: issuer,
        version: nsshared_proto::account::RosterVersion(1),
        issued_at_unix_ms: 0,
        valid_until_unix_ms: 86_400_000,
        identities: vec![],
    };
    assert!(roster.canonical().is_ok());
    roster.valid_until_unix_ms -= 1;
    assert!(roster.canonical().is_err());
}

#[test]
fn admission_identity_count_bound_and_atomic_classes() {
    use nsshared_proto::account::{AccountError, IdentityClass, MAX_IDENTITIES, RosterVersion};
    let entries: Vec<_> = (0..=MAX_IDENTITIES)
        .map(|index| {
            let mut seed = [0; 32];
            seed[..8].copy_from_slice(&(index as u64).to_le_bytes());
            let identity = IdentitySecret::from_seed(seed).public();
            serde_json::json!({"identity": identity.to_string(), "class": "gateway_node"})
        })
        .collect();
    let local = |count| {
        serde_json::to_vec(&serde_json::json!({
            "schema_version": 2, "issued_at_unix_ms": 1000, "roster_version": 7,
            "identities": &entries[..count],
        }))
        .unwrap()
    };
    let mut accepted = validate_snapshot(&local(MAX_IDENTITIES), 1000, 0).unwrap();
    assert!(
        accepted
            .identities
            .iter()
            .all(|entry| entry.class == IdentityClass::GatewayNode)
    );
    assert!(matches!(
        validate_snapshot(&local(MAX_IDENTITIES + 1), 1000, 0),
        Err(AccountError::Bounds)
    ));
    accepted.identities.sort_by_key(|entry| entry.identity);
    let issuer = accepted.identities[0].identity;
    let mut roster = Roster {
        issuer,
        recipient: issuer,
        version: RosterVersion(7),
        issued_at_unix_ms: 1000,
        valid_until_unix_ms: 86_401_000,
        identities: accepted.identities,
    };
    assert_eq!(
        Roster::decode(&roster.canonical().unwrap()).unwrap(),
        roster
    );
    roster.identities.push(roster.identities[0].clone());
    assert!(matches!(roster.canonical(), Err(AccountError::Bounds)));
}

#[test]
fn candidate_cbor_refuses_trailing_and_nonminimal_forms() {
    for vector in fixtures()
        .into_iter()
        .filter(|v| v.get("expect") != Some(&"reject"))
    {
        let kind = vector["kind"];
        if matches!(
            kind,
            "snapshot"
                | "enrollment"
                | "participant-roster"
                | "bootstrap-discovery"
                | "bootstrap-envelope"
                | "bootstrap-boundary"
                | "subnet-selection"
        ) {
            continue;
        }
        let decode = |input: &[u8]| match kind {
            "registry" => FamilyRegistry::decode(input).map(|_| ()),
            "lifecycle" => Lifecycle::decode(input).map(|_| ()),
            "l3" => NodeL3::decode(input).map(|_| ()),
            "usage" => ServiceUsage::decode(input).map(|_| ()),
            "signed-roster" => SignedRoster::decode(input).map(|_| ()),
            _ => panic!("unknown vector kind: {kind}"),
        };
        let input = bytes(vector["bytes"]);
        let mut trailing = input.clone();
        trailing.push(0);
        assert!(decode(&trailing).is_err(), "{}", vector["name"]);
        let mut nonminimal = vec![0x98, input[0] & 31];
        nonminimal.extend_from_slice(&input[1..]);
        assert!(decode(&nonminimal).is_err(), "{}", vector["name"]);
    }
}
