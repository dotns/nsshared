#![allow(clippy::unwrap_used, clippy::panic)]

use nsshared_control::account::{
    AccountError,
    relay::{AdmissionSnapshotEntry, IdentityClass, RosterVersion, validate_admission_snapshot},
};
use nsshared_testkit::hex::unhex;

#[test]
fn network_scoped_snapshot_requires_exact_network_per_identity() {
    let identity = nsshared_identity::keys::IdentitySecret::from_seed([3; 32]).public();
    let network = nsshared_identity::realm::RealmId::from_bytes([4; 16]);
    let bytes = serde_json::to_vec(&serde_json::json!({
        "schema_version": 4,
        "issued_at_unix_ms": 1000,
        "roster_version": 2,
        "identities": [{
            "identity": identity.to_string(),
            "class": "ordinary_node",
            "admission_since": 1,
            "network": network.to_string()
        }]
    }))
    .unwrap();
    let snapshot = validate_admission_snapshot(&bytes, 1000, 0).unwrap();
    assert_eq!(snapshot.identities[0].network, Some(network));
    let omitted = String::from_utf8(bytes)
        .unwrap()
        .replace(&format!(",\"network\":\"{network}\""), "");
    assert!(validate_admission_snapshot(omitted.as_bytes(), 1000, 0).is_err());
}

#[test]
fn one_identity_may_have_distinct_network_grants_with_one_class_and_admission_start() {
    let identity = nsshared_identity::keys::IdentitySecret::from_seed([3; 32]).public();
    let a = nsshared_identity::realm::RealmId::from_bytes([4; 16]);
    let b = nsshared_identity::realm::RealmId::from_bytes([5; 16]);
    let entry = |network: &str, class: &str, since: u64| {
        serde_json::json!({
            "identity": identity.to_string(), "network": network,
            "class": class, "admission_since": since,
        })
    };
    let snapshot = |entries: Vec<serde_json::Value>| {
        serde_json::to_vec(&serde_json::json!({
            "schema_version": 4, "issued_at_unix_ms": 1000,
            "roster_version": 2, "identities": entries,
        }))
        .unwrap()
    };
    let first = entry(&a.to_string(), "gateway_node", 1);
    let second = entry(&b.to_string(), "gateway_node", 1);
    let accepted =
        validate_admission_snapshot(&snapshot(vec![first.clone(), second.clone()]), 1000, 0)
            .unwrap();
    assert_eq!(accepted.identities.len(), 2);
    assert_eq!(accepted.identities[0].network, Some(a));
    assert_eq!(accepted.identities[1].network, Some(b));
    assert!(
        validate_admission_snapshot(&snapshot(vec![first.clone(), first.clone()]), 1000, 0)
            .is_err()
    );
    assert!(
        validate_admission_snapshot(
            &snapshot(vec![
                first.clone(),
                entry(&b.to_string(), "ordinary_node", 1)
            ]),
            1000,
            0
        )
        .is_err()
    );
    assert!(
        validate_admission_snapshot(
            &snapshot(vec![first, entry(&b.to_string(), "gateway_node", 2)]),
            1000,
            0
        )
        .is_err()
    );
}

#[test]
fn admission_history_vectors() {
    let vectors = nsshared_testkit::vector_fields!("account/relay/admission-snapshot");
    for name in [
        "continuous-and-readmitted",
        "complete-empty",
        "schema-two",
        "schema-two-empty",
        "legacy-history-free",
        "missing-admission-start",
        "zero",
        "above-version",
        "null",
        "negative",
        "string",
        "fraction",
        "first-version",
        "maximum-version",
    ] {
        assert!(vectors.iter().any(|v| v.get("name") == Some(&name)));
    }
    for vector in vectors.iter().filter(|v| v.contains_key("name")) {
        let result = validate_admission_snapshot(&unhex(vector["bytes"]), 1000, 0);
        let decision = match &result {
            Ok(_) => "accepted",
            Err(AccountError::Field) => "field",
            Err(AccountError::Json(_)) => "json",
            other => panic!("unexpected decision: {other:?}"),
        };
        assert_eq!(decision, vector["decision"], "{}", vector["name"]);
        if let Ok(snapshot) = result {
            assert_eq!(snapshot.schema_version, 3);
            assert_eq!(snapshot.issued_at_unix_ms, 1000);
            assert_eq!(
                snapshot.roster_version,
                RosterVersion(vector["roster_version"].parse().unwrap())
            );
            let expected: Vec<AdmissionSnapshotEntry> = if vector["mapping"] == "empty" {
                vec![]
            } else {
                vector["mapping"]
                    .split(',')
                    .map(|entry| {
                        let parts: Vec<_> = entry.split(':').collect();
                        AdmissionSnapshotEntry {
                            identity: parts[0].parse().unwrap(),
                            class: match parts[1] {
                                "ordinary_node" => IdentityClass::OrdinaryNode,
                                "gateway_node" => IdentityClass::GatewayNode,
                                other => panic!("unknown class: {other}"),
                            },
                            admission_since: RosterVersion(parts[2].parse().unwrap()),
                            network: None,
                        }
                    })
                    .collect()
            };
            assert_eq!(snapshot.identities, expected, "{}", vector["name"]);
        }
    }
}
