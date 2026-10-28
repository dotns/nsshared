#![allow(clippy::unwrap_used, clippy::panic)]

use nsshared_control::account::{
    AccountError,
    relay::{AdmissionSnapshotEntry, IdentityClass, RosterVersion, validate_admission_snapshot},
};
use nsshared_testkit::hex::unhex;

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
                        }
                    })
                    .collect()
            };
            assert_eq!(snapshot.identities, expected, "{}", vector["name"]);
        }
    }
}
