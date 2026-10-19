#![allow(clippy::unwrap_used)]

use nsshared_proto::{IdentitySecret, account::validate_snapshot};

#[test]
fn named_root_fields_are_required_for_roster_snapshots() {
    let valid =
        br#"{"schema_version":2,"issued_at_unix_ms":1000,"roster_version":7,"identities":[]}"#;
    assert!(validate_snapshot(valid, 1000, 0).is_ok());
    let missing_version = br#"{"schema_version":2,"issued_at_unix_ms":1000,"identities":[]}"#;
    assert!(validate_snapshot(missing_version, 1000, 0).is_err());

    let positional = br"[2,1000,7,[]]";
    let result = validate_snapshot(positional, 1000, 0);
    assert!(
        result.is_err(),
        "a root array has none of the required named fields and must not withdraw admission: {result:?}"
    );
}

#[test]
fn named_identity_class_fields_are_required_for_roster_snapshots() {
    let identity = IdentitySecret::from_seed([42; 32]).public().to_string();
    let snapshot = |entries| {
        serde_json::to_vec(&serde_json::json!({
            "schema_version": 2,
            "issued_at_unix_ms": 1000,
            "roster_version": 7,
            "identities": entries,
        }))
        .unwrap()
    };
    let valid = snapshot(serde_json::json!([
        {"identity": identity, "class": "gateway_node"}
    ]));
    assert!(validate_snapshot(&valid, 1000, 0).is_ok());
    let missing_class = snapshot(serde_json::json!([{"identity": identity}]));
    assert!(validate_snapshot(&missing_class, 1000, 0).is_err());

    let positional = snapshot(serde_json::json!([[identity, "gateway_node"]]));
    let result = validate_snapshot(&positional, 1000, 0);
    assert!(
        result.is_err(),
        "an entry array has no named identity or class field and must not grant admission: {result:?}"
    );
}
