#![allow(clippy::unwrap_used)]

use nsshared_control::account::relay::validate_admission_snapshot;
use nsshared_identity::keys::IdentitySecret;

#[test]
fn named_root_fields_are_required_for_roster_snapshots() {
    let valid =
        br#"{"schema_version":3,"issued_at_unix_ms":1000,"roster_version":7,"identities":[]}"#;
    assert!(validate_admission_snapshot(valid, 1000, 0).is_ok());
    let missing_version = br#"{"schema_version":3,"issued_at_unix_ms":1000,"identities":[]}"#;
    assert!(validate_admission_snapshot(missing_version, 1000, 0).is_err());

    let positional = br"[3,1000,7,[]]";
    let result = validate_admission_snapshot(positional, 1000, 0);
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
            "schema_version": 3,
            "issued_at_unix_ms": 1000,
            "roster_version": 7,
            "identities": entries,
        }))
        .unwrap()
    };
    let valid = snapshot(serde_json::json!([
        {"identity": identity, "class": "gateway_node", "admission_since": 3}
    ]));
    assert!(validate_admission_snapshot(&valid, 1000, 0).is_ok());
    let missing_class = snapshot(serde_json::json!([{"identity": identity, "admission_since": 3}]));
    assert!(validate_admission_snapshot(&missing_class, 1000, 0).is_err());

    let positional = snapshot(serde_json::json!([[identity, "gateway_node", 3]]));
    let result = validate_admission_snapshot(&positional, 1000, 0);
    assert!(
        result.is_err(),
        "an entry array has no named identity or class field and must not grant admission: {result:?}"
    );
}

#[test]
fn named_roster_fields_reject_duplicates_and_unknown_names() {
    let identity = IdentitySecret::from_seed([42; 32]).public().to_string();
    let entry =
        format!(r#"{{"identity":"{identity}","admission_since":3,"class":"gateway_node"}}"#);
    let snapshot = |entry: &str| {
        format!(
            r#"{{"schema_version":3,"issued_at_unix_ms":1000,"roster_version":7,"identities":[{entry}]}}"#
        )
    };
    assert!(validate_admission_snapshot(snapshot(&entry).as_bytes(), 1000, 0).is_ok());
    for invalid in [
        entry.replace(
            "\"admission_since\":3",
            "\"admission_since\":3,\"admission_since\":4",
        ),
        format!(
            r#"{{"identity":"{identity}","identity":"{identity}","admission_since":3,"class":"gateway_node"}}"#
        ),
        format!(
            r#"{{"identity":"{identity}","admission_since":3,"class":"gateway_node","class":"ordinary_node"}}"#
        ),
        format!(
            r#"{{"identity":"{identity}","admission_since":3,"class":"gateway_node","unknown":0}}"#
        ),
    ] {
        assert!(
            validate_admission_snapshot(snapshot(&invalid).as_bytes(), 1000, 0).is_err(),
            "{invalid}"
        );
    }
    for invalid in [
        r#"{"schema_version":3,"issued_at_unix_ms":1000,"roster_version":7,"roster_version":8,"identities":[]}"#,
        r#"{"schema_version":3,"issued_at_unix_ms":1000,"roster_version":7,"identities":[],"unknown":0}"#,
    ] {
        assert!(
            validate_admission_snapshot(invalid.as_bytes(), 1000, 0).is_err(),
            "{invalid}"
        );
    }
}

#[test]
fn schema_three_admission_history_is_required() {
    let identity = IdentitySecret::from_seed([42; 32]).public().to_string();
    let input = serde_json::to_vec(&serde_json::json!({
        "schema_version": 3, "issued_at_unix_ms": 1000, "roster_version": 7,
        "identities": [{"identity": identity, "class": "gateway_node", "admission_since": 3}]
    }))
    .unwrap();
    assert!(validate_admission_snapshot(&input, 1000, 0).is_ok());
}
