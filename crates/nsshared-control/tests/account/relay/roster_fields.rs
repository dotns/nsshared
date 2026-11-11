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

#[test]
fn separate_attribution_epoch_schema_round_trips() {
    use nsshared_codec::cbor::CborWriter;
    use nsshared_control::account::relay::Roster;

    let issuer = IdentitySecret::from_seed([1; 32]).public();
    let recipient = IdentitySecret::from_seed([2; 32]).public();
    let mut writer = CborWriter::default();
    writer
        .array(8)
        .uint(2)
        .bytes(issuer.as_bytes())
        .bytes(recipient.as_bytes())
        .uint(8)
        .uint(3)
        .uint(1000)
        .uint(86_401_000)
        .array(0);
    let bytes = writer.into_bytes();
    let roster =
        Roster::decode(&bytes).expect("schema 2 must carry an independent attribution epoch");
    assert_eq!(roster.canonical().unwrap(), bytes);
    assert_eq!(roster.version.0, 8);
    assert_eq!(roster.attribution_epoch.0, 3);
    let mut invalid = roster.clone();
    invalid.attribution_epoch.0 = 0;
    assert!(invalid.canonical().is_err());
    invalid = roster.clone();
    invalid.schema_version = 1;
    assert!(invalid.canonical().is_err());
    invalid = roster;
    invalid.schema_version = 3;
    assert_eq!(
        Roster::decode(&invalid.canonical().unwrap()).unwrap(),
        invalid
    );
    for (arity, schema) in [(7, 2), (8, 1), (8, 4)] {
        let mut invalid = bytes.clone();
        invalid[0] = 0x80 + arity;
        invalid[1] = schema;
        assert!(Roster::decode(&invalid).is_err());
    }
}

#[test]
fn signed_schema_three_binds_each_identity_to_its_network() {
    use ed25519_dalek::{Signer as _, SigningKey};
    use nsshared_control::account::{
        domains::ROSTER_DOMAIN,
        relay::{
            IdentityClass, Roster, RosterEntry, RosterVersion, SignedRoster,
            verify_participant_roster,
        },
    };
    use nsshared_identity::realm::RealmId;

    let signer = SigningKey::from_bytes(&[1; 32]);
    let issuer = IdentitySecret::from_seed([1; 32]).public();
    let recipient = IdentitySecret::from_seed([2; 32]).public();
    let identity = IdentitySecret::from_seed([3; 32]).public();
    let network = RealmId::from_bytes([9; 16]);
    let content = Roster {
        schema_version: 3,
        issuer,
        recipient,
        version: RosterVersion(5),
        attribution_epoch: RosterVersion(4),
        issued_at_unix_ms: 1_000,
        valid_until_unix_ms: 86_401_000,
        identities: vec![RosterEntry {
            identity,
            class: IdentityClass::OrdinaryNode,
            network: Some(network),
        }],
    };
    let mut message = ROSTER_DOMAIN.to_vec();
    message.extend_from_slice(&content.canonical().unwrap());
    let signed = SignedRoster {
        content,
        signature: signer.sign(&message).to_bytes(),
    };
    let bytes = signed.canonical().unwrap();
    let generation = verify_participant_roster(&bytes, issuer, recipient, 0, 0, 2_000).unwrap();
    assert_eq!(generation.identities[0].network, Some(network));
    let mut tampered = signed.clone();
    tampered.content.identities[0].network = Some(RealmId::from_bytes([8; 16]));
    assert!(
        verify_participant_roster(
            &tampered.canonical().unwrap(),
            issuer,
            recipient,
            0,
            0,
            2_000
        )
        .is_err()
    );
    tampered.content.identities[0].network = None;
    assert!(tampered.canonical().is_err());
}
