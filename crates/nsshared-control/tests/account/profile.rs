#![allow(clippy::unwrap_used, clippy::panic)]

use nsshared_control::{
    account::node::Lifecycle, account::node::NodeL3, account::publication::FamilyRegistry,
    account::relay::Roster, account::relay::SignedRoster,
    account::relay::validate_admission_snapshot, account::usage::BatchLossWindow,
    account::usage::ServiceUsage,
};
use nsshared_identity::keys::IdentitySecret;
use nsshared_testkit::hex::unhex as bytes;
use std::collections::BTreeMap;

fn fixtures() -> Vec<BTreeMap<&'static str, &'static str>> {
    nsshared_testkit::vector_fields!("account/profile")
        .into_iter()
        .filter(|fields| fields.contains_key("name"))
        .collect()
}

#[test]
fn profile_contract_vectors() {
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
                | "publication-event"
                | "publication-snapshot"
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
        let result = validate_admission_snapshot(&input, 1000, 100);
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
    roster.verify(issuer, recipient, 6, 6, 1000).unwrap();
    assert!(roster.verify(issuer, recipient, 7, 6, 1000).is_err());
    assert!(roster.verify(issuer, recipient, 6, 6, 999).is_err());
    assert!(roster.verify(issuer, recipient, 6, 6, 86_401_000).is_err());
    assert!(roster.verify(recipient, recipient, 6, 6, 1000).is_err());
    assert!(roster.verify(issuer, issuer, 6, 6, 1000).is_err());
    for vector in vectors
        .iter()
        .filter(|v| v["kind"] == "signed-roster" && v["expect"] == "reject")
    {
        let result = SignedRoster::decode(&bytes(vector["bytes"]))
            .and_then(|r| r.verify(issuer, recipient, 6, 6, 1000));
        assert!(result.is_err(), "{}", vector["name"]);
    }
    let content = Roster::decode(&roster.content.canonical().unwrap()).unwrap();
    assert_eq!(content, roster.content);
}

#[test]
fn roster_freshness_and_empty_replacement() {
    let issuer = IdentitySecret::from_seed([1; 32]).public();
    let snapshot =
        r#"{"schema_version":3,"issued_at_unix_ms":900,"roster_version":7,"identities":[]}"#;
    assert!(
        validate_admission_snapshot(snapshot.as_bytes(), 1000, 100)
            .unwrap()
            .identities
            .is_empty()
    );
    assert!(validate_admission_snapshot(snapshot.as_bytes(), 1001, 100).is_err());
    let mut roster = Roster {
        schema_version: 1,
        issuer,
        recipient: issuer,
        version: nsshared_control::account::relay::RosterVersion(1),
        attribution_epoch: nsshared_control::account::relay::RosterVersion(1),
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
    use nsshared_control::{
        account::AccountError, account::MAX_IDENTITIES, account::relay::IdentityClass,
        account::relay::RosterVersion,
    };
    let entries: Vec<_> = (0..=MAX_IDENTITIES)
        .map(|index| {
            let mut seed = [0; 32];
            seed[..8].copy_from_slice(&(index as u64).to_le_bytes());
            let identity = IdentitySecret::from_seed(seed).public();
            serde_json::json!({"identity": identity.to_string(), "class": "gateway_node", "admission_since": 3})
        })
        .collect();
    let local = |count| {
        serde_json::to_vec(&serde_json::json!({
            "schema_version": 3, "issued_at_unix_ms": 1000, "roster_version": 7,
            "identities": &entries[..count],
        }))
        .unwrap()
    };
    let mut accepted = validate_admission_snapshot(&local(MAX_IDENTITIES), 1000, 0).unwrap();
    assert!(
        accepted
            .identities
            .iter()
            .all(|entry| entry.class == IdentityClass::GatewayNode)
    );
    assert!(matches!(
        validate_admission_snapshot(&local(MAX_IDENTITIES + 1), 1000, 0),
        Err(AccountError::Bounds)
    ));
    accepted.identities.sort_by_key(|entry| entry.identity);
    let issuer = accepted.identities[0].identity;
    let mut roster = Roster {
        schema_version: 1,
        issuer,
        recipient: issuer,
        version: RosterVersion(7),
        attribution_epoch: RosterVersion(7),
        issued_at_unix_ms: 1000,
        valid_until_unix_ms: 86_401_000,
        identities: accepted
            .identities
            .into_iter()
            .map(|entry| nsshared_control::account::relay::RosterEntry {
                identity: entry.identity,
                class: entry.class,
                network: None,
            })
            .collect(),
    };
    assert_eq!(
        Roster::decode(&roster.canonical().unwrap()).unwrap(),
        roster
    );
    roster.identities.push(roster.identities[0].clone());
    assert!(matches!(roster.canonical(), Err(AccountError::Bounds)));
}

#[test]
fn profile_cbor_refuses_trailing_and_nonminimal_forms() {
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
                | "publication-event"
                | "publication-snapshot"
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

pub(super) fn node_l3_protocol_fixture() -> NodeL3 {
    fixtures()
        .into_iter()
        .filter(|vector| vector["kind"] == "l3" && vector.get("expect") != Some(&"reject"))
        .map(|vector| NodeL3::decode(&bytes(vector["bytes"])).unwrap())
        .find(|policy| !policy.rules.is_empty())
        .unwrap()
}

pub(super) fn node_l3_protocol_bytes(
    policy: &NodeL3,
    protocol: u64,
    first: u64,
    last: u64,
) -> Vec<u8> {
    use nsshared_codec::cbor::CborWriter;

    let mut out = CborWriter::default();
    out.array(6)
        .uint(1)
        .bytes(policy.issuer.as_bytes())
        .bytes(policy.recipient.as_bytes())
        .uint(policy.revision)
        .array(policy.scopes.len());
    for scope in &policy.scopes {
        out.array(2)
            .bytes(&scope.namespace)
            .array(scope.identities.len());
        for identity in &scope.identities {
            out.bytes(identity.as_bytes());
        }
    }
    let rule = &policy.rules[0];
    out.array(1)
        .array(6)
        .bytes(&rule.namespace)
        .bytes(rule.source.as_bytes())
        .bytes(rule.destination.as_bytes())
        .uint(protocol)
        .uint(first)
        .uint(last);
    out.into_bytes()
}

#[test]
fn ordinary_node_echo_canonical_protocol_forms() {
    let policy = node_l3_protocol_fixture();
    for (protocol, first, last, suffix) in [
        (6, 1, 65535, &[6, 1, 0x19, 0xff, 0xff][..]),
        (17, 53, 53, &[17, 0x18, 53, 0x18, 53][..]),
        (1, 0, 0, &[1, 0, 0][..]),
        (58, 0, 0, &[0x18, 58, 0, 0][..]),
    ] {
        let wire = node_l3_protocol_bytes(&policy, protocol, first, last);
        assert!(wire.ends_with(suffix));
        let decoded = NodeL3::decode(&wire)
            .unwrap_or_else(|error| panic!("protocol {protocol} must decode: {error:?}"));
        assert_eq!(decoded.canonical().unwrap(), wire);
        assert_eq!(decoded.rules[0].protocol as u64, protocol);
        assert_eq!(u64::from(decoded.rules[0].first_port), first);
        assert_eq!(u64::from(decoded.rules[0].last_port), last);
    }
}

#[test]
fn ordinary_node_echo_refuses_other_selectors_and_malformed_forms() {
    use nsshared_codec::cbor::CborWriter;
    use nsshared_control::account::node::L3Protocol;

    let policy = node_l3_protocol_fixture();
    for (protocol, selector) in [(1, L3Protocol::EchoV4), (58, L3Protocol::EchoV6)] {
        let wire = node_l3_protocol_bytes(&policy, protocol, 0, 0);
        let mut decoded = NodeL3::decode(&wire).unwrap();
        assert_eq!(decoded.rules[0].protocol, selector);
        for (first, last) in [(0, 1), (1, 0), (1, 1), (8, 0), (128, 129), (0, 65536)] {
            assert!(
                NodeL3::decode(&node_l3_protocol_bytes(&policy, protocol, first, last)).is_err()
            );
        }
        decoded.rules[0].first_port = 1;
        assert!(decoded.canonical().is_err());
        decoded.rules[0].first_port = 0;
        decoded.rules[0].last_port = 1;
        assert!(decoded.canonical().is_err());

        let mut prefix = CborWriter::default();
        prefix.array(1).array(6).bytes(&policy.rules[0].namespace);
        let prefix = prefix.into_bytes();
        let offsets: Vec<_> = wire
            .windows(prefix.len())
            .enumerate()
            .filter_map(|(index, bytes)| (bytes == prefix).then_some(index))
            .collect();
        assert_eq!(offsets.len(), 1);
        for extra in [&[8][..], &[8, 0][..], &[128, 1][..]] {
            let mut extended = wire.clone();
            extended[offsets[0] + 1] += u8::try_from(extra.len()).unwrap();
            extended.extend_from_slice(extra);
            assert!(NodeL3::decode(&extended).is_err());
        }
        let mut trailing = wire.clone();
        trailing.push(0);
        assert!(NodeL3::decode(&trailing).is_err());
        let mut nonminimal = vec![0x98, 6];
        nonminimal.extend_from_slice(&wire[1..]);
        assert!(NodeL3::decode(&nonminimal).is_err());
    }
    for protocol in [6, 17] {
        for (first, last) in [(0, 0), (0, 1), (1, 0), (2, 1), (1, 65536)] {
            assert!(
                NodeL3::decode(&node_l3_protocol_bytes(&policy, protocol, first, last)).is_err()
            );
        }
    }
    for protocol in [0, 2, 8, 128, 129, 255, u64::MAX] {
        for (first, last) in [(0, 0), (1, 65535)] {
            assert!(
                NodeL3::decode(&node_l3_protocol_bytes(&policy, protocol, first, last)).is_err()
            );
        }
    }
    let mut combined = NodeL3::decode(&node_l3_protocol_bytes(&policy, 1, 0, 0)).unwrap();
    let first = combined.rules[0].clone();
    for protocol in [L3Protocol::Tcp, L3Protocol::Udp, L3Protocol::EchoV6] {
        let mut rule = first.clone();
        rule.protocol = protocol;
        if matches!(protocol, L3Protocol::Tcp | L3Protocol::Udp) {
            rule.first_port = 1;
            rule.last_port = u16::MAX;
        }
        combined.rules.push(rule);
    }
    let wire = combined.canonical().unwrap();
    assert_eq!(NodeL3::decode(&wire).unwrap(), combined);
    combined.rules.swap(0, 1);
    assert!(combined.canonical().is_err());
    combined.rules.sort();
    combined.rules.insert(0, first);
    assert!(combined.canonical().is_err());
}
