#![allow(clippy::unwrap_used, clippy::panic)]

use nsshared_proto::account::{
    AcceptedPublication, PolicyVersion, PublicationChannel, PublicationDecision, PublicationError,
    PublicationExpectation, PublicationKey, PublicationScope, RealmPeers, decide_publication,
};
use std::collections::BTreeMap;

fn configured_key(family: u64, kind: &'static str) -> PublicationKey<'static> {
    let identity = |seed| {
        nsshared_proto::IdentityKey::from_bytes(
            &ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
                .verifying_key()
                .to_bytes(),
        )
        .unwrap()
    };
    PublicationKey {
        issuer: identity(1),
        recipient: identity(2),
        served_realm: "served",
        scope: "collection",
        family,
        kind,
    }
}

type Vector = BTreeMap<&'static str, &'static str>;
fn vectors() -> Vec<Vector> {
    include_str!("fixtures/vectors/realm-publication.vec")
        .split("\n\n")
        .filter_map(|block| {
            let fields: Vector = block.lines().filter_map(|v| v.split_once(" = ")).collect();
            fields.contains_key("bytes").then_some(fields)
        })
        .collect()
}
fn bytes(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|v| u8::from_str_radix(std::str::from_utf8(v).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn realm_payload_consumer_vectors() {
    let all = vectors();
    assert_eq!(all.iter().filter(|v| v["kind"] != "event").count(), 33);
    for vector in all.iter().filter(|v| v["kind"] != "event") {
        let raw = bytes(vector["bytes"]);
        let result = if vector["kind"] == "membership" {
            RealmPeers::decode(&raw).and_then(|value| value.canonical())
        } else {
            PolicyVersion::decode(&raw).and_then(|value| value.canonical())
        };
        assert_eq!(
            result.is_ok(),
            vector["decision"] == "accept",
            "{}: {result:?}",
            vector["name"]
        );
        if let Ok(encoded) = result {
            assert_eq!(encoded, raw);
        }
    }
}

#[test]
fn realm_membership_replacement() {
    let all = vectors();
    let inputs: Vec<_> = all
        .iter()
        .filter(|v| v["kind"] == "event" && !v["name"].starts_with("policy-"))
        .map(|v| bytes(v["bytes"]))
        .collect();
    let key = configured_key(2, "realm-peers");
    let scopes = [PublicationScope {
        served_realm: "served",
        scope: "collection",
    }];
    let expected = PublicationExpectation {
        issuer: key.issuer,
        recipient: key.recipient,
        scopes: &scopes,
        channel: PublicationChannel::Snapshot,
        now_seconds: 150,
    };
    let mut accepted = Vec::new();
    let mut current = RealmPeers { realms: vec![] };
    let mut renewed_version = 0;
    let mut original_expiry = 0;
    for (index, raw) in inputs.iter().enumerate() {
        let decision = decide_publication(&accepted, Some(raw), &expected);
        let previous = current.clone();
        let previous_version = renewed_version;
        let previous_expiry = original_expiry;
        match decision {
            PublicationDecision::Replace(event) => {
                if let Ok(value) = RealmPeers::decode(event.content().payload) {
                    value.validate_at(150).unwrap();
                    current = value;
                    accepted = vec![AcceptedPublication {
                        key,
                        version: event.content().version,
                    }];
                    renewed_version = event.content().version;
                    original_expiry = event.content().expires_seconds;
                }
            }
            PublicationDecision::Withdraw(event) => {
                current.realms.clear();
                renewed_version = event.content().version;
                accepted = vec![AcceptedPublication {
                    key,
                    version: renewed_version,
                }];
            }
            PublicationDecision::Refused(_) | PublicationDecision::ChannelMismatch(_) => {}
            other => panic!("unexpected decision {other:?}"),
        }
        match index {
            0 => {
                assert_eq!(
                    current
                        .realms
                        .iter()
                        .map(|v| v.realm.as_str())
                        .collect::<Vec<_>>(),
                    ["realm-a", "realm-b"]
                );
                assert_eq!(
                    current
                        .realms
                        .iter()
                        .map(|v| v.members.len())
                        .sum::<usize>(),
                    2
                );
                assert_eq!(renewed_version, 1);
            }
            1 | 4 | 6..=8 => {
                assert_eq!(current, previous);
                assert_eq!(renewed_version, previous_version);
                assert_eq!(original_expiry, previous_expiry);
            }
            2 => {
                assert_eq!(current.realms.len(), 1);
                assert_eq!(current.realms[0], previous.realms[0]);
                assert_eq!(renewed_version, 2);
            }
            3 => {
                assert!(current.realms.is_empty());
                assert_eq!(renewed_version, 3);
                // Restore the caller's persisted version tombstone before replay.
                let persisted = accepted[0].version.to_be_bytes();
                accepted = vec![AcceptedPublication {
                    key,
                    version: u64::from_be_bytes(persisted),
                }];
                assert!(matches!(
                    decide_publication(&accepted, Some(&inputs[2]), &expected),
                    PublicationDecision::Refused(PublicationError::Stale)
                ));
            }
            5 => {
                assert!(current.realms.is_empty());
                assert_eq!(renewed_version, 4);
            }
            _ => panic!("unexpected vector"),
        }
    }
    assert_eq!(inputs.len(), 9);
}

#[test]
fn policy_observations_use_publication_versions() {
    let all = vectors();
    let inputs: Vec<_> = all
        .iter()
        .filter(|v| v["kind"] == "event" && v["name"].starts_with("policy-"))
        .map(|v| bytes(v["bytes"]))
        .collect();
    let key = configured_key(11, "policy-version");
    let scopes = [PublicationScope {
        served_realm: "served",
        scope: "collection",
    }];
    let expected = PublicationExpectation {
        issuer: key.issuer,
        recipient: key.recipient,
        scopes: &scopes,
        channel: PublicationChannel::Stream,
        now_seconds: 150,
    };
    let mut accepted = Vec::new();
    let mut observation = None;
    for (index, raw) in inputs.iter().enumerate() {
        if let PublicationDecision::Replace(event) =
            decide_publication(&accepted, Some(raw), &expected)
            && let Ok(value) = PolicyVersion::decode(event.content().payload)
        {
            observation = Some(value.counter);
            accepted = vec![AcceptedPublication {
                key,
                version: event.content().version,
            }];
        }
        assert_eq!(observation, Some(if index == 0 { 42 } else { 1 }));
        assert_eq!(accepted[0].version, if index == 0 { 1 } else { 2 });
    }
    assert_eq!(inputs.len(), 5);
}

#[test]
fn constructed_membership_validation() {
    use nsshared_proto::account::{AccountError, MAX_BYTES, MAX_IDENTITIES, MAX_PEER_REALMS};
    let all = vectors();
    let raw = bytes(all.iter().find(|v| v["name"] == "two-realms").unwrap()["bytes"]);
    let value = RealmPeers::decode(&raw).unwrap();
    value.validate_at(199).unwrap();
    assert!(matches!(
        value.validate_at(200),
        Err(AccountError::Authority)
    ));
    let mut changed = value.clone();
    changed.realms[1].members[0].binding = value.realms[0].members[0].binding.clone();
    assert!(changed.canonical().is_err());
    let mut changed = value.clone();
    changed.realms[0].members[0].binding.wg_key = [0; 32];
    assert!(changed.canonical().is_err());
    let mut changed = value.clone();
    changed.realms[0].members[0].binding.generation.0 += 1;
    assert!(changed.canonical().is_err());
    let mut changed = value.clone();
    changed.realms.reverse();
    assert!(changed.canonical().is_err());
    let mut changed = value.clone();
    changed.realms[0].realm.clear();
    assert!(changed.canonical().is_err());
    let mut changed = value.clone();
    changed.realms = vec![value.realms[0].clone(); MAX_PEER_REALMS + 1];
    assert!(matches!(changed.canonical(), Err(AccountError::Bounds)));
    let mut changed = value.clone();
    changed.realms[0].members = vec![value.realms[0].members[0].clone(); MAX_IDENTITIES + 1];
    assert!(matches!(changed.canonical(), Err(AccountError::Bounds)));
    assert!(RealmPeers::decode(&vec![0; MAX_BYTES + 1]).is_err());
    assert!(PolicyVersion::decode(&[0; 14]).is_err());
}
