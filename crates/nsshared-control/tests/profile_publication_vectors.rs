#![allow(clippy::unwrap_used, clippy::panic)]

use std::collections::BTreeMap;

use nsshared_control::{
    account::control::MAX_PUBLICATION_BYTES, account::control::MembershipScope,
    account::publication::AcceptedPublication, account::publication::DeliveryContext,
    account::publication::PublicationChannel, account::publication::PublicationDecision,
    account::publication::PublicationError, account::publication::PublicationEvent,
    account::publication::PublicationExpectation, account::publication::PublicationScope,
    account::publication::SignedSourceBinding, account::publication::decide_publication,
    account::publication::decide_source_publication, account::usage::NodeControlProfilePublication,
    account::usage::ProfilePublicationPayload, account::usage::UsageProfilePublication,
};
use nsshared_identity::keys::IdentitySecret;

type Vector = BTreeMap<&'static str, &'static str>;

fn vectors() -> Vec<Vector> {
    include_str!("fixtures/vectors/profile-publications.vec")
        .split("\n\n")
        .filter_map(|block| {
            let v: Vector = block
                .lines()
                .filter_map(|line| line.split_once(" = "))
                .collect();
            v.contains_key("bytes").then_some(v)
        })
        .collect()
}

fn bytes(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn profile_payload_vectors() {
    let reporter = IdentitySecret::from_seed([1; 32]).public();
    let other = IdentitySecret::from_seed([2; 32]).public();
    let accepted = MembershipScope {
        nsd_id: [3; 16],
        network_id: [3; 16],
    };
    let mut counts = [0; 2];
    for v in vectors()
        .iter()
        .filter(|v| matches!(v["kind"], "usage" | "control"))
    {
        let raw = bytes(v["bytes"]);
        let result = if v["kind"] == "usage" {
            UsageProfilePublication::decode(&raw).map(|payload| {
                payload
                    .validate_reporter(reporter)
                    .unwrap_or_else(|error| panic!("{}: {error}", v["name"]));
                assert!(payload.validate_reporter(other).is_err());
                let mut invalid = payload.clone();
                invalid.profiles.clear();
                assert!(invalid.canonical().is_err());
                payload.canonical().unwrap()
            })
        } else {
            NodeControlProfilePublication::decode(&raw).map(|payload| {
                let expected = if v["name"] == "control-zero-identifiers" {
                    MembershipScope {
                        nsd_id: [0; 16],
                        network_id: [0; 16],
                    }
                } else {
                    accepted.clone()
                };
                payload.validate_membership(&expected).unwrap();
                for field in 0..2 {
                    let mut wrong = expected.clone();
                    if field == 0 {
                        wrong.nsd_id[0] ^= 1;
                    } else {
                        wrong.network_id[0] ^= 1;
                    }
                    assert!(payload.validate_membership(&wrong).is_err());
                }
                let mut invalid = payload.clone();
                invalid.capabilities = vec![5];
                assert!(invalid.canonical().is_err());
                payload.canonical().unwrap()
            })
        };
        if v["expect"] == "accept" {
            assert_eq!(result.unwrap(), raw, "{}", v["name"]);
            counts[0] += 1;
        } else {
            assert!(result.is_err(), "{}", v["name"]);
            counts[1] += 1;
        }
    }
    assert_eq!(counts, [5, 39]);
    let oversized = vec![0; MAX_PUBLICATION_BYTES + 1];
    assert!(UsageProfilePublication::decode(&oversized).is_err());
    assert!(NodeControlProfilePublication::decode(&oversized).is_err());
}

#[test]
fn profile_publication_replacement() {
    let fixtures = vectors();
    let wire: Vec<_> = fixtures
        .iter()
        .filter(|v| v["kind"] == "publication")
        .map(|v| bytes(v["source_publication"]))
        .collect();
    let sequence: Vec<_> = fixtures
        .iter()
        .filter(|v| v["kind"] == "publication")
        .collect();
    let source = SignedSourceBinding::decode(&bytes(sequence[0]["binding"])).unwrap();
    let delivery = DeliveryContext::decode(&bytes(sequence[0]["delivery"])).unwrap();
    let scopes = [PublicationScope {
        served_realm: "030C1G60R30C1G60R30C1G60R3".parse().unwrap(),
        scope: "nodes",
    }];
    let expected = PublicationExpectation {
        issuer: IdentitySecret::from_seed([2; 32]).public(),
        recipient: IdentitySecret::from_seed([1; 32]).public(),
        scopes: &scopes,
        channel: PublicationChannel::Stream,
        now_seconds: 150,
    };
    let mut versions = Vec::new();
    let mut installed = BTreeMap::new();
    for (index, (raw, v)) in wire.iter().zip(&sequence).enumerate() {
        let decision =
            decide_source_publication(&versions, Some(raw), &source.binding, &delivery, &expected)
                .unwrap();
        match decision {
            PublicationDecision::Replace(event) => {
                assert_eq!(v["expect"], "replace");
                let typed = event.decode_profile_payload().unwrap().unwrap();
                match &typed {
                    ProfilePublicationPayload::Usage(value) => {
                        value.validate_reporter(expected.recipient).unwrap()
                    }
                    ProfilePublicationPayload::NodeControl(value) => value
                        .validate_membership(&MembershipScope {
                            nsd_id: [3; 16],
                            network_id: [3; 16],
                        })
                        .unwrap(),
                }
                let content = event.content();
                installed.insert(content.key, typed);
                versions.push(AcceptedPublication {
                    key: content.key,
                    version: content.version,
                });
            }
            PublicationDecision::Withdraw(event) => {
                assert_eq!(v["expect"], "withdraw");
                assert!(event.decode_profile_payload().unwrap().is_none());
                let content = event.content();
                installed.remove(&content.key);
                versions.retain(|state| state.key != content.key);
                versions.push(AcceptedPublication {
                    key: content.key,
                    version: content.version,
                });
            }
            PublicationDecision::Refused(error) => {
                assert_eq!(v["expect"], "refused");
                if index == 2 {
                    assert!(matches!(error, PublicationError::Fields));
                } else {
                    assert!(matches!(error, PublicationError::Stale));
                }
            }
            other => panic!("unexpected {other:?}"),
        }
        if index == 2 {
            assert_eq!(installed.len(), 2);
            assert!(versions.iter().all(|state| state.version == 1));
        }
        if index >= 3 {
            assert_eq!(installed.len(), 1);
            assert_eq!(installed.keys().next().unwrap().family, 10);
            assert_eq!(
                versions
                    .iter()
                    .find(|state| state.key.family == 9)
                    .unwrap()
                    .version,
                2
            );
        }
        let event_bytes = bytes(v["bytes"]);
        let event = PublicationEvent::decode(&event_bytes).unwrap();
        assert_eq!(event.canonical(), event_bytes);
    }
}

#[test]
fn profile_publication_context_refusals() {
    let scopes = [PublicationScope {
        served_realm: "030C1G60R30C1G60R30C1G60R3".parse().unwrap(),
        scope: "nodes",
    }];
    let expected = PublicationExpectation {
        issuer: IdentitySecret::from_seed([2; 32]).public(),
        recipient: IdentitySecret::from_seed([1; 32]).public(),
        scopes: &scopes,
        channel: PublicationChannel::Stream,
        now_seconds: 150,
    };
    for v in vectors().iter().filter(|v| v["kind"] == "context") {
        let raw = bytes(v["bytes"]);
        match decide_publication(&[], Some(&raw), &expected) {
            PublicationDecision::Replace(event) => {
                assert_eq!(v["expect"], "replace");
                let Some(ProfilePublicationPayload::NodeControl(value)) =
                    event.decode_profile_payload().unwrap()
                else {
                    panic!()
                };
                assert!(
                    value
                        .validate_membership(&MembershipScope {
                            nsd_id: [3; 16],
                            network_id: [3; 16],
                        })
                        .is_err()
                );
            }
            PublicationDecision::Refused(PublicationError::Fields) => {
                assert_eq!(v["expect"], "refused")
            }
            other => panic!("{}: {other:?}", v["name"]),
        }
    }
}
