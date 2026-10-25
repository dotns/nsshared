#![allow(clippy::unwrap_used, clippy::panic)]
use nsshared_control::account::AccountError;

use std::collections::{BTreeMap, BTreeSet};

use nsshared_codec::cbor::CborReader;
use nsshared_control::{
    account::publication::AcceptedPublication, account::publication::PublicationChannel,
    account::publication::PublicationDecision, account::publication::PublicationError,
    account::publication::PublicationEvent, account::publication::PublicationExpectation,
    account::publication::PublicationKey, account::publication::PublicationScope,
    account::publication::decide_publication, account::publication::decide_publication_snapshot,
};
use nsshared_identity::keys::IdentityKey;

type Vector = BTreeMap<&'static str, &'static str>;

fn bytes(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn identity(value: &str) -> IdentityKey {
    IdentityKey::from_bytes(&bytes(value).try_into().unwrap()).unwrap()
}

fn read_identity(reader: &mut CborReader<'_>) -> IdentityKey {
    IdentityKey::from_bytes(&reader.fixed_bytes().unwrap()).unwrap()
}

fn states(raw: &[u8]) -> Vec<AcceptedPublication<'_>> {
    let mut reader = CborReader::new(raw, raw.len()).unwrap();
    let count = reader.array_up_to(raw.len()).unwrap();
    let result = (0..count)
        .map(|_| {
            reader.array(7).unwrap();
            AcceptedPublication {
                key: PublicationKey {
                    issuer: read_identity(&mut reader),
                    recipient: read_identity(&mut reader),
                    served_realm: reader.text_up_to(26).unwrap().parse().unwrap(),
                    scope: reader.text_up_to(256).unwrap(),
                    family: reader.uint().unwrap(),
                    kind: reader.text_up_to(256).unwrap(),
                },
                version: reader.uint().unwrap(),
            }
        })
        .collect();
    reader.finish().unwrap();
    result
}

fn scopes(raw: &[u8]) -> Vec<PublicationScope<'_>> {
    let mut reader = CborReader::new(raw, raw.len()).unwrap();
    let count = reader.array_up_to(raw.len()).unwrap();
    let result = (0..count)
        .map(|_| {
            reader.array(2).unwrap();
            PublicationScope {
                served_realm: reader.text_up_to(26).unwrap().parse().unwrap(),
                scope: reader.text_up_to(256).unwrap(),
            }
        })
        .collect();
    reader.finish().unwrap();
    result
}

fn reason(error: &PublicationError) -> &'static str {
    match error {
        PublicationError::Contract(AccountError::Cbor(_)) => "encoding",
        PublicationError::Bounds => "bounds",
        PublicationError::Field => "fields",
        PublicationError::Issuer => "issuer",
        PublicationError::Recipient => "recipient",
        PublicationError::Scope => "scope",
        PublicationError::Validity => "validity",
        PublicationError::Signature => "signature",
        PublicationError::Incomplete => "incomplete",
        PublicationError::Stale => "stale",
        PublicationError::Order => "order",
        _ => "unexpected",
    }
}

fn decision(value: &PublicationDecision<'_>) -> &'static str {
    match value {
        PublicationDecision::Replace(_) => "replace",
        PublicationDecision::Withdraw(_) => "withdraw",
        PublicationDecision::FetchFailed(_) => "fetch-failed",
        PublicationDecision::Absent => "absent",
        PublicationDecision::UnknownKind(_) => "unknown-kind",
        PublicationDecision::ChannelMismatch(_) => "channel-mismatch",
        PublicationDecision::Refused(_) => "refused",
        PublicationDecision::TerminateStream => "terminate-stream",
    }
}

fn assert_noncanonical_refused(raw: &[u8], refuses: impl Fn(&[u8]) -> bool) {
    let mut trailing = raw.to_vec();
    trailing.push(0);
    assert!(refuses(&trailing));
    let mut nonminimal = vec![0x98, raw[0] & 31];
    nonminimal.extend_from_slice(&raw[1..]);
    assert!(refuses(&nonminimal));
}

fn apply<'a>(last: &mut Vec<AcceptedPublication<'a>>, value: &PublicationDecision<'a>) {
    match value {
        PublicationDecision::Replace(event)
        | PublicationDecision::Withdraw(event)
        | PublicationDecision::FetchFailed(event) => {
            let content = event.content();
            last.retain(|state| state.key != content.key);
            last.push(AcceptedPublication {
                key: content.key,
                version: content.version,
            });
        }
        _ => {}
    }
}

#[test]
fn publication_decoder_vectors() {
    // Calibrate the byte reader before using measured fixture lengths.
    assert_eq!(bytes("820102"), [0x82, 1, 2]);
    assert_eq!(bytes("000102ff").len(), 4);
    let mut seen = BTreeSet::new();
    for block in include_str!("fixtures/vectors/account.vec").split("\n\n") {
        let v: Vector = block
            .lines()
            .filter_map(|line| line.split_once(" = "))
            .collect();
        if !v
            .get("kind")
            .is_some_and(|kind| kind.starts_with("publication-"))
        {
            continue;
        }
        seen.insert(v["name"]);
        let raw = bytes(v["bytes"]);
        assert_eq!(
            raw.len(),
            v["encoded_length"].parse::<usize>().unwrap(),
            "{}",
            v["name"]
        );
        let state_bytes = bytes(v["states"]);
        let last = states(&state_bytes);
        let mut next = last.clone();
        let scope_bytes = bytes(v["scopes"]);
        let authorized = scopes(&scope_bytes);
        let expected = PublicationExpectation {
            issuer: identity(v["issuer"]),
            recipient: identity(v["recipient"]),
            scopes: &authorized,
            channel: if v["channel"] == "0" {
                PublicationChannel::Stream
            } else {
                PublicationChannel::Snapshot
            },
            now_seconds: v["now"].parse().unwrap(),
        };
        if v["kind"] == "publication-snapshot" {
            match decide_publication_snapshot(&last, &raw, &expected) {
                Ok(snapshot) => {
                    assert_eq!(v["decision"], "accepted", "{}", v["name"]);
                    assert_eq!(snapshot.canonical(), bytes(v["canonical"]));
                    assert_noncanonical_refused(&raw, |bytes| {
                        decide_publication_snapshot(&last, bytes, &expected).is_err()
                    });
                    let actual: Vec<_> = snapshot
                        .decisions()
                        .map(|value| {
                            apply(&mut next, &value);
                            decision(&value)
                        })
                        .collect();
                    assert_eq!(
                        if actual.is_empty() {
                            "none".to_owned()
                        } else {
                            actual.join(",")
                        },
                        v["decisions"],
                        "{}",
                        v["name"]
                    );
                }
                Err(error) => {
                    assert_eq!(v["decision"], "rejected", "{}: {error}", v["name"]);
                    assert_eq!(reason(&error), v["reason"], "{}", v["name"]);
                }
            }
        } else {
            let value = decide_publication(
                &last,
                (v["present"] == "1").then_some(raw.as_slice()),
                &expected,
            );
            assert_eq!(decision(&value), v["decision"], "{}: {value:?}", v["name"]);
            apply(&mut next, &value);
            if let PublicationDecision::Refused(error) = &value {
                assert_eq!(reason(error), v["reason"], "{}", v["name"]);
            }
            if let Ok(event) = PublicationEvent::decode(&raw) {
                assert_noncanonical_refused(&raw, |bytes| PublicationEvent::decode(bytes).is_err());
                assert_eq!(event.canonical(), bytes(v["canonical"]), "{}", v["name"]);
                let payload = event.content().payload;
                let start = raw.as_ptr() as usize;
                let end = start + raw.len();
                assert!((start..=end).contains(&(payload.as_ptr() as usize)));
                assert!(payload.as_ptr() as usize + payload.len() <= end);
            }
        }
        next.sort_by_key(|state| state.key);
        let next_bytes = bytes(v["next_states"]);
        assert_eq!(
            next,
            states(&next_bytes),
            "{}: retained versions",
            v["name"]
        );
    }
    for required in [
        "complete",
        "empty",
        "absent",
        "fetch-failed",
        "unknown-kind",
        "signed-channel-mismatch",
        "received-channel-mismatch",
        "different-scope",
        "stale",
        "replayed",
        "wrong-issuer",
        "wrong-recipient",
        "at-expiry",
        "exact-limit",
        "over-limit",
        "truncated-length",
        "declared-beyond-input",
        "nested-truncated-length",
        "nested-declared-beyond-input",
        "snapshot-atomic-invalid",
        "snapshot-empty",
        "snapshot-scopes",
    ] {
        assert!(
            seen.contains(format!("publication-{required}").as_str()),
            "missing {required}"
        );
    }
}
