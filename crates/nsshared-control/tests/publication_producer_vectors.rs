#![allow(clippy::unwrap_used, clippy::panic)]

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signer, SigningKey};
use nsshared_codec::cbor::CborReader;
use nsshared_control::{
    account::publication::PublicationChannel, account::publication::PublicationContent,
    account::publication::PublicationDecision, account::publication::PublicationError,
    account::publication::PublicationEvent, account::publication::PublicationExpectation,
    account::publication::PublicationKey, account::publication::PublicationOutcome,
    account::publication::PublicationScope, account::publication::decide_publication,
    account::publication::encode_publication,
};
use nsshared_identity::keys::IdentityKey;

fn bytes(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn content(raw: &[u8]) -> PublicationContent<'_> {
    let mut r = CborReader::new(raw, raw.len()).unwrap();
    r.array(14).unwrap();
    assert_eq!(r.uint().unwrap(), 1);
    let key = PublicationKey {
        issuer: IdentityKey::from_bytes(&r.fixed_bytes().unwrap()).unwrap(),
        recipient: IdentityKey::from_bytes(&r.fixed_bytes().unwrap()).unwrap(),
        served_realm: r.text_up_to(26).unwrap().parse().unwrap(),
        scope: r.text_up_to(257).unwrap(),
        family: r.uint().unwrap(),
        kind: r.text_up_to(257).unwrap(),
    };
    let channel = match r.uint().unwrap() {
        0 => PublicationChannel::Stream,
        1 => PublicationChannel::Snapshot,
        _ => panic!("unrepresentable channel"),
    };
    let complete = r.boolean().unwrap();
    let version = r.uint().unwrap();
    let issued_seconds = r.uint().unwrap();
    let expires_seconds = r.uint().unwrap();
    let outcome = match r.uint().unwrap() {
        0 => PublicationOutcome::Data,
        1 => PublicationOutcome::FetchFailed,
        _ => panic!("unrepresentable outcome"),
    };
    let payload = r.bytes_up_to(raw.len()).unwrap();
    r.finish().unwrap();
    PublicationContent {
        key,
        channel,
        complete,
        version,
        issued_seconds,
        expires_seconds,
        outcome,
        payload,
    }
}

fn refusal<T: std::fmt::Debug>(result: Result<T, PublicationError>, expected: &str) {
    match (result, expected) {
        (Err(PublicationError::Field), "fields") | (Err(PublicationError::Bounds), "bounds") => {}
        (actual, _) => panic!("expected {expected}, got {actual:?}"),
    }
}

fn round_trip(raw: &[u8]) {
    let Ok(event) = PublicationEvent::decode(raw) else {
        return;
    };
    let c = event.content();
    let valid =
        nsshared_control::account::publication::publication_channel(c.key.family, c.key.kind)
            == Some(c.channel);
    if valid {
        assert_eq!(encode_publication(c, event.signature()).unwrap(), raw);
        assert_eq!(c.signing_input().unwrap(), event.signing_input());
    } else {
        refusal(c.canonical(), "fields");
        refusal(c.signing_input(), "fields");
        refusal(encode_publication(c, event.signature()), "fields");
    }
}

#[test]
fn publication_event_producer() {
    assert_eq!(bytes("820102"), [0x82, 1, 2]);
    let mut seen = BTreeSet::new();
    for block in include_str!("fixtures/vectors/account.vec").split("\n\n") {
        let v: BTreeMap<_, _> = block
            .lines()
            .filter_map(|line| line.split_once(" = "))
            .collect();
        let Some(kind) = v.get("kind") else { continue };
        if !kind.starts_with("publication-") {
            continue;
        }
        let raw = bytes(v["bytes"]);
        if *kind == "publication-event" {
            round_trip(&raw);
        } else if *kind == "publication-snapshot" {
            let mut r = CborReader::new(&raw, raw.len()).unwrap();
            if r.array(2).is_ok()
                && r.uint().is_ok()
                && let Ok(count) = r.array_up_to(raw.len())
            {
                for _ in 0..count {
                    let Ok(event) = r.bytes_up_to(raw.len()) else {
                        break;
                    };
                    round_trip(event);
                }
            }
        }
        let Some(result) = v.get("producer_result") else {
            continue;
        };
        seen.insert(v["name"]);
        let canonical = bytes(v["producer_content"]);
        let c = content(&canonical);
        let mut r = CborReader::new(&raw, raw.len()).unwrap();
        r.array(2).unwrap();
        r.bytes_up_to(raw.len()).unwrap();
        let signature = r.fixed_bytes().unwrap();
        r.finish().unwrap();
        if *result != "accept" {
            refusal(c.canonical(), result);
            refusal(c.signing_input(), result);
            refusal(encode_publication(&c, &signature), result);
            continue;
        }
        assert_eq!(c.canonical().unwrap(), canonical, "{}", v["name"]);
        assert_eq!(
            c.signing_input().unwrap(),
            bytes(v["signing_input"]),
            "{}",
            v["name"]
        );
        assert_eq!(
            encode_publication(&c, &signature).unwrap(),
            raw,
            "{}",
            v["name"]
        );
        if v["name"] == "publication-complete" {
            let key = SigningKey::from_bytes(&[1; 32]);
            assert_eq!(key.verifying_key().to_bytes(), *c.key.issuer.as_bytes());
            let signature = key.sign(&c.signing_input().unwrap()).to_bytes();
            let encoded = encode_publication(&c, &signature).unwrap();
            let scopes = [PublicationScope {
                served_realm: c.key.served_realm,
                scope: c.key.scope,
            }];
            let expected = PublicationExpectation {
                issuer: c.key.issuer,
                recipient: c.key.recipient,
                scopes: &scopes,
                channel: c.channel,
                now_seconds: 150,
            };
            assert!(matches!(
                decide_publication(&[], Some(&encoded), &expected),
                PublicationDecision::Replace(_)
            ));
        }
    }
    for name in [
        "complete",
        "partial",
        "unknown-kind",
        "unknown-family",
        "signed-channel-mismatch",
        "zero-version",
        "empty-validity",
        "reversed-validity",
        "empty-scope",
        "empty-kind",
        "long-kind",
        "long-scope",
        "wrong-failure-kind",
        "wrong-failure-family",
        "empty-failure",
        "exact-limit",
        "over-limit",
        "misplaced-usage-profile",
    ] {
        assert!(
            seen.contains(format!("publication-{name}").as_str()),
            "missing {name}"
        );
    }
}
