#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use nsshared_control::{
    account::control::BootstrapEnvelope, account::control::CONFIG_SNAPSHOT,
    account::control::EnvelopeDirection, account::control::EnvelopeExpectation,
    account::control::EnvelopePins, account::publication::PublicationChannel,
    account::publication::PublicationExpectation, account::publication::PublicationScope,
    account::publication::PublicationSnapshotRequest, account::publication::SignedSourceBinding,
};

#[test]
fn snapshot_carrier_refuses_plain_entries() {
    let vectors = nsshared_testkit::vectors!("account/publication/snapshot-request");
    let pending = PublicationSnapshotRequest::decode(&vectors[0].hex("bytes")).unwrap();
    let current: Vec<_> = vectors
        .iter()
        .filter(|v| v.get("mode") == "source")
        .map(|v| {
            SignedSourceBinding::decode(&v.hex("bytes"))
                .unwrap()
                .binding
        })
        .collect();
    let vector = vectors.iter().find(|v| v.name() == "plain-entry").unwrap();
    let envelope = BootstrapEnvelope::decode(&vector.hex("bytes")).unwrap();
    let pins = EnvelopePins::intersect(&[vector.get("pin").into()], &[]).unwrap();
    let carrier = EnvelopeExpectation {
        pins: &pins,
        direction: EnvelopeDirection::Response,
        recipient: pending.subscriber,
        kind: CONFIG_SNAPSHOT,
        now_seconds: 100,
        previous_acceptance_seconds: None,
    };
    let scopes: Vec<_> = pending
        .scopes
        .iter()
        .map(|s| PublicationScope {
            served_realm: s.served_realm,
            scope: &s.scope,
        })
        .collect();
    let publication = PublicationExpectation {
        issuer: envelope.signer,
        recipient: pending.subscriber,
        scopes: &scopes,
        channel: PublicationChannel::Snapshot,
        now_seconds: 100,
    };
    assert!(
        pending
            .response(&envelope, &carrier, &[], &current, &publication)
            .is_err(),
        "plain publication response must be refused"
    );
}

#[test]
fn snapshot_carrier_requires_the_exact_independently_accepted_scope_set() {
    let vectors = nsshared_testkit::vectors!("account/publication/snapshot-request");
    let pending = PublicationSnapshotRequest::decode(&vectors[0].hex("bytes")).unwrap();
    let current: Vec<_> = vectors
        .iter()
        .filter(|v| v.get("mode") == "source")
        .map(|v| {
            SignedSourceBinding::decode(&v.hex("bytes"))
                .unwrap()
                .binding
        })
        .collect();
    let vector = vectors
        .iter()
        .find(|v| v.name() == "response-empty")
        .unwrap();
    let envelope = BootstrapEnvelope::decode(&vector.hex("bytes")).unwrap();
    let pins = EnvelopePins::intersect(&[vector.get("pin").into()], &[]).unwrap();
    let carrier = EnvelopeExpectation {
        pins: &pins,
        direction: EnvelopeDirection::Response,
        recipient: pending.subscriber,
        kind: CONFIG_SNAPSHOT,
        now_seconds: 100,
        previous_acceptance_seconds: None,
    };
    let scopes: Vec<_> = pending
        .scopes
        .iter()
        .map(|s| s.publication_scope())
        .collect();
    let expected = PublicationExpectation {
        issuer: envelope.signer,
        recipient: pending.subscriber,
        scopes: &scopes,
        channel: PublicationChannel::Snapshot,
        now_seconds: 100,
    };
    assert!(
        pending
            .response(&envelope, &carrier, &[], &current, &expected)
            .unwrap()
            .is_empty()
    );
    for sources in [
        vec![],
        vec![current[0].clone()],
        vec![current[0].clone(), current[0].clone()],
        vec![current[0].clone(), current[1].clone(), current[1].clone()],
    ] {
        assert!(
            pending
                .response(&envelope, &carrier, &[], &sources, &expected)
                .is_err()
        );
    }
    let mut outside = current.clone();
    outside[1].scope = "unrequested".into();
    assert!(
        pending
            .response(&envelope, &carrier, &[], &outside, &expected)
            .is_err()
    );
    let mut wrong_expected = expected;
    wrong_expected.scopes = &scopes[..1];
    assert!(
        pending
            .response(&envelope, &carrier, &[], &current, &wrong_expected)
            .is_err()
    );
    let duplicate = [scopes[0], scopes[0]];
    wrong_expected.scopes = &duplicate;
    assert!(
        pending
            .response(&envelope, &carrier, &[], &current, &wrong_expected)
            .is_err()
    );
    let mut invalid_pending = pending.clone();
    invalid_pending.attempt_counter = 0;
    assert!(
        invalid_pending
            .response(&envelope, &carrier, &[], &current, &expected)
            .is_err()
    );
}
