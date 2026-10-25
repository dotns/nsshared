#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod support;
use nsshared_control::{
    account::control::BootstrapEnvelope, account::control::CONFIG_SNAPSHOT,
    account::control::EnvelopeDirection, account::control::EnvelopeExpectation,
    account::control::EnvelopePins, account::publication::PublicationChannel,
    account::publication::PublicationExpectation, account::publication::PublicationSnapshotRequest,
    account::publication::SignedSourceBinding, account::publication::SubscriptionScope,
};

#[test]
fn empty_poll_refuses_a_pending_request_that_cannot_be_encoded_within_its_limit() {
    let vectors = support::vectors::load("publication-snapshot-request");
    let original = PublicationSnapshotRequest::decode(&vectors[0].hex("bytes")).unwrap();
    let template = SignedSourceBinding::decode(
        &vectors
            .iter()
            .find(|v| v.name() == "current-source-0")
            .unwrap()
            .hex("bytes"),
    )
    .unwrap()
    .binding;
    let vector = vectors
        .iter()
        .find(|v| v.name() == "response-empty")
        .unwrap();
    let envelope = BootstrapEnvelope::decode(&vector.hex("bytes")).unwrap();
    let pins = EnvelopePins::intersect(&[vector.get("pin").into()], &[]).unwrap();
    let carrier = EnvelopeExpectation {
        pins: &pins,
        direction: EnvelopeDirection::Response,
        recipient: original.subscriber,
        kind: CONFIG_SNAPSHOT,
        now_seconds: 100,
        previous_acceptance_seconds: None,
    };
    let original_current: Vec<_> = vectors
        .iter()
        .filter(|v| v.get("mode") == "source")
        .map(|v| {
            SignedSourceBinding::decode(&v.hex("bytes"))
                .unwrap()
                .binding
        })
        .collect();
    let original_scopes: Vec<_> = original
        .scopes
        .iter()
        .map(SubscriptionScope::publication_scope)
        .collect();
    let mut expected = PublicationExpectation {
        issuer: envelope.signer,
        recipient: original.subscriber,
        scopes: &original_scopes,
        channel: PublicationChannel::Snapshot,
        now_seconds: 100,
    };
    assert!(
        original
            .response(&envelope, &carrier, &[], &original_current, &expected)
            .unwrap()
            .is_empty()
    );

    let current: Vec<_> = (0..32)
        .map(|index| {
            let mut binding = template.clone();
            binding.scope = format!("{index:02}{}", "x".repeat(254));
            binding.canonical().unwrap();
            binding
        })
        .collect();
    let mut pending = original.clone();
    pending.scopes = current
        .iter()
        .map(|binding| SubscriptionScope {
            issuer: binding.nsd,
            recipient: binding.recipient,
            served_realm: binding.served_realm,
            scope: binding.scope.clone(),
        })
        .collect();
    assert!(
        pending.canonical().is_err(),
        "pending request exceeds its encoded limit"
    );
    let scopes: Vec<_> = pending
        .scopes
        .iter()
        .map(SubscriptionScope::publication_scope)
        .collect();
    expected.scopes = &scopes;
    let mut invalid_signature = envelope.clone();
    invalid_signature.signature[0] ^= 1;
    assert!(
        pending
            .response(&invalid_signature, &carrier, &[], &current, &expected)
            .is_err()
    );
    assert!(
        pending
            .response(&envelope, &carrier, &[], &current, &expected)
            .is_err(),
        "a pending request rejected by its own encoder must not validate a poll response"
    );
}
