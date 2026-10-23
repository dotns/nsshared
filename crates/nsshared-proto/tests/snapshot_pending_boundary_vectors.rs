#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod support;
use nsshared_proto::{
    account::{
        AccountError, BootstrapEnvelope, EnvelopeDirection, EnvelopeExpectation, EnvelopePins,
        PublicationChannel, PublicationExpectation,
        control_exchange::CONFIG_SNAPSHOT,
        publication_snapshot_request::{
            MAX_SNAPSHOT_REQUEST_BYTES, PublicationSnapshotRequest, SnapshotRequestError,
        },
        publication_subscription::SubscriptionScope,
        source_binding::SignedSourceBinding,
    },
    encoding::CborReader,
};

#[test]
fn independent_pending_byte_boundaries_apply_to_authenticated_empty_polls() {
    let original = support::vectors::load("publication-snapshot-request");
    let template = PublicationSnapshotRequest::decode(&original[0].hex("bytes")).unwrap();
    let source = SignedSourceBinding::decode(
        &original
            .iter()
            .find(|v| v.name() == "current-source-0")
            .unwrap()
            .hex("bytes"),
    )
    .unwrap()
    .binding;
    for vector in support::vectors::load("snapshot-pending-boundaries") {
        let scope_bytes = vector.hex("scope_texts");
        let mut reader = CborReader::new(&scope_bytes, MAX_SNAPSHOT_REQUEST_BYTES).unwrap();
        let count = reader.array_up_to(32).unwrap();
        assert_eq!(count, 32);
        let mut pending = template.clone();
        pending.scopes.clear();
        let mut current = Vec::new();
        for _ in 0..count {
            let scope = reader.text_up_to(256).unwrap().to_string();
            assert!(!scope.is_empty() && !scope.chars().any(char::is_control));
            let mut binding = source.clone();
            binding.scope.clone_from(&scope);
            binding.canonical().unwrap();
            pending.scopes.push(SubscriptionScope {
                issuer: binding.nsd,
                recipient: binding.recipient,
                served_realm: binding.served_realm,
                scope,
            });
            current.push(binding);
        }
        reader.finish().unwrap();
        assert!(pending.scopes.windows(2).all(|pair| pair[0] < pair[1]));
        let raw = vector.hex("pending");
        assert_eq!(raw.len() as u64, vector.u64("encoded_length"));
        let accepted = vector.get("decision") == "accepted";
        if accepted {
            assert_eq!(raw.len(), MAX_SNAPSHOT_REQUEST_BYTES);
            assert_eq!(pending.canonical().unwrap(), raw);
            assert_eq!(PublicationSnapshotRequest::decode(&raw).unwrap(), pending);
        } else {
            assert_eq!(raw.len(), MAX_SNAPSHOT_REQUEST_BYTES + 1);
            assert!(pending.canonical().is_err());
            assert!(PublicationSnapshotRequest::decode(&raw).is_err());
        }
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
        envelope.verify(&carrier).unwrap();
        assert_eq!(envelope.payload, [0x82, 0x01, 0x80]);
        let scopes: Vec<_> = pending
            .scopes
            .iter()
            .map(SubscriptionScope::publication_scope)
            .collect();
        let expected = PublicationExpectation {
            issuer: envelope.signer,
            recipient: pending.subscriber,
            scopes: &scopes,
            channel: PublicationChannel::Snapshot,
            now_seconds: 100,
        };
        let result = pending.response(&envelope, &carrier, &[], &current, &expected);
        if accepted {
            assert!(result.unwrap().is_empty());
            let mut tampered = envelope.clone();
            tampered.signature[0] ^= 1;
            assert!(
                pending
                    .response(&tampered, &carrier, &[], &current, &expected)
                    .is_err()
            );
        } else {
            assert!(matches!(
                result,
                Err(SnapshotRequestError::Contract(AccountError::InvalidField))
            ));
        }
    }
}
