#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod support;

use ed25519_dalek::{Signer, SigningKey};
use nsshared_proto::{
    account::{
        PublicationChannel, PublicationDecision, PublicationExpectation, PublicationScope,
        source_binding::DeliveryContext,
        source_publication::{
            SourcePublication, decide_source_snapshot, encode_source_publication,
            source_publication_signing_input,
        },
    },
    encoding::CborWriter,
};

#[test]
fn a_signed_stream_entry_rejects_the_entire_source_bound_poll() {
    let vectors = support::vectors::load("source-selection");
    let fixture = |name: &str| {
        vectors
            .iter()
            .find(|v| v.name() == name)
            .unwrap()
            .hex("bytes")
    };
    let valid_raw = fixture("current-b");
    let valid = SourcePublication::decode(&valid_raw).unwrap();
    let stream_raw = fixture("source-public-edge");
    let stream = SourcePublication::decode(&stream_raw).unwrap();
    let pending = DeliveryContext::Snapshot {
        boot_nonce: [4; 16],
        attempt_counter: 1,
        correlation: [5; 16],
    };
    let binding = &valid.binding().binding;
    let scopes = [PublicationScope {
        served_realm: binding.served_realm,
        scope: &binding.scope,
    }];
    let expected = PublicationExpectation {
        issuer: binding.nsd,
        recipient: binding.recipient,
        scopes: &scopes,
        channel: PublicationChannel::Snapshot,
        now_seconds: 150,
    };
    let snapshot = |entries: &[&[u8]]| {
        let mut out = CborWriter::default();
        out.array(2).uint(1).array(entries.len());
        for entry in entries {
            out.bytes(entry);
        }
        out.into_bytes()
    };
    let good = snapshot(&[&valid_raw]);
    let decisions = decide_source_snapshot(&[], &good, binding, &pending, &expected).unwrap();
    assert!(matches!(
        decisions.as_slice(),
        [PublicationDecision::Replace(_)]
    ));

    // The actual authority signs a snapshot delivery association for a valid
    // stream-owned event. Both signatures remain valid; only ownership is wrong.
    let event = stream.event().unwrap();
    assert_eq!(event.content().channel, PublicationChannel::Stream);
    let key = SigningKey::from_bytes(&[2; 32]);
    assert_eq!(key.verifying_key().as_bytes(), binding.nsd.as_bytes());
    let message =
        source_publication_signing_input(valid.binding(), &pending, event.canonical()).unwrap();
    let signature = key.sign(&message).to_bytes();
    let wrong = encode_source_publication(valid.binding(), &pending, event.canonical(), &signature)
        .unwrap();
    let mixed = snapshot(&[&wrong, &valid_raw]);
    let result = decide_source_snapshot(&[], &mixed, binding, &pending, &expected);
    assert!(
        result.is_err(),
        "wrong-channel poll exposed actions: {result:?}"
    );
}
