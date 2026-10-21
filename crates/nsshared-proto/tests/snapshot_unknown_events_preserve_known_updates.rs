#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ed25519_dalek::{Signer as _, SigningKey};
use nsshared_proto::{
    IdentityKey,
    account::{
        BootstrapEnvelope, EnvelopeDirection, EnvelopeExpectation, EnvelopePins,
        PUBLICATION_SIGNATURE_DOMAIN, PublicationChannel, PublicationDecision,
        PublicationExpectation, PublicationScope, control_exchange::CONFIG_SNAPSHOT,
        decide_publication_snapshot, publication_snapshot_request::PublicationSnapshotRequest,
        publication_subscription::SubscriptionScope,
    },
    encoding::{CborWriter, encode_base64url},
};
use sha2::{Digest as _, Sha256};

fn event(signer: &SigningKey, recipient: IdentityKey, family: u64, kind: &str) -> Vec<u8> {
    let mut content = CborWriter::default();
    content
        .array(14)
        .uint(1)
        .bytes(signer.verifying_key().as_bytes())
        .bytes(recipient.as_bytes())
        .text("030C1G60R30C1G60R30C1G60R3")
        .text("nodes")
        .uint(family)
        .text(kind)
        .uint(1)
        .boolean(true)
        .uint(8)
        .uint(100)
        .uint(200)
        .uint(0)
        .bytes(b"fixture-data");
    let content = content.into_bytes();
    let mut message = PUBLICATION_SIGNATURE_DOMAIN.to_vec();
    message.extend_from_slice(&content);
    let mut wire = CborWriter::default();
    wire.array(2)
        .bytes(&content)
        .bytes(&signer.sign(&message).to_bytes());
    wire.into_bytes()
}

fn check_extension(family: u64, kind: &str) {
    let signer = SigningKey::from_bytes(&[2; 32]);
    let issuer = IdentityKey::from_bytes(signer.verifying_key().as_bytes()).unwrap();
    let subscriber =
        IdentityKey::from_bytes(SigningKey::from_bytes(&[1; 32]).verifying_key().as_bytes())
            .unwrap();
    let pending = PublicationSnapshotRequest {
        subscriber,
        scopes: vec![SubscriptionScope {
            issuer,
            recipient: subscriber,
            served_realm: "030C1G60R30C1G60R30C1G60R3".parse().unwrap(),
            scope: "nodes".into(),
        }],
        boot_nonce: [3; 16],
        attempt_counter: 1,
        correlation: [5; 16],
    };
    let scopes = [PublicationScope {
        served_realm: "030C1G60R30C1G60R30C1G60R3".parse().unwrap(),
        scope: "nodes",
    }];
    let expected = PublicationExpectation {
        issuer,
        recipient: subscriber,
        scopes: &scopes,
        channel: PublicationChannel::Snapshot,
        now_seconds: 100,
    };
    let x = encode_base64url(issuer.as_bytes());
    let jwk = format!("{{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"{x}\"}}");
    let pin = encode_base64url(&Sha256::digest(jwk.as_bytes()));
    let pins = EnvelopePins::intersect(&[pin], &[]).unwrap();
    let carrier = EnvelopeExpectation {
        pins: &pins,
        direction: EnvelopeDirection::Response,
        recipient: subscriber,
        kind: CONFIG_SNAPSHOT,
        now_seconds: 100,
        previous_acceptance_seconds: None,
    };
    let known = event(&signer, subscriber, 11, "node-l3");
    let unknown = event(&signer, subscriber, family, kind);
    let mut snapshot = CborWriter::default();
    snapshot
        .array(2)
        .uint(1)
        .array(2)
        .bytes(&known)
        .bytes(&unknown);
    let snapshot = snapshot.into_bytes();

    // Establish the existing snapshot contract on the exact signed bytes.
    let baseline = decide_publication_snapshot(&[], &snapshot, &expected).unwrap();
    let mut decisions = baseline.decisions();
    assert!(matches!(
        decisions.next(),
        Some(PublicationDecision::Replace(_))
    ));
    assert!(matches!(
        decisions.next(),
        Some(PublicationDecision::UnknownKind(_))
    ));
    assert!(decisions.next().is_none());
    drop(decisions);

    let mut envelope = BootstrapEnvelope {
        direction: EnvelopeDirection::Response,
        signer: issuer,
        recipient: Some(subscriber),
        kind: CONFIG_SNAPSHOT.into(),
        unix_seconds: 100,
        nonce: pending.correlation,
        payload: snapshot,
        signature: [0; 64],
    };
    let mut control = envelope.clone();
    let mut known_only = CborWriter::default();
    known_only.array(2).uint(1).array(1).bytes(&known);
    control.payload = known_only.into_bytes();
    control.signature = signer.sign(&control.signing_input().unwrap()).to_bytes();
    assert!(pending.response(&control, &carrier, &[], &expected).is_ok());
    let mut invalid_signature = control.clone();
    invalid_signature.signature[0] ^= 1;
    assert!(
        pending
            .response(&invalid_signature, &carrier, &[], &expected)
            .is_err()
    );

    envelope.signature = signer.sign(&envelope.signing_input().unwrap()).to_bytes();
    envelope.verify(&carrier).unwrap();
    let result = pending.response(&envelope, &carrier, &[], &expected);
    assert!(
        result.is_ok(),
        "authenticated extension must preserve known updates: {result:?}"
    );
}

#[test]
fn snapshot_poll_keeps_known_update_beside_unknown_kind() {
    check_extension(11, "zz-future-kind");
}

#[test]
fn snapshot_poll_keeps_known_update_beside_unknown_family() {
    check_extension(99, "future-kind");
}
