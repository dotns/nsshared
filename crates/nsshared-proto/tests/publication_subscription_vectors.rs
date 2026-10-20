#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod support;
use nsshared_proto::{
    IdentityKey,
    account::{
        BootstrapEnvelope, EnvelopeDirection, EnvelopeExpectation, EnvelopePins,
        control_exchange::{CONFIG_STREAM, CONFIG_STREAM_PATH},
        publication_subscription::PublicationSubscriptionRequest,
    },
};

#[test]
fn publication_subscription_vectors() {
    let vectors = support::vectors::parse(include_str!(
        "fixtures/vectors/publication-subscription.vec"
    ));
    for v in vectors
        .iter()
        .filter(|v| !v.get("decision").starts_with("signed"))
    {
        let bytes = v.hex("bytes");
        let result = PublicationSubscriptionRequest::decode(&bytes);
        assert_eq!(
            result.is_ok(),
            v.get("decision") == "accepted",
            "{}: {result:?}",
            v.name()
        );
        if let Ok(value) = result {
            assert_eq!(value.canonical().unwrap(), bytes, "{}", v.name());
            assert!(value.scopes.iter().all(|s| s.recipient == value.subscriber));
            if v.name() == "populated" {
                assert_eq!(value.scopes.len(), 2);
                assert_eq!(value.scopes[0].served_realm, "realm-a");
                assert_eq!(value.scopes[0].scope, "edge");
                assert_eq!(value.capabilities, ["node.control", "public.edge"]);
                assert_eq!(value.public_ingress, [0]);
                assert_eq!(value.boot_nonce, [3; 16]);
                assert_eq!(value.attempt_counter, 1);
                let mut wrong = value.clone();
                wrong.scopes[0].recipient = wrong.scopes[0].issuer;
                assert!(wrong.canonical().is_err());
            }
        }
    }
}

#[test]
fn publication_subscription_signed_carrier() {
    let vectors = support::vectors::parse(include_str!(
        "fixtures/vectors/publication-subscription.vec"
    ));
    for v in vectors
        .iter()
        .filter(|v| v.get("decision").starts_with("signed"))
    {
        let mut envelope = BootstrapEnvelope::decode(&v.hex("bytes")).unwrap();
        assert_eq!(envelope.signing_input().unwrap(), v.hex("signing_input"));
        let pins = EnvelopePins::intersect(&[v.get("pin").into()], &[]).unwrap();
        let subscriber = IdentityKey::from_bytes(&v.hex_array("subscriber")).unwrap();
        let issuer = IdentityKey::from_bytes(&v.hex_array("issuer")).unwrap();
        let expected = EnvelopeExpectation {
            pins: &pins,
            direction: EnvelopeDirection::Request,
            recipient: issuer,
            kind: CONFIG_STREAM,
            now_seconds: 100,
            previous_acceptance_seconds: None,
        };
        let result = PublicationSubscriptionRequest::from_envelope(&envelope, &expected);
        assert_eq!(
            result.is_ok(),
            v.get("decision") == "signed",
            "{}: {result:?}",
            v.name()
        );
        if let Ok(request) = result {
            assert_eq!(request.subscriber, subscriber);
            assert_eq!(request.scopes[0].issuer, issuer);
            let replay = EnvelopeExpectation {
                previous_acceptance_seconds: Some(100),
                ..expected
            };
            assert!(PublicationSubscriptionRequest::from_envelope(&envelope, &replay).is_err());
            envelope.signature[0] ^= 1;
            assert!(PublicationSubscriptionRequest::from_envelope(&envelope, &expected).is_err());
        }
    }
    assert_eq!(CONFIG_STREAM, "config.stream");
    assert_eq!(CONFIG_STREAM_PATH, "/api/v1/config/stream");
}
