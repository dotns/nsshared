#![allow(clippy::unwrap_used)]
mod support;

use nsshared_proto::account::publication_subscription::PublicationSubscriptionRequest;

fn check_identifier(field: &str) {
    let vectors =
        support::vectors::parse(include_str!("fixtures/vectors/service-control-carrier.vec"));
    let vector = vectors
        .iter()
        .find(|v| v.name() == "subscription-4")
        .unwrap();
    let bytes = vector.hex("bytes");
    let original = PublicationSubscriptionRequest::decode(&bytes).unwrap();
    assert_eq!(original.canonical().unwrap(), bytes);

    {
        let mut value = original.clone();
        let binding = value.service_control.as_mut().unwrap();
        let id = if field == "runtime_id" {
            &mut binding.runtime_id
        } else {
            &mut binding.session_request_id
        };
        let old = *id;
        *id = [0; 16];
        // Replace the independently encoded field without using the encoder under test.
        let offset = bytes.windows(16).position(|window| window == old).unwrap();
        let mut invalid = bytes.clone();
        invalid[offset..offset + 16].fill(0);
        assert!(
            PublicationSubscriptionRequest::decode(&invalid).is_err(),
            "a subscription accepted all-zero {field}, which cannot identify an admitted M6 session"
        );
        assert!(value.canonical().is_err());
    }
}

#[test]
fn bound_subscription_rejects_zero_runtime_identifier() {
    check_identifier("runtime_id");
}

#[test]
fn bound_subscription_rejects_zero_session_request_identifier() {
    check_identifier("session_request_id");
}
