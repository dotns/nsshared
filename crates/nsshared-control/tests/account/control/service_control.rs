#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use nsshared_control::service::Message;
use nsshared_control::{
    account::control::BootstrapEnvelope, account::control::EnvelopeDirection,
    account::control::EnvelopeExpectation, account::control::EnvelopePins,
    account::control::PendingRequest, account::control::SERVICE_CONTROL,
    account::control::StreamExpectation, account::control::UnaryReply,
    account::control::validate_reverse_result, account::control::validate_stream_event,
    account::control::validate_unary_reply, account::control::validate_unary_request,
    account::publication::PublicationSubscriptionRequest,
};
use nsshared_identity::keys::IdentityKey;

#[test]
fn contribution_network_sessions() {
    let vectors = nsshared_testkit::vectors!("account/control/service-control");
    for v in &vectors {
        let node = IdentityKey::from_bytes(&v.hex_array("node")).unwrap();
        let authority = IdentityKey::from_bytes(&v.hex_array("authority")).unwrap();
        let node_pins = EnvelopePins::intersect(&[v.get("node_pin").into()], &[]).unwrap();
        let authority_pins =
            EnvelopePins::intersect(&[v.get("authority_pin").into()], &[]).unwrap();
        let request_expected = EnvelopeExpectation {
            pins: &node_pins,
            direction: EnvelopeDirection::Request,
            recipient: authority,
            kind: SERVICE_CONTROL,
            now_seconds: 100,
            previous_acceptance_seconds: None,
        };
        let expected = EnvelopeExpectation {
            pins: &authority_pins,
            direction: EnvelopeDirection::Response,
            recipient: node,
            kind: SERVICE_CONTROL,
            now_seconds: 100,
            previous_acceptance_seconds: None,
        };
        let bytes = v.hex("bytes");
        let accepted = v.get("decision") == "accepted";
        match v.get("mode") {
            "subscription" => {
                let value = PublicationSubscriptionRequest::decode(&bytes).unwrap();
                assert_eq!(value.canonical().unwrap(), bytes);
                assert!(value.service_control.is_some());
            }
            "request" => {
                if v.opt("message_valid") == Some("yes") {
                    let envelope = BootstrapEnvelope::decode(&bytes).unwrap();
                    Message::decode(&envelope.payload).unwrap();
                }
                let result = BootstrapEnvelope::decode(&bytes)
                    .ok()
                    .and_then(|e| validate_unary_request(&e, &request_expected).ok());
                assert_eq!(result.is_some(), accepted, "{}: {result:?}", v.name());
            }
            "reply" => {
                let request = BootstrapEnvelope::decode(&v.hex("request")).unwrap();
                let pending = PendingRequest::from_envelope(&request, &request_expected)
                    .unwrap_or_else(|e| panic!("{} request: {e:?}", v.name()));
                assert_eq!(
                    pending.message().encode().unwrap(),
                    request.payload,
                    "{}",
                    v.name()
                );
                let envelope = BootstrapEnvelope::decode(&bytes).unwrap();
                let result = validate_unary_reply(&envelope, &expected, &pending);
                assert_eq!(result.is_ok(), accepted, "{}: {result:?}", v.name());
                if let Ok(reply) = result {
                    match reply {
                        UnaryReply::Receipt => assert_eq!(v.get("outcome"), "receipt"),
                        UnaryReply::Failure(message) => {
                            assert_eq!(v.get("outcome"), "failure");
                            assert_eq!(message.encode().unwrap(), envelope.payload);
                        }
                        UnaryReply::Message(message) => {
                            assert_eq!(v.get("outcome"), "message");
                            assert_eq!(message.encode().unwrap(), envelope.payload);
                        }
                    }
                    let replay = EnvelopeExpectation {
                        previous_acceptance_seconds: Some(100),
                        ..expected
                    };
                    assert!(validate_unary_reply(&envelope, &replay, &pending).is_err());
                    let mut invalid = envelope.clone();
                    invalid.signature[0] ^= 1;
                    assert!(validate_unary_reply(&invalid, &expected, &pending).is_err());
                }
            }
            "event" => {
                let subscription =
                    PublicationSubscriptionRequest::decode(&v.hex("binding")).unwrap();
                let stream = StreamExpectation {
                    authority,
                    subject: node,
                    binding: subscription.service_control.as_ref().unwrap(),
                };
                let data = URL_SAFE_NO_PAD.encode(&bytes);
                if let Some(independent) = v.opt("data") {
                    assert_eq!(data, independent);
                }
                let result = validate_stream_event(SERVICE_CONTROL, &data, &expected, &stream);
                assert_eq!(result.is_ok(), accepted, "{}: {result:?}", v.name());
                if let Ok(message) = result {
                    for runtime in [true, false] {
                        let mut invalid_binding = stream.binding.clone();
                        if runtime {
                            invalid_binding.runtime_id = [0; 16];
                        } else {
                            invalid_binding.session_request_id = [0; 16];
                        }
                        let invalid_stream = StreamExpectation {
                            binding: &invalid_binding,
                            ..stream
                        };
                        assert!(
                            validate_stream_event(
                                SERVICE_CONTROL,
                                &data,
                                &expected,
                                &invalid_stream
                            )
                            .is_err()
                        );
                    }
                    assert_eq!(
                        message.encode().unwrap(),
                        BootstrapEnvelope::decode(&bytes).unwrap().payload
                    );
                    assert!(
                        validate_stream_event("config.stream", &data, &expected, &stream).is_err()
                    );
                    assert!(
                        validate_stream_event(
                            SERVICE_CONTROL,
                            &(data.clone() + "="),
                            &expected,
                            &stream
                        )
                        .is_err()
                    );
                    let replay = EnvelopeExpectation {
                        previous_acceptance_seconds: Some(100),
                        ..expected
                    };
                    assert!(
                        validate_stream_event(SERVICE_CONTROL, &data, &replay, &stream).is_err()
                    );
                }
            }
            "reverse" => {
                let operation = Message::decode(&v.hex("operation")).unwrap();
                let result = Message::decode(&bytes).unwrap();
                assert_eq!(
                    validate_reverse_result(&operation, &result).is_ok(),
                    accepted,
                    "{}",
                    v.name()
                );
            }
            other => panic!("unknown mode {other}"),
        }
    }
}
