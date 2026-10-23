#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod support;
use nsshared_proto::{
    account::{
        PublicationChannel, PublicationDecision, PublicationExpectation, PublicationScope,
        control_exchange::{
            CONFIG_PUBLICATION_EVENT, CONFIG_STREAM_REQUEST_PARAM, MAX_PUBLICATION_BYTES,
            MAX_PUBLICATION_ENCODED_BYTES, MAX_PUBLICATION_FRAMED_BYTES,
        },
        source_binding::{DeliveryContext, SignedSourceBinding},
        source_publication::{SourcePublication, decide_source_publication},
    },
    encoding::{decode_base64url, encode_base64url},
};

#[test]
fn control_candidate_publications_stream_boundaries() {
    // Calibrate Base64 encoding and complete frame counting independently.
    assert_eq!(encode_base64url(&[251, 255]), "-_8");
    assert_eq!(b"event: config-envelope.v1\r\ndata: -_8\r\n\r\n".len(), 40);
    assert_eq!(CONFIG_PUBLICATION_EVENT, "config-envelope.v1");
    assert_eq!(CONFIG_STREAM_REQUEST_PARAM, "request");
    assert_eq!(MAX_PUBLICATION_BYTES, 1_048_576);
    assert_eq!(MAX_PUBLICATION_ENCODED_BYTES, 1_398_102);
    assert_eq!(MAX_PUBLICATION_FRAMED_BYTES, 1_398_139);
    for v in support::vectors::load("publication-delivery") {
        let bytes = v.hex("bytes");
        let frame = v.hex("frame");
        let source = SignedSourceBinding::decode(&v.hex("binding")).unwrap();
        let pending = DeliveryContext::decode(&v.hex("context")).unwrap();
        let scopes = [PublicationScope {
            served_realm: source.binding.served_realm,
            scope: &source.binding.scope,
        }];
        let expected = PublicationExpectation {
            issuer: source.binding.nsd,
            recipient: source.binding.recipient,
            scopes: &scopes,
            channel: PublicationChannel::Stream,
            now_seconds: 100,
        };
        let ending = if v.name().starts_with("lf-") {
            "\n"
        } else {
            "\r\n"
        };
        let encoded = encode_base64url(&bytes);
        assert_eq!(
            frame,
            format!("event: {CONFIG_PUBLICATION_EVENT}{ending}data: {encoded}{ending}{ending}")
                .as_bytes()
        );
        assert_eq!(frame.len() as u64, v.u64("framed_length"));
        assert_eq!(encoded.len() as u64, v.u64("encoded_length"));
        let decision =
            decide_source_publication(&[], Some(&bytes), &source.binding, &pending, &expected)
                .unwrap();
        if v.get("decision") == "terminate" {
            if ending == "\r\n" {
                assert!(frame.len() > MAX_PUBLICATION_FRAMED_BYTES);
            } else {
                assert!(frame.len() <= MAX_PUBLICATION_FRAMED_BYTES);
            }
            assert!(bytes.len() > MAX_PUBLICATION_BYTES);
            assert!(decode_base64url(&encoded, MAX_PUBLICATION_BYTES).is_err());
            assert!(matches!(decision, PublicationDecision::TerminateStream));
        } else {
            assert_eq!(bytes.len(), MAX_PUBLICATION_BYTES);
            assert_eq!(
                frame.len(),
                MAX_PUBLICATION_FRAMED_BYTES - if ending == "\n" { 3 } else { 0 }
            );
            assert_eq!(
                decode_base64url(&encoded, MAX_PUBLICATION_BYTES).unwrap(),
                bytes
            );
            SourcePublication::decode(&bytes).unwrap();
            assert!(matches!(decision, PublicationDecision::Replace(_)));
        }
    }
}
