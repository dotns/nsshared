#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use nsshared_codec::{base64::decode_base64url, base64::encode_base64url};
use nsshared_control::{
    account::control::CONFIG_PUBLICATION_EVENT, account::control::CONFIG_STREAM_REQUEST_PARAM,
    account::control::MAX_PUBLICATION_BYTES, account::control::MAX_PUBLICATION_ENCODED_BYTES,
    account::control::MAX_PUBLICATION_FRAMED_BYTES, account::publication::DeliveryContext,
    account::publication::PublicationChannel, account::publication::PublicationDecision,
    account::publication::PublicationExpectation, account::publication::PublicationScope,
    account::publication::SignedSourceBinding, account::publication::SourcePublication,
    account::publication::decide_source_publication,
};

#[test]
fn control_publications_stream_boundaries() {
    // Calibrate Base64 encoding and complete frame counting independently.
    assert_eq!(encode_base64url(&[251, 255]), "-_8");
    assert_eq!(b"event: config-envelope.v1\r\ndata: -_8\r\n\r\n".len(), 40);
    assert_eq!(CONFIG_PUBLICATION_EVENT, "config-envelope.v1");
    assert_eq!(CONFIG_STREAM_REQUEST_PARAM, "request");
    assert_eq!(MAX_PUBLICATION_BYTES, 1_048_576);
    assert_eq!(MAX_PUBLICATION_ENCODED_BYTES, 1_398_102);
    assert_eq!(MAX_PUBLICATION_FRAMED_BYTES, 1_398_139);
    for v in nsshared_testkit::vectors!("account/publication/delivery") {
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
