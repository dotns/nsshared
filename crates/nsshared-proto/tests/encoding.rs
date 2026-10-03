//! Shared text encodings: strict base64url and padded standard base64.

use nsshared_proto::encoding::{
    Base64Error, decode_base64, decode_base64url, encode_base64, encode_base64url,
};
use proptest::prelude::*;

#[test]
fn base64url_is_unpadded_and_url_safe() {
    assert_eq!(encode_base64url(&[0xff, 0xef]), "_-8");
    assert_eq!(decode_base64url("_-8", 2), Ok(vec![0xff, 0xef]));
    assert_eq!(decode_base64url("", 0), Ok(Vec::new()));
}

#[test]
fn base64url_rejects_non_canonical_text() {
    for bad in ["_-8=", "/+8", "_-9", "A", "AQID AQ"] {
        assert_eq!(decode_base64url(bad, 16), Err(Base64Error), "{bad}");
    }
    assert_eq!(decode_base64url("AQID", 2), Err(Base64Error));
    assert_eq!(decode_base64url(&"A".repeat(100), 16), Err(Base64Error));
}

#[test]
fn base64_is_padded_standard() {
    assert_eq!(encode_base64(&[0xff, 0xef]), "/+8=");
    assert_eq!(decode_base64("/+8=", 2), Ok(vec![0xff, 0xef]));
    for bad in ["/+8", "_-8=", "/+9=", "/+8==", "AQID AQ=="] {
        assert_eq!(decode_base64(bad, 16), Err(Base64Error), "{bad}");
    }
    assert_eq!(decode_base64("AQID", 2), Err(Base64Error));
}

proptest! {
    #[test]
    fn round_trips(bytes in proptest::collection::vec(any::<u8>(), 0..96)) {
        prop_assert_eq!(decode_base64url(&encode_base64url(&bytes), bytes.len()), Ok(bytes.clone()));
        prop_assert_eq!(decode_base64(&encode_base64(&bytes), bytes.len()), Ok(bytes));
    }
}
