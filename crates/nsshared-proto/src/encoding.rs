//! Shared text encodings: strict unpadded base64url (identity keys, node records in DNS,
//! every byte string of the rendezvous JSON, rendezvous §3) and strict padded standard
//! base64 (WireGuard keys, as `wg` prints them).
//!
//! Decoding is canonical: padding where it is not expected, missing padding where it is,
//! other alphabets and non-zero trailing bits are rejected, so every byte string has
//! exactly one text form. Canonical CBOR (quick-v2 §12.1) is [`CborReader`] / [`CborWriter`].

use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use thiserror::Error;

pub use crate::codec::{CborError, CborReader, CborWriter};

/// A text that is not strict base64 of an accepted length.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("invalid base64 byte string")]
pub struct Base64Error;

/// Encodes bytes as unpadded base64url.
#[must_use]
pub fn encode_base64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Strictly decodes unpadded base64url of at most `maximum` decoded bytes; the length is
/// checked before decoding.
///
/// # Errors
///
/// [`Base64Error`] when the text is too long or not strict unpadded base64url.
pub fn decode_base64url(text: &str, maximum: usize) -> Result<Vec<u8>, Base64Error> {
    if text.len() > maximum.saturating_mul(4).div_ceil(3) {
        return Err(Base64Error);
    }
    let bytes = URL_SAFE_NO_PAD.decode(text).map_err(|_| Base64Error)?;
    if bytes.len() > maximum {
        return Err(Base64Error);
    }
    Ok(bytes)
}

/// Encodes bytes as padded standard base64.
#[must_use]
pub fn encode_base64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

/// Strictly decodes padded standard base64 of at most `maximum` decoded bytes; the length
/// is checked before decoding.
///
/// # Errors
///
/// [`Base64Error`] when the text is too long or not strict padded standard base64.
pub fn decode_base64(text: &str, maximum: usize) -> Result<Vec<u8>, Base64Error> {
    if text.len() > maximum.div_ceil(3).saturating_mul(4) {
        return Err(Base64Error);
    }
    let bytes = STANDARD.decode(text).map_err(|_| Base64Error)?;
    if bytes.len() > maximum {
        return Err(Base64Error);
    }
    Ok(bytes)
}
