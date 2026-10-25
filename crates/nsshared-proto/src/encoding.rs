//! Shared text encodings: strict unpadded base64url (identity keys, node records in DNS,
//! every byte string of the rendezvous JSON, rendezvous §3) and strict padded standard
//! base64 (WireGuard keys, as `wg` prints them), and canonical CBOR (quick-v2 §12.1),
//! [`CborReader`] / [`CborWriter`]. Defined in `nsshared-codec`.

pub use nsshared_codec::base64::{
    Base64Error, decode_base64, decode_base64url, encode_base64, encode_base64url,
};
pub use nsshared_codec::cbor::{CborError, CborReader, CborWriter};
