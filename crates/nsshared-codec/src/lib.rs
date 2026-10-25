#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! NS shared encodings. Pure: no I/O and no cryptography.
//!
//! | Module | Contents |
//! | --- | --- |
//! | [`cbor`] | Canonical CBOR: the NS array profile ([`cbor::CborReader`], [`cbor::CborWriter`]) and the M6 value profile ([`cbor::value`]) |
//! | [`base64`] | Strict unpadded base64url and padded standard base64 |
//!
//! Every public item has one path, inside its module.

pub mod base64;
pub mod cbor;
