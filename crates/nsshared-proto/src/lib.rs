#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! NS shared protocols: identities and keys, node records, relay packets v2 (docs
//! ns/quick-v2.md) and the rendezvous service `/rendezvous/v1` ([`rendezvous`], docs
//! ns/rendezvous.md), plus the shared encodings ([`encoding`], canonical CBOR).
//!
//! Pure: no I/O, async runtime or TLS. Typed keys ([`IdentityKey`], [`IdentitySecret`],
//! [`WgSessionKey`], [`WgSessionSecret`]) carry key generation, the canonical key encodings
//! and the identity derivations.

mod codec;
mod constants;
pub mod encoding;
mod identifier;
mod identity;
mod keys;
mod record;
mod relay;
pub mod rendezvous;

pub use codec::{CborError, CborReader, CborWriter};
pub use constants::*;
pub use identifier::*;
pub use identity::*;
pub use keys::*;
pub use record::*;
pub use relay::*;
