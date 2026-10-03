#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Synchronous NS protocol v2 wire, derivation and validation primitives (docs ns/quick-v2.md).
//!
//! Typed keys ([`IdentityKey`], [`IdentitySecret`], [`WgSessionKey`], [`WgSessionSecret`]) carry
//! the canonical key encodings and the identity derivations; their module docs list which
//! ns `NodeIdentity` helpers they replace ("Replaces in ns").

mod alias;
mod codec;
mod constants;
mod control;
mod identifier;
mod identity;
mod keys;
mod lan;
mod record;
mod relay;

pub use alias::*;
pub use codec::{CborError, CborReader, CborWriter};
pub use constants::*;
pub use control::*;
pub use identifier::*;
pub use identity::*;
pub use keys::*;
pub use lan::*;
pub use record::*;
pub use relay::*;
