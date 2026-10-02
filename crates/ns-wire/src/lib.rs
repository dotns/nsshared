#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Synchronous NS protocol v2 wire, derivation and validation primitives (docs ns/quick-v2.md).

mod alias;
mod codec;
mod constants;
mod identifier;
mod identity;
mod record;
mod relay;

pub use alias::*;
pub use codec::CborError;
pub use constants::*;
pub use identifier::*;
pub use identity::*;
pub use record::*;
pub use relay::*;
