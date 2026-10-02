#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Synchronous NS protocol v2 wire, derivation and validation primitives (docs ns/quick-v2.md).

mod alias;
mod codec;
mod constants;
mod control;
mod identifier;
mod identity;
mod lan;
mod record;
mod region;
mod relay;

pub use alias::*;
pub use codec::CborError;
pub use constants::*;
pub use control::*;
pub use identifier::*;
pub use identity::*;
pub use lan::*;
pub use record::*;
pub use region::*;
pub use relay::*;
