#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Synchronous NS protocol v2 wire, derivation and validation primitives (docs ns/quick-v2.md).

mod alias;
mod constants;
mod identity;

pub use alias::*;
pub use constants::*;
pub use identity::*;
