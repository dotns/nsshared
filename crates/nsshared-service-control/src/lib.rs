#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Pure wire types and deterministic CBOR for M6 private service control.
//! Authentication and durable state transitions belong to the caller.

pub mod cbor;
pub mod contract;
pub mod message;
mod message_codec;
pub mod snapshot;

pub use cbor::{CborError, Value, decode_canonical, encode_canonical};
pub use contract::*;
pub use message::*;
pub use snapshot::*;
