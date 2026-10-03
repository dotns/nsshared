#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! NS rendezvous v2 (`/quick/v2`) messages (docs ns/rendezvous.md, ns/quick-v2.md §7, §10).
//!
//! A pure library: JSON transport, capability tokens, actor authentication, the relay
//! directory, mailbox payloads, the node registry and pairing payloads. It performs no
//! I/O and reads no clock or randomness; callers pass `now`, ids, digits, nonces and keys.

pub mod auth;
pub mod capability;
pub mod directory;
pub mod error;
pub mod limits;
pub mod message;
pub mod pairing;
pub mod phase;
pub mod region;
pub mod registry;
pub mod transport;

mod crypto;
