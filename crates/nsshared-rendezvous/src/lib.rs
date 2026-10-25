#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! NS rendezvous service `/rendezvous/v1` messages (docs ns/rendezvous.md, ns/quick-v2.md
//! §7).
//!
//! JSON transport, capability tokens, actor authentication, the relay directory, mailbox
//! payloads and phase rules, and the node registry. Pure: no I/O, clock or randomness;
//! callers pass `now`, ids, digits, nonces and keys. Every public item has one path, inside
//! its module; registry shard constants are in [`constants`].

pub mod auth;
pub mod capability;
pub mod constants;
pub mod directory;
pub mod error;
pub mod limits;
pub mod message;
pub mod phase;
pub mod registry;
pub mod transport;

mod crypto;
