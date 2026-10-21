#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! NS shared protocols (docs ns/quick-v2.md, ns/rendezvous.md).
//!
//! | Module | Contents |
//! | --- | --- |
//! | [`keys`] | Typed identity and WireGuard keys: generation, canonical encodings, derivations |
//! | [`identity`] | Raw identities, node ID, address group, `node6` / `node4`, address conflicts |
//! | [`node_control`] | Node-control v2 messages, ACK hashes and endpoint selection |
//! | [`record`] | `NodeRecord`, its signature and the §3.3 ordering / conflict rules |
//! | [`relay`] | Relay identifiers and relay packets v2; budget defaults in [`relay::budget`] |
//! | [`discovery`] | Public DNS discovery of records: TXT encoding and answer checks |
//! | [`rendezvous`] | The `/rendezvous/v1` messages: transport, capabilities, `hello`, directory, mailbox, registry |
//! | [`encoding`] | Strict base64url / base64 and canonical CBOR |
//! | [`constants`] | Protocol constants, derivation labels and signature contexts |
//!
//! The most used types are also re-exported at the crate root. Pure: no I/O, async
//! runtime or TLS; callers pass time, randomness and keys.

/// Pure L8 account payload candidate contracts and admission validators.
pub mod account;
mod codec;
pub mod constants;
pub mod discovery;
pub mod encoding;
mod identifier;
pub mod identity;
pub mod keys;
pub mod node_control;
mod realm_id;
pub mod record;
pub mod relay;
pub mod rendezvous;

pub use identity::NodeId;
pub use keys::{IdentityKey, IdentitySecret, WgSessionKey, WgSessionSecret};
pub use realm_id::{RealmId, RealmIdError};
pub use record::NodeRecord;
pub use relay::RelayId;
