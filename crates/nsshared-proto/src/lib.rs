#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! NS shared protocols (docs ns/quick-v2.md, ns/rendezvous.md).
//!
//! Deprecated facade: every module keeps its 0.6 path and re-exports the crate that now
//! defines it. New code depends on the defining crate; this facade is removed in a later
//! major release.
//!
//! | Module | Contents | Defined in |
//! | --- | --- | --- |
//! | [`keys`] | Typed identity and WireGuard keys: generation, canonical encodings, derivations | `nsshared_identity::keys` |
//! | [`identity`] | Raw identities, node ID, address group, `node6` / `node4`, address conflicts | `nsshared_identity::identity` |
//! | [`node_control`] | Node-control v2 messages, ACK hashes and endpoint selection | `nsshared_control::node_control` |
//! | [`record`] | `NodeRecord`, its signature and the §3.3 ordering / conflict rules | `nsshared_identity::record` |
//! | [`relay`] | Relay identifiers and relay packets v2; budget defaults in [`relay::budget`] | `nsshared_relay`, `nsshared_identity::relay_id` |
//! | [`discovery`] | Public DNS discovery of records: TXT encoding and answer checks | `nsshared_identity::discovery` |
//! | [`rendezvous`] | The `/rendezvous/v1` messages: transport, capabilities, `hello`, directory, mailbox, registry | `nsshared_rendezvous` |
//! | [`encoding`] | Strict base64url / base64 and canonical CBOR | `nsshared_codec` |
//! | [`constants`] | Protocol constants, derivation labels and signature contexts | `constants` of `nsshared_identity`, `nsshared_relay`, `nsshared_rendezvous` |
//!
//! The most used types are also re-exported at the crate root. Pure: no I/O, async
//! runtime or TLS; callers pass time, randomness and keys. The account contracts are not
//! re-exported here; they are `nsshared_control::account`, available unconditionally
//! and covered by semver from v0.8.0.

pub mod constants;
pub mod encoding;
pub mod relay;

pub use identity::NodeId;
pub use keys::{IdentityKey, IdentitySecret, WgSessionKey, WgSessionSecret};
pub use nsshared_control::node_control;
pub use nsshared_identity::realm::{RealmId, RealmIdError};
pub use nsshared_identity::{discovery, identity, keys, record};
pub use nsshared_rendezvous as rendezvous;
pub use record::{NetworkNodeRecord, NetworkRecordKey, NodeRecord, derive_network_identity};
pub use relay::RelayId;
