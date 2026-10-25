#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! NS shared identities (docs ns/quick-v2.md §2, §3, §11.2).
//!
//! | Module | Contents |
//! | --- | --- |
//! | [`keys`] | Typed identity and WireGuard keys: generation, canonical encodings, derivations |
//! | [`identity`] | Raw identities, node ID, address group, `node6` / `node4`, address conflicts |
//! | [`realm`] | Canonical membership realm identifiers |
//! | [`relay_id`] | Canonical relay identifiers `host:port` |
//! | [`record`] | `NodeRecord`, its signature and the §3.3 ordering / conflict rules |
//! | [`discovery`] | Public DNS discovery of records: TXT encoding and answer checks |
//! | [`constants`] | Identity and record constants, derivation labels and the record signature context |
//!
//! Every public item has one path, inside its module. Pure: no I/O; callers pass time,
//! randomness and keys.

pub mod constants;
pub mod discovery;
pub mod identity;
pub mod keys;
pub mod realm;
pub mod record;
pub mod relay_id;
