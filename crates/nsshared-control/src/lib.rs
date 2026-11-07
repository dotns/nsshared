#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! NS shared control contracts.
//!
//! | Module | Contents |
//! | --- | --- |
//! | [`service`] | M6 private service control: wire types, digests and snapshots |
//! | [`node_control`] | Node-control v2 messages, ACK hashes and endpoint selection |
//! | [`account`] | Account payload contracts by layer and family |
//!
//! `account` is part of the public API and covered by semver from v0.8.0.
//! All modules are available unconditionally; `service` and `node_control` do not
//! depend on `account`.
//!
//! Every public item has one path, inside its module. Pure: no I/O, runtime state or
//! clock; callers pass time, randomness, keys and authenticated context.

pub mod account;
pub mod node_control;
pub mod service;
