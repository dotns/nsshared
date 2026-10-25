#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! NS shared control contracts.
//!
//! | Module | Contents |
//! | --- | --- |
//! | [`service`] | M6 private service control: wire types, digests and snapshots |
//! | [`node_control`] | Node-control v2 messages, ACK hashes and endpoint selection |
//! | `account` | Candidate account payload contracts by layer and family; feature `unstable-account` |
//!
//! `account` is a candidate contract behind the `unstable-account` feature (default
//! off). It is not covered by semver and may change incompatibly before the gate is
//! removed and a release is made. `service` and `node_control` do not depend on it.
//!
//! Every public item has one path, inside its module. Pure: no I/O, runtime state or
//! clock; callers pass time, randomness, keys and authenticated context.

#[cfg(feature = "unstable-account")]
pub mod account;
pub mod node_control;
pub mod service;
