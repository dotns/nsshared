#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! NS shared control contracts.
//!
//! | Module | Contents |
//! | --- | --- |
//! | [`service`] | M6 private service control: wire types, digests and snapshots |
//!
//! Every public item has one path, inside its module. Pure: no I/O, runtime state or
//! clock; callers pass time, randomness, keys and authenticated context.

pub mod service;
