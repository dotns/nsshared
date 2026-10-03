#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Single-instance mock of the NS rendezvous v2 (`/quick/v2`) relay (docs
//! ns/rendezvous.md, ns/quick-v2.md §7).
//!
//! The protocol layer comes from `nsshared-rendezvous`; this crate adds only storage,
//! indexes, randomness, clocks, rate limits, wake-ups and I/O. There is no region: no
//! owner epochs, forwarding or replication. State modules do no I/O and read no clock
//! or OS randomness; callers pass `now` and an RNG. [`server::RendezvousServer`] is the
//! embeddable TLS WebSocket front end and the only reader of the clock and OS randomness.

pub mod config;
pub mod mailbox;
pub mod rate;
pub mod registry;
pub mod server;
pub mod tls;

pub use config::{Config, Limits, TlsSource};
pub use server::{RendezvousServer, ServerError};
pub use tls::{ServerTls, TlsError};
