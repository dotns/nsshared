#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! A single-instance, in-memory relay v2 mock for tests (docs ns/quick-v2.md §8).
//!
//! This crate is **not** a production relay. It keeps every registration, record mark and
//! session in memory, runs exactly one relay instance (no region, mesh or owner fencing),
//! persists nothing and applies only a few simple per-node limits instead of the global
//! production budgets of quick-protocol §5.2.1.
//!
//! The core is sans-IO: [`Relay`] never touches a socket, a clock or the OS random source.
//! Every call takes the current [`Now`], the [`Peer`] a packet came from and the packet
//! bytes, and returns the [`Transmit`]s to send. The relay ephemeral comes from an
//! injected [`rand_core::CryptoRng`], so tests are deterministic. Encodings, admission
//! checks, the session key and MACs all come from `nsshared-wire`.
//!
//! Spec coverage (quick-v2 §8, with the v1 rules of quick-protocol §12.5 it inherits):
//!
//! - §8.1-§8.2: header, the eight packet types and STATUS codes 1-6; STATUS is never
//!   answered, and unattributable packets are dropped silently.
//! - §8.3 rules 1-5 and 7: REGISTER admission against per-identity record marks, the 10 s
//!   provisional registration keyed by the exact REGISTER and source, confirmation by
//!   PRESENCE, incarnation ordering, `seq` high water, presence expiry, REFLECT on
//!   confirmed UDP sessions at most once per PRESENCE interval, and REVOKE.
//! - §8.4: DATA forwarding between confirmed sessions with a per-sender DATA budget and a
//!   per-destination handshake-initiation budget.
//! - §8.5 budgets: only the per-node values listed in [`Limits`].
//!
//! The [`testing`] module holds a node-side helper that builds the packets a node sends.
//!
//! [`MockRelay`] runs the core on tokio: the UDP carrier and the WSS carrier
//! (`wss://host:port/ns/v2`, subprotocol `ns-relay-v2`) on the relay identifier's port,
//! with a self-signed or PEM certificate (quick-v2 §8.5, §8.6). The
//! `nsshared-mock-relay` binary wraps it.

mod bucket;
mod config;
mod inspect;
mod peer;
mod relay;
mod runtime;
pub mod testing;

pub use config::{ConfigError, Limits, PROVISIONAL_LIFETIME, RelayConfig};
pub use inspect::{Counters, Reason, SessionInfo};
pub use peer::{Carrier, Now, Peer, Transmit};
pub use relay::Relay;
pub use runtime::{
    Error, GeneratedCert, MockRelay, MockRelayConfig, TlsSource, accept_relay_request,
    relay_websocket_config,
};
