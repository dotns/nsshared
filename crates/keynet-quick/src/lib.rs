//! Bounded, relay-addressed temporary pairing. A code locates an invitation;
//! it never authorizes a peer or derives a permanent connection key.
#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

mod crypto;
mod directory;
mod protocol;

pub use crypto::*;
pub use directory::*;
pub use protocol::*;

/// Maximum JSON message size, checked before parsing.
pub const MAX_MESSAGE_BYTES: usize = 16 * 1024;
/// Maximum invitation lifetime, also applied to resumed sessions.
pub const MAX_TTL_SECONDS: u64 = 900;
/// TLS WebSocket endpoint, isolated from the existing relay data plane.
pub const PATH: &str = "/quick/v1";
/// Required WebSocket subprotocol.
pub const SUBPROTOCOL: &str = "ns-quick-v1";

/// Public errors never contain a code, token, key or untrusted input.
#[derive(
    Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, thiserror::Error,
)]
#[serde(rename_all = "snake_case")]
pub enum Error {
    #[error("invalid invitation format")]
    InvalidCode,
    #[error("unknown relay; update the relay directory or ask for a full invitation")]
    UnknownRelay,
    #[error("invalid relay directory")]
    InvalidDirectory,
    #[error("invalid pairing message")]
    InvalidMessage,
    #[error("pairing proof is invalid")]
    InvalidProof,
    #[error("invitation has expired or is no longer available")]
    Unavailable,
    #[error("another recipient was selected")]
    NotSelected,
    #[error("pairing capacity reached; try again later")]
    Capacity,
    #[error("too many pairing attempts; try again later")]
    RateLimited,
    #[error("pairing state conflicts with this request")]
    Conflict,
    #[error("secure randomness is unavailable")]
    Randomness,
    #[error("encrypted invitation authentication failed")]
    Encryption,
    #[error("temporary pairing storage is unavailable")]
    Storage,
}

/// OS randomness with errors surfaced instead of a panic or predictable fallback.
pub fn random<const N: usize>() -> Result<[u8; N], Error> {
    use rand_core::RngCore as _;
    let mut bytes = [0; N];
    rand_core::OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| Error::Randomness)?;
    Ok(bytes)
}
