//! Capability tokens announced by a relay (rendezvous §3.1).
//!
//! The same tokens appear in each directory entry, in the `/quick/v2` `challenge` and in
//! the relay packet handshake reply. A capability only says what a relay offers and never
//! authorizes an operation. Unknown well-formed tokens are kept and ignored.

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use std::borrow::Cow;
use thiserror::Error;

/// Maximum token length in bytes (rendezvous §3.1).
pub const MAX_CAPABILITY_BYTES: usize = 32;
/// Maximum tokens in one announcement (rendezvous §3.1).
pub const MAX_CAPABILITIES: usize = 16;

/// `udp`: the relay UDP carrier (rendezvous §3.1).
pub const UDP: Capability = Capability(Cow::Borrowed("udp"));
/// `wss`: the `/keynet/v1` WSS carrier (rendezvous §3.1).
pub const WSS: Capability = Capability(Cow::Borrowed("wss"));
/// `mailbox`: the `/quick/v2` rendezvous mailbox (rendezvous §3.1).
pub const MAILBOX: Capability = Capability(Cow::Borrowed("mailbox"));
/// `region`: the authority is a relay region served by several members (rendezvous §3.1).
pub const REGION: Capability = Capability(Cow::Borrowed("region"));
/// `registry`: the `registry.v1` node registry (rendezvous §3.1, quick-v2 §7).
pub const REGISTRY: Capability = Capability(Cow::Borrowed("registry"));

/// A capability token, `[a-z0-9.-]{1,32}` (rendezvous §3.1).
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Capability(Cow<'static, str>);

/// A malformed capability announcement (rendezvous §3.1).
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CapabilityError {
    /// A token is not `[a-z0-9.-]{1,32}`.
    #[error("capability token must be [a-z0-9.-]{{1,{MAX_CAPABILITY_BYTES}}}")]
    Token,
    /// More than 16 tokens.
    #[error("at most {MAX_CAPABILITIES} capability tokens are allowed")]
    TooMany,
}

impl Capability {
    /// Parses a token (rendezvous §3.1).
    ///
    /// # Errors
    ///
    /// [`CapabilityError::Token`] when `text` is not `[a-z0-9.-]{1,32}`.
    pub fn parse(text: &str) -> Result<Self, CapabilityError> {
        if text.is_empty()
            || text.len() > MAX_CAPABILITY_BYTES
            || !text.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
            })
        {
            return Err(CapabilityError::Token);
        }
        Ok(Self(Cow::Owned(text.to_owned())))
    }

    /// Returns the token text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Serialize for Capability {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Capability {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::parse(&text).map_err(D::Error::custom)
    }
}

/// An announced capability list of at most 16 tokens, kept in announcement order
/// (rendezvous §3.1).
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct Capabilities(Vec<Capability>);

impl Capabilities {
    /// Wraps a token list (rendezvous §3.1).
    ///
    /// # Errors
    ///
    /// [`CapabilityError::TooMany`] for more than 16 tokens.
    pub fn new(tokens: Vec<Capability>) -> Result<Self, CapabilityError> {
        if tokens.len() > MAX_CAPABILITIES {
            return Err(CapabilityError::TooMany);
        }
        Ok(Self(tokens))
    }

    /// Whether `capability` is announced.
    #[must_use]
    pub fn contains(&self, capability: &Capability) -> bool {
        self.0.contains(capability)
    }

    /// Returns the tokens in announcement order, unknown ones included.
    #[must_use]
    pub fn as_slice(&self) -> &[Capability] {
        &self.0
    }
}

impl<'de> Deserialize<'de> for Capabilities {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(Vec::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}
