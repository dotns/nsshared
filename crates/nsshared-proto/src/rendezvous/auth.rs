//! Connection challenge and actor `hello` (rendezvous §3, §4).

use crate::RelayId;
use crate::rendezvous::{capability::Capabilities, crypto, error::ErrorCode, transport};
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use thiserror::Error;

/// Signature context of `hello`: `"ns-rendezvous-actor-v1\0"` (rendezvous §4).
pub const ACTOR_CONTEXT: &[u8] = b"ns-rendezvous-actor-v1\0";

/// The broker's first message on every connection (rendezvous §3).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Challenge {
    /// 32 random bytes, not all zero.
    #[serde(
        serialize_with = "transport::bytes::serialize",
        deserialize_with = "nonzero_nonce"
    )]
    pub nonce: [u8; 32],
    /// The relay or region identity `host:port` (rendezvous §5.4).
    #[serde(with = "relay_id")]
    pub authority: RelayId,
    /// The announced capabilities (rendezvous §3.1).
    pub capabilities: Capabilities,
}

/// A failed challenge or `hello` check (rendezvous §3, §4).
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AuthError {
    /// The challenge authority differs from the relay or region the client expected; the
    /// client disconnects.
    #[error("challenge authority differs from the expected relay")]
    AuthorityMismatch,
    /// The `hello` signature does not verify under strict Ed25519.
    #[error("hello signature does not verify")]
    InvalidSignature,
}

impl From<AuthError> for ErrorCode {
    fn from(error: AuthError) -> Self {
        match error {
            AuthError::AuthorityMismatch => Self::InvalidMessage,
            AuthError::InvalidSignature => Self::InvalidActor,
        }
    }
}

impl Challenge {
    /// Requires that `authority` equals the relay or region the client expected
    /// (rendezvous §3).
    ///
    /// # Errors
    ///
    /// [`AuthError::AuthorityMismatch`].
    pub fn check_authority(&self, expected: &RelayId) -> Result<(), AuthError> {
        if &self.authority == expected {
            Ok(())
        } else {
            Err(AuthError::AuthorityMismatch)
        }
    }
}

/// `hello {actor, signature}`: binds the connection to an actor (rendezvous §4).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Hello {
    /// The actor's Ed25519 public key, fresh for each mailbox.
    #[serde(with = "transport::bytes")]
    pub actor: [u8; 32],
    /// `Ed25519_actor("ns-rendezvous-actor-v1\0" ‖ nonce ‖ authority)`.
    #[serde(with = "transport::bytes")]
    pub signature: [u8; 64],
}

impl Hello {
    /// Signs a challenge with the actor key (rendezvous §4).
    #[must_use]
    pub fn sign(actor_key: &SigningKey, nonce: &[u8; 32], authority: &RelayId) -> Self {
        Self {
            actor: actor_key.verifying_key().to_bytes(),
            signature: actor_key.sign(&signed_message(nonce, authority)).to_bytes(),
        }
    }

    /// Verifies the signature over the connection's challenge with strict Ed25519
    /// (rendezvous §4).
    ///
    /// # Errors
    ///
    /// [`AuthError::InvalidSignature`], also for an invalid or small-order actor key.
    pub fn verify(&self, nonce: &[u8; 32], authority: &RelayId) -> Result<(), AuthError> {
        if crypto::verify_strict(
            &self.actor,
            &signed_message(nonce, authority),
            &self.signature,
        ) {
            Ok(())
        } else {
            Err(AuthError::InvalidSignature)
        }
    }
}

/// `"ns-rendezvous-actor-v1\0" ‖ nonce ‖ authority`, without length prefixes (rendezvous §4).
fn signed_message(nonce: &[u8; 32], authority: &RelayId) -> Vec<u8> {
    let authority = authority.as_str().as_bytes();
    let mut message = Vec::with_capacity(ACTOR_CONTEXT.len() + nonce.len() + authority.len());
    message.extend_from_slice(ACTOR_CONTEXT);
    message.extend_from_slice(nonce);
    message.extend_from_slice(authority);
    message
}

fn nonzero_nonce<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 32], D::Error> {
    let nonce: [u8; 32] = transport::bytes::deserialize(deserializer)?;
    if nonce == [0; 32] {
        return Err(D::Error::custom("challenge nonce is all zero"));
    }
    Ok(nonce)
}

/// Serde for a canonical [`RelayId`] string (quick-v2 §8.6).
pub(crate) mod relay_id {
    use crate::RelayId;
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

    pub(crate) fn serialize<S: Serializer>(
        value: &RelayId,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(value.as_str())
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<RelayId, D::Error> {
        RelayId::parse(&String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}
