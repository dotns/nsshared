use serde::{Deserialize, Serialize};

use crate::{Error, MAX_TTL_SECONDS, validate_authority};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Invite,
    Join,
}

/// Immutable endpoint-owned session identity. Fresh transport challenges do not
/// change this transcript, so reconnection cannot switch keys or recipients.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hello {
    pub version: u8,
    pub session: [u8; 16],
    pub role: Role,
    pub identity: [u8; 32],
    pub ephemeral: [u8; 32],
    pub authority: String,
    pub expires: u64,
}

impl Hello {
    pub fn validate(&self, now: u64) -> Result<(), Error> {
        if self.version != 1
            || self.session == [0; 16]
            || self.identity == [0; 32]
            || self.ephemeral == [0; 32]
            || self.expires <= now
            || self.expires.saturating_sub(now) > MAX_TTL_SECONDS
        {
            return Err(Error::InvalidProof);
        }
        validate_authority(&self.authority).map_err(|_| Error::InvalidProof)
    }

    pub fn signing_message(&self, challenge: &[u8; 32]) -> Result<Vec<u8>, Error> {
        let mut message = b"ns-quick-identity-v1\0".to_vec();
        message.extend_from_slice(challenge);
        message.extend(serde_json::to_vec(self).map_err(|_| Error::InvalidMessage)?);
        Ok(message)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proof {
    pub hello: Hello,
    pub challenge: [u8; 32],
    pub signature: Vec<u8>,
}

impl Proof {
    pub fn verify(&self, now: u64) -> Result<(), Error> {
        self.hello.validate(now)?;
        let key = ed25519_dalek::VerifyingKey::from_bytes(&self.hello.identity)
            .map_err(|_| Error::InvalidProof)?;
        let signature = ed25519_dalek::Signature::from_slice(&self.signature)
            .map_err(|_| Error::InvalidProof)?;
        key.verify_strict(&self.hello.signing_message(&self.challenge)?, &signature)
            .map_err(|_| Error::InvalidProof)
    }
}

/// Opaque ciphertext; the broker never sees the long-lived pairing credential.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedToken {
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

impl std::fmt::Debug for SealedToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SealedToken([REDACTED])")
    }
}

/// Requests are deliberately not Debug: lookup codes must never enter logs.
#[derive(Clone, Serialize, Deserialize)]
#[serde(
    tag = "operation",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum Request {
    Directory,
    Create(Proof),
    Lookup(String),
    Join(Proof),
    Resume(Proof),
    Poll,
    Select([u8; 32]),
    Reject([u8; 32]),
    Deliver(SealedToken),
    Cancel,
    Complete,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    Waiting,
    Selected,
    Delivered,
    Completed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub stage: Stage,
    pub candidates: Vec<Proof>,
    pub selected: Option<Proof>,
    pub sealed: Option<SealedToken>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(
    tag = "result",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum Response {
    Challenge { nonce: [u8; 32], authority: String },
    Directory(crate::Directory),
    Created { digits: String, expires: u64 },
    Offer(Proof),
    State(Observation),
    Ok,
    Error(Error),
}
