//! Error codes carried by `{"result": "error", "value": <code>}` (rendezvous §7).
//!
//! An error never carries digits, payloads or other untrusted input: the code is the
//! whole error.

use serde::{Deserialize, Serialize};
use std::str::FromStr;
use thiserror::Error;

/// A rendezvous error code (rendezvous §7).
#[derive(Clone, Copy, Debug, Deserialize, Eq, Error, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", try_from = "String")]
#[non_exhaustive]
pub enum ErrorCode {
    /// The message is malformed, oversize or violates a field rule.
    #[error("invalid message")]
    InvalidMessage,
    /// The `hello` actor or its signature is invalid, or `hello` is missing or repeated.
    #[error("invalid actor")]
    InvalidActor,
    /// The digits do not locate a mailbox.
    #[error("invalid code")]
    InvalidCode,
    /// The relay is not in the directory.
    #[error("unknown relay")]
    UnknownRelay,
    /// The relay directory is invalid or not a valid update.
    #[error("invalid relay directory")]
    InvalidDirectory,
    /// The mailbox does not exist or has been removed.
    #[error("unknown mailbox")]
    UnknownMailbox,
    /// The actor may not perform this operation on the mailbox.
    #[error("not permitted")]
    NotPermitted,
    /// The mailbox stage does not allow this operation.
    #[error("wrong mailbox stage")]
    WrongStage,
    /// A capacity limit was reached.
    #[error("capacity reached")]
    Capacity,
    /// The message queue is full.
    #[error("queue full")]
    QueueFull,
    /// A rate limit was reached.
    #[error("rate limited")]
    RateLimited,
    /// The request conflicts with the stored state.
    #[error("conflict")]
    Conflict,
    /// Secure randomness is unavailable.
    #[error("randomness unavailable")]
    Randomness,
    /// Private storage is unavailable.
    #[error("storage unavailable")]
    Storage,
    /// The member is unavailable; retry on the next region member.
    #[error("unavailable")]
    Unavailable,
}

impl ErrorCode {
    /// Every error code in the order of rendezvous §7.
    pub const ALL: [Self; 15] = [
        Self::InvalidMessage,
        Self::InvalidActor,
        Self::InvalidCode,
        Self::UnknownRelay,
        Self::InvalidDirectory,
        Self::UnknownMailbox,
        Self::NotPermitted,
        Self::WrongStage,
        Self::Capacity,
        Self::QueueFull,
        Self::RateLimited,
        Self::Conflict,
        Self::Randomness,
        Self::Storage,
        Self::Unavailable,
    ];

    /// Returns the snake_case wire name (rendezvous §7).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidMessage => "invalid_message",
            Self::InvalidActor => "invalid_actor",
            Self::InvalidCode => "invalid_code",
            Self::UnknownRelay => "unknown_relay",
            Self::InvalidDirectory => "invalid_directory",
            Self::UnknownMailbox => "unknown_mailbox",
            Self::NotPermitted => "not_permitted",
            Self::WrongStage => "wrong_stage",
            Self::Capacity => "capacity",
            Self::QueueFull => "queue_full",
            Self::RateLimited => "rate_limited",
            Self::Conflict => "conflict",
            Self::Randomness => "randomness",
            Self::Storage => "storage",
            Self::Unavailable => "unavailable",
        }
    }

    /// Whether the client retries on the next region member: only `unavailable`; every
    /// other relay error is final (rendezvous §7).
    #[must_use]
    pub const fn retry_on_next_member(self) -> bool {
        matches!(self, Self::Unavailable)
    }
}

/// Text that is not one of the rendezvous §7 error codes.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("unknown error code")]
pub struct UnknownErrorCode;

impl FromStr for ErrorCode {
    type Err = UnknownErrorCode;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|code| code.as_str() == text)
            .ok_or(UnknownErrorCode)
    }
}

impl TryFrom<String> for ErrorCode {
    type Error = UnknownErrorCode;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        text.parse()
    }
}
