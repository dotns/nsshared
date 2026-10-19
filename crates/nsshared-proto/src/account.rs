//! Pure L8 account payload candidate; see `docs/l8-account-payload-profile.md`.
//!
//! M6 objects and their bytes remain in `nsshared-service-control`. This module
//! adds no runtime or transport and reads no clock or filesystem.

mod enrollment;
mod l3;
mod lifecycle;
mod participant_roster;
mod registry;
mod roster;
mod usage;

pub use enrollment::{
    Enrollment, EnrollmentDecision, EnrollmentError, MAX_CAPABILITIES, MAX_CAPABILITY_BYTES,
    RebindAuthorization, decide_enrollment,
};
pub use l3::{L3Rule, L3Scope, NodeL3, TransportProtocol};
pub use lifecycle::{
    GrantIncarnation, Lifecycle, MembershipIdentityVersion, NodeBinding, RecordGeneration,
    ReporterIncarnation, Transition,
};
pub use participant_roster::{
    ParticipantRosterError, ParticipantRosterGeneration, ParticipantRosterScope,
    ParticipantRosterStatus, participant_roster_status, verify_participant_roster,
};
pub use registry::{
    FAMILIES, FamilyId, FamilyRegistration, FamilyRegistry, M6Reuse, ReplacementRule,
};
pub use roster::{
    AdmissionSnapshot, IdentityClass, MIN_ROSTER_VALIDITY_MS, ROSTER_SIGNATURE_DOMAIN, Roster,
    RosterEntry, RosterVersion, SignedRoster, validate_snapshot,
};
pub use usage::{BatchLossWindow, Direction, ServiceBoundary, ServiceUsage};

use crate::{
    IdentityKey,
    encoding::{CborError, CborReader},
};
use thiserror::Error;

/// Candidate CBOR schema version. Local admission JSON has its own schema 2.
pub const SCHEMA: u64 = 1;
/// Maximum encoded candidate or local snapshot size, in bytes.
pub const MAX_BYTES: usize = 1_048_576;
/// Maximum identities in a complete admission roster.
pub const MAX_IDENTITIES: usize = 8_192;

/// A rejected candidate contract. Invalid content never represents withdrawal.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AccountError {
    /// Malformed or noncanonical CBOR.
    #[error(transparent)]
    Cbor(#[from] CborError),
    /// JSON shape, required field or field type is invalid.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// Unsupported schema or invalid contract fields.
    #[error("invalid account contract field")]
    InvalidField,
    /// Input or a collection exceeds its contract bound.
    #[error("account contract bound exceeded")]
    Bounds,
    /// The signature is invalid.
    #[error("invalid participant roster signature")]
    Signature,
    /// Issuer, recipient, version or time does not match the caller's authority.
    #[error("participant roster authority or freshness mismatch")]
    Authority,
}

fn require(condition: bool) -> Result<(), AccountError> {
    if condition {
        Ok(())
    } else {
        Err(AccountError::InvalidField)
    }
}

fn identity(reader: &mut CborReader<'_>) -> Result<IdentityKey, AccountError> {
    IdentityKey::from_bytes(&reader.fixed_bytes()?).map_err(|_| AccountError::InvalidField)
}

fn reader(input: &[u8], arity: u64) -> Result<CborReader<'_>, AccountError> {
    let mut reader = CborReader::new(input, MAX_BYTES)?;
    reader.array(arity)?;
    require(reader.uint()? == SCHEMA)?;
    Ok(reader)
}

fn bounded(bytes: Vec<u8>) -> Result<Vec<u8>, AccountError> {
    if bytes.len() > MAX_BYTES {
        Err(AccountError::Bounds)
    } else {
        Ok(bytes)
    }
}
