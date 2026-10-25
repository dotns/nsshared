//! Account payload contracts; see `docs/l8-account-payload-profile.md`.
//!
//! | Module | Contents |
//! | --- | --- |
//! | [`node`] | Enrollment, identity lifecycle, Node L3 form and authority |
//! | [`control`] | Bootstrap, envelopes, control exchanges and reports, machine tokens, route commands, Node L3 status, M6 carrier |
//! | [`publication`] | Publication events and snapshots, family registry, source bindings, subscriptions, snapshot requests |
//! | [`realm`] | Family 2: realms and peers, policy subjects, rules and claims |
//! | [`grants`] | Families 3, 5 and 6: grants, payers, resource authority |
//! | [`subnet`] | Family 4: Subnet views, provider mappings and reports |
//! | [`edge`] | Family 7: public edge, declarations, material, confidential authentication |
//! | [`relay`] | Family 8: rosters, participant sessions, directory bindings |
//! | [`usage`] | Families 9 and 10: usage, reports, answers, profile publications |
//!
//! M6 objects and their bytes are [`crate::service`]. This module adds no runtime or
//! transport and reads no clock or filesystem.

/// Implements `From<CborError>` for an error whose `Contract` variant wraps
/// [`AccountError`]: every CBOR refusal is reported as [`AccountError::Cbor`].
macro_rules! contract_error {
    ($error:ty) => {
        impl From<nsshared_codec::cbor::CborError> for $error {
            fn from(error: nsshared_codec::cbor::CborError) -> Self {
                Self::Contract(crate::account::AccountError::Cbor(error))
            }
        }
    };
}
pub(crate) use contract_error;

mod codec;
pub mod control;
mod families;
mod limits;
pub mod node;
pub mod publication;

pub use families::{edge, grants, realm, relay, subnet, usage};

use nsshared_codec::cbor::CborError;
use nsshared_identity::realm::RealmIdError;
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
    /// Noncanonical membership realm text.
    #[error(transparent)]
    Realm(#[from] RealmIdError),
    /// Malformed or noncanonical CBOR.
    #[error(transparent)]
    Cbor(#[from] CborError),
    /// JSON shape, required field or field type is invalid.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// Unsupported schema or invalid contract fields.
    #[error("invalid account contract field")]
    Field,
    /// Input or a collection exceeds its contract bound.
    #[error("account contract bound exceeded")]
    Bounds,
    /// The signature is invalid.
    #[error("invalid account contract signature")]
    Signature,
    /// Issuer, recipient, version or time does not match the caller's authority.
    #[error("account contract authority or freshness mismatch")]
    Authority,
}
