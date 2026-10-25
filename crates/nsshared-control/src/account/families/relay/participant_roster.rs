use crate::{
    account::AccountError, account::MAX_BYTES, account::MAX_IDENTITIES, account::identity,
    account::reader, account::relay::IdentityClass, account::relay::MIN_ROSTER_VALIDITY_MS,
    account::relay::Roster, account::relay::RosterEntry, account::relay::RosterVersion,
    account::relay::SignedRoster,
};
use nsshared_codec::cbor::CborReader;
use nsshared_identity::keys::IdentityKey;
use std::collections::BTreeSet;
use thiserror::Error;

/// The participant's own credential scope, already present in signed content.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParticipantRosterScope {
    /// Trusted account authority issuing the complete roster.
    pub issuer: IdentityKey,
    /// Independent relay participant receiving this authority.
    pub recipient: IdentityKey,
}

/// One authenticated complete publication, including its inseparable attribution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParticipantRosterGeneration {
    /// Signed issuer/recipient scope; no broader authorization is implied.
    pub scope: ParticipantRosterScope,
    /// Monotonic roster version and attribution epoch for every entry.
    pub version: RosterVersion,
    /// Complete identity/class mapping. Empty withdraws all membership.
    pub identities: Vec<RosterEntry>,
    /// Signed issue time in Unix milliseconds.
    pub issued_at_unix_ms: u64,
    /// Exclusive signed deadline; consumer renewal never extends it.
    pub valid_until_unix_ms: u64,
}

/// Refusal to accept a participant roster. Refusal never represents withdrawal.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ParticipantRosterError {
    /// Malformed, noncanonical, unordered, unbounded or otherwise invalid content.
    #[error(transparent)]
    Contract(#[from] AccountError),
    /// The publication is from a different authority.
    #[error("wrong participant roster issuer")]
    Issuer,
    /// The publication addresses another participant.
    #[error("wrong participant roster recipient")]
    Recipient,
    /// The version is below or equal to the accepted epoch.
    #[error("stale or replayed participant roster version")]
    Stale,
    /// The signed issue time is later than the supplied clock.
    #[error("participant roster issue is in the future")]
    FutureIssue,
    /// The supplied clock is at or beyond the exclusive deadline.
    #[error("participant roster expired")]
    Expired,
    /// The signed lifetime is less than 24 hours, or ends before issue.
    #[error("participant roster lifetime is below the minimum")]
    ShortLifetime,
    /// The signature fails strict verification over the canonical domain/content.
    #[error("invalid participant roster signature")]
    Signature,
    /// An identity entry lacks its attribution class.
    #[error("missing participant roster class")]
    MissingClass,
    /// An identity entry carries more than one class.
    #[error("duplicate participant roster class")]
    DuplicateClass,
    /// An identity entry uses an undefined class value.
    #[error("unknown participant roster class")]
    UnknownClass,
    /// The complete mapping assigns an identity more than once.
    #[error("duplicate participant roster identity")]
    DuplicateIdentity,
}

crate::account::contract_error!(ParticipantRosterError);

fn validate_content(roster: &Roster) -> Result<(), ParticipantRosterError> {
    if roster
        .valid_until_unix_ms
        .checked_sub(roster.issued_at_unix_ms)
        .is_none_or(|duration| duration < MIN_ROSTER_VALIDITY_MS)
    {
        return Err(ParticipantRosterError::ShortLifetime);
    }
    if roster.identities.len() > MAX_IDENTITIES {
        return Err(AccountError::Bounds.into());
    }
    let mut seen = BTreeSet::new();
    for entry in &roster.identities {
        if !seen.insert(entry.identity) {
            return Err(ParticipantRosterError::DuplicateIdentity);
        }
    }
    Ok(())
}

impl SignedRoster {
    /// Authenticates a complete publication and returns its atomic attribution epoch.
    /// The caller supplies trust, persisted version and current time; no state is stored.
    ///
    /// # Errors
    /// Returns a typed authority, version, time, lifetime, signature or mapping refusal.
    pub fn verify_generation(
        &self,
        issuer: IdentityKey,
        recipient: IdentityKey,
        last_version: u64,
        now_ms: u64,
    ) -> Result<ParticipantRosterGeneration, ParticipantRosterError> {
        validate_content(&self.content)?;
        // Preserve the existing canonical validation for constructed publications too.
        self.content.canonical()?;
        let roster = &self.content;
        if roster.issuer != issuer {
            return Err(ParticipantRosterError::Issuer);
        }
        if roster.recipient != recipient {
            return Err(ParticipantRosterError::Recipient);
        }
        if roster.version.0 <= last_version {
            return Err(ParticipantRosterError::Stale);
        }
        if now_ms < roster.issued_at_unix_ms {
            return Err(ParticipantRosterError::FutureIssue);
        }
        if now_ms >= roster.valid_until_unix_ms {
            return Err(ParticipantRosterError::Expired);
        }
        self.verify(issuer, recipient, last_version, now_ms)
            .map_err(|error| match error {
                AccountError::Signature => ParticipantRosterError::Signature,
                other => ParticipantRosterError::Contract(other),
            })?;
        Ok(ParticipantRosterGeneration {
            scope: ParticipantRosterScope {
                issuer: roster.issuer,
                recipient: roster.recipient,
            },
            version: roster.version,
            identities: roster.identities.clone(),
            issued_at_unix_ms: roster.issued_at_unix_ms,
            valid_until_unix_ms: roster.valid_until_unix_ms,
        })
    }
}

/// Decodes and authenticates the existing signed carrier with typed class refusals.
/// The scope is exactly its issuer/recipient pair, not a new signed field.
///
/// # Errors
/// Refuses malformed canonical bytes, missing/duplicate/unknown classes and every
/// authority, version, time, lifetime or signature failure before returning a generation.
pub fn verify_participant_roster(
    bytes: &[u8],
    issuer: IdentityKey,
    recipient: IdentityKey,
    last_version: u64,
    now_ms: u64,
) -> Result<ParticipantRosterGeneration, ParticipantRosterError> {
    let mut carrier = CborReader::new(bytes, MAX_BYTES)?;
    carrier.array(2)?;
    let mut input = reader(carrier.bytes_up_to(MAX_BYTES)?, 7)?;
    let mut content = Roster {
        issuer: identity(&mut input)?,
        recipient: identity(&mut input)?,
        version: RosterVersion(input.uint()?),
        issued_at_unix_ms: input.uint()?,
        valid_until_unix_ms: input.uint()?,
        identities: vec![],
    };
    let count = input.array_up_to(MAX_IDENTITIES)?;
    content.identities.reserve(count);
    for _ in 0..count {
        match input.array_up_to(MAX_BYTES)? {
            0 | 1 => return Err(ParticipantRosterError::MissingClass),
            2 => {}
            _ => return Err(ParticipantRosterError::DuplicateClass),
        }
        let identity = identity(&mut input)?;
        let class = match input.uint()? {
            0 => IdentityClass::OrdinaryNode,
            1 => IdentityClass::GatewayNode,
            _ => return Err(ParticipantRosterError::UnknownClass),
        };
        content.identities.push(RosterEntry { identity, class });
    }
    input.finish()?;
    let signature = carrier.fixed_bytes()?;
    carrier.finish()?;
    SignedRoster { content, signature }.verify_generation(issuer, recipient, last_version, now_ms)
}

/// Supplied-clock lifecycle state of already authenticated complete authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParticipantRosterStatus {
    /// Valid signed authority; admit according to the complete mapping.
    Valid,
    /// No authenticated renewal for 24 hours; still admit the complete mapping.
    Degraded,
    /// At or beyond the exclusive signed deadline; deny membership.
    Expired,
}

/// Reports expiry first, then diagnostic degradation since authenticated renewal.
/// The caller supplies renewal state and time. Outage never extends the deadline.
#[must_use]
pub fn participant_roster_status(
    generation: &ParticipantRosterGeneration,
    last_authenticated_renewal_ms: u64,
    now_ms: u64,
) -> ParticipantRosterStatus {
    if now_ms >= generation.valid_until_unix_ms {
        ParticipantRosterStatus::Expired
    } else if now_ms
        .checked_sub(last_authenticated_renewal_ms)
        .is_some_and(|age| age >= MIN_ROSTER_VALIDITY_MS)
    {
        ParticipantRosterStatus::Degraded
    } else {
        ParticipantRosterStatus::Valid
    }
}
