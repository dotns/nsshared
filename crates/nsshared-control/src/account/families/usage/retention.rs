//! Immutable participant custody closure and correlated durable acknowledgement.

use crate::{
    account::AccountError, account::MAX_IDENTITIES, account::SCHEMA, account::codec::bounded,
    account::codec::identity, account::codec::reader, account::codec::require,
    account::domains::RETENTION_SEAL_DIGEST_DOMAIN, account::node::ReporterIncarnation,
    account::relay::ParticipantRosterScope, account::relay::RosterVersion,
    account::usage::UsageProfile, service::domain_digest,
};
use nsshared_codec::cbor::{CborReader, CborWriter};
use thiserror::Error;

/// Retention refusal; errors never acknowledge closure or authorize deletion.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RetentionError {
    /// Malformed, noncanonical, unordered or unbounded content.
    #[error(transparent)]
    Contract(#[from] AccountError),
    /// The issuer differs from the authenticated authority.
    #[error("retention issuer mismatch")]
    Issuer,
    /// The recipient differs from the authenticated participant.
    #[error("retention recipient mismatch")]
    Recipient,
    /// The custody generation differs from retained ownership.
    #[error("retention owner generation mismatch")]
    OwnerGeneration,
    /// The acknowledgement or duplicate names another epoch.
    #[error("retention epoch mismatch")]
    Epoch,
    /// The acknowledgement does not commit the pending seal.
    #[error("retention seal digest mismatch")]
    Digest,
    /// Different content reused a retained seal identity.
    #[error("conflicting retention seal")]
    Conflict,
}

crate::account::contract_error!(RetentionError);

/// One immutable part captured under the closed epoch, across all incarnations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetentionPart {
    /// Original reporter lifecycle.
    pub incarnation: ReporterIncarnation,
    /// Original quantity profile.
    pub profile: UsageProfile,
    /// Positive original sequence in that lifecycle and profile.
    pub sequence: u64,
    /// Original zero-based partition index.
    pub part_index: u64,
    /// Exact original usage part commitment.
    pub part_digest: [u8; 32],
}

impl RetentionPart {
    fn key(&self) -> (&[u8; 16], &str, u64, u64) {
        (
            &self.incarnation.0,
            self.profile.as_str(),
            self.sequence,
            self.part_index,
        )
    }

    fn write(&self, out: &mut CborWriter) {
        out.array(5)
            .bytes(&self.incarnation.0)
            .text(self.profile.as_str())
            .uint(self.sequence)
            .uint(self.part_index)
            .bytes(&self.part_digest);
    }

    fn read(input: &mut CborReader<'_>) -> Result<Self, RetentionError> {
        input.array(5)?;
        Ok(Self {
            incarnation: ReporterIncarnation(input.fixed_bytes()?),
            profile: match input.text_up_to(32)? {
                "l8-completed-io-v1" => UsageProfile::Service,
                "l8-relay-data-v1" => UsageProfile::Relay,
                _ => return Err(AccountError::Field.into()),
            },
            sequence: input.uint()?,
            part_index: input.uint()?,
            part_digest: input.fixed_bytes()?,
        })
    }
}

/// Complete immutable closure of an epoch under one participant custody.
/// Empty parts explicitly declare that no part was captured. Completeness,
/// durable closure and retained historical attribution remain caller-owned.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetentionSeal {
    /// Issuer and recipient of the captured signed roster.
    pub scope: ParticipantRosterScope,
    /// Positive generation from retained participant custody.
    pub owner_generation: u64,
    /// Permanently closed roster epoch.
    pub epoch: RosterVersion,
    /// Strictly increasing by incarnation bytes, profile text, sequence and index.
    pub parts: Vec<RetentionPart>,
}

fn check_identity(
    scope: ParticipantRosterScope,
    generation: u64,
    expected: ParticipantRosterScope,
    expected_generation: u64,
) -> Result<(), RetentionError> {
    if scope.issuer != expected.issuer {
        return Err(RetentionError::Issuer);
    }
    if scope.recipient != expected.recipient {
        return Err(RetentionError::Recipient);
    }
    if generation != expected_generation {
        return Err(RetentionError::OwnerGeneration);
    }
    Ok(())
}

impl RetentionSeal {
    /// Encodes the complete seal for participant REPORT (kind 5).
    ///
    /// # Errors
    /// Refuses zero generation/epoch/sequence, invalid indices, unordered or
    /// duplicate part identities and collection or encoded size overflow.
    pub fn canonical(&self) -> Result<Vec<u8>, RetentionError> {
        require(self.owner_generation > 0 && self.epoch.0 > 0)?;
        if self.parts.len() > MAX_IDENTITIES {
            return Err(AccountError::Bounds.into());
        }
        require(
            self.parts
                .windows(2)
                .all(|pair| pair[0].key() < pair[1].key()),
        )?;
        let mut out = CborWriter::default();
        out.array(8)
            .uint(SCHEMA)
            .uint(9)
            .uint(2)
            .bytes(self.scope.issuer.as_bytes())
            .bytes(self.scope.recipient.as_bytes())
            .uint(self.owner_generation)
            .uint(self.epoch.0)
            .array(self.parts.len());
        for part in &self.parts {
            require(part.sequence > 0 && part.part_index < MAX_IDENTITIES as u64)?;
            part.write(&mut out);
        }
        Ok(bounded(out.into_bytes())?)
    }

    /// Decodes one bounded canonical seal without establishing custody closure.
    ///
    /// # Errors
    /// Refuses malformed CBOR, invalid tags, fields, ordering, widths or bounds.
    pub fn decode(bytes: &[u8]) -> Result<Self, RetentionError> {
        let mut input = reader(bytes, 8)?;
        require(input.uint()? == 9 && input.uint()? == 2)?;
        let scope = ParticipantRosterScope {
            issuer: identity(&mut input)?,
            recipient: identity(&mut input)?,
        };
        let owner_generation = input.uint()?;
        let epoch = RosterVersion(input.uint()?);
        let count = input.array_up_to(MAX_IDENTITIES)?;
        let parts = (0..count)
            .map(|_| RetentionPart::read(&mut input))
            .collect::<Result<_, _>>()?;
        input.finish()?;
        let value = Self {
            scope,
            owner_generation,
            epoch,
            parts,
        };
        value.canonical()?;
        Ok(value)
    }

    /// Commits the entire canonical seal using its distinct text digest domain.
    ///
    /// # Errors
    /// Refuses any invalid seal field or bound.
    pub fn computed_digest(&self) -> Result<[u8; 32], RetentionError> {
        Ok(domain_digest(
            RETENTION_SEAL_DIGEST_DOMAIN,
            &self.canonical()?,
        ))
    }

    /// Checks supplied authenticated scope and retained expected custody generation.
    /// This performs no authentication, storage or historical receipt lookup.
    ///
    /// # Errors
    /// Refuses malformed seals or mismatched issuer, recipient or generation.
    pub fn validate_for(
        &self,
        authenticated: ParticipantRosterScope,
        expected_generation: u64,
    ) -> Result<(), RetentionError> {
        self.canonical()?;
        check_identity(
            self.scope,
            self.owner_generation,
            authenticated,
            expected_generation,
        )
    }

    /// Accepts exact replay of a retained seal, without changing its receipt.
    ///
    /// # Errors
    /// Refuses invalid seals, different identities and conflicting content.
    pub fn validate_duplicate(&self, previous: &Self) -> Result<(), RetentionError> {
        self.validate_for(previous.scope, previous.owner_generation)?;
        previous.canonical()?;
        if self.epoch != previous.epoch {
            return Err(RetentionError::Epoch);
        }
        if self != previous {
            return Err(RetentionError::Conflict);
        }
        Ok(())
    }
}

/// Receiver result for a complete seal; only committed acknowledges delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub enum RetentionOutcome {
    /// The exact seal has committed to durable custody; not proof of part settlement.
    Committed = 0,
    /// Participant scope or custody authority is forbidden.
    Forbidden = 1,
    /// The seal is permanently invalid.
    InvalidRequest = 2,
    /// Another immutable seal already occupies this identity.
    Conflict = 3,
    /// Retained custody or historical projection is unavailable; repair is required.
    UnknownMapping = 4,
}

/// Correlated seal result carried only in participant ANSWER (kind 6).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetentionSealAck {
    /// Original issuer and recipient.
    pub scope: ParticipantRosterScope,
    /// Original custody generation.
    pub owner_generation: u64,
    /// Original closed epoch.
    pub epoch: RosterVersion,
    /// Digest of the exact canonical pending seal.
    pub seal_digest: [u8; 32],
    /// Durable commitment or explicit refusal; no implicit settlement.
    pub outcome: RetentionOutcome,
}

impl RetentionSealAck {
    /// Encodes the correlated receiver result with arity distinct from usage answers.
    ///
    /// # Errors
    /// Refuses zero generation or epoch.
    pub fn canonical(&self) -> Result<Vec<u8>, RetentionError> {
        require(self.owner_generation > 0 && self.epoch.0 > 0)?;
        let mut out = CborWriter::default();
        out.array(9)
            .uint(SCHEMA)
            .uint(9)
            .uint(3)
            .bytes(self.scope.issuer.as_bytes())
            .bytes(self.scope.recipient.as_bytes())
            .uint(self.owner_generation)
            .uint(self.epoch.0)
            .bytes(&self.seal_digest)
            .uint(self.outcome as u64);
        Ok(out.into_bytes())
    }

    /// Decodes a bounded canonical acknowledgement or refusal.
    ///
    /// # Errors
    /// Refuses malformed CBOR, tags, identities, widths, fields or unknown outcomes.
    pub fn decode(bytes: &[u8]) -> Result<Self, RetentionError> {
        let mut input = reader(bytes, 9)?;
        require(input.uint()? == 9 && input.uint()? == 3)?;
        let value = Self {
            scope: ParticipantRosterScope {
                issuer: identity(&mut input)?,
                recipient: identity(&mut input)?,
            },
            owner_generation: input.uint()?,
            epoch: RosterVersion(input.uint()?),
            seal_digest: input.fixed_bytes()?,
            outcome: match input.uint()? {
                0 => RetentionOutcome::Committed,
                1 => RetentionOutcome::Forbidden,
                2 => RetentionOutcome::InvalidRequest,
                3 => RetentionOutcome::Conflict,
                4 => RetentionOutcome::UnknownMapping,
                _ => return Err(AccountError::Field.into()),
            },
        };
        input.finish()?;
        value.canonical()?;
        Ok(value)
    }

    /// Compares every echoed identity field and digest with the immutable pending seal.
    /// Callers authenticate the response and inspect the returned outcome.
    ///
    /// # Errors
    /// Refuses malformed content, another seal identity or another content digest.
    pub fn validate_for(&self, seal: &RetentionSeal) -> Result<RetentionOutcome, RetentionError> {
        self.canonical()?;
        seal.validate_for(self.scope, self.owner_generation)?;
        if self.epoch != seal.epoch {
            return Err(RetentionError::Epoch);
        }
        if self.seal_digest != seal.computed_digest()? {
            return Err(RetentionError::Digest);
        }
        Ok(self.outcome)
    }
}
