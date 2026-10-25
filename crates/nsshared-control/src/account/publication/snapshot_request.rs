//! Pure independently polled snapshot requests and pending-response validation.

use crate::{
    account::AccountError, account::SCHEMA, account::control::BootstrapEnvelope,
    account::control::BootstrapError, account::control::EnvelopeDirection,
    account::control::EnvelopeExpectation, account::identity,
    account::publication::AcceptedPublication, account::publication::PublicationDecision,
    account::publication::PublicationError, account::publication::PublicationExpectation,
    account::publication::source_binding::DeliveryContext,
    account::publication::source_binding::SourceBinding,
    account::publication::source_binding::SourceError,
    account::publication::source_publication::decide_source_snapshot_scopes,
    account::publication::subscription::SubscriptionScope, account::require, account::scope_text,
};
use nsshared_codec::{cbor::CborReader, cbor::CborWriter};
use nsshared_identity::keys::IdentityKey;
use thiserror::Error;

/// Maximum exact requested authority scopes.
pub const MAX_SNAPSHOT_SCOPES: usize = 32;
/// Maximum encoded request payload, excluding the signed carrier.
pub const MAX_SNAPSHOT_REQUEST_BYTES: usize = 8192;

/// Typed refusal without changing accepted authority or retained versions.
#[derive(Debug, Error)]
pub enum SnapshotRequestError {
    /// Invalid canonical request or fields.
    #[error(transparent)]
    Contract(#[from] AccountError),
    /// Invalid signed carrier.
    #[error(transparent)]
    Envelope(#[from] BootstrapError),
    /// Invalid existing signed publication snapshot.
    #[error(transparent)]
    Publication(#[from] PublicationError),
    /// Invalid source binding, signature or pending delivery context.
    #[error(transparent)]
    Source(#[from] SourceError),
    /// Poll correlation differs from the pending request.
    #[error("snapshot poll correlation mismatch")]
    Correlation,
    /// Carrier signer differs from subscriber or expected publication issuer.
    #[error("snapshot poll signer mismatch")]
    Signer,
    /// Recipient differs from the pending subscriber.
    #[error("snapshot poll recipient mismatch")]
    Recipient,
    /// Requested or returned authority is outside the pending scope set.
    #[error("snapshot poll scope mismatch")]
    Scope,
    /// A returned kind does not belong to the snapshot channel.
    #[error("snapshot poll channel mismatch")]
    Channel,
}

/// Requests every snapshot-owned kind within each exact authority scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicationSnapshotRequest {
    /// Signing subscriber, also the recipient of every requested scope.
    pub subscriber: IdentityKey,
    /// Strictly sorted unique subscription-shaped authority entries.
    pub scopes: Vec<SubscriptionScope>,
    /// Nonzero caller-supplied active subscription restart identity.
    pub boot_nonce: [u8; 16],
    /// Positive checked logical subscription attempt; never a publication version.
    pub attempt_counter: u32,
    /// Nonzero caller-supplied poll identity, echoed by the signed response nonce.
    pub correlation: [u8; 16],
}
impl PublicationSnapshotRequest {
    fn validate(&self) -> Result<(), AccountError> {
        require(self.scopes.len() <= MAX_SNAPSHOT_SCOPES)?;
        require(self.scopes.windows(2).all(|pair| pair[0] < pair[1]))?;
        for scope in &self.scopes {
            require(scope.recipient == self.subscriber)?;
            scope_text(&scope.scope)?;
        }
        require(self.boot_nonce != [0; 16] && self.attempt_counter > 0)?;
        require(self.correlation != [0; 16])
    }

    /// Encodes the exact request without sorting or normalizing scopes.
    /// # Errors
    /// Refuses malformed fields, noncanonical sets and oversized payloads.
    pub fn canonical(&self) -> Result<Vec<u8>, SnapshotRequestError> {
        self.validate()?;
        let mut out = CborWriter::default();
        out.array(6)
            .uint(SCHEMA)
            .bytes(self.subscriber.as_bytes())
            .array(self.scopes.len());
        for scope in &self.scopes {
            out.array(4)
                .bytes(scope.issuer.as_bytes())
                .bytes(scope.recipient.as_bytes())
                .text(&scope.served_realm.to_string())
                .text(&scope.scope);
        }
        out.bytes(&self.boot_nonce)
            .uint(u64::from(self.attempt_counter))
            .bytes(&self.correlation);
        let bytes = out.into_bytes();
        require(bytes.len() <= MAX_SNAPSHOT_REQUEST_BYTES)?;
        Ok(bytes)
    }

    /// Decodes bounded canonical CBOR without inferring authorization.
    /// # Errors
    /// Refuses unknown fields, malformed or oversized input and invalid scopes.
    pub fn decode(bytes: &[u8]) -> Result<Self, SnapshotRequestError> {
        Ok(Self::read(bytes)?)
    }

    fn read(bytes: &[u8]) -> Result<Self, AccountError> {
        let mut input = CborReader::new(bytes, MAX_SNAPSHOT_REQUEST_BYTES)?;
        input.array(6)?;
        require(input.uint()? == SCHEMA)?;
        let subscriber = identity(&mut input)?;
        let count = input.array_up_to(MAX_SNAPSHOT_SCOPES)?;
        let mut scopes = Vec::new();
        for _ in 0..count {
            input.array(4)?;
            scopes.push(SubscriptionScope {
                issuer: identity(&mut input)?,
                recipient: identity(&mut input)?,
                served_realm: input.text_up_to(26)?.parse().map_err(AccountError::from)?,
                scope: input.text_up_to(256)?.into(),
            });
        }
        let value = Self {
            subscriber,
            scopes,
            boot_nonce: input.fixed_bytes()?,
            attempt_counter: u32::try_from(input.uint()?)
                .map_err(|_| AccountError::InvalidField)?,
            correlation: input.fixed_bytes()?,
        };
        input.finish()?;
        value.validate()?;
        Ok(value)
    }

    /// Authenticates subscriber, requested issuer and poll correlation.
    /// Callers separately authorize exact scopes and the active subscription pair.
    /// # Errors
    /// Refuses invalid carriers, signer, operation, addressing or correlation.
    pub fn from_envelope(
        envelope: &BootstrapEnvelope,
        expected: &EnvelopeExpectation<'_>,
    ) -> Result<Self, SnapshotRequestError> {
        envelope.verify(expected)?;
        if envelope.direction != EnvelopeDirection::Request
            || envelope.kind != crate::account::control::exchange::CONFIG_SNAPSHOT
        {
            return Err(BootstrapError::Kind.into());
        }
        let value = Self::decode(&envelope.payload)?;
        if envelope.signer != value.subscriber {
            return Err(SnapshotRequestError::Signer);
        }
        if envelope.recipient != Some(expected.recipient)
            || value
                .scopes
                .iter()
                .any(|scope| scope.issuer != expected.recipient)
        {
            return Err(SnapshotRequestError::Scope);
        }
        if envelope.nonce != value.correlation {
            return Err(SnapshotRequestError::Correlation);
        }
        Ok(value)
    }

    /// Validates the sole source-bound config.snapshot response against a pending poll.
    /// The complete pending request must fit its canonical encoded byte ceiling.
    /// Every requested scope needs exactly one independently accepted current source.
    /// All entries pass validation before any decision becomes available; omission
    /// retains state and each complete outer entry keeps its decoded byte ceiling.
    /// # Errors
    /// Refuses carrier trust/address/operation/correlation, scope-set differences,
    /// plain or mixed entries, invalid source/context, ordering and publication errors.
    pub fn response<'a>(
        &self,
        envelope: &'a BootstrapEnvelope,
        carrier: &EnvelopeExpectation<'_>,
        last: &[AcceptedPublication<'_>],
        current: &[SourceBinding],
        expected: &PublicationExpectation<'_>,
    ) -> Result<Vec<PublicationDecision<'a>>, SnapshotRequestError> {
        self.canonical()?;
        envelope.verify(carrier)?;
        if envelope.direction != EnvelopeDirection::Response
            || envelope.kind != crate::account::control::exchange::CONFIG_SNAPSHOT
        {
            return Err(BootstrapError::Kind.into());
        }
        if envelope.nonce != self.correlation {
            return Err(SnapshotRequestError::Correlation);
        }
        if envelope.recipient != Some(self.subscriber) || expected.recipient != self.subscriber {
            return Err(SnapshotRequestError::Recipient);
        }
        if envelope.signer != expected.issuer {
            return Err(SnapshotRequestError::Signer);
        }
        if current.len() != self.scopes.len()
            || expected.scopes.len() != self.scopes.len()
            || self.scopes.iter().any(|scope| {
                scope.issuer != envelope.signer
                    || current
                        .iter()
                        .filter(|binding| {
                            binding.nsd == scope.issuer
                                && binding.recipient == scope.recipient
                                && binding.served_realm == scope.served_realm
                                && binding.scope == scope.scope
                        })
                        .count()
                        != 1
                    || expected
                        .scopes
                        .iter()
                        .filter(|publication| {
                            publication.served_realm == scope.served_realm
                                && publication.scope == scope.scope
                        })
                        .count()
                        != 1
            })
        {
            return Err(SnapshotRequestError::Scope);
        }
        let pending = DeliveryContext::Snapshot {
            boot_nonce: self.boot_nonce,
            attempt_counter: self.attempt_counter,
            correlation: self.correlation,
        };
        Ok(decide_source_snapshot_scopes(
            last,
            &envelope.payload,
            current,
            &pending,
            expected,
        )?)
    }
}
