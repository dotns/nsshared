//! Pure independently polled snapshot requests and pending-response validation.
use super::{
    AcceptedPublication, AccountError, BootstrapEnvelope, BootstrapError, EnvelopeDirection,
    EnvelopeExpectation, MAX_CONTROL_BODY, PublicationChannel, PublicationError, PublicationEvent,
    PublicationExpectation, PublicationSnapshot, SCHEMA, decide_publication_snapshot, identity,
    publication_channel, publication_subscription::SubscriptionScope, require,
};
use crate::{
    IdentityKey,
    encoding::{CborReader, CborWriter},
};
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
            for text in [&scope.served_realm, &scope.scope] {
                require(
                    !text.is_empty() && text.len() <= 256 && !text.chars().any(char::is_control),
                )?;
            }
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
                .text(&scope.served_realm)
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
                served_realm: input.text_up_to(256)?.into(),
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
            || envelope.kind != super::control_exchange::CONFIG_SNAPSHOT
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

    /// Returns the existing snapshot only after checking the pending request.
    /// Acceptance and version retention remain per full publication key.
    /// # Errors
    /// Refuses trust, correlation, recipient, unrequested scopes and known stream kinds,
    /// then applies every existing whole-snapshot validation rule.
    pub fn response<'a, 's>(
        &self,
        envelope: &'a BootstrapEnvelope,
        carrier: &EnvelopeExpectation<'_>,
        last: &'s [AcceptedPublication<'s>],
        expected: &'s PublicationExpectation<'s>,
    ) -> Result<PublicationSnapshot<'a, 's>, SnapshotRequestError> {
        self.validate()?;
        envelope.verify(carrier)?;
        if envelope.direction != EnvelopeDirection::Response
            || envelope.kind != super::control_exchange::CONFIG_SNAPSHOT
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
        if self
            .scopes
            .iter()
            .any(|scope| scope.issuer != envelope.signer)
        {
            return Err(SnapshotRequestError::Scope);
        }
        self.check_events(&envelope.payload)?;
        Ok(decide_publication_snapshot(
            last,
            &envelope.payload,
            expected,
        )?)
    }

    fn check_events(&self, bytes: &[u8]) -> Result<(), SnapshotRequestError> {
        // Decode the existing container, without adding a second response format.
        let mut reader = CborReader::new(bytes, MAX_CONTROL_BODY).map_err(AccountError::from)?;
        reader.array(2).map_err(AccountError::from)?;
        require(reader.uint().map_err(AccountError::from)? == SCHEMA)?;
        let count = reader
            .array_up_to(bytes.len())
            .map_err(AccountError::from)?;
        for _ in 0..count {
            let event = PublicationEvent::decode(
                reader
                    .bytes_up_to(MAX_CONTROL_BODY)
                    .map_err(AccountError::from)?,
            )?;
            let content = event.content();
            let key = content.key;
            if key.recipient != self.subscriber {
                return Err(SnapshotRequestError::Recipient);
            }
            if !self.scopes.iter().any(|scope| {
                scope.issuer == key.issuer
                    && scope.recipient == key.recipient
                    && scope.served_realm == key.served_realm
                    && scope.scope == key.scope
            }) {
                return Err(SnapshotRequestError::Scope);
            }
            if content.channel != PublicationChannel::Snapshot
                || publication_channel(key.family, key.kind) == Some(PublicationChannel::Stream)
            {
                return Err(SnapshotRequestError::Channel);
            }
        }
        reader.finish().map_err(AccountError::from)?;
        Ok(())
    }
}
