//! Pure authenticated publication requests; acceptance remains per publication key.
use super::{
    AccountError, BootstrapEnvelope, BootstrapError, EnvelopeDirection, EnvelopeExpectation,
    MAX_CAPABILITIES, MAX_CAPABILITY_BYTES, PublicationScope, SCHEMA,
    control_exchange::{CONFIG_STREAM, ExchangeError},
    enrollment::validate_capabilities,
    identity, require,
};
use crate::{
    IdentityKey,
    encoding::{CborReader, CborWriter},
};

/// Maximum exact requested scopes and public ingress indices.
pub const MAX_SUBSCRIPTION_SCOPES: usize = 32;
/// Maximum canonical request payload, excluding the signed carrier.
pub const MAX_SUBSCRIPTION_BYTES: usize = 8192;

/// Exact requested authority; requesting it does not authorize its use.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SubscriptionScope {
    /// Externally provisioned publication issuer.
    pub issuer: IdentityKey,
    /// Subscriber receiving publications.
    pub recipient: IdentityKey,
    /// Exact served realm.
    pub served_realm: String,
    /// Exact opaque authority scope.
    pub scope: String,
}
impl SubscriptionScope {
    /// Borrows the existing publication realm/scope pair.
    #[must_use]
    pub fn publication_scope(&self) -> PublicationScope<'_> {
        PublicationScope {
            served_realm: &self.served_realm,
            scope: &self.scope,
        }
    }
}

/// Canonical request facts, without transport, sessions or acceptance state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicationSubscriptionRequest {
    /// Signing subscriber; every requested recipient must equal it.
    pub subscriber: IdentityKey,
    /// Strictly sorted unique exact authority entries.
    pub scopes: Vec<SubscriptionScope>,
    /// Sorted unique enrollment-syntax declarations, never grants.
    pub capabilities: Vec<String>,
    /// Sorted unique scope indices requesting family 7 public-edge content.
    pub public_ingress: Vec<u32>,
    /// Caller-supplied nonzero restart identity; uniqueness is external.
    pub boot_nonce: [u8; 16],
    /// Positive checked logical attempt number; no publication version meaning.
    pub attempt_counter: u32,
}

fn text(value: &str) -> Result<(), AccountError> {
    require(!value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control))
}
impl PublicationSubscriptionRequest {
    fn validate(&self) -> Result<(), ExchangeError> {
        require(self.scopes.len() <= MAX_SUBSCRIPTION_SCOPES)?;
        require(self.scopes.windows(2).all(|p| p[0] < p[1]))?;
        for scope in &self.scopes {
            require(scope.recipient == self.subscriber)?;
            text(&scope.served_realm)?;
            text(&scope.scope)?;
        }
        validate_capabilities(&self.capabilities)?;
        require(self.public_ingress.len() <= MAX_SUBSCRIPTION_SCOPES)?;
        require(self.public_ingress.windows(2).all(|p| p[0] < p[1]))?;
        for index in &self.public_ingress {
            require(usize::try_from(*index).is_ok_and(|i| i < self.scopes.len()))?;
        }
        require(self.boot_nonce != [0; 16] && self.attempt_counter > 0)?;
        Ok(())
    }

    /// Encodes exact canonical request bytes without normalizing any set.
    /// # Errors
    /// Refuses invalid fields, ordering, capabilities, indices and byte bounds.
    pub fn canonical(&self) -> Result<Vec<u8>, ExchangeError> {
        self.validate()?;
        let mut out = CborWriter::default();
        out.array(7)
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
        out.array(self.capabilities.len());
        for capability in &self.capabilities {
            out.text(capability);
        }
        out.array(self.public_ingress.len());
        for index in &self.public_ingress {
            out.uint(u64::from(*index));
        }
        out.bytes(&self.boot_nonce)
            .uint(u64::from(self.attempt_counter));
        let bytes = out.into_bytes();
        if bytes.len() > MAX_SUBSCRIPTION_BYTES {
            return Err(AccountError::Bounds.into());
        }
        Ok(bytes)
    }

    /// Decodes canonical CBOR with byte and list bounds checked before allocation.
    /// # Errors
    /// Refuses unsupported schema, unknown fields, malformed and invalid input.
    pub fn decode(bytes: &[u8]) -> Result<Self, ExchangeError> {
        let value = Self::read(bytes)?;
        value.validate()?;
        Ok(value)
    }

    fn read(bytes: &[u8]) -> Result<Self, AccountError> {
        let mut input = CborReader::new(bytes, MAX_SUBSCRIPTION_BYTES)?;
        input.array(7)?;
        require(input.uint()? == SCHEMA)?;
        let subscriber = identity(&mut input)?;
        let count = input.array_up_to(MAX_SUBSCRIPTION_SCOPES)?;
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
        let count = input.array_up_to(MAX_CAPABILITIES)?;
        let mut capabilities = Vec::new();
        for _ in 0..count {
            capabilities.push(input.text_up_to(MAX_CAPABILITY_BYTES)?.into());
        }
        let count = input.array_up_to(MAX_SUBSCRIPTION_SCOPES)?;
        let mut public_ingress = Vec::new();
        for _ in 0..count {
            public_ingress
                .push(u32::try_from(input.uint()?).map_err(|_| AccountError::InvalidField)?);
        }
        let boot_nonce = input.fixed_bytes()?;
        let attempt_counter =
            u32::try_from(input.uint()?).map_err(|_| AccountError::InvalidField)?;
        input.finish()?;
        Ok(Self {
            subscriber,
            scopes,
            capabilities,
            public_ingress,
            boot_nonce,
            attempt_counter,
        })
    }

    /// Verifies the existing carrier, subscriber self-binding and issuer address.
    /// The caller must separately authorize each requested exact scope.
    /// # Errors
    /// Refuses unauthenticated, replayed, misaddressed or wrongly signed requests.
    pub fn from_envelope(
        envelope: &BootstrapEnvelope,
        expected: &EnvelopeExpectation<'_>,
    ) -> Result<Self, ExchangeError> {
        envelope.verify(expected)?;
        if envelope.direction != EnvelopeDirection::Request || envelope.kind != CONFIG_STREAM {
            return Err(BootstrapError::Kind.into());
        }
        let value = Self::decode(&envelope.payload)?;
        if envelope.signer != value.subscriber {
            return Err(ExchangeError::Binding);
        }
        if envelope.recipient != Some(expected.recipient)
            || value.scopes.iter().any(|s| s.issuer != expected.recipient)
        {
            return Err(ExchangeError::Scope);
        }
        Ok(value)
    }
}
