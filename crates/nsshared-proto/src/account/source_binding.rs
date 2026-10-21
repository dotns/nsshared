//! Signed contribution authority and subscriber-produced delivery context.

use ed25519_dalek::{Signature, VerifyingKey};
use thiserror::Error;

use super::{
    AccountError, BootstrapEnvelope, BootstrapError, EnvelopeDirection, EnvelopeExpectation,
    PublicationChannel, PublicationError, SubnetError, identity, require,
};
use crate::{
    IdentityKey, RealmId,
    encoding::{CborReader, CborWriter},
};

/// Inclusive encoded ceiling for source bindings and route commands.
pub const MAX_SOURCE_BYTES: usize = 16_384;
/// Signature domain for durable NSD contribution authority.
pub const SOURCE_BINDING_DOMAIN: &[u8] = b"ns.account.source-binding.v1\0";

/// Assigned enrollment profile; no predecessor profile conversion exists.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceProfile {
    /// Explicit Node and route authority.
    ExplicitGateway,
}
impl SourceProfile {
    /// Exact assigned wire vocabulary.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        "explicit-gateway-profile"
    }
}

/// Typed refusal; no error withdraws or renews existing authority.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SourceError {
    /// Invalid bounded canonical encoding or fields.
    #[error(transparent)]
    Contract(#[from] AccountError),
    /// Invalid confidential signed carrier.
    #[error(transparent)]
    Envelope(#[from] BootstrapError),
    /// Invalid existing publication.
    #[error(transparent)]
    Publication(#[from] PublicationError),
    /// Invalid existing Subnet scope.
    #[error(transparent)]
    Subnet(#[from] SubnetError),
    /// Source, caller, profile or pending request differs.
    #[error("source authority mismatch")]
    Authority,
    /// Subscriber restart, attempt, channel or poll differs.
    #[error("source delivery context mismatch")]
    Context,
    /// Signature is invalid under the independently expected NSD.
    #[error("invalid source signature")]
    Signature,
    /// Request identity was reused for different content.
    #[error("route request content conflict")]
    Conflict,
    /// Invalid canonical M6 service reference.
    #[error("invalid route reference")]
    Reference,
}
impl From<crate::encoding::CborError> for SourceError {
    fn from(value: crate::encoding::CborError) -> Self {
        Self::Contract(value.into())
    }
}

pub(super) fn nonzero(value: &[u8; 16]) -> Result<(), SourceError> {
    Ok(require(*value != [0; 16])?)
}
pub(super) fn verify_signature(
    issuer: IdentityKey,
    domain: &[u8],
    bytes: &[u8],
    signature: &[u8; 64],
) -> Result<(), SourceError> {
    let key = VerifyingKey::from_bytes(issuer.as_bytes()).map_err(|_| SourceError::Signature)?;
    let mut message = domain.to_vec();
    message.extend_from_slice(bytes);
    key.verify_strict(&message, &Signature::from_bytes(signature))
        .map_err(|_| SourceError::Signature)
}

/// Exact durable source authority, distinct from record or local attachment generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceBinding {
    /// Enrolled NSD signing identity.
    pub nsd: IdentityKey,
    /// Authenticated control recipient.
    pub recipient: IdentityKey,
    /// Authorized enclosing collection realm.
    pub served_realm: RealmId,
    /// Exact authority scope, independent of contributing realms.
    pub scope: String,
    /// Profile assigned by authenticated enrollment.
    pub profile: SourceProfile,
    /// Full source Node identity I, never a gateway id or address.
    pub source_node: IdentityKey,
    /// NSD-allocated durable contribution identity.
    pub contribution: [u8; 16],
    /// Positive NSD source epoch, unrelated to M6 authority_epoch.
    pub source_epoch: u64,
    /// Positive durable NSD generation, checked by exact equality.
    pub source_generation: u64,
}
impl SourceBinding {
    /// Encodes without inferring authority or normalizing fields.
    /// # Errors
    /// Refuses invalid scope, contribution or counters.
    pub fn canonical(&self) -> Result<Vec<u8>, SourceError> {
        require(
            !self.scope.is_empty()
                && self.scope.len() <= 256
                && !self.scope.chars().any(char::is_control),
        )?;
        nonzero(&self.contribution)?;
        require(self.source_epoch > 0 && self.source_generation > 0)?;
        let mut out = CborWriter::default();
        out.array(10)
            .uint(1)
            .bytes(self.nsd.as_bytes())
            .bytes(self.recipient.as_bytes())
            .text(&self.served_realm.to_string())
            .text(&self.scope)
            .text(self.profile.as_str())
            .bytes(self.source_node.as_bytes())
            .bytes(&self.contribution)
            .uint(self.source_epoch)
            .uint(self.source_generation);
        Ok(out.into_bytes())
    }
    /// Decodes exact source fields without establishing current authority.
    /// # Errors
    /// Refuses retired profiles, unknown fields, malformed input and bounds.
    pub fn decode(bytes: &[u8]) -> Result<Self, SourceError> {
        let mut input = CborReader::new(bytes, MAX_SOURCE_BYTES)?;
        input.array(10)?;
        require(input.uint()? == 1)?;
        let nsd = identity(&mut input)?;
        let recipient = identity(&mut input)?;
        let served_realm = input.text_up_to(26)?.parse().map_err(AccountError::from)?;
        let scope = input.text_up_to(256)?.to_owned();
        require(input.text_up_to(64)? == SourceProfile::ExplicitGateway.as_str())?;
        let value = Self {
            nsd,
            recipient,
            served_realm,
            scope,
            profile: SourceProfile::ExplicitGateway,
            source_node: identity(&mut input)?,
            contribution: input.fixed_bytes()?,
            source_epoch: input.uint()?,
            source_generation: input.uint()?,
        };
        input.finish()?;
        value.canonical()?;
        Ok(value)
    }
}

/// NSD signature over every source binding field; decoding is not acceptance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedSourceBinding {
    /// Exact signed facts.
    pub binding: SourceBinding,
    /// Domain-separated NSD signature.
    pub signature: [u8; 64],
}
impl SignedSourceBinding {
    /// Source domain and canonical binding bytes.
    /// # Errors
    /// Refuses invalid constructed binding fields.
    pub fn signing_input(&self) -> Result<Vec<u8>, SourceError> {
        let mut bytes = SOURCE_BINDING_DOMAIN.to_vec();
        bytes.extend_from_slice(&self.binding.canonical()?);
        Ok(bytes)
    }
    /// Exact signed form, without signing or acquiring authority.
    /// # Errors
    /// Refuses invalid binding fields.
    pub fn canonical(&self) -> Result<Vec<u8>, SourceError> {
        let mut out = CborWriter::default();
        out.array(2)
            .bytes(&self.binding.canonical()?)
            .bytes(&self.signature);
        Ok(out.into_bytes())
    }
    /// Strict bounded signed form; verification is separate.
    /// # Errors
    /// Refuses malformed, retired or extended forms.
    pub fn decode(bytes: &[u8]) -> Result<Self, SourceError> {
        let mut input = CborReader::new(bytes, MAX_SOURCE_BYTES)?;
        input.array(2)?;
        let binding = SourceBinding::decode(input.bytes_up_to(MAX_SOURCE_BYTES)?)?;
        let signature = input.fixed_bytes()?;
        input.finish()?;
        Ok(Self { binding, signature })
    }
    /// Verifies against independently accepted NSD identity, never a self-presented key.
    /// # Errors
    /// Refuses issuer disagreement, invalid fields or signature.
    pub fn verify(&self, nsd: IdentityKey) -> Result<(), SourceError> {
        if self.binding.nsd != nsd {
            return Err(SourceError::Authority);
        }
        verify_signature(
            nsd,
            SOURCE_BINDING_DOMAIN,
            &self.binding.canonical()?,
            &self.signature,
        )
    }
}

/// Exact outstanding subscriber context, never a producer freshness counter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeliveryContext {
    /// Authenticated subscription context.
    Stream {
        /// Nonzero subscriber restart identity.
        boot_nonce: [u8; 16],
        /// Positive subscriber attempt.
        attempt_counter: u32,
    },
    /// Snapshot poll within an authenticated subscription context.
    Snapshot {
        /// Nonzero subscriber restart identity.
        boot_nonce: [u8; 16],
        /// Positive subscriber attempt.
        attempt_counter: u32,
        /// Nonzero pending poll correlation.
        correlation: [u8; 16],
    },
}
impl DeliveryContext {
    /// The sole channel allowed for this context.
    #[must_use]
    pub const fn channel(&self) -> PublicationChannel {
        match self {
            Self::Stream { .. } => PublicationChannel::Stream,
            Self::Snapshot { .. } => PublicationChannel::Snapshot,
        }
    }
    /// Exact context bytes.
    /// # Errors
    /// Refuses zero nonce, correlation or attempt.
    pub fn canonical(&self) -> Result<Vec<u8>, SourceError> {
        let (boot_nonce, attempt_counter, correlation) = match self {
            Self::Stream {
                boot_nonce,
                attempt_counter,
            } => (boot_nonce, attempt_counter, None),
            Self::Snapshot {
                boot_nonce,
                attempt_counter,
                correlation,
            } => (boot_nonce, attempt_counter, Some(correlation)),
        };
        nonzero(boot_nonce)?;
        require(*attempt_counter > 0)?;
        let mut out = CborWriter::default();
        out.array(if correlation.is_some() { 4 } else { 3 })
            .uint(self.channel() as u64)
            .bytes(boot_nonce)
            .uint(u64::from(*attempt_counter));
        if let Some(correlation) = correlation {
            nonzero(correlation)?;
            out.bytes(correlation);
        }
        Ok(out.into_bytes())
    }
    /// Decodes only the two exact tagged shapes.
    /// # Errors
    /// Refuses malformed, extra or invalid fields and overflowing attempts.
    pub fn decode(bytes: &[u8]) -> Result<Self, SourceError> {
        let mut input = CborReader::new(bytes, MAX_SOURCE_BYTES)?;
        let count = input.array_up_to(4)?;
        let tag = input.uint()?;
        let boot_nonce = input.fixed_bytes()?;
        let attempt_counter = u32::try_from(input.uint()?).map_err(|_| SourceError::Context)?;
        let value = match (tag, count) {
            (0, 3) => Self::Stream {
                boot_nonce,
                attempt_counter,
            },
            (1, 4) => Self::Snapshot {
                boot_nonce,
                attempt_counter,
                correlation: input.fixed_bytes()?,
            },
            _ => return Err(SourceError::Context),
        };
        input.finish()?;
        value.canonical()?;
        Ok(value)
    }
}

/// Independently provisioned enrollment facts and a pending control request.
#[derive(Clone, Debug)]
pub struct SourceEnrollmentExpectation<'a> {
    /// Accepted enrolled NSD identity.
    pub nsd: IdentityKey,
    /// Expected recipient.
    pub recipient: IdentityKey,
    /// Expected enclosing realm.
    pub served_realm: RealmId,
    /// Expected authority scope.
    pub scope: &'a str,
    /// Authenticated enrollment profile.
    pub profile: SourceProfile,
    /// Expected full source Node.
    pub source_node: IdentityKey,
    /// Pending request correlation.
    pub request_id: [u8; 16],
}

/// Correlated source authority delivered by an authenticated control response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceAcceptance {
    /// NSD-produced signed authority.
    pub binding: SignedSourceBinding,
    /// Original request identity.
    pub request_id: [u8; 16],
}
impl SourceAcceptance {
    /// Exact payload for the existing authenticated control response.
    /// # Errors
    /// Refuses malformed binding or zero correlation.
    pub fn canonical(&self) -> Result<Vec<u8>, SourceError> {
        nonzero(&self.request_id)?;
        let mut out = CborWriter::default();
        out.array(3)
            .uint(1)
            .bytes(&self.binding.canonical()?)
            .bytes(&self.request_id);
        Ok(out.into_bytes())
    }
    /// Decodes without trusting the supplied source.
    /// # Errors
    /// Refuses missing, extended, malformed or invalid fields.
    pub fn decode(bytes: &[u8]) -> Result<Self, SourceError> {
        let mut input = CborReader::new(bytes, MAX_SOURCE_BYTES)?;
        input.array(3)?;
        require(input.uint()? == 1)?;
        let value = Self {
            binding: SignedSourceBinding::decode(input.bytes_up_to(MAX_SOURCE_BYTES)?)?,
            request_id: input.fixed_bytes()?,
        };
        input.finish()?;
        value.canonical()?;
        Ok(value)
    }
    /// Verifies the NSD response and original enrollment/request before acceptance.
    /// # Errors
    /// Refuses trust, operation, recipient, correlation or enrollment disagreement.
    pub fn from_envelope(
        envelope: &BootstrapEnvelope,
        carrier: &EnvelopeExpectation<'_>,
        pending: &SourceEnrollmentExpectation<'_>,
    ) -> Result<Self, SourceError> {
        envelope.verify(carrier)?;
        let value = Self::decode(&envelope.payload)?;
        let binding = &value.binding.binding;
        value.binding.verify(pending.nsd)?;
        if envelope.direction != EnvelopeDirection::Response
            || !matches!(
                envelope.kind.as_str(),
                super::control_exchange::MACHINE_REGISTER | super::control_exchange::MACHINE_AUTH
            )
            || envelope.signer != pending.nsd
            || envelope.recipient != Some(pending.recipient)
            || carrier.recipient != pending.recipient
            || envelope.nonce != pending.request_id
            || value.request_id != pending.request_id
            || binding.recipient != pending.recipient
            || binding.served_realm != pending.served_realm
            || binding.scope != pending.scope
            || binding.profile != pending.profile
            || binding.source_node != pending.source_node
        {
            return Err(SourceError::Authority);
        }
        Ok(value)
    }
}
