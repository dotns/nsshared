//! Signed opaque control carriers; service-control message bytes stay unchanged.

use crate::{
    account::control::bootstrap::BootstrapError, account::control::bootstrap::ControlBoundary,
    account::control::bootstrap::EnvelopePins, account::control::bootstrap::MAX_CONTROL_BODY,
    account::control::bootstrap::validate_control_input, account::domains::ACCOUNT_REQUEST_DOMAIN,
    account::domains::ACCOUNT_RESPONSE_DOMAIN, account::limits::MAX_TEXT_BYTES,
    account::signing::SignatureFailure, account::signing::signing_input, account::signing::verify,
};
use nsshared_codec::{cbor::CborReader, cbor::CborWriter};
use nsshared_identity::keys::IdentityKey;

/// Inclusive absolute timestamp skew in seconds.
pub const CONTROL_CLOCK_SKEW_SECONDS: u64 = 60;
/// Inclusive nonce observation retention in seconds.
pub const CONTROL_REPLAY_WINDOW_SECONDS: u64 = 120;

/// Signed request or response direction, with distinct signature domains.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub enum EnvelopeDirection {
    /// Request from an authorized caller.
    Request = 0,
    /// Response from the control authority.
    Response = 1,
}

impl EnvelopeDirection {
    fn domain(self) -> &'static [u8] {
        match self {
            Self::Request => ACCOUNT_REQUEST_DOMAIN,
            Self::Response => ACCOUNT_RESPONSE_DOMAIN,
        }
    }
}

/// Authentication expectations and replay facts supplied by the consumer.
#[derive(Debug)]
pub struct EnvelopeExpectation<'a> {
    /// Effective pins for the expected issuer, established from authenticated trust.
    pub pins: &'a EnvelopePins,
    /// Expected request/response signature domain.
    pub direction: EnvelopeDirection,
    /// Expected identity when the carrier names a recipient.
    pub recipient: IdentityKey,
    /// Exact expected nonempty operation identifier.
    pub kind: &'a str,
    /// Current Unix seconds; no clock is read internally.
    pub now_seconds: u64,
    /// Retained acceptance time for this exact signer/direction/nonce, if any.
    pub previous_acceptance_seconds: Option<u64>,
}

/// Canonical authenticated carrier; its payload is opaque, including M6 bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootstrapEnvelope {
    /// Signed direction selecting the signature domain.
    pub direction: EnvelopeDirection,
    /// Issuer's Ed25519 identity, always checked against effective pins.
    pub signer: IdentityKey,
    /// Optional recipient; bootstrap responses may omit it.
    pub recipient: Option<IdentityKey>,
    /// Nonempty operation identifier of at most 256 UTF-8 bytes.
    pub kind: String,
    /// Signed Unix timestamp in seconds.
    pub unix_seconds: u64,
    /// Caller-generated nonce whose replay observations remain external.
    pub nonce: [u8; 16],
    /// Exact opaque payload; no parallel service-control message is defined.
    pub payload: Vec<u8>,
    /// Ed25519 signature of the domain and canonical content bytes.
    pub signature: [u8; 64],
}

impl BootstrapEnvelope {
    fn content(&self) -> Result<Vec<u8>, BootstrapError> {
        if self.kind.is_empty() || self.kind.len() > MAX_TEXT_BYTES {
            return Err(BootstrapError::Kind);
        }
        validate_control_input(ControlBoundary::CallBody, &self.payload)?;
        let mut out = CborWriter::default();
        out.array(8)
            .uint(1)
            .uint(self.direction as u64)
            .bytes(self.signer.as_bytes());
        if let Some(recipient) = self.recipient {
            out.bytes(recipient.as_bytes());
        } else {
            out.null();
        }
        out.text(&self.kind)
            .uint(self.unix_seconds)
            .bytes(&self.nonce)
            .bytes(&self.payload);
        Ok(out.into_bytes())
    }

    /// Returns the existing direction domain followed by canonical content bytes.
    ///
    /// # Errors
    /// Rejects invalid kind or oversized opaque payload.
    pub fn signing_input(&self) -> Result<Vec<u8>, BootstrapError> {
        Ok(signing_input(self.direction.domain(), &self.content()?))
    }

    /// Encodes the canonical signed carrier without changing opaque payload bytes.
    ///
    /// # Errors
    /// Rejects invalid kind or a carrier exceeding the call-body limit.
    pub fn canonical(&self) -> Result<Vec<u8>, BootstrapError> {
        let content = self.content()?;
        let mut out = CborWriter::default();
        out.array(2).bytes(&content).bytes(&self.signature);
        let bytes = out.into_bytes();
        validate_control_input(ControlBoundary::CallBody, &bytes)?;
        Ok(bytes)
    }

    /// Decodes canonical carrier/content bytes; authentication requires [`Self::verify`].
    ///
    /// # Errors
    /// Rejects unsupported/missing versions, invalid identities, bounds and encodings.
    pub fn decode(bytes: &[u8]) -> Result<Self, BootstrapError> {
        let mut carrier = CborReader::new(bytes, MAX_CONTROL_BODY)?;
        carrier.array(2)?;
        let content = carrier.bytes_up_to(MAX_CONTROL_BODY)?;
        let signature = carrier.fixed_bytes()?;
        carrier.finish()?;
        let mut input = CborReader::new(content, MAX_CONTROL_BODY)?;
        input.array(8)?;
        if input.take_null() || input.uint()? != 1 {
            return Err(BootstrapError::Version);
        }
        let direction = match input.uint()? {
            0 => EnvelopeDirection::Request,
            1 => EnvelopeDirection::Response,
            _ => return Err(BootstrapError::Direction),
        };
        let signer =
            IdentityKey::from_bytes(&input.fixed_bytes()?).map_err(|_| BootstrapError::Signer)?;
        let recipient = if input.take_null() {
            None
        } else {
            Some(
                IdentityKey::from_bytes(&input.fixed_bytes()?)
                    .map_err(|_| BootstrapError::Recipient)?,
            )
        };
        let kind = input.text_up_to(MAX_TEXT_BYTES)?.to_owned();
        let unix_seconds = input.uint()?;
        let nonce = input.fixed_bytes()?;
        let payload = input.bytes_up_to(MAX_CONTROL_BODY)?.to_vec();
        input.finish()?;
        let value = Self {
            direction,
            signer,
            recipient,
            kind,
            unix_seconds,
            nonce,
            payload,
            signature,
        };
        value.content()?;
        Ok(value)
    }

    /// Verifies every signature and supplied trust, scope, time and replay expectation.
    ///
    /// The caller authenticates discovery, retains nonce observations for at least
    /// the replay window, and atomically records successful acceptance externally.
    ///
    /// # Errors
    /// Refuses invalid content, domain, pin, recipient, kind, skew, replay or signature.
    pub fn verify(&self, expected: &EnvelopeExpectation<'_>) -> Result<(), BootstrapError> {
        self.canonical()?;
        if self.direction != expected.direction {
            return Err(BootstrapError::Direction);
        }
        if !expected.pins.trusts(self.signer) {
            return Err(BootstrapError::Signer);
        }
        if self
            .recipient
            .is_some_and(|recipient| recipient != expected.recipient)
        {
            return Err(BootstrapError::Recipient);
        }
        if self.kind != expected.kind {
            return Err(BootstrapError::Kind);
        }
        if self.unix_seconds.abs_diff(expected.now_seconds) > CONTROL_CLOCK_SKEW_SECONDS {
            return Err(BootstrapError::Clock);
        }
        verify(
            self.signer,
            self.direction.domain(),
            &self.content()?,
            &self.signature,
        )
        .map_err(|failure| match failure {
            SignatureFailure::Key => BootstrapError::Signer,
            SignatureFailure::Signature => BootstrapError::Signature,
        })?;
        if expected.previous_acceptance_seconds.is_some_and(|seen| {
            expected.now_seconds.saturating_sub(seen) <= CONTROL_REPLAY_WINDOW_SECONDS
        }) {
            return Err(BootstrapError::Replay);
        }
        Ok(())
    }
}
