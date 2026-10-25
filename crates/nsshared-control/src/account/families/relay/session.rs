//! Pure participant frames and supplied-authorization checks on verified TLS.

use std::fmt;

use ed25519_dalek::{Signature, VerifyingKey};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use thiserror::Error;

use crate::account::AccountError;
use nsshared_identity::keys::IdentityKey;

/// Regular completed-handshake TLS exporter label, including resumed handshakes.
pub const EXPORTER_LABEL: &[u8] = b"EXPORTER-nsgw-participant-candidate-v1";
/// Existing Ed25519 proof domain, including the zero separator.
pub const PROOF_DOMAIN: &[u8] = b"nsgw-participant-candidate-v1\0";
/// Maximum body bytes, preserving the existing roster/report frame bound.
pub const MAX_FRAME_BODY: usize = 1_048_576;
/// Participant frame kinds; the discriminant is the wire kind byte.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum FrameKind {
    /// Participant authentication request.
    Authenticate = 1,
    /// Authenticated session metadata.
    Authenticated = 2,
    /// Refusal with no withdrawal semantics.
    Refused = 3,
    /// Unchanged signed complete roster bytes.
    Roster = 4,
    /// Unchanged immutable usage report bytes.
    Report = 5,
    /// Unchanged usage answer bytes.
    Answer = 6,
    /// Dedicated enrollment request.
    Enroll = 7,
    /// Correlated enrollment acceptance.
    Enrolled = 8,
    /// Renewal on an already authenticated session.
    Renew = 9,
    /// Correlated renewal acceptance.
    Renewed = 10,
}

impl FrameKind {
    /// The kind for a wire kind byte, or `None` for an unknown operation.
    #[must_use]
    pub const fn from_byte(byte: u8) -> Option<Self> {
        Some(match byte {
            1 => Self::Authenticate,
            2 => Self::Authenticated,
            3 => Self::Refused,
            4 => Self::Roster,
            5 => Self::Report,
            6 => Self::Answer,
            7 => Self::Enroll,
            8 => Self::Enrolled,
            9 => Self::Renew,
            10 => Self::Renewed,
            _ => return None,
        })
    }

    /// The wire kind byte.
    #[must_use]
    pub const fn byte(self) -> u8 {
        self as u8
    }

    /// True for the kinds that carry the issuer/participant pair.
    const fn has_pair(self) -> bool {
        matches!(self, Self::Authenticate) || self.has_correlation()
    }

    /// True for the kinds that carry a request correlation.
    const fn has_correlation(self) -> bool {
        matches!(
            self,
            Self::Enroll | Self::Enrolled | Self::Renew | Self::Renewed
        )
    }
}

/// Refusal never supplies signed withdrawal or a renewed deadline.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SessionError {
    /// Invalid keys or contract fields.
    #[error(transparent)]
    Contract(#[from] AccountError),
    /// Unknown kind, invalid length, malformed field or trailing bytes.
    #[error("invalid participant frame")]
    Frame,
    /// Pair is not provisioned, enabled or currently valid.
    #[error("participant authorization refused")]
    Unauthorized,
    /// Possession proof does not match this connection's exporter.
    #[error("invalid participant connection proof")]
    Proof,
    /// Response differs from the exact pending operation, pair or request.
    #[error("participant response correlation mismatch")]
    Correlation,
}

/// Raw issuer then recipient, with no additional scope or encoded wrapper.
#[must_use]
pub fn exporter_context(issuer: IdentityKey, participant: IdentityKey) -> [u8; 64] {
    let mut context = [0; 64];
    context[..32].copy_from_slice(issuer.as_bytes());
    context[32..].copy_from_slice(participant.as_bytes());
    context
}

/// Existing proof preimage; caller obtains fresh exporter bytes after each handshake.
#[must_use]
pub fn proof_input(exporter: &[u8; 32]) -> Vec<u8> {
    let mut input = PROOF_DOMAIN.to_vec();
    input.extend_from_slice(exporter);
    input
}

/// Current NSD authorization supplied independently of presented authentication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Authorization {
    /// Trusted provisioned issuer.
    pub issuer: IdentityKey,
    /// Enrolled participant public identity, exactly the roster recipient.
    pub participant: IdentityKey,
    /// False refuses authentication, renewal and report acceptance.
    pub enabled: bool,
    /// Actual exclusive credential deadline; absent supplies no finite bound.
    pub deadline_ms: Option<u64>,
}
impl Authorization {
    /// Checks current authorization before authentication, renewal or report acceptance.
    /// # Errors
    /// Refuses a different pair, disabled authorization or an expired finite bound.
    pub fn validate(
        &self,
        issuer: IdentityKey,
        participant: IdentityKey,
        now_ms: u64,
    ) -> Result<(), SessionError> {
        if !self.enabled
            || self.issuer != issuer
            || self.participant != participant
            || self.deadline_ms.is_some_and(|deadline| now_ms >= deadline)
        {
            return Err(SessionError::Unauthorized);
        }
        Ok(())
    }
}

/// Independently provisioned enrollment-only credential; never a session token.
pub struct EnrollmentProvision<'a> {
    /// Intended trusted issuer.
    pub issuer: IdentityKey,
    /// Exact authorized participant key.
    pub participant: IdentityKey,
    /// Dedicated confidential provisioning value, borrowed without custody.
    pub credential: &'a [u8; 32],
}
impl fmt::Debug for EnrollmentProvision<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnrollmentProvision")
            .field("issuer", &self.issuer)
            .field("participant", &self.participant)
            .finish_non_exhaustive()
    }
}

/// Client-owned pending request on a verified TLS connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PendingResponse {
    /// Exactly [`FrameKind::Enrolled`] or [`FrameKind::Renewed`].
    pub kind: FrameKind,
    /// Expected trusted issuer.
    pub issuer: IdentityKey,
    /// Own public identity.
    pub participant: IdentityKey,
    /// Nonzero pending request correlation.
    pub correlation: [u8; 16],
}

/// Validated frame shape. Debug output never includes enrollment credentials.
#[derive(Clone, Eq, PartialEq)]
pub struct Frame {
    kind: FrameKind,
    body: Vec<u8>,
}
impl fmt::Debug for Frame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Frame")
            .field("kind", &self.kind)
            .field("body_len", &self.body.len())
            .finish()
    }
}

/// Validate header length before allocating a body. Length includes the kind byte.
/// # Errors
/// Rejects unknown operations and every kind-specific or global length violation.
pub fn validate_header(length: u32, kind: u8) -> Result<usize, SessionError> {
    let body_len = usize::try_from(length)
        .ok()
        .and_then(|n| n.checked_sub(1))
        .filter(|n| *n <= MAX_FRAME_BODY)
        .ok_or(SessionError::Frame)?;
    let valid = match FrameKind::from_byte(kind) {
        Some(FrameKind::Authenticate) => body_len == 128,
        Some(FrameKind::Authenticated) => matches!(body_len, 1 | 9),
        Some(FrameKind::Refused) => body_len == 0,
        Some(FrameKind::Roster | FrameKind::Report | FrameKind::Answer) => body_len > 0,
        Some(FrameKind::Enroll) => body_len == 176,
        Some(FrameKind::Enrolled | FrameKind::Renewed) => matches!(body_len, 81 | 89),
        Some(FrameKind::Renew) => body_len == 80,
        None => false,
    };
    if !valid {
        return Err(SessionError::Frame);
    }
    Ok(body_len)
}

/// Decode exact optional deadline bytes. Zero remains a finite deadline.
/// # Errors
/// Refuses unknown tags, truncation and extra bytes.
pub fn credential_deadline(body: &[u8]) -> Result<Option<u64>, SessionError> {
    match body {
        [0] => Ok(None),
        [1, bytes @ ..] => Ok(Some(u64::from_be_bytes(
            bytes.try_into().map_err(|_| SessionError::Frame)?,
        ))),
        _ => Err(SessionError::Frame),
    }
}

fn deadline_bytes(deadline_ms: Option<u64>) -> Vec<u8> {
    deadline_ms.map_or_else(
        || vec![0],
        |deadline| {
            let mut bytes = vec![1];
            bytes.extend_from_slice(&deadline.to_be_bytes());
            bytes
        },
    )
}

/// Preserve a finite retained bound when authenticated metadata omits one.
/// Apply this only when a fresh complete roster has passed independent acceptance.
#[must_use]
pub fn retained_credential_deadline(previous: Option<u64>, received: Option<u64>) -> Option<u64> {
    received.or(previous)
}

fn identity(bytes: &[u8]) -> Result<IdentityKey, SessionError> {
    IdentityKey::try_from(bytes).map_err(|_| SessionError::Frame)
}

impl Frame {
    /// Construct a bounded frame with exact operation fields; no session is granted.
    /// # Errors
    /// Refuses malformed lengths, identities, correlations and deadline encodings.
    pub fn new(kind: FrameKind, body: Vec<u8>) -> Result<Self, SessionError> {
        let length = u32::try_from(body.len())
            .ok()
            .and_then(|n| n.checked_add(1))
            .ok_or(SessionError::Frame)?;
        validate_header(length, kind.byte())?;
        if kind.has_pair() {
            identity(&body[..32])?;
            identity(&body[32..64])?;
        }
        if kind.has_correlation() && body[64..80] == [0; 16] {
            return Err(SessionError::Frame);
        }
        match kind {
            FrameKind::Authenticated => {
                credential_deadline(&body)?;
            }
            FrameKind::Enrolled | FrameKind::Renewed => {
                credential_deadline(&body[80..])?;
            }
            _ => {}
        }
        Ok(Self { kind, body })
    }
    /// Construct the existing connection authentication tuple.
    /// # Errors
    /// Refuses invalid frame fields or bounds.
    pub fn authentication(
        issuer: IdentityKey,
        participant: IdentityKey,
        proof: [u8; 64],
    ) -> Result<Self, SessionError> {
        let mut body = exporter_context(issuer, participant).to_vec();
        body.extend_from_slice(&proof);
        Self::new(FrameKind::Authenticate, body)
    }
    /// Construct an enrollment request with its dedicated provisioning credential.
    /// # Errors
    /// Refuses a zero correlation or invalid frame fields.
    pub fn enrollment(
        issuer: IdentityKey,
        participant: IdentityKey,
        correlation: [u8; 16],
        credential: &[u8; 32],
        proof: [u8; 64],
    ) -> Result<Self, SessionError> {
        let mut body = exporter_context(issuer, participant).to_vec();
        body.extend_from_slice(&correlation);
        body.extend_from_slice(credential);
        body.extend_from_slice(&proof);
        Self::new(FrameKind::Enroll, body)
    }
    /// Construct renewal on an independently authenticated session.
    /// # Errors
    /// Refuses a zero correlation or invalid fields.
    pub fn renewal(
        issuer: IdentityKey,
        participant: IdentityKey,
        correlation: [u8; 16],
    ) -> Result<Self, SessionError> {
        let mut body = exporter_context(issuer, participant).to_vec();
        body.extend_from_slice(&correlation);
        Self::new(FrameKind::Renew, body)
    }
    /// Construct enrolled/renewed metadata for the exact request and actual deadline.
    /// # Errors
    /// Refuses a different operation or zero correlation.
    pub fn response(
        pending: &PendingResponse,
        deadline_ms: Option<u64>,
    ) -> Result<Self, SessionError> {
        if !matches!(pending.kind, FrameKind::Enrolled | FrameKind::Renewed) {
            return Err(SessionError::Frame);
        }
        let mut body = exporter_context(pending.issuer, pending.participant).to_vec();
        body.extend_from_slice(&pending.correlation);
        body.extend_from_slice(&deadline_bytes(deadline_ms));
        Self::new(pending.kind, body)
    }
    /// Construct existing authenticated metadata without inventing a finite bound.
    /// # Errors
    /// Refuses invalid frame bounds.
    pub fn authenticated(deadline_ms: Option<u64>) -> Result<Self, SessionError> {
        Self::new(FrameKind::Authenticated, deadline_bytes(deadline_ms))
    }
    /// Read exact request correlation without exposing enrollment credentials.
    /// # Errors
    /// Refuses operations without a correlation.
    pub fn correlation(&self) -> Result<[u8; 16], SessionError> {
        if !self.kind.has_correlation() {
            return Err(SessionError::Frame);
        }
        self.body[64..80]
            .try_into()
            .map_err(|_| SessionError::Frame)
    }
    /// Read the exact issuer/recipient pair without granting authority.
    /// # Errors
    /// Refuses operations that do not carry a pair.
    pub fn scope(&self) -> Result<(IdentityKey, IdentityKey), SessionError> {
        if !self.kind.has_pair() {
            return Err(SessionError::Frame);
        }
        self.pair()
    }
    /// Decode a complete frame, refusing truncation and trailing bytes.
    /// # Errors
    /// Rejects invalid header, fields and bounds before copying any body.
    pub fn decode(bytes: &[u8]) -> Result<Self, SessionError> {
        let header: [u8; 4] = bytes
            .get(..4)
            .ok_or(SessionError::Frame)?
            .try_into()
            .map_err(|_| SessionError::Frame)?;
        let byte = *bytes.get(4).ok_or(SessionError::Frame)?;
        let length = validate_header(u32::from_be_bytes(header), byte)?;
        if bytes.len() != length + 5 {
            return Err(SessionError::Frame);
        }
        let kind = FrameKind::from_byte(byte).ok_or(SessionError::Frame)?;
        Self::new(kind, bytes[5..].to_vec())
    }
    /// Exact wire bytes; roster/report/answer bodies are never reinterpreted.
    /// # Errors
    /// Rejects invalid lengths rather than truncating their integer representation.
    pub fn canonical(&self) -> Result<Vec<u8>, SessionError> {
        let length = u32::try_from(self.body.len() + 1).map_err(|_| SessionError::Frame)?;
        validate_header(length, self.kind.byte())?;
        let mut bytes = length.to_be_bytes().to_vec();
        bytes.push(self.kind.byte());
        bytes.extend_from_slice(&self.body);
        Ok(bytes)
    }
    /// Shared operation identifier.
    #[must_use]
    pub const fn kind(&self) -> FrameKind {
        self.kind
    }
    /// Exact body, including unchanged roster/report/answer content.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }
    fn pair(&self) -> Result<(IdentityKey, IdentityKey), SessionError> {
        Ok((
            identity(self.body.get(..32).ok_or(SessionError::Frame)?)?,
            identity(self.body.get(32..64).ok_or(SessionError::Frame)?)?,
        ))
    }
    fn proof(
        &self,
        participant: IdentityKey,
        exporter: &[u8; 32],
        offset: usize,
    ) -> Result<(), SessionError> {
        let signature = Signature::from_slice(self.body.get(offset..).ok_or(SessionError::Proof)?)
            .map_err(|_| SessionError::Proof)?;
        VerifyingKey::from_bytes(participant.as_bytes())
            .map_err(|_| SessionError::Proof)?
            .verify_strict(&proof_input(exporter), &signature)
            .map_err(|_| SessionError::Proof)
    }
    /// Compare independently provisioned enrollment authority and verify connection possession.
    /// Caller records authorization only after success and applies provisioning policy separately.
    /// # Errors
    /// Refuses wrong operation, pair, enrollment credential or proof.
    pub fn validate_enrollment(
        &self,
        provision: &EnrollmentProvision<'_>,
        exporter: &[u8; 32],
    ) -> Result<(), SessionError> {
        if self.kind != FrameKind::Enroll
            || self.pair()? != (provision.issuer, provision.participant)
        {
            return Err(SessionError::Unauthorized);
        }
        // Compare fixed-length credentials through constant-time MAC verification.
        let mut expected = Hmac::<Sha256>::new_from_slice(provision.credential)
            .map_err(|_| SessionError::Unauthorized)?;
        expected.update(b"ns.participant.enrollment-comparison.v1");
        let mut presented = Hmac::<Sha256>::new_from_slice(&self.body[80..112])
            .map_err(|_| SessionError::Unauthorized)?;
        presented.update(b"ns.participant.enrollment-comparison.v1");
        expected
            .verify_slice(&presented.finalize().into_bytes())
            .map_err(|_| SessionError::Unauthorized)?;
        self.proof(provision.participant, exporter, 112)
    }
    /// Verify the enrolled pair, current authorization and this handshake's proof.
    /// # Errors
    /// Refuses disabled/expired authorization, wrong pair/operation or stale proof.
    pub fn validate_authentication(
        &self,
        authorization: &Authorization,
        exporter: &[u8; 32],
        now_ms: u64,
    ) -> Result<(), SessionError> {
        if self.kind != FrameKind::Authenticate {
            return Err(SessionError::Frame);
        }
        let (issuer, participant) = self.pair()?;
        authorization.validate(issuer, participant, now_ms)?;
        self.proof(participant, exporter, 64)
    }
    /// Validate renewal against an independently authenticated session and current authorization.
    /// # Errors
    /// Refuses a different session pair, wrong operation or revoked/expired authorization.
    pub fn validate_renewal(
        &self,
        authorization: &Authorization,
        authenticated_pair: (IdentityKey, IdentityKey),
        now_ms: u64,
    ) -> Result<(), SessionError> {
        if self.kind != FrameKind::Renew || self.pair()? != authenticated_pair {
            return Err(SessionError::Unauthorized);
        }
        authorization.validate(authenticated_pair.0, authenticated_pair.1, now_ms)
    }
    /// Compare an authenticated TLS response to the client's exact pending operation.
    /// Returned absence supplies no new finite bound and never erases a retained one.
    /// # Errors
    /// Refuses wrong operation, issuer, participant, correlation or expired deadline.
    pub fn validate_response(
        &self,
        pending: &PendingResponse,
        now_ms: u64,
    ) -> Result<Option<u64>, SessionError> {
        if !matches!(pending.kind, FrameKind::Enrolled | FrameKind::Renewed)
            || self.kind != pending.kind
            || pending.correlation == [0; 16]
            || self.pair()? != (pending.issuer, pending.participant)
            || self.body[64..80] != pending.correlation
        {
            return Err(SessionError::Correlation);
        }
        let deadline = credential_deadline(&self.body[80..])?;
        if deadline.is_some_and(|value| now_ms >= value) {
            return Err(SessionError::Unauthorized);
        }
        Ok(deadline)
    }
}
