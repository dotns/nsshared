//! Pure interrupted-capture commands; results never confer roster or custody authority.

use super::participant_roster::ParticipantRosterScope;
use super::session::{Frame, FrameKind, SessionError, exporter_context};
use nsshared_identity::keys::IdentityKey;

const REQUEST_LEN: usize = 97;
const RESULT_LEN: usize = 122;
const VERSION: u8 = 1;

/// Version-1 recovery outcomes; discriminants are the exact wire bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum EpochOutcome {
    /// The authority committed a fresh epoch.
    Allocated = 0,
    /// An independently newer or previously allocated epoch satisfies the request.
    AlreadyFresh = 1,
    /// Another attempt must wait until the supplied not-before time.
    RateLimited = 2,
    /// The accepted session custody is no longer current.
    StaleCustody = 3,
    /// The fenced epoch is invalid for this command.
    InvalidEpoch = 4,
    /// No successful allocation receipt is available.
    Unavailable = 5,
}
impl EpochOutcome {
    /// Decode a known outcome without interpreting it as authority.
    #[must_use]
    pub const fn from_byte(byte: u8) -> Option<Self> {
        Some(match byte {
            0 => Self::Allocated,
            1 => Self::AlreadyFresh,
            2 => Self::RateLimited,
            3 => Self::StaleCustody,
            4 => Self::InvalidEpoch,
            5 => Self::Unavailable,
            _ => return None,
        })
    }

    /// Exact wire outcome byte.
    #[must_use]
    pub const fn byte(self) -> u8 {
        self as u8
    }
}

/// A validated request to recover interrupted capture under unchanged custody.
///
/// ```
/// use nsshared_control::account::relay::{
///     EpochOutcome, EpochRequest, EpochResult, ParticipantRosterScope, PendingEpochResponse,
/// };
/// use nsshared_identity::keys::IdentitySecret;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let scope = ParticipantRosterScope {
///     issuer: IdentitySecret::from_seed([1; 32]).public(),
///     recipient: IdentitySecret::from_seed([2; 32]).public(),
/// };
/// let request = EpochRequest::new(scope, [6; 16], 17, 23)?;
/// let pending = PendingEpochResponse::new(request);
/// let result = EpochResult::new(request, EpochOutcome::Allocated, 24, 1, 0)?;
/// EpochResult::decode(&result.canonical()?)?.validate_for(&pending)?;
/// // Adoption still requires a separately verified signed roster and durable floors.
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EpochRequest {
    scope: ParticipantRosterScope,
    correlation: [u8; 16],
    owner_generation: u64,
    fenced_epoch: u64,
}
impl EpochRequest {
    /// Construct the sole version-1 intent, `interrupted_capture`.
    /// # Errors
    /// Refuses zero correlation, generation or fenced epoch.
    pub fn new(
        scope: ParticipantRosterScope,
        correlation: [u8; 16],
        owner_generation: u64,
        fenced_epoch: u64,
    ) -> Result<Self, SessionError> {
        if correlation == [0; 16] || owner_generation == 0 || fenced_epoch == 0 {
            return Err(SessionError::Frame);
        }
        Ok(Self {
            scope,
            correlation,
            owner_generation,
            fenced_epoch,
        })
    }

    /// Decode an exact complete EpochRequest frame.
    /// # Errors
    /// Refuses any other kind, malformed fields, version, lengths or trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, SessionError> {
        Self::from_frame(&Frame::decode(bytes)?)
    }

    /// Read a validated frame without granting session authorization.
    /// # Errors
    /// Refuses other operations.
    pub fn from_frame(frame: &Frame) -> Result<Self, SessionError> {
        if frame.kind() != FrameKind::EpochRequest {
            return Err(SessionError::Frame);
        }
        Self::from_body(frame.body())
    }

    fn from_body(body: &[u8]) -> Result<Self, SessionError> {
        if body.len() != REQUEST_LEN {
            return Err(SessionError::Frame);
        }
        if body[80] != VERSION {
            return Err(SessionError::Version);
        }
        let scope = ParticipantRosterScope {
            issuer: IdentityKey::try_from(&body[..32]).map_err(|_| SessionError::Frame)?,
            recipient: IdentityKey::try_from(&body[32..64]).map_err(|_| SessionError::Frame)?,
        };
        Self::new(
            scope,
            body[64..80].try_into().map_err(|_| SessionError::Frame)?,
            read_u64(&body[81..89])?,
            read_u64(&body[89..97])?,
        )
    }

    fn body(self) -> Vec<u8> {
        let mut body = exporter_context(self.scope.issuer, self.scope.recipient).to_vec();
        body.extend_from_slice(&self.correlation);
        body.push(VERSION);
        body.extend_from_slice(&self.owner_generation.to_be_bytes());
        body.extend_from_slice(&self.fenced_epoch.to_be_bytes());
        body
    }

    /// Construct its exact participant frame.
    /// # Errors
    /// Refuses invalid frame fields or bounds.
    pub fn frame(&self) -> Result<Frame, SessionError> {
        Frame::new(FrameKind::EpochRequest, self.body())
    }

    /// Encode the complete canonical frame, including length and kind.
    /// # Errors
    /// Refuses invalid frame fields or bounds.
    pub fn canonical(&self) -> Result<Vec<u8>, SessionError> {
        self.frame()?.canonical()
    }

    /// Compare independently authenticated scope and accepted session generation.
    /// Current authorization, epoch validity and allocation remain caller-owned.
    /// # Errors
    /// Refuses another pair or generation; it cannot authorize a custody update.
    pub fn validate_for(
        &self,
        authenticated_scope: ParticipantRosterScope,
        accepted_owner_generation: u64,
    ) -> Result<(), SessionError> {
        if self.scope != authenticated_scope || self.owner_generation != accepted_owner_generation {
            return Err(SessionError::Correlation);
        }
        Ok(())
    }

    /// Expected issuer and participant, not newly authenticated metadata.
    #[must_use]
    pub const fn scope(&self) -> ParticipantRosterScope {
        self.scope
    }
    /// Nonzero identifier of one transport exchange, not its semantic idempotency key.
    #[must_use]
    pub const fn correlation(&self) -> [u8; 16] {
        self.correlation
    }
    /// Expected accepted session custody; never a requested replacement generation.
    #[must_use]
    pub const fn owner_generation(&self) -> u64 {
        self.owner_generation
    }
    /// Positive epoch whose interrupted capture is fenced locally.
    #[must_use]
    pub const fn fenced_epoch(&self) -> u64 {
        self.fenced_epoch
    }
}

/// Exact pending recovery exchange, distinct from enrollment and renewal pending state.
/// The session driver owns cancellation and single consumption, including on reconnect.
/// Renewal pending state cannot validate an epoch result:
///
/// ```compile_fail
/// use nsshared_control::account::relay::{EpochResult, PendingResponse};
/// fn wrong_operation(result: &EpochResult, pending: &PendingResponse) {
///     result.validate_for(pending);
/// }
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PendingEpochResponse {
    request: EpochRequest,
}
impl PendingEpochResponse {
    /// Retain the complete validated request on the same authenticated connection.
    #[must_use]
    pub const fn new(request: EpochRequest) -> Self {
        Self { request }
    }

    /// Exact pending request; none of its fields are new authority.
    #[must_use]
    pub const fn request(&self) -> &EpochRequest {
        &self.request
    }
}

/// A validated command result. Only a separately verified signed roster permits epoch adoption.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EpochResult {
    request: EpochRequest,
    outcome: EpochOutcome,
    result_epoch: u64,
    publication_version: u64,
    retry_not_before_unix_ms: u64,
}
impl EpochResult {
    /// Echo the request, including stale custody, with strictly shaped outcome fields.
    /// # Errors
    /// Refuses non-advancing success, zero publication, or forbidden/missing retry fields.
    pub fn new(
        request: EpochRequest,
        outcome: EpochOutcome,
        result_epoch: u64,
        publication_version: u64,
        retry_not_before_unix_ms: u64,
    ) -> Result<Self, SessionError> {
        let valid = match outcome {
            EpochOutcome::Allocated | EpochOutcome::AlreadyFresh => {
                result_epoch > request.fenced_epoch
                    && publication_version > 0
                    && retry_not_before_unix_ms == 0
            }
            EpochOutcome::RateLimited => {
                result_epoch == 0 && publication_version == 0 && retry_not_before_unix_ms > 0
            }
            EpochOutcome::StaleCustody | EpochOutcome::InvalidEpoch | EpochOutcome::Unavailable => {
                result_epoch == 0 && publication_version == 0 && retry_not_before_unix_ms == 0
            }
        };
        if !valid {
            return Err(SessionError::Frame);
        }
        Ok(Self {
            request,
            outcome,
            result_epoch,
            publication_version,
            retry_not_before_unix_ms,
        })
    }

    /// Decode an exact complete EpochResult frame.
    /// # Errors
    /// Refuses another kind, wrong version, malformed fields, lengths or trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, SessionError> {
        Self::from_frame(&Frame::decode(bytes)?)
    }

    /// Read a validated frame; the echoed generation grants no new custody.
    /// # Errors
    /// Refuses other operations.
    pub fn from_frame(frame: &Frame) -> Result<Self, SessionError> {
        if frame.kind() != FrameKind::EpochResult {
            return Err(SessionError::Frame);
        }
        Self::from_body(frame.body())
    }

    fn from_body(body: &[u8]) -> Result<Self, SessionError> {
        if body.len() != RESULT_LEN {
            return Err(SessionError::Frame);
        }
        Self::new(
            EpochRequest::from_body(&body[..REQUEST_LEN])?,
            EpochOutcome::from_byte(body[97]).ok_or(SessionError::Frame)?,
            read_u64(&body[98..106])?,
            read_u64(&body[106..114])?,
            read_u64(&body[114..122])?,
        )
    }

    /// Construct its exact participant frame.
    /// # Errors
    /// Refuses invalid frame fields or bounds.
    pub fn frame(&self) -> Result<Frame, SessionError> {
        let mut body = self.request.body();
        body.push(self.outcome.byte());
        body.extend_from_slice(&self.result_epoch.to_be_bytes());
        body.extend_from_slice(&self.publication_version.to_be_bytes());
        body.extend_from_slice(&self.retry_not_before_unix_ms.to_be_bytes());
        Frame::new(FrameKind::EpochResult, body)
    }

    /// Encode the complete canonical frame, including length and kind.
    /// # Errors
    /// Refuses invalid frame fields or bounds.
    pub fn canonical(&self) -> Result<Vec<u8>, SessionError> {
        self.frame()?.canonical()
    }

    /// Compare every pending field without consuming deadlines or granting authority.
    /// The caller must reject unsolicited/duplicate results and consume the exchange once.
    /// # Errors
    /// Refuses a different pair, correlation, generation or fenced epoch.
    pub fn validate_for(&self, pending: &PendingEpochResponse) -> Result<(), SessionError> {
        if self.request != pending.request {
            return Err(SessionError::Correlation);
        }
        Ok(())
    }

    /// Exact echoed command, even for StaleCustody.
    #[must_use]
    pub const fn request(&self) -> &EpochRequest {
        &self.request
    }
    /// Command outcome; success is not roster authority or a usage/seal acknowledgement.
    #[must_use]
    pub const fn outcome(&self) -> EpochOutcome {
        self.outcome
    }
    /// Committed decision's epoch, possibly from an older idempotent receipt.
    #[must_use]
    pub const fn result_epoch(&self) -> u64 {
        self.result_epoch
    }
    /// Committed decision's publication, without a claim that it is live or latest.
    #[must_use]
    pub const fn publication_version(&self) -> u64 {
        self.publication_version
    }
    /// Not-before time for the next allocation attempt; recheck against the caller's clock.
    #[must_use]
    pub const fn retry_not_before_unix_ms(&self) -> u64 {
        self.retry_not_before_unix_ms
    }
}

fn read_u64(bytes: &[u8]) -> Result<u64, SessionError> {
    Ok(u64::from_be_bytes(
        bytes.try_into().map_err(|_| SessionError::Frame)?,
    ))
}

pub(super) fn validate_body(kind: FrameKind, body: &[u8]) -> Result<(), SessionError> {
    match kind {
        FrameKind::EpochRequest => EpochRequest::from_body(body).map(|_| ()),
        FrameKind::EpochResult => EpochResult::from_body(body).map(|_| ()),
        _ => Err(SessionError::Frame),
    }
}
