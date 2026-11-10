//! Typed refusal receipts; authentication and current authority remain distinct.
use super::{
    NodeHeartbeatRequest, NodePostureRequest, NodeReportContext, NodeReportError, NodeRuntimeFence,
};
use crate::account::{
    AccountError,
    codec::require,
    control::{
        BootstrapEnvelope, EnvelopeDirection, EnvelopeExpectation, MembershipScope, NODE_HEARTBEAT,
        NODE_POSTURE,
    },
};
use nsshared_codec::cbor::{CborReader, CborWriter};

/// Maximum encoded bytes in a version-1 Node liveness refusal.
pub const MAX_NODE_LIVENESS_REFUSAL_BYTES: usize = 256;

/// Only these report operations carry a Node liveness refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeLivenessOperation {
    /// Scoped ordinary Node heartbeat.
    Heartbeat,
    /// Complete ordinary Node posture snapshot.
    Posture,
}
impl NodeLivenessOperation {
    /// Exact operation in both the payload and signed carrier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Heartbeat => NODE_HEARTBEAT,
            Self::Posture => NODE_POSTURE,
        }
    }
    fn read(input: &mut CborReader<'_>) -> Result<Self, AccountError> {
        match input.text_up_to(14)? {
            NODE_HEARTBEAT => Ok(Self::Heartbeat),
            NODE_POSTURE => Ok(Self::Posture),
            _ => Err(AccountError::Field),
        }
    }
}

/// Current-authority classification; diagnostic reasons grant no permission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeLivenessRefusalCode {
    /// Current business/enrollment authority is valid; runtime rebind is needed.
    RuntimeRebindRequired,
    /// Committed stop or supersession; automatic takeover is not authorized.
    RuntimeConflict,
    /// Current credential, enrollment or scoped business authority was refused.
    AuthorityRevoked,
}
impl NodeLivenessRefusalCode {
    /// Exact closed wire token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RuntimeRebindRequired => "runtime_rebind_required",
            Self::RuntimeConflict => "runtime_conflict",
            Self::AuthorityRevoked => "authority_revoked",
        }
    }
    /// Required HTTP carrier status; a different status is a protocol failure.
    #[must_use]
    pub const fn http_status(self) -> u16 {
        match self {
            Self::RuntimeRebindRequired | Self::RuntimeConflict => 409,
            Self::AuthorityRevoked => 403,
        }
    }
    fn read(input: &mut CborReader<'_>) -> Result<Self, AccountError> {
        match input.text_up_to(23)? {
            "runtime_rebind_required" => Ok(Self::RuntimeRebindRequired),
            "runtime_conflict" => Ok(Self::RuntimeConflict),
            "authority_revoked" => Ok(Self::AuthorityRevoked),
            _ => Err(AccountError::Field),
        }
    }
}

/// Bounded diagnostic refinement, never an independent recovery authorization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeLivenessRefusalReason {
    /// Presence elapsed while current business/enrollment authority remains valid.
    LeaseElapsed,
    /// NSD authority epoch changed while current business/enrollment authority remains valid.
    AuthorityEpochChanged,
    /// An explicit runtime stop was committed.
    RuntimeStopped,
    /// A replacement runtime superseded the requested runtime.
    RuntimeSuperseded,
    /// Current authority was genuinely refused, without disclosing revocation detail.
    AuthorityChanged,
}
impl NodeLivenessRefusalReason {
    /// Exact closed wire token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LeaseElapsed => "lease_elapsed",
            Self::AuthorityEpochChanged => "authority_epoch_changed",
            Self::RuntimeStopped => "runtime_stopped",
            Self::RuntimeSuperseded => "runtime_superseded",
            Self::AuthorityChanged => "authority_changed",
        }
    }
    fn read(input: &mut CborReader<'_>) -> Result<Self, AccountError> {
        match input.text_up_to(23)? {
            "lease_elapsed" => Ok(Self::LeaseElapsed),
            "authority_epoch_changed" => Ok(Self::AuthorityEpochChanged),
            "runtime_stopped" => Ok(Self::RuntimeStopped),
            "runtime_superseded" => Ok(Self::RuntimeSuperseded),
            "authority_changed" => Ok(Self::AuthorityChanged),
            _ => Err(AccountError::Field),
        }
    }
}

/// Negative receipt for an exact pending heartbeat or posture request.
/// Decoding alone authenticates neither the receipt nor current authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeLivenessRefusal {
    /// Must equal the signed response carrier's operation.
    pub operation: NodeLivenessOperation,
    /// Echo of the rejected request's membership.
    pub scope: MembershipScope,
    /// Echo of the rejected fence, never a replacement runtime or fresh custody.
    pub fence: NodeRuntimeFence,
    /// Nonzero logical heartbeat or snapshot identifier, distinct from outer nonce.
    pub request_id: [u8; 16],
    /// Typed classification determining permitted consumer handling.
    pub code: NodeLivenessRefusalCode,
    /// Diagnostic refinement restricted to the code's legal reasons.
    pub reason: NodeLivenessRefusalReason,
}
impl NodeLivenessRefusal {
    /// Encodes the distinct seven-item version-1 refusal form.
    /// # Errors
    /// Refuses zero identifiers/counters or an illegal code/reason combination.
    pub fn canonical(&self) -> Result<Vec<u8>, AccountError> {
        use NodeLivenessRefusalCode as Code;
        use NodeLivenessRefusalReason as Reason;
        require(self.request_id != [0; 16])?;
        require(matches!(
            (self.code, self.reason),
            (
                Code::RuntimeRebindRequired,
                Reason::LeaseElapsed | Reason::AuthorityEpochChanged
            ) | (
                Code::RuntimeConflict,
                Reason::RuntimeStopped | Reason::RuntimeSuperseded
            ) | (Code::AuthorityRevoked, Reason::AuthorityChanged)
        ))?;
        let mut out = CborWriter::default();
        out.array(7).uint(1).text(self.operation.as_str());
        self.scope.write(&mut out);
        self.fence.write(&mut out)?;
        out.bytes(&self.request_id)
            .text(self.code.as_str())
            .text(self.reason.as_str());
        Ok(out.into_bytes())
    }
    /// Decodes only a bounded, canonical version-1 refusal with exact arities.
    /// # Errors
    /// Refuses malformed, noncanonical, unknown, invalid or oversized input.
    pub fn decode(bytes: &[u8]) -> Result<Self, AccountError> {
        let mut input = CborReader::new(bytes, MAX_NODE_LIVENESS_REFUSAL_BYTES)?;
        input.array(7)?;
        require(input.uint()? == 1)?;
        let value = Self {
            operation: NodeLivenessOperation::read(&mut input)?,
            scope: MembershipScope::read(&mut input)?,
            fence: NodeRuntimeFence::read(&mut input)?,
            request_id: input.fixed_bytes()?,
            code: NodeLivenessRefusalCode::read(&mut input)?,
            reason: NodeLivenessRefusalReason::read(&mut input)?,
        };
        input.finish()?;
        value.canonical()?;
        Ok(value)
    }
    /// Correlates with the complete retained heartbeat after carrier verification.
    /// # Errors
    /// Refuses invalid content or any operation, membership, fence or ID mismatch.
    pub fn validate_for_heartbeat(
        &self,
        pending: &NodeHeartbeatRequest,
    ) -> Result<(), AccountError> {
        pending.canonical()?;
        self.validate_for(
            NodeLivenessOperation::Heartbeat,
            &pending.scope,
            &pending.fence,
            pending.heartbeat.request_id,
        )
    }
    /// Correlates with the complete retained posture request after carrier verification.
    /// # Errors
    /// Refuses invalid content or any operation, membership, fence or ID mismatch.
    pub fn validate_for_posture(&self, pending: &NodePostureRequest) -> Result<(), AccountError> {
        pending.canonical()?;
        self.validate_for(
            NodeLivenessOperation::Posture,
            &pending.scope,
            &pending.fence,
            pending.request_id,
        )
    }
    fn validate_for(
        &self,
        operation: NodeLivenessOperation,
        scope: &MembershipScope,
        fence: &NodeRuntimeFence,
        request_id: [u8; 16],
    ) -> Result<(), AccountError> {
        self.canonical()?;
        require(
            self.operation == operation
                && &self.scope == scope
                && &self.fence == fence
                && self.request_id == request_id,
        )
    }
}

impl NodeReportContext {
    /// Verifies a refusal's signed response, persisted custody, nonce and HTTP status.
    /// Then call its operation-specific correlation method with the retained request.
    /// The consumer records replay acceptance atomically and classifies current authority.
    /// # Errors
    /// Refuses authentication, direction, signer, recipient, kind, scope, nonce or status mismatch.
    pub fn validate_liveness_refusal(
        &self,
        envelope: &BootstrapEnvelope,
        expected: &EnvelopeExpectation<'_>,
        pending_nonce: [u8; 16],
        http_status: u16,
    ) -> Result<NodeLivenessRefusal, NodeReportError> {
        envelope.verify(expected)?;
        if expected.direction != EnvelopeDirection::Response {
            return Err(NodeReportError::Operation);
        }
        if envelope.signer != self.authority {
            return Err(NodeReportError::Authority);
        }
        if expected.recipient != self.subject || envelope.recipient != Some(self.subject) {
            return Err(NodeReportError::Subject);
        }
        let refusal = NodeLivenessRefusal::decode(&envelope.payload)?;
        if envelope.kind != refusal.operation.as_str() {
            return Err(NodeReportError::Operation);
        }
        if refusal.scope != self.scope {
            return Err(NodeReportError::Scope);
        }
        require(envelope.nonce == pending_nonce && http_status == refusal.code.http_status())?;
        Ok(refusal)
    }
}
