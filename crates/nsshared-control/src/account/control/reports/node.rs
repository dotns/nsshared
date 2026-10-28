//! Ordinary Node liveness contracts and persisted-context validation.
use super::{ControlReportOperation, HeartbeatRequest, HeartbeatResponse};
use crate::{
    account::AccountError,
    account::MAX_BYTES,
    account::codec::{bounded, reader, require},
    account::control::{
        BootstrapEnvelope, BootstrapError, EnvelopeDirection, EnvelopeExpectation, MembershipScope,
    },
    service::Id,
};
use nsshared_codec::{cbor::CborReader, cbor::CborWriter};
use nsshared_identity::keys::IdentityKey;
use thiserror::Error;

/// Accepted runtime identity; freshness is checked against consumer storage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeRuntimeFence {
    /// Nonzero identifier from the accepted service runtime.
    pub runtime_id: Id,
    /// Positive persistent runtime generation.
    pub runtime_generation: u64,
    /// Positive accepted authority epoch.
    pub authority_epoch: u64,
}
impl NodeRuntimeFence {
    fn write(&self, out: &mut CborWriter) -> Result<(), AccountError> {
        require(
            self.runtime_id != [0; 16] && self.runtime_generation > 0 && self.authority_epoch > 0,
        )?;
        out.array(3)
            .bytes(&self.runtime_id)
            .uint(self.runtime_generation)
            .uint(self.authority_epoch);
        Ok(())
    }
    fn read(input: &mut CborReader<'_>) -> Result<Self, AccountError> {
        input.array(3)?;
        Ok(Self {
            runtime_id: input.fixed_bytes()?,
            runtime_generation: input.uint()?,
            authority_epoch: input.uint()?,
        })
    }
}

/// Ordinary Node liveness observations within one accepted membership/runtime.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeHeartbeatRequest {
    /// Exact accepted provisioned membership IDs.
    pub scope: MembershipScope,
    /// Accepted runtime fence, not an assertion of freshness.
    pub fence: NodeRuntimeFence,
    /// Existing process observations and pending request identifier.
    pub heartbeat: HeartbeatRequest,
}
impl NodeHeartbeatRequest {
    /// Encodes bounded membership, fence and observations.
    /// # Errors
    /// Refuses invalid runtime shape or heartbeat fields and oversized input.
    pub fn canonical(&self) -> Result<Vec<u8>, AccountError> {
        let mut out = CborWriter::default();
        out.array(4).uint(1);
        self.scope.write(&mut out);
        self.fence.write(&mut out)?;
        out.bytes(&self.heartbeat.canonical()?);
        bounded(out.into_bytes())
    }
    /// Decodes the exact Node form, distinct from gateway heartbeat bytes.
    /// # Errors
    /// Refuses wrong arity, version, malformed fields and excessive bounds.
    pub fn decode(bytes: &[u8]) -> Result<Self, AccountError> {
        let mut input = reader(bytes, 4)?;
        let value = Self {
            scope: MembershipScope::read(&mut input)?,
            fence: NodeRuntimeFence::read(&mut input)?,
            heartbeat: HeartbeatRequest::decode(input.bytes_up_to(MAX_BYTES)?)?,
        };
        input.finish()?;
        value.canonical()?;
        Ok(value)
    }
}

/// Receipt for an exact Node heartbeat membership and runtime.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeHeartbeatResponse {
    /// Echo of the accepted request membership.
    pub scope: MembershipScope,
    /// Echo of the accepted request runtime fence.
    pub fence: NodeRuntimeFence,
    /// Exact request receipt and inert feature observations.
    pub heartbeat: HeartbeatResponse,
}
impl NodeHeartbeatResponse {
    /// Encodes the bounded receipt.
    /// # Errors
    /// Refuses invalid runtime shape, features or bounds.
    pub fn canonical(&self) -> Result<Vec<u8>, AccountError> {
        let mut out = CborWriter::default();
        out.array(4).uint(1);
        self.scope.write(&mut out);
        self.fence.write(&mut out)?;
        out.bytes(&self.heartbeat.canonical()?);
        bounded(out.into_bytes())
    }
    /// Decodes the exact Node receipt.
    /// # Errors
    /// Refuses malformed, noncanonical or oversized values.
    pub fn decode(bytes: &[u8]) -> Result<Self, AccountError> {
        let mut input = reader(bytes, 4)?;
        let value = Self {
            scope: MembershipScope::read(&mut input)?,
            fence: NodeRuntimeFence::read(&mut input)?,
            heartbeat: HeartbeatResponse::decode(input.bytes_up_to(MAX_BYTES)?)?,
        };
        input.finish()?;
        value.canonical()?;
        Ok(value)
    }
    /// Correlates a receipt with its retained request, without renewing a lease.
    /// # Errors
    /// Refuses any scope, runtime or request identifier difference.
    pub fn validate_for(&self, pending: &NodeHeartbeatRequest) -> Result<(), AccountError> {
        self.canonical()?;
        pending.canonical()?;
        require(self.scope == pending.scope && self.fence == pending.fence)?;
        self.heartbeat.validate_for(&pending.heartbeat)
    }
}

/// Intent to disconnect one exact ordinary Node runtime.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeDisconnectRequest {
    /// Exact accepted provisioned membership IDs.
    pub scope: MembershipScope,
    /// Runtime to disconnect; current custody is compared by the consumer.
    pub fence: NodeRuntimeFence,
    /// Node-minted pending request identifier.
    pub request_id: [u8; 16],
}
impl NodeDisconnectRequest {
    /// Encodes the scoped disconnect intent.
    /// # Errors
    /// Refuses an invalid runtime fence.
    pub fn canonical(&self) -> Result<Vec<u8>, AccountError> {
        let mut out = CborWriter::default();
        out.array(4).uint(1);
        self.scope.write(&mut out);
        self.fence.write(&mut out)?;
        out.bytes(&self.request_id);
        bounded(out.into_bytes())
    }
    /// Decodes a bounded canonical disconnect intent.
    /// # Errors
    /// Refuses malformed, noncanonical or invalid runtime fields.
    pub fn decode(bytes: &[u8]) -> Result<Self, AccountError> {
        let mut input = reader(bytes, 4)?;
        let value = Self {
            scope: MembershipScope::read(&mut input)?,
            fence: NodeRuntimeFence::read(&mut input)?,
            request_id: input.fixed_bytes()?,
        };
        input.finish()?;
        value.canonical()?;
        Ok(value)
    }
}

/// Receipt of the exact disconnect intent after consumer commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeDisconnectResponse {
    /// Exact accepted request, including scope and runtime fence.
    pub request: NodeDisconnectRequest,
}
impl NodeDisconnectResponse {
    /// Encodes an exact receipt.
    /// # Errors
    /// Refuses an invalid nested request.
    pub fn canonical(&self) -> Result<Vec<u8>, AccountError> {
        let mut out = CborWriter::default();
        out.array(2).uint(1).bytes(&self.request.canonical()?);
        bounded(out.into_bytes())
    }
    /// Decodes a canonical receipt.
    /// # Errors
    /// Refuses malformed, noncanonical or invalid nested request bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, AccountError> {
        let mut input = reader(bytes, 2)?;
        let value = Self {
            request: NodeDisconnectRequest::decode(input.bytes_up_to(MAX_BYTES)?)?,
        };
        input.finish()?;
        value.canonical()?;
        Ok(value)
    }
    /// Correlates every field with a retained request.
    /// # Errors
    /// Refuses invalid fields or any mismatch.
    pub fn validate_for(&self, pending: &NodeDisconnectRequest) -> Result<(), AccountError> {
        self.canonical()?;
        pending.canonical()?;
        require(&self.request == pending)
    }
}

/// Trusted membership and endpoint identities read from persisted consumer state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeReportContext {
    /// Accepted membership from enrollment and source custody, never the request.
    pub scope: MembershipScope,
    /// Enrolled Node signing identity.
    pub subject: IdentityKey,
    /// Trusted NSD signing identity for the accepted membership.
    pub authority: IdentityKey,
}
/// Typed carrier, contract or persisted-context refusal.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum NodeReportError {
    /// Existing carrier authentication failed.
    #[error(transparent)]
    Envelope(#[from] BootstrapError),
    /// Canonical contract decoding failed.
    #[error(transparent)]
    Contract(#[from] AccountError),
    /// Operation or direction is not a Node liveness request.
    #[error("invalid Node report operation or direction")]
    Operation,
    /// Signer differs from the enrolled Node.
    #[error("Node report subject mismatch")]
    Subject,
    /// Recipient differs from the persisted NSD authority or is absent.
    #[error("Node report authority mismatch")]
    Authority,
    /// Either provisioned membership identifier differs.
    #[error("Node report membership scope mismatch")]
    Scope,
}
impl NodeReportContext {
    /// Authenticates a Node liveness request against persisted membership custody.
    /// Runtime freshness and durable effects remain the consumer's responsibility.
    /// # Errors
    /// Refuses authentication, operation, subject, authority, scope or shape mismatch.
    pub fn validate_envelope(
        &self,
        operation: ControlReportOperation,
        envelope: &BootstrapEnvelope,
        expected: &EnvelopeExpectation<'_>,
    ) -> Result<(), NodeReportError> {
        envelope.verify(expected)?;
        if envelope.direction != EnvelopeDirection::Request || envelope.kind != operation.as_str() {
            return Err(NodeReportError::Operation);
        }
        let scope = match operation {
            ControlReportOperation::NodeHeartbeat => {
                NodeHeartbeatRequest::decode(&envelope.payload)?.scope
            }
            ControlReportOperation::NodeDisconnect => {
                NodeDisconnectRequest::decode(&envelope.payload)?.scope
            }
            _ => return Err(NodeReportError::Operation),
        };
        if envelope.signer != self.subject {
            return Err(NodeReportError::Subject);
        }
        if envelope.recipient != Some(self.authority) {
            return Err(NodeReportError::Authority);
        }
        if scope != self.scope {
            return Err(NodeReportError::Scope);
        }
        Ok(())
    }
}
