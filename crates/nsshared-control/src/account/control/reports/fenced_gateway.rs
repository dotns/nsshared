//! Gateway observations bound to accepted membership and runtime custody.
use super::{GatewayReport, GatewayReportResponse, NodeRuntimeFence};
use crate::account::{
    AccountError, MAX_BYTES,
    codec::{bounded, reader, require},
    control::MembershipScope,
};
use nsshared_codec::cbor::CborWriter;

/// Gateway report or drain intent for one accepted membership and runtime.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FencedGatewayReportRequest {
    /// Exact accepted membership from registration and source custody.
    pub scope: MembershipScope,
    /// Accepted runtime; the consumer compares freshness with persisted custody.
    pub fence: NodeRuntimeFence,
    /// Unchanged observations, including the pending request identifier.
    pub report: GatewayReport,
}
impl FencedGatewayReportRequest {
    /// Encodes the scoped report, retaining its existing canonical bytes.
    /// # Errors
    /// Refuses invalid runtime fields, observations or excessive bounds.
    pub fn canonical(&self) -> Result<Vec<u8>, AccountError> {
        let mut out = CborWriter::default();
        out.array(4).uint(1);
        self.scope.write(&mut out);
        self.fence.write(&mut out)?;
        out.bytes(&self.report.canonical()?);
        bounded(out.into_bytes())
    }
    /// Decodes one exact canonical scoped report.
    /// # Errors
    /// Refuses malformed, noncanonical, invalid or oversized fields.
    pub fn decode(bytes: &[u8]) -> Result<Self, AccountError> {
        let mut input = reader(bytes, 4)?;
        let value = Self {
            scope: MembershipScope::read(&mut input)?,
            fence: NodeRuntimeFence::read(&mut input)?,
            report: GatewayReport::decode(input.bytes_up_to(MAX_BYTES)?)?,
        };
        input.finish()?;
        value.canonical()?;
        Ok(value)
    }
}

/// Existing gateway receipt bound to the accepted scope and runtime.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FencedGatewayReportResponse {
    /// Echo of the accepted membership.
    pub scope: MembershipScope,
    /// Echo of the accepted runtime fence.
    pub fence: NodeRuntimeFence,
    /// Unchanged operation result carrying the exact request identifier.
    pub response: GatewayReportResponse,
}
impl FencedGatewayReportResponse {
    /// Encodes the scoped receipt with the existing operation result.
    /// # Errors
    /// Refuses invalid runtime fields.
    pub fn canonical(&self) -> Result<Vec<u8>, AccountError> {
        let mut out = CborWriter::default();
        out.array(4).uint(1);
        self.scope.write(&mut out);
        self.fence.write(&mut out)?;
        out.bytes(&self.response.canonical()?);
        bounded(out.into_bytes())
    }
    /// Decodes one exact canonical scoped receipt.
    /// # Errors
    /// Refuses malformed, noncanonical or invalid fields.
    pub fn decode(bytes: &[u8]) -> Result<Self, AccountError> {
        let mut input = reader(bytes, 4)?;
        let value = Self {
            scope: MembershipScope::read(&mut input)?,
            fence: NodeRuntimeFence::read(&mut input)?,
            response: GatewayReportResponse::decode(input.bytes_up_to(MAX_BYTES)?)?,
        };
        input.finish()?;
        value.canonical()?;
        Ok(value)
    }
    /// Correlates membership, runtime and receipt with the exact pending report.
    /// # Errors
    /// Refuses invalid fields or any scope, runtime or request identifier mismatch.
    pub fn validate_for(&self, pending: &FencedGatewayReportRequest) -> Result<(), AccountError> {
        self.canonical()?;
        pending.canonical()?;
        require(self.scope == pending.scope && self.fence == pending.fence)?;
        self.response.validate_for(&pending.report)
    }
}
