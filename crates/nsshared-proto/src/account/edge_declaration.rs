//! Correlated service requests and replies carrying exact existing M6 bytes.

use nsshared_service_control::{Declaration, Digest, ListenerIntent, ReportContent, domain_digest};

use super::{AccountError, MAX_BYTES, bounded, identity, reader, require};
use crate::{IdentityKey, encoding::CborWriter};

/// Existing M6 object carried by a confidential service operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EdgeServiceBody {
    /// One private service declaration.
    Declaration(Declaration),
    /// Complete service declaration report.
    Report(ReportContent),
    /// Exact publisher listener intent.
    Listener(ListenerIntent),
}

impl EdgeServiceBody {
    /// Stable operation discriminator, without introducing another M6 message kind.
    #[must_use]
    pub const fn kind(&self) -> u64 {
        match self {
            Self::Declaration(_) => 0,
            Self::Report(_) => 1,
            Self::Listener(_) => 2,
        }
    }

    /// Returns unchanged M6 canonical bytes and their correlation digest.
    ///
    /// # Errors
    /// Rejects invalid nested M6 values.
    pub fn canonical(&self) -> Result<(Vec<u8>, Digest), AccountError> {
        match self {
            Self::Declaration(value) => {
                let bytes = value.canonical().map_err(|_| AccountError::InvalidField)?;
                let digest = domain_digest("ns.account.declaration.v1", &bytes);
                Ok((bytes, digest))
            }
            Self::Report(value) => value.canonical().map_err(|_| AccountError::InvalidField),
            Self::Listener(value) => value.canonical().map_err(|_| AccountError::InvalidField),
        }
    }
}

/// Complete service operation context retained until an authenticated reply.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EdgeServiceRequest {
    /// Stable request identity.
    pub request_id: [u8; 16],
    /// Full publisher identity, never an address or display name.
    pub publisher: IdentityKey,
    /// Exact M6 NSD identifier.
    pub nsd_id: [u8; 16],
    /// Exact M6 Network identifier.
    pub network_id: [u8; 16],
    /// Positive content revision.
    pub revision: u64,
    /// Existing object and its exact serializer.
    pub body: EdgeServiceBody,
}

impl EdgeServiceRequest {
    /// Encodes scope and correlation metadata around unchanged M6 bytes.
    ///
    /// # Errors
    /// Rejects invalid bodies, mismatched ownership/scope/revision or bounds.
    pub fn canonical(&self) -> Result<Vec<u8>, AccountError> {
        require(self.revision > 0)?;
        match &self.body {
            EdgeServiceBody::Declaration(_) => {}
            EdgeServiceBody::Report(value) => require(
                value.publisher_identity == *self.publisher.as_bytes()
                    && value.nsd_id == self.nsd_id
                    && value.network_id == self.network_id,
            )?,
            EdgeServiceBody::Listener(value) => require(
                value.publisher_identity == *self.publisher.as_bytes()
                    && value.service_ref.nsd_id == self.nsd_id
                    && value.service_ref.network_id == self.network_id
                    && value.listener_revision == self.revision,
            )?,
        }
        let (bytes, digest) = self.body.canonical()?;
        let mut out = CborWriter::default();
        out.array(9)
            .uint(1)
            .bytes(&self.request_id)
            .bytes(self.publisher.as_bytes())
            .bytes(&self.nsd_id)
            .bytes(&self.network_id)
            .uint(self.revision)
            .uint(self.body.kind())
            .bytes(&bytes)
            .bytes(&digest);
        bounded(out.into_bytes())
    }

    /// Decodes and validates metadata and delegates the body to its M6 decoder.
    ///
    /// # Errors
    /// Rejects malformed/noncanonical values, ownership or digest mismatch.
    pub fn decode(bytes: &[u8]) -> Result<Self, AccountError> {
        let mut input = reader(bytes, 9)?;
        let request_id = input.fixed_bytes()?;
        let publisher = identity(&mut input)?;
        let nsd_id = input.fixed_bytes()?;
        let network_id = input.fixed_bytes()?;
        let revision = input.uint()?;
        let kind = input.uint()?;
        let raw = input.bytes_up_to(MAX_BYTES)?;
        let body = match kind {
            0 => EdgeServiceBody::Declaration(
                Declaration::decode(raw).map_err(|_| AccountError::InvalidField)?,
            ),
            1 => EdgeServiceBody::Report(
                ReportContent::decode(raw).map_err(|_| AccountError::InvalidField)?,
            ),
            2 => EdgeServiceBody::Listener(
                ListenerIntent::decode(raw).map_err(|_| AccountError::InvalidField)?,
            ),
            _ => return Err(AccountError::InvalidField),
        };
        let digest: Digest = input.fixed_bytes()?;
        input.finish()?;
        require(body.canonical()?.1 == digest)?;
        let value = Self {
            request_id,
            publisher,
            nsd_id,
            network_id,
            revision,
            body,
        };
        value.canonical()?;
        Ok(value)
    }
}

/// Authenticated service response and ACK, without listener-readiness semantics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EdgeServiceResponse {
    /// Correlated pending operation.
    pub request_id: [u8; 16],
    /// Exact publisher.
    pub publisher: IdentityKey,
    /// Exact M6 NSD scope.
    pub nsd_id: [u8; 16],
    /// Exact M6 Network scope.
    pub network_id: [u8; 16],
    /// Exact accepted/rejected revision.
    pub revision: u64,
    /// Request body discriminator, 0 declaration, 1 report, 2 listener.
    pub body_kind: u64,
    /// Exact request digest, unchanged for M6 report/listener bodies.
    pub digest: Digest,
    /// True means content accepted, false explicitly rejected.
    pub accepted: bool,
}

impl EdgeServiceResponse {
    /// Encodes an explicit scoped response with no default status.
    ///
    /// # Errors
    /// Rejects zero revisions, unknown body kinds and oversized input.
    pub fn canonical(&self) -> Result<Vec<u8>, AccountError> {
        require(self.revision > 0 && self.body_kind <= 2)?;
        let mut out = CborWriter::default();
        out.array(9)
            .uint(1)
            .bytes(&self.request_id)
            .bytes(self.publisher.as_bytes())
            .bytes(&self.nsd_id)
            .bytes(&self.network_id)
            .uint(self.revision)
            .uint(self.body_kind)
            .bytes(&self.digest)
            .uint(u64::from(!self.accepted));
        bounded(out.into_bytes())
    }

    /// Decodes an exact explicit accepted/rejected service response.
    ///
    /// # Errors
    /// Rejects malformed/noncanonical metadata and unknown discriminants.
    pub fn decode(bytes: &[u8]) -> Result<Self, AccountError> {
        let mut input = reader(bytes, 9)?;
        let request_id = input.fixed_bytes()?;
        let publisher = identity(&mut input)?;
        let nsd_id = input.fixed_bytes()?;
        let network_id = input.fixed_bytes()?;
        let revision = input.uint()?;
        let body_kind = input.uint()?;
        let digest = input.fixed_bytes()?;
        let accepted = match input.uint()? {
            0 => true,
            1 => false,
            _ => return Err(AccountError::InvalidField),
        };
        input.finish()?;
        let value = Self {
            request_id,
            publisher,
            nsd_id,
            network_id,
            revision,
            body_kind,
            digest,
            accepted,
        };
        value.canonical()?;
        Ok(value)
    }

    /// Matches every correlation field against an externally retained request.
    ///
    /// # Errors
    /// Rejects mismatched request, scope, ownership, kind, revision or digest.
    /// Explicit rejection is a matching response whose accepted flag stays false.
    pub fn validate_request(&self, request: &EdgeServiceRequest) -> Result<(), AccountError> {
        self.canonical()?;
        request.canonical()?;
        require(
            self.request_id == request.request_id
                && self.publisher == request.publisher
                && self.nsd_id == request.nsd_id
                && self.network_id == request.network_id
                && self.revision == request.revision
                && self.body_kind == request.body.kind()
                && self.digest == request.body.canonical()?.1,
        )
    }
}
