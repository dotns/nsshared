//! Private ordinary record evidence, independent of relay publication and grants.

use crate::{
    account::{
        AccountError,
        codec::{ensure, reader, require},
        control::{
            BootstrapEnvelope, EnvelopeDirection, EnvelopeExpectation, ExchangeError,
            MembershipScope, NODE_RECORD_REPORT, NodeReportContext, NodeRuntimeFence,
            RegistrationCondition,
        },
        node::NodeBinding,
        publication::{MAX_SOURCE_BYTES, SignedSourceBinding},
    },
    service::domain_digest,
};
use nsshared_codec::cbor::CborWriter;
use nsshared_identity::{constants::MAX_NODE_RECORD_BYTES, realm::RealmId, record::NodeRecord};

/// Inclusive ceiling for the complete canonical request payload.
pub const MAX_NODE_RECORD_REPORT_BYTES: usize = 65_536;

/// Existing root record submitted through its independently authenticated source.
/// Current custody, runtime admission and record freshness remain consumer-owned.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeRecordReportRequest {
    /// Exact provisioned NSD and Network identifiers, both nonzero.
    pub scope: MembershipScope,
    /// Accepted root identity, WireGuard key and independent binding counters.
    pub binding: NodeBinding,
    /// Retained Node, credential incarnation and activation identifiers.
    pub registration: RegistrationCondition,
    /// Unchanged source witness retained from shared authentication.
    pub signed_source: SignedSourceBinding,
    /// Independently bound runtime and authority epoch.
    pub fence: NodeRuntimeFence,
    /// Signed root record with no relay advertisement; not a Network registry record.
    pub record: NodeRecord,
}

impl NodeRecordReportRequest {
    /// Encode all seven fields without inventing authority or sampling a clock.
    /// # Errors
    /// Refuses invalid bounds, source self-binding or record/binding disagreement.
    pub fn canonical(&self) -> Result<Vec<u8>, ExchangeError> {
        require(self.scope.nsd_id != [0; 16] && self.scope.network_id != [0; 16])?;
        self.binding.validate()?;
        let source = &self.signed_source.binding;
        require(
            source.scope == "nodes"
                && source.served_realm == RealmId::from_bytes(self.scope.network_id)
                && source.recipient == self.binding.identity
                && source.source_node == self.binding.identity
                && self.record.identity() == self.binding.identity.as_bytes()
                && self.record.wg_key() == &self.binding.wg_key
                && self.record.generation() == self.binding.generation.0
                && self.record.relays().is_empty(),
        )?;
        let signed_source = self.signed_source.canonical()?;
        ensure(
            signed_source.len() <= MAX_SOURCE_BYTES,
            AccountError::Bounds,
        )?;
        let mut out = CborWriter::default();
        out.array(7).uint(1);
        self.scope.write(&mut out);
        self.binding.write(&mut out);
        self.registration.write(&mut out)?;
        out.bytes(&signed_source);
        self.fence.write(&mut out)?;
        out.bytes(self.record.as_bytes());
        let bytes = out.into_bytes();
        ensure(
            bytes.len() <= MAX_NODE_RECORD_REPORT_BYTES,
            AccountError::Bounds,
        )?;
        Ok(bytes)
    }

    /// Decode strict canonical arrays and the independently signed root record.
    /// # Errors
    /// Refuses unsupported shape/version, record signature, field mismatch or bounds.
    pub fn decode(bytes: &[u8]) -> Result<Self, ExchangeError> {
        ensure(
            bytes.len() <= MAX_NODE_RECORD_REPORT_BYTES,
            AccountError::Bounds,
        )?;
        let mut input = reader(bytes, 7)?;
        let scope = MembershipScope::read(&mut input)?;
        let binding = NodeBinding::read(&mut input)?;
        let registration = RegistrationCondition::read(&mut input)?;
        let signed_source = SignedSourceBinding::decode(
            input
                .bytes_up_to(MAX_SOURCE_BYTES)
                .map_err(AccountError::from)?,
        )?;
        let fence = NodeRuntimeFence::read(&mut input)?;
        let record = NodeRecord::decode(
            input
                .bytes_up_to(MAX_NODE_RECORD_BYTES)
                .map_err(AccountError::from)?,
        )
        .map_err(|_| AccountError::Field)?;
        input.finish().map_err(AccountError::from)?;
        let value = Self {
            scope,
            binding,
            registration,
            signed_source,
            fence,
            record,
        };
        require(value.canonical()? == bytes)?;
        Ok(value)
    }

    /// Check scope, root subject and source signature against retained trust.
    /// # Errors
    /// Refuses any mismatch; current registration/runtime and expiry require Store admission.
    pub fn validate_context(&self, context: &NodeReportContext) -> Result<(), ExchangeError> {
        self.canonical()?;
        if self.scope != context.scope {
            return Err(ExchangeError::Scope);
        }
        if self.binding.identity != context.subject {
            return Err(ExchangeError::Binding);
        }
        self.signed_source.verify(context.authority)?;
        Ok(())
    }

    /// Authenticate the exact request operation, full subject and mandatory recipient.
    /// # Errors
    /// Refuses authentication, source/context disagreement or a zero nonce.
    pub fn from_envelope(
        envelope: &BootstrapEnvelope,
        expected: &EnvelopeExpectation<'_>,
        context: &NodeReportContext,
    ) -> Result<Self, ExchangeError> {
        envelope.verify(expected)?;
        require(
            envelope.direction == EnvelopeDirection::Request
                && envelope.kind == NODE_RECORD_REPORT
                && envelope.signer == context.subject
                && envelope.recipient == Some(context.authority)
                && expected.recipient == context.authority
                && envelope.nonce != [0; 16],
        )?;
        let request = Self::decode(&envelope.payload)?;
        request.validate_context(context)?;
        Ok(request)
    }
}

/// Digest of the complete canonical request, including source, runtime and signed record.
#[must_use]
pub fn node_record_report_digest(payload: &[u8]) -> [u8; 32] {
    domain_digest("ns.node.record.report.v1", payload)
}

/// Exact persisted-submission receipt; not membership readiness or an access grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeRecordReportAccepted {
    /// Domain digest over every byte of the canonical submitted request.
    pub request_digest: [u8; 32],
}

impl NodeRecordReportAccepted {
    /// Construct a correlated receipt; the consumer must commit before signing it.
    /// # Errors
    /// Refuses an invalid request and performs no current-authority admission.
    pub fn for_request(request: &NodeRecordReportRequest) -> Result<Self, ExchangeError> {
        Ok(Self {
            request_digest: node_record_report_digest(&request.canonical()?),
        })
    }

    /// Encode exactly the version and complete request digest.
    #[must_use]
    pub fn canonical(&self) -> Vec<u8> {
        let mut out = CborWriter::default();
        out.array(2).uint(1).bytes(&self.request_digest);
        out.into_bytes()
    }

    /// Decode the exact canonical receipt.
    /// # Errors
    /// Refuses unsupported version/arity, digest width, trailing or noncanonical bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, ExchangeError> {
        let mut input = reader(bytes, 2)?;
        let value = Self {
            request_digest: input.fixed_bytes().map_err(AccountError::from)?,
        };
        input.finish().map_err(AccountError::from)?;
        require(value.canonical() == bytes)?;
        Ok(value)
    }

    /// Correlate every submitted field without asserting current authorization.
    /// # Errors
    /// Refuses an invalid pending request or a different complete request digest.
    pub fn validate_for(&self, pending: &NodeRecordReportRequest) -> Result<(), ExchangeError> {
        require(self == &Self::for_request(pending)?)?;
        Ok(())
    }

    /// Authenticate issuer, operation, recipient, request digest and pending nonce.
    /// # Errors
    /// Refuses any carrier/source or correlation mismatch; callers recheck local custody.
    pub fn from_envelope(
        envelope: &BootstrapEnvelope,
        expected: &EnvelopeExpectation<'_>,
        pending: &NodeRecordReportRequest,
        pending_nonce: [u8; 16],
    ) -> Result<Self, ExchangeError> {
        envelope.verify(expected)?;
        require(
            envelope.direction == EnvelopeDirection::Response
                && envelope.kind == NODE_RECORD_REPORT
                && envelope.signer == pending.signed_source.binding.nsd
                && envelope.recipient == Some(pending.binding.identity)
                && expected.recipient == pending.binding.identity
                && pending_nonce != [0; 16]
                && envelope.nonce == pending_nonce,
        )?;
        pending.signed_source.verify(envelope.signer)?;
        let accepted = Self::decode(&envelope.payload)?;
        accepted.validate_for(pending)?;
        Ok(accepted)
    }
}
