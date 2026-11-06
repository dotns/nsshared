//! Ordinary Node runtime support declarations; current custody remains caller-owned.

use crate::{
    account::{
        AccountError,
        codec::{ensure, reader, require},
        control::{
            BootstrapEnvelope, EnvelopeDirection, EnvelopeExpectation, ExchangeError,
            MembershipScope, NODE_RUNTIME_DECLARE, NodeReportContext, NodeRuntimeFence,
            RegistrationCondition,
        },
        node::{
            MAX_CAPABILITIES, MAX_CAPABILITY_BYTES, NodeBinding, enrollment::validate_capabilities,
        },
        publication::{MAX_SOURCE_BYTES, SignedSourceBinding},
    },
    service::domain_digest,
};
use nsshared_codec::cbor::CborWriter;
use nsshared_identity::realm::RealmId;

/// Inclusive ceiling for the complete canonical declaration request payload.
pub const MAX_RUNTIME_DECLARATION_BYTES: usize = 65_536;

/// Complete support snapshot after independently accepted registration, source and runtime bind.
/// Decoding does not authenticate the source or establish current Account custody.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeDeclarationRequest {
    /// Exact provisioned NSD and Network identifiers, both nonzero.
    pub scope: MembershipScope,
    /// Exact accepted Node identity, WireGuard key and independent binding counters.
    pub binding: NodeBinding,
    /// Original server Node, credential incarnation and Account activation identifiers.
    pub registration: RegistrationCondition,
    /// Unchanged canonical source witness retained from shared authentication.
    pub signed_source: SignedSourceBinding,
    /// Real bound runtime, in id, generation, authority-epoch order.
    pub fence: NodeRuntimeFence,
    /// Positive persist-before-send sequence, independent of all other counters.
    pub declaration_seq: u64,
    /// Actual complete supported set, sorted and unique; unknown identifiers grant nothing.
    pub capabilities: Vec<String>,
}

impl RuntimeDeclarationRequest {
    /// Encodes exactly eight fields, preserving the full source and capability set.
    /// # Errors
    /// Refuses invalid bindings, source self-binding, registration, fence, sequence or bounds.
    pub fn canonical(&self) -> Result<Vec<u8>, ExchangeError> {
        require(self.scope.nsd_id != [0; 16] && self.scope.network_id != [0; 16])?;
        self.binding.validate()?;
        require(self.declaration_seq > 0)?;
        validate_capabilities(&self.capabilities)?;
        let source = &self.signed_source.binding;
        require(
            source.scope == "nodes"
                && source.served_realm == RealmId::from_bytes(self.scope.network_id)
                && source.recipient == self.binding.identity
                && source.source_node == self.binding.identity,
        )?;
        let signed_source = self.signed_source.canonical()?;
        ensure(
            signed_source.len() <= MAX_SOURCE_BYTES,
            AccountError::Bounds,
        )?;
        let mut out = CborWriter::default();
        out.array(8).uint(1);
        self.scope.write(&mut out);
        self.binding.write(&mut out);
        self.registration.write(&mut out)?;
        out.bytes(&signed_source);
        self.fence.write(&mut out)?;
        out.uint(self.declaration_seq)
            .array(self.capabilities.len());
        for capability in &self.capabilities {
            out.text(capability);
        }
        let bytes = out.into_bytes();
        ensure(
            bytes.len() <= MAX_RUNTIME_DECLARATION_BYTES,
            AccountError::Bounds,
        )?;
        Ok(bytes)
    }

    /// Decodes strict canonical nested arrays and the unchanged signed-source byte string.
    /// # Errors
    /// Refuses unsupported versions, arities, nonminimal encodings, trailing bytes or bounds.
    pub fn decode(bytes: &[u8]) -> Result<Self, ExchangeError> {
        ensure(
            bytes.len() <= MAX_RUNTIME_DECLARATION_BYTES,
            AccountError::Bounds,
        )?;
        let mut input = reader(bytes, 8)?;
        let scope = MembershipScope::read(&mut input)?;
        let binding = NodeBinding::read(&mut input)?;
        let registration = RegistrationCondition::read(&mut input)?;
        let signed_source = SignedSourceBinding::decode(
            input
                .bytes_up_to(MAX_SOURCE_BYTES)
                .map_err(AccountError::from)?,
        )?;
        let fence = NodeRuntimeFence::read(&mut input)?;
        let declaration_seq = input.uint().map_err(AccountError::from)?;
        let count = input
            .array_up_to(MAX_CAPABILITIES)
            .map_err(AccountError::from)?;
        let mut capabilities = Vec::with_capacity(count);
        for _ in 0..count {
            capabilities.push(
                input
                    .text_up_to(MAX_CAPABILITY_BYTES)
                    .map_err(AccountError::from)?
                    .to_owned(),
            );
        }
        input.finish().map_err(AccountError::from)?;
        let value = Self {
            scope,
            binding,
            registration,
            signed_source,
            fence,
            declaration_seq,
            capabilities,
        };
        require(value.canonical()? == bytes)?;
        Ok(value)
    }

    /// Checks membership, subject and source signature against independently retained trust.
    /// Current enrollment, registration, Account, source and runtime admission remain external.
    /// # Errors
    /// Refuses scope, subject or source issuer/signature disagreement.
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

    /// Authenticates the exact operation, full signer, mandatory recipient and nested source.
    /// The caller supplies replay facts and atomically records nonce acceptance externally.
    /// # Errors
    /// Refuses carrier authentication, context mismatch, zero nonce or any contract violation.
    pub fn from_envelope(
        envelope: &BootstrapEnvelope,
        expected: &EnvelopeExpectation<'_>,
        context: &NodeReportContext,
    ) -> Result<Self, ExchangeError> {
        envelope.verify(expected)?;
        require(
            envelope.direction == EnvelopeDirection::Request
                && envelope.kind == NODE_RUNTIME_DECLARE
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

/// SHA-256 over the fixed ASCII domain, a zero byte and the complete canonical request.
/// Callers validate canonical request bytes before using this digest for admission.
#[must_use]
pub fn runtime_declaration_digest(payload: &[u8]) -> [u8; 32] {
    domain_digest("ns.node.runtime.declaration.v1", payload)
}

/// Exact committed declaration receipt; carries no token, renewal or policy grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeDeclarationAccepted {
    /// Positive sequence from the accepted request.
    pub declaration_seq: u64,
    /// Domain digest over every byte of the canonical request, including the source signature.
    pub request_digest: [u8; 32],
}

impl RuntimeDeclarationAccepted {
    /// Constructs a receipt for an exact request; the caller must commit before signing success.
    /// # Errors
    /// Refuses an invalid request; does not perform current-authority admission.
    pub fn for_request(request: &RuntimeDeclarationRequest) -> Result<Self, ExchangeError> {
        Ok(Self {
            declaration_seq: request.declaration_seq,
            request_digest: runtime_declaration_digest(&request.canonical()?),
        })
    }

    /// Encodes exactly `[1, declaration_seq, request_digest]`.
    /// # Errors
    /// Refuses a zero sequence.
    pub fn canonical(&self) -> Result<Vec<u8>, ExchangeError> {
        require(self.declaration_seq > 0)?;
        let mut out = CborWriter::default();
        out.array(3)
            .uint(1)
            .uint(self.declaration_seq)
            .bytes(&self.request_digest);
        Ok(out.into_bytes())
    }

    /// Decodes the exact canonical three-element receipt.
    /// # Errors
    /// Refuses version, arity, width, zero sequence, noncanonical or trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, ExchangeError> {
        let mut input = reader(bytes, 3)?;
        let value = Self {
            declaration_seq: input.uint().map_err(AccountError::from)?,
            request_digest: input.fixed_bytes().map_err(AccountError::from)?,
        };
        input.finish().map_err(AccountError::from)?;
        require(value.canonical()? == bytes)?;
        Ok(value)
    }

    /// Correlates sequence and every pending request byte without asserting current authority.
    /// # Errors
    /// Refuses invalid fields or any difference from the retained request.
    pub fn validate_for(&self, pending: &RuntimeDeclarationRequest) -> Result<(), ExchangeError> {
        self.canonical()?;
        require(self == &Self::for_request(pending)?)?;
        Ok(())
    }

    /// Authenticates the pinned issuer, exact operation, mandatory recipient and pending nonce.
    /// Consumers must recheck their current attachment, registration and runtime before acceptance.
    /// # Errors
    /// Refuses carrier/source trust, correlation, sequence or digest disagreement.
    pub fn from_envelope(
        envelope: &BootstrapEnvelope,
        expected: &EnvelopeExpectation<'_>,
        pending: &RuntimeDeclarationRequest,
        pending_nonce: [u8; 16],
    ) -> Result<Self, ExchangeError> {
        envelope.verify(expected)?;
        require(
            envelope.direction == EnvelopeDirection::Response
                && envelope.kind == NODE_RUNTIME_DECLARE
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
