//! Pure exact Node L3 application reports; authentication and current state are caller-owned.

use crate::{
    account::AccountError, account::MAX_BYTES, account::codec::bounded, account::codec::identity,
    account::codec::reader, account::codec::realm, account::codec::require,
    account::control::BootstrapEnvelope, account::control::EnvelopeDirection,
    account::control::EnvelopeExpectation, account::control::exchange::NODE_L3_STATUS,
    account::limits::MAX_TEXT_BYTES, account::node::NodeL3Authority,
    account::publication::PublicationChannel, account::publication::PublicationEvent,
    account::publication::PublicationKey, account::publication::PublicationOutcome,
    account::publication::source_binding::MAX_SOURCE_BYTES,
    account::publication::source_binding::SourceBinding,
    account::publication::source_binding::SourceError, service::domain_digest,
};

use nsshared_codec::cbor::CborWriter;
use nsshared_identity::{keys::IdentityKey, realm::RealmId};

/// Exact owning key for the snapshot-only Node L3 collection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeL3StatusKey {
    /// Full independently authorized NSD signing identity.
    pub issuer: IdentityKey,
    /// Full authenticated recipient Node identity.
    pub recipient: IdentityKey,
    /// Authorized enclosing realm.
    pub served_realm: RealmId,
    /// Existing publication scope.
    pub scope: String,
}
impl NodeL3StatusKey {
    /// Full publication key; no family or kind substitution is possible.
    #[must_use]
    pub fn publication_key(&self) -> PublicationKey<'_> {
        PublicationKey {
            issuer: self.issuer,
            recipient: self.recipient,
            served_realm: self.served_realm,
            scope: &self.scope,
            family: 11,
            kind: "node-l3",
        }
    }
}

/// Application result, never an accepted-only or queued-installation phase.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NodeL3Status {
    /// Exact Data replacement was installed; complete-empty proves removal only.
    Applied,
    /// Verified event could not be installed; grants no permission.
    Rejected(String),
    /// Verified authenticated FetchFailed collection was denied; grants no permission.
    FetchFailedDenied,
}

/// Exact report copied from independently accepted source and inner publication context.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeL3StatusRequest {
    /// Recipient-produced nonzero pending-report correlation identifier.
    pub request_id: [u8; 16],
    /// Exact owning collection.
    pub key: NodeL3StatusKey,
    /// All accepted source fields, without the binding signature.
    pub source_binding: SourceBinding,
    /// Positive signed enclosing event version.
    pub event_version: u64,
    /// Domain digest of the exact signed inner PublicationEvent, including its signature.
    pub event_digest: [u8; 32],
    /// Actual application result for this exact context.
    pub status: NodeL3Status,
}

/// Independently retained authenticated issuance or still-current accepted application context.
/// Never construct expected state from the report being checked. Signature, expiry,
/// source authorization and version/tombstone acceptance remain caller responsibilities.
#[derive(Clone, Copy, Debug)]
pub struct NodeL3StatusContext<'a, 'event> {
    /// Retained exact signed inner event, excluding outer delivery wrappers.
    pub event: &'a PublicationEvent<'event>,
    /// Every field of the independently retained current source authority.
    pub source_binding: &'a SourceBinding,
}

/// Computes the fixed domain digest without recreating policy or event bytes.
#[must_use]
pub fn node_l3_event_digest(event: &PublicationEvent<'_>) -> [u8; 32] {
    domain_digest("ns.account.node-l3.v1", event.canonical())
}

impl NodeL3StatusRequest {
    /// Encodes one exact report; does not authenticate its claimed context.
    /// # Errors
    /// Refuses zero correlation/version, binding/key mismatch, invalid reason or bounds.
    pub fn canonical(&self) -> Result<Vec<u8>, SourceError> {
        require(self.request_id != [0; 16] && self.event_version > 0)?;
        let key = &self.key;
        let binding = &self.source_binding;
        require(
            key.issuer == binding.nsd
                && key.recipient == binding.recipient
                && key.served_realm == binding.served_realm
                && key.scope == binding.scope,
        )?;
        let source = binding.canonical()?;
        require(source.len() <= MAX_SOURCE_BYTES)?;
        let mut out = CborWriter::default();
        out.array(7)
            .uint(1)
            .bytes(&self.request_id)
            .array(6)
            .bytes(key.issuer.as_bytes())
            .bytes(key.recipient.as_bytes())
            .text(&key.served_realm.to_string())
            .text(&key.scope)
            .uint(11)
            .text("node-l3")
            .bytes(&source)
            .uint(self.event_version)
            .bytes(&self.event_digest);
        match &self.status {
            NodeL3Status::Applied => {
                out.array(1).uint(0);
            }
            NodeL3Status::Rejected(reason) => {
                require(
                    !reason.is_empty()
                        && reason.len() <= MAX_TEXT_BYTES
                        && !reason.chars().any(char::is_control),
                )?;
                out.array(2).uint(1).text(reason);
            }
            NodeL3Status::FetchFailedDenied => {
                out.array(1).uint(2);
            }
        }
        Ok(bounded(out.into_bytes())?)
    }

    /// Decodes strict canonical bytes, including the embedded source binding.
    /// # Errors
    /// Refuses unknown statuses, extra fields, noncanonical encodings and invalid fields.
    pub fn decode(bytes: &[u8]) -> Result<Self, SourceError> {
        let mut input = reader(bytes, 7)?;
        let request_id = input.fixed_bytes()?;
        input.array(6)?;
        let key = NodeL3StatusKey {
            issuer: identity(&mut input)?,
            recipient: identity(&mut input)?,
            served_realm: realm(&mut input)?,
            scope: input.text_up_to(MAX_TEXT_BYTES)?.to_owned(),
        };
        require(input.uint()? == 11 && input.text_up_to(MAX_TEXT_BYTES)? == "node-l3")?;
        let source_binding = SourceBinding::decode(input.bytes_up_to(MAX_SOURCE_BYTES)?)?;
        let event_version = input.uint()?;
        let event_digest = input.fixed_bytes()?;
        let arity = input.array_up_to(2)?;
        let status = match (arity, input.uint()?) {
            (1, 0) => NodeL3Status::Applied,
            (2, 1) => NodeL3Status::Rejected(input.text_up_to(MAX_TEXT_BYTES)?.to_owned()),
            (1, 2) => NodeL3Status::FetchFailedDenied,
            _ => return Err(AccountError::Field.into()),
        };
        input.finish()?;
        let value = Self {
            request_id,
            key,
            source_binding,
            event_version,
            event_digest,
            status,
        };
        require(value.canonical()? == bytes)?;
        Ok(value)
    }

    fn validate_context(&self, current: NodeL3StatusContext<'_, '_>) -> Result<(), SourceError> {
        self.canonical()?;
        let content = current.event.content();
        content.canonical()?;
        require(content.channel == PublicationChannel::Snapshot && content.complete)?;
        require(
            self.key.publication_key() == content.key
                && &self.source_binding == current.source_binding
                && self.event_version == content.version
                && self.event_digest == node_l3_event_digest(current.event),
        )?;
        match (&self.status, content.outcome) {
            (NodeL3Status::Applied, PublicationOutcome::FetchFailed)
            | (NodeL3Status::FetchFailedDenied, PublicationOutcome::Data) => {
                return Err(SourceError::Authority);
            }
            _ => {}
        }
        if content.outcome == PublicationOutcome::Data && !content.payload.is_empty() {
            let authority =
                NodeL3Authority::decode(content.payload).map_err(|_| SourceError::Authority)?;
            require(
                authority.policy.issuer == content.key.issuer
                    && authority.policy.recipient == content.key.recipient
                    && authority.policy.revision == content.version,
            )?;
        }
        Ok(())
    }

    /// NSD comparison with independently retained current issuance and every source field.
    /// Matching Rejected/FetchFailedDenied remains negative evidence; Applied empty means removal.
    /// # Errors
    /// Refuses any superseded source, key, version, digest or payload context.
    pub fn validate_issuance(
        &self,
        current: NodeL3StatusContext<'_, '_>,
    ) -> Result<(), SourceError> {
        self.validate_context(current)
    }

    /// Recipient comparison before reporting an actual application result for its still-current context.
    /// Successful comparison does not establish that installation occurred; callers supply that result.
    /// # Errors
    /// Refuses any changed source/event or status inconsistent with the event outcome.
    pub fn validate_application(
        &self,
        current: NodeL3StatusContext<'_, '_>,
    ) -> Result<(), SourceError> {
        self.validate_context(current)
    }

    /// Authenticates request trust, operation, direction and full signer/recipient identities.
    /// Confidential carrier enforcement remains with the transport boundary.
    /// # Errors
    /// Refuses envelope authentication, direction, identity or payload mismatch.
    pub fn from_envelope(
        envelope: &BootstrapEnvelope,
        expected: &EnvelopeExpectation<'_>,
    ) -> Result<Self, SourceError> {
        envelope.verify(expected)?;
        let report = Self::decode(&envelope.payload)?;
        require(
            envelope.direction == EnvelopeDirection::Request
                && envelope.kind == NODE_L3_STATUS
                && envelope.signer == report.key.recipient
                && envelope.recipient == Some(report.key.issuer),
        )?;
        Ok(report)
    }
}

/// NSD receipt echoing the exact canonical request, never remote data-plane observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeL3StatusResponse {
    /// Exact echoed request, including correlation id and negative status.
    pub report: NodeL3StatusRequest,
}
impl NodeL3StatusResponse {
    /// Encodes `[1, bstr(exact_canonical_request)]`.
    /// # Errors
    /// Refuses invalid nested reports or encoded bounds.
    pub fn canonical(&self) -> Result<Vec<u8>, SourceError> {
        let mut out = CborWriter::default();
        out.array(2).uint(1).bytes(&self.report.canonical()?);
        Ok(bounded(out.into_bytes())?)
    }
    /// Decodes an exact canonical receipt without accepting its claimed report.
    /// # Errors
    /// Refuses malformed, noncanonical or extended response/request bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, SourceError> {
        let mut input = reader(bytes, 2)?;
        let report = NodeL3StatusRequest::decode(input.bytes_up_to(MAX_BYTES)?)?;
        input.finish()?;
        let value = Self { report };
        require(value.canonical()? == bytes)?;
        Ok(value)
    }
    /// Compares the full echoed canonical bytes with an independently retained pending report.
    /// # Errors
    /// Refuses any changed field, request id or application status.
    pub fn validate_for(&self, pending: &NodeL3StatusRequest) -> Result<(), SourceError> {
        require(self.report.canonical()? == pending.canonical()?)?;
        Ok(())
    }
    /// Authenticates receipt trust/direction/operation, identities and pending envelope nonce.
    /// # Errors
    /// Refuses any envelope mismatch or difference from the exact pending report.
    pub fn from_envelope(
        envelope: &BootstrapEnvelope,
        expected: &EnvelopeExpectation<'_>,
        pending: &NodeL3StatusRequest,
        pending_nonce: [u8; 16],
    ) -> Result<Self, SourceError> {
        envelope.verify(expected)?;
        require(
            envelope.direction == EnvelopeDirection::Response
                && envelope.kind == NODE_L3_STATUS
                && envelope.signer == pending.key.issuer
                && envelope.recipient == Some(pending.key.recipient)
                && envelope.nonce == pending_nonce,
        )?;
        let receipt = Self::decode(&envelope.payload)?;
        receipt.validate_for(pending)?;
        Ok(receipt)
    }
}
