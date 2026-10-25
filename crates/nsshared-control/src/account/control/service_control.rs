//! Pure M6 carrier correlation; durable ownership and effects remain external.

use crate::{
    account::AccountError, account::control::BootstrapEnvelope, account::control::BootstrapError,
    account::control::EnvelopeDirection, account::control::EnvelopeExpectation,
    account::control::MAX_CONTROL_BODY, account::control::exchange::SERVICE_CONTROL,
    service::ContractError, service::Id, service::Message, service::MessageBody,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use nsshared_codec::{cbor::CborReader, cbor::CborWriter};
use nsshared_identity::keys::IdentityKey;
use thiserror::Error;

/// Exact admitted session carried by a subscription, without session state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceControlBinding {
    /// Accepted NSD identity identifier.
    pub nsd_id: Id,
    /// Exact contributing Network identifier.
    pub network_id: Id,
    /// Persistent Node runtime generation.
    pub runtime_generation: u64,
    /// Current nonzero Node runtime identifier.
    pub runtime_id: Id,
    /// Accepted M6 authority epoch.
    pub authority_epoch: u64,
    /// Accepted connection attempt sequence.
    pub session_seq: u64,
    /// Nonzero logical request identifier of the accepted SessionOpen.
    pub session_request_id: Id,
}
impl ServiceControlBinding {
    pub(in crate::account) fn validate(&self) -> Result<(), AccountError> {
        crate::account::codec::require(
            self.runtime_generation > 0
                && self.authority_epoch > 0
                && self.session_seq > 0
                && self.runtime_id != [0; 16]
                && self.session_request_id != [0; 16],
        )
    }
    pub(in crate::account) fn write(&self, out: &mut CborWriter) {
        out.array(7)
            .bytes(&self.nsd_id)
            .bytes(&self.network_id)
            .uint(self.runtime_generation)
            .bytes(&self.runtime_id)
            .uint(self.authority_epoch)
            .uint(self.session_seq)
            .bytes(&self.session_request_id);
    }
    pub(in crate::account) fn read(input: &mut CborReader<'_>) -> Result<Self, AccountError> {
        input.array(7)?;
        let value = Self {
            nsd_id: input.fixed_bytes()?,
            network_id: input.fixed_bytes()?,
            runtime_generation: input.uint()?,
            runtime_id: input.fixed_bytes()?,
            authority_epoch: input.uint()?,
            session_seq: input.uint()?,
            session_request_id: input.fixed_bytes()?,
        };
        value.validate()?;
        Ok(value)
    }
}

/// A carrier or context refusal never grants authority.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ServiceControlError {
    /// Existing authenticated envelope checks failed.
    #[error(transparent)]
    Envelope(#[from] BootstrapError),
    /// Existing M6 decoder refused the payload.
    #[error(transparent)]
    Message(#[from] ContractError),
    /// Carrier direction, body, recipient or correlation differs.
    #[error("service control context mismatch")]
    Context,
    /// SSE data is not canonical bounded base64url.
    #[error("invalid service control event encoding")]
    Encoding,
}
fn require(value: bool) -> Result<(), ServiceControlError> {
    if value {
        Ok(())
    } else {
        Err(ServiceControlError::Context)
    }
}

fn verify(
    envelope: &BootstrapEnvelope,
    expected: &EnvelopeExpectation<'_>,
    direction: EnvelopeDirection,
) -> Result<(), ServiceControlError> {
    require(expected.kind == SERVICE_CONTROL && expected.direction == direction)?;
    envelope.verify(expected)?;
    require(envelope.recipient == Some(expected.recipient))
}

/// Validates an authenticated Node request, including the singleton lease rule.
/// # Errors
/// Refuses invalid authentication, subject, body, encoding or service count.
pub fn validate_unary_request(
    envelope: &BootstrapEnvelope,
    expected: &EnvelopeExpectation<'_>,
) -> Result<Message, ServiceControlError> {
    verify(envelope, expected, EnvelopeDirection::Request)?;
    let message = Message::decode(&envelope.payload)?;
    require(message.subject_identity == *envelope.signer.as_bytes())?;
    validate_request_body(&message)?;
    Ok(message)
}
fn validate_request_body(message: &Message) -> Result<(), ServiceControlError> {
    require(match &message.body {
        MessageBody::RuntimeFloor
        | MessageBody::RuntimeBind(_)
        | MessageBody::SessionOpen
        | MessageBody::ReportHead
        | MessageBody::ReportReplace(_)
        | MessageBody::ListenerReady(_)
        | MessageBody::LeaseRefresh(_)
        | MessageBody::SnapshotAck(_)
        | MessageBody::PortResult(_)
        | MessageBody::PortQueryResult(_)
        | MessageBody::ServiceRetryPort(_) => true,
        MessageBody::LeaseAcquire(body) => body.services.len() == 1,
        _ => false,
    })
}

/// Authenticated pending association; consumers fence it on ownership changes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingRequest {
    message: Message,
    authority: IdentityKey,
    nonce: [u8; 16],
}
impl PendingRequest {
    /// Retains the exact authenticated request and outer correlation facts.
    /// # Errors
    /// Refuses anything rejected by [`validate_unary_request`].
    pub fn from_envelope(
        envelope: &BootstrapEnvelope,
        expected: &EnvelopeExpectation<'_>,
    ) -> Result<Self, ServiceControlError> {
        Ok(Self {
            message: validate_unary_request(envelope, expected)?,
            authority: expected.recipient,
            nonce: envelope.nonce,
        })
    }
    /// Exact retained logical request; retries preserve its bytes.
    #[must_use]
    pub const fn message(&self) -> &Message {
        &self.message
    }
}

/// Authenticated outcome; failure and carrier acceptance are distinct from results.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UnaryReply {
    /// Zero-byte carrier acceptance, with no service effect.
    Receipt,
    /// A correlated existing Error, never a successful result.
    Failure(Message),
    /// Existing typed result, including its unchanged negative outcomes.
    Message(Message),
}
fn accepts_receipt(body: &MessageBody) -> bool {
    matches!(
        body,
        MessageBody::SnapshotAck(_)
            | MessageBody::PortResult(_)
            | MessageBody::PortQueryResult(_)
            | MessageBody::ServiceRetryPort(_)
    )
}
fn same_context(request: &Message, reply: &Message) -> bool {
    request.nsd_id == reply.nsd_id
        && request.network_id == reply.network_id
        && request.subject_identity == reply.subject_identity
        && request.request_id == reply.request_id
        && request.runtime_generation == reply.runtime_generation
        && request.runtime_id == reply.runtime_id
}

/// Compares a signed reply with an exact retained pending request.
/// # Errors
/// Refuses authentication, nonce, legal-pair or M6 context/content mismatches.
pub fn validate_unary_reply(
    envelope: &BootstrapEnvelope,
    expected: &EnvelopeExpectation<'_>,
    pending: &PendingRequest,
) -> Result<UnaryReply, ServiceControlError> {
    verify(envelope, expected, EnvelopeDirection::Response)?;
    let request = &pending.message;
    require(
        envelope.signer == pending.authority
            && envelope.nonce == pending.nonce
            && *expected.recipient.as_bytes() == request.subject_identity,
    )?;
    if envelope.payload.is_empty() {
        require(accepts_receipt(&request.body))?;
        return Ok(UnaryReply::Receipt);
    }
    let reply = Message::decode(&envelope.payload)?;
    require(same_context(request, &reply))?;
    let bootstrap = matches!(
        request.body,
        MessageBody::RuntimeFloor | MessageBody::RuntimeBind(_)
    );
    if !bootstrap {
        require(request.authority_epoch == reply.authority_epoch)?;
    }
    if matches!(reply.body, MessageBody::Error(_)) {
        require(
            request.runtime_generation.is_some()
                && request.runtime_id.is_some()
                && reply.authority_epoch.is_some_and(|epoch| epoch > 0)
                && reply.session_seq.is_none(),
        )?;
        return Ok(UnaryReply::Failure(reply));
    }
    require(request.session_seq == reply.session_seq)?;
    validate_pair(request, &reply)?;
    Ok(UnaryReply::Message(reply))
}
fn validate_pair(request: &Message, reply: &Message) -> Result<(), ServiceControlError> {
    require(match (&request.body, &reply.body) {
        (MessageBody::RuntimeFloor, MessageBody::RuntimeFloorResult(body)) => {
            body.authority_epoch > 0 && reply.authority_epoch == Some(body.authority_epoch)
        }
        (MessageBody::RuntimeBind(_), MessageBody::RuntimeBindResult(epoch)) => {
            *epoch > 0 && reply.authority_epoch == Some(*epoch)
        }
        (MessageBody::SessionOpen, MessageBody::SessionOpenResult(seq)) => {
            Some(*seq) == request.session_seq
        }
        (MessageBody::ReportHead, MessageBody::ReportHeadResult(_)) => true,
        (MessageBody::ReportReplace(body), MessageBody::ReportAccepted(result)) => {
            let (_, digest) = body.report.canonical()?;
            result.accepted_revision == body.report_revision && result.report_digest == Some(digest)
        }
        (
            MessageBody::ListenerReady(body) | MessageBody::LeaseRefresh(body),
            MessageBody::LeaseResult(result),
        ) => {
            result.service.service_ref == body.proposal.service_ref
                && result.service.listener_revision == body.proposal.listener_revision
                && result.service.intent_digest == body.proposal.intent_digest
                && result.refresh_seq == Some(body.refresh_seq)
                && result.consumer_seq.is_none()
        }
        (MessageBody::LeaseAcquire(body), MessageBody::LeaseResult(result)) => {
            body.services.len() == 1
                && body.services.first() == Some(&result.service)
                && result.consumer_seq == Some(body.consumer_seq)
                && result.refresh_seq.is_none()
                && result.snapshot_revision == Some(body.snapshot_revision)
                && result.snapshot_digest == Some(body.snapshot_digest)
        }
        _ => false,
    })
}

/// Accepted stream facts supplied by the consumer, without durable state.
#[derive(Debug)]
pub struct StreamExpectation<'a> {
    /// Exact authenticated NSD signing identity, distinct from its M6 identifier.
    pub authority: IdentityKey,
    /// Exact authenticated Node recipient/subject.
    pub subject: IdentityKey,
    /// Current accepted session tuple, independently checked against contribution custody.
    pub binding: &'a ServiceControlBinding,
}

/// Decodes and verifies one bounded canonical SSE event against its accepted stream.
/// # Errors
/// Refuses encoding, authentication, non-event bodies or any stream context mismatch.
pub fn validate_stream_event(
    event_name: &str,
    data: &str,
    expected: &EnvelopeExpectation<'_>,
    stream: &StreamExpectation<'_>,
) -> Result<Message, ServiceControlError> {
    require(event_name == SERVICE_CONTROL)?;
    if data.len() > MAX_CONTROL_BODY.div_ceil(3) * 4 {
        return Err(ServiceControlError::Encoding);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(data)
        .map_err(|_| ServiceControlError::Encoding)?;
    if URL_SAFE_NO_PAD.encode(&bytes) != data {
        return Err(ServiceControlError::Encoding);
    }
    let envelope = BootstrapEnvelope::decode(&bytes)?;
    verify(&envelope, expected, EnvelopeDirection::Response)?;
    require(envelope.signer == stream.authority && expected.recipient == stream.subject)?;
    let message = Message::decode(&envelope.payload)?;
    require(matches!(
        message.body,
        MessageBody::SnapshotPush(_) | MessageBody::PortCancel(_) | MessageBody::PortQuery(_)
    ))?;
    let binding = stream.binding;
    require(
        binding.validate().is_ok()
            && message.nsd_id == binding.nsd_id
            && message.network_id == binding.network_id
            && message.subject_identity == *stream.subject.as_bytes()
            && message.runtime_generation == Some(binding.runtime_generation)
            && message.runtime_id == Some(binding.runtime_id)
            && message.authority_epoch == Some(binding.authority_epoch)
            && message.session_seq == Some(binding.session_seq),
    )?;
    Ok(message)
}

/// Compares a reverse-operation answer with its retained authenticated operation.
/// # Errors
/// Refuses invalid M6 values, operation/result kinds, context or proposal fields.
pub fn validate_reverse_result(
    operation: &Message,
    answer: &Message,
) -> Result<(), ServiceControlError> {
    operation.encode()?;
    answer.encode()?;
    require(
        same_context(operation, answer)
            && operation.authority_epoch == answer.authority_epoch
            && operation.session_seq == answer.session_seq,
    )?;
    require(match (&operation.body, &answer.body) {
        (MessageBody::PortCancel(proposal), MessageBody::PortResult(result))
        | (MessageBody::PortQuery(proposal), MessageBody::PortQueryResult(result)) => {
            *proposal == result.proposal
        }
        _ => false,
    })
}
