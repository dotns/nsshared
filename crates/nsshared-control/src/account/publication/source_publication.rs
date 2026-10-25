//! Exact source and delivery fences before existing publication decisions.

use crate::{
    account::control::MAX_CONTROL_BODY, account::control::MAX_PUBLICATION_BYTES,
    account::publication::AcceptedPublication, account::publication::PublicationChannel,
    account::publication::PublicationDecision, account::publication::PublicationError,
    account::publication::PublicationEvent, account::publication::PublicationExpectation,
    account::publication::decide_publication,
    account::publication::source_binding::DeliveryContext,
    account::publication::source_binding::MAX_SOURCE_BYTES,
    account::publication::source_binding::SignedSourceBinding,
    account::publication::source_binding::SourceBinding,
    account::publication::source_binding::SourceError,
    account::publication::source_binding::verify_signature, account::require,
};
use nsshared_codec::{cbor::CborReader, cbor::CborWriter};

/// Mandatory outer signature domain; unbound event signatures cannot substitute.
pub const SOURCE_PUBLICATION_DOMAIN: &[u8] = b"ns.account.source-publication.v1\0";

/// Borrowed exact signed wrapper; no authority is inferred by decoding.
#[derive(Debug)]
pub struct SourcePublication<'a> {
    binding: SignedSourceBinding,
    delivery: DeliveryContext,
    event: &'a [u8],
    content: &'a [u8],
    signature: [u8; 64],
    wire: &'a [u8],
}
impl<'a> SourcePublication<'a> {
    /// Decodes the mandatory bound form, measuring the entire received event.
    /// # Errors
    /// Refuses old forms, missing fields, malformed input and size violations.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, SourceError> {
        if bytes.len() > MAX_PUBLICATION_BYTES {
            return Err(PublicationError::Bounds.into());
        }
        let mut input = CborReader::new(bytes, MAX_PUBLICATION_BYTES)?;
        input.array(2)?;
        let content = input.bytes_up_to(MAX_PUBLICATION_BYTES)?;
        let signature = input.fixed_bytes()?;
        input.finish()?;
        let mut input = CborReader::new(content, MAX_PUBLICATION_BYTES)?;
        input.array(4)?;
        require(input.uint()? == 1)?;
        let binding = SignedSourceBinding::decode(input.bytes_up_to(MAX_SOURCE_BYTES)?)?;
        let delivery = DeliveryContext::decode(input.bytes_up_to(MAX_SOURCE_BYTES)?)?;
        let event = input.bytes_up_to(MAX_PUBLICATION_BYTES)?;
        input.finish()?;
        PublicationEvent::decode(event)?;
        Ok(Self {
            binding,
            delivery,
            event,
            content,
            signature,
            wire: bytes,
        })
    }
    /// Exact received canonical bytes.
    #[must_use]
    pub const fn canonical(&self) -> &'a [u8] {
        self.wire
    }
    /// Exact outer signing input for independent producers.
    #[must_use]
    pub fn signing_input(&self) -> Vec<u8> {
        let mut bytes = SOURCE_PUBLICATION_DOMAIN.to_vec();
        bytes.extend_from_slice(self.content);
        bytes
    }
    /// Unauthenticated inner facts; only the decision API validates authority.
    /// # Errors
    /// Refuses invalid existing publication encoding or fields.
    pub fn event(&self) -> Result<PublicationEvent<'a>, SourceError> {
        Ok(PublicationEvent::decode(self.event)?)
    }
    /// Exact outer signature; authenticity still requires the decision API.
    #[must_use]
    pub const fn signature(&self) -> &[u8; 64] {
        &self.signature
    }
    /// Signed source facts, without claiming they match current authority.
    #[must_use]
    pub const fn binding(&self) -> &SignedSourceBinding {
        &self.binding
    }
    /// Signed delivery facts, without claiming an outstanding request.
    #[must_use]
    pub const fn delivery(&self) -> &DeliveryContext {
        &self.delivery
    }

    fn verify(
        &self,
        current: &SourceBinding,
        pending: &DeliveryContext,
        expected: &PublicationExpectation<'_>,
    ) -> Result<(), SourceError> {
        current.canonical()?;
        pending.canonical()?;
        self.binding.verify(expected.issuer)?;
        verify_signature(
            expected.issuer,
            SOURCE_PUBLICATION_DOMAIN,
            self.content,
            &self.signature,
        )?;
        if &self.binding.binding != current
            || current.nsd != expected.issuer
            || current.recipient != expected.recipient
        {
            return Err(SourceError::Authority);
        }
        if &self.delivery != pending || pending.channel() != expected.channel {
            return Err(SourceError::Context);
        }
        let event = self.event()?;
        let key = event.content().key;
        if key.issuer != current.nsd
            || key.recipient != current.recipient
            || key.served_realm != current.served_realm
            || key.scope != current.scope
        {
            return Err(SourceError::Authority);
        }
        match (key.family, key.kind) {
            (4, "exit-grants" | "subnet-routes" | "provider-mappings")
                if key.scope != "nodes" || current.source_node != current.recipient =>
            {
                return Err(SourceError::Authority);
            }
            (3, "egress-grants") if key.scope != "egress" => {
                return Err(SourceError::Authority);
            }
            _ => {}
        }
        Ok(())
    }
}

/// Constructs canonical outer content for a producer to sign.
/// # Errors
/// Refuses invalid binding, context, nested event or complete signed-event bounds.
pub fn source_publication_signing_input(
    binding: &SignedSourceBinding,
    delivery: &DeliveryContext,
    event: &[u8],
) -> Result<Vec<u8>, SourceError> {
    PublicationEvent::decode(event)?;
    let mut content = CborWriter::default();
    content
        .array(4)
        .uint(1)
        .bytes(&binding.canonical()?)
        .bytes(&delivery.canonical()?)
        .bytes(event);
    let content = content.into_bytes();
    let mut carrier = CborWriter::default();
    carrier.array(2).bytes(&content).bytes(&[0; 64]);
    if carrier.into_bytes().len() > MAX_PUBLICATION_BYTES {
        return Err(PublicationError::Bounds.into());
    }
    let mut message = SOURCE_PUBLICATION_DOMAIN.to_vec();
    message.extend_from_slice(&content);
    Ok(message)
}

/// Encodes the exact new form using a producer-supplied outer signature.
/// # Errors
/// Refuses invalid constructed fields, nested encoding or encoded bounds.
pub fn encode_source_publication(
    binding: &SignedSourceBinding,
    delivery: &DeliveryContext,
    event: &[u8],
    signature: &[u8; 64],
) -> Result<Vec<u8>, SourceError> {
    let message = source_publication_signing_input(binding, delivery, event)?;
    let mut carrier = CborWriter::default();
    carrier
        .array(2)
        .bytes(&message[SOURCE_PUBLICATION_DOMAIN.len()..])
        .bytes(signature);
    Ok(carrier.into_bytes())
}

/// Checks source and outstanding context before any existing per-key decision.
/// The caller retains provenance through queues and serializes final installation.
/// # Errors
/// Refuses missing/old source forms, signatures or mismatched source/session facts.
pub fn decide_source_publication<'a>(
    last: &[AcceptedPublication<'_>],
    presented: Option<&'a [u8]>,
    current: &SourceBinding,
    pending: &DeliveryContext,
    expected: &PublicationExpectation<'_>,
) -> Result<PublicationDecision<'a>, SourceError> {
    let Some(bytes) = presented else {
        return Ok(PublicationDecision::Absent);
    };
    if bytes.len() > MAX_PUBLICATION_BYTES && expected.channel == PublicationChannel::Stream {
        return Ok(PublicationDecision::TerminateStream);
    }
    let value = SourcePublication::decode(bytes)?;
    value.verify(current, pending, expected)?;
    Ok(decide_publication(last, Some(value.event), expected))
}

/// Validates all source-bound snapshot entries before exposing any decisions.
/// # Errors
/// Refuses one bad event, duplicate/out-of-order keys, wrong channel or bounds.
pub fn decide_source_snapshot<'a>(
    last: &[AcceptedPublication<'_>],
    bytes: &'a [u8],
    current: &SourceBinding,
    pending: &DeliveryContext,
    expected: &PublicationExpectation<'_>,
) -> Result<Vec<PublicationDecision<'a>>, SourceError> {
    decide_source_snapshot_scopes(
        last,
        bytes,
        std::slice::from_ref(current),
        pending,
        expected,
    )
}

/// Validates one complete multi-scope poll against independently accepted bindings.
/// Each exact issuer/recipient/realm/scope has one current source; the existing
/// request bound applies before any event can expose an action.
/// # Errors
/// Refuses ambiguous sources, mismatched context, malformed or invalid events.
pub fn decide_source_snapshot_scopes<'a>(
    last: &[AcceptedPublication<'_>],
    bytes: &'a [u8],
    current: &[SourceBinding],
    pending: &DeliveryContext,
    expected: &PublicationExpectation<'_>,
) -> Result<Vec<PublicationDecision<'a>>, SourceError> {
    require(current.len() <= crate::account::publication::snapshot_request::MAX_SNAPSHOT_SCOPES)?;
    pending.canonical()?;
    for (index, binding) in current.iter().enumerate() {
        binding.canonical()?;
        if binding.nsd != expected.issuer
            || binding.recipient != expected.recipient
            || current[..index].iter().any(|other| {
                other.nsd == binding.nsd
                    && other.recipient == binding.recipient
                    && other.served_realm == binding.served_realm
                    && other.scope == binding.scope
            })
        {
            return Err(SourceError::Authority);
        }
    }
    if expected.channel != PublicationChannel::Snapshot || pending.channel() != expected.channel {
        return Err(SourceError::Context);
    }
    let mut input = CborReader::new(bytes, MAX_CONTROL_BODY)?;
    input.array(2)?;
    require(input.uint()? == 1)?;
    let count = input.array_up_to(bytes.len())?;
    let mut decisions = Vec::new();
    let mut previous = None;
    for _ in 0..count {
        let bytes = input.bytes_up_to(MAX_PUBLICATION_BYTES)?;
        let presented = SourcePublication::decode(bytes)?;
        let binding = current
            .iter()
            .find(|binding| **binding == presented.binding.binding)
            .ok_or(SourceError::Authority)?;
        let decision = decide_source_publication(last, Some(bytes), binding, pending, expected)?;
        let event = match &decision {
            PublicationDecision::Replace(event)
            | PublicationDecision::Withdraw(event)
            | PublicationDecision::FetchFailed(event)
            | PublicationDecision::UnknownKind(event) => event,
            PublicationDecision::ChannelMismatch(_) => return Err(SourceError::Context),
            PublicationDecision::Refused(_)
            | PublicationDecision::Absent
            | PublicationDecision::TerminateStream => return Err(PublicationError::Field.into()),
        };
        // Unknown pairs bypass registry ownership checks in the event decision,
        // but every source snapshot entry must still declare the snapshot channel.
        if event.content().channel != PublicationChannel::Snapshot {
            return Err(SourceError::Context);
        }
        let key = event.content().key;
        if previous.is_some_and(|previous| previous >= key) {
            return Err(PublicationError::Order.into());
        }
        previous = Some(key);
        decisions.push(decision);
    }
    input.finish()?;
    Ok(decisions)
}
