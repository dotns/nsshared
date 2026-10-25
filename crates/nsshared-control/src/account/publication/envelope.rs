//! Signed per-kind authority; payloads remain the owning family's exact bytes.

use crate::{
    account::codec::is_token, account::control::MAX_CONTROL_BODY,
    account::control::MAX_PUBLICATION_BYTES, account::domains::PUBLICATION_DOMAIN,
    account::limits::MAX_TEXT_BYTES, account::signing::signing_input, account::signing::verify,
};
use nsshared_identity::realm::RealmId;

use thiserror::Error;

use nsshared_codec::{cbor::CborReader, cbor::CborWriter};
use nsshared_identity::keys::IdentityKey;

/// The independent channel carrying a kind's authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub enum PublicationChannel {
    /// Control stream; oversize input requires termination and reconnection.
    Stream = 0,
    /// Independently polled snapshot; invalid events reject the entire snapshot.
    Snapshot = 1,
}

/// Exact signed publication scope; neither component implies another scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicationScope<'a> {
    /// Authorized served realm.
    pub served_realm: RealmId,
    /// Opaque authority scope within the served realm.
    pub scope: &'a str,
}

/// A version is ordered only within this full authenticated key.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PublicationKey<'a> {
    /// Full expected control authority identity.
    pub issuer: IdentityKey,
    /// Full recipient identity.
    pub recipient: IdentityKey,
    /// Signed served realm.
    pub served_realm: RealmId,
    /// Signed opaque scope within the realm.
    pub scope: &'a str,
    /// Owning family number, including unknown future families.
    pub family: u64,
    /// Exact owning-family kind identifier.
    pub kind: &'a str,
}

/// Caller-retained version, including withdrawal and typed failure tombstones.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcceptedPublication<'a> {
    /// Full accepted authority key.
    pub key: PublicationKey<'a>,
    /// Highest atomically accepted publication version for this key.
    pub version: u64,
}

/// Independent consumer inputs; no authority or clock is inferred from arrival.
#[derive(Clone, Copy, Debug)]
pub struct PublicationExpectation<'a> {
    /// Trusted authorized issuer, established outside this event.
    pub issuer: IdentityKey,
    /// Expected recipient.
    pub recipient: IdentityKey,
    /// Exact externally authorized realm/scope pairs.
    pub scopes: &'a [PublicationScope<'a>],
    /// Actual receiving channel, independent of the signed channel field.
    pub channel: PublicationChannel,
    /// Supplied Unix seconds; expiry is exclusive.
    pub now_seconds: u64,
}

/// Signed payload outcome; outer transport failure is never this value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub enum PublicationOutcome {
    /// Complete data; an empty byte string explicitly withdraws authority.
    Data = 0,
    /// Authenticated Node L3 ACL fetch failure, denying immediately.
    FetchFailed = 1,
}

/// Borrowed signed fields; access through [`PublicationEvent::content`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicationContent<'a> {
    /// Exact scope, recipient, issuer and owning-family kind.
    pub key: PublicationKey<'a>,
    /// Signed channel, also checked against actual receipt and kind ownership.
    pub channel: PublicationChannel,
    /// Only complete publications can replace known owned kinds.
    pub complete: bool,
    /// Positive authority version, never an arrival timestamp.
    pub version: u64,
    /// Inclusive issue time in Unix seconds.
    pub issued_seconds: u64,
    /// Exclusive expiry time in Unix seconds.
    pub expires_seconds: u64,
    /// Typed data or authenticated ACL fetch failure.
    pub outcome: PublicationOutcome,
    /// Exact opaque owning-family payload bytes; M6 bytes stay unchanged.
    pub payload: &'a [u8],
}

impl PublicationContent<'_> {
    /// Canonical signed content for a producer, with opaque family payload bytes.
    /// Known partial publications are valid; completeness is a consumer decision.
    /// # Errors
    /// Refuses invalid fields, unknown ownership, wrong channels and encoded bounds.
    pub fn canonical(&self) -> Result<Vec<u8>, PublicationError> {
        let key = &self.key;
        if !is_token(key.scope)
            || key.kind.is_empty()
            || key.kind.len() > MAX_TEXT_BYTES
            || publication_channel(key.family, key.kind) != Some(self.channel)
            || self.version == 0
            || self.issued_seconds >= self.expires_seconds
            || (self.outcome == PublicationOutcome::FetchFailed
                && (key.family != 11 || key.kind != "node-l3" || self.payload.is_empty()))
        {
            return Err(PublicationError::Field);
        }
        if self.payload.len() > MAX_PUBLICATION_BYTES {
            return Err(PublicationError::Bounds);
        }
        let mut writer = CborWriter::default();
        writer
            .array(14)
            .uint(1)
            .bytes(key.issuer.as_bytes())
            .bytes(key.recipient.as_bytes())
            .text(&key.served_realm.to_string())
            .text(key.scope)
            .uint(key.family)
            .text(key.kind)
            .uint(self.channel as u64)
            .boolean(self.complete)
            .uint(self.version)
            .uint(self.issued_seconds)
            .uint(self.expires_seconds)
            .uint(self.outcome as u64)
            .bytes(self.payload);
        let bytes = writer.into_bytes();
        let mut carrier = CborWriter::default();
        carrier.array(2).bytes(&bytes).bytes(&[0; 64]);
        if carrier.into_bytes().len() > MAX_PUBLICATION_BYTES {
            return Err(PublicationError::Bounds);
        }
        Ok(bytes)
    }

    /// Domain-separated canonical input for a producer-held signing key.
    /// # Errors
    /// Refuses the same invalid content and complete-event bounds as canonical.
    pub fn signing_input(&self) -> Result<Vec<u8>, PublicationError> {
        Ok(signing_input(PUBLICATION_DOMAIN, &self.canonical()?))
    }
}

/// Encodes validated content with a producer-supplied signature; holds no key.
/// Signature authenticity is checked only by the consumer decision API.
/// # Errors
/// Refuses invalid content, unknown ownership, wrong channels and encoded bounds.
pub fn encode_publication(
    content: &PublicationContent<'_>,
    signature: &[u8; 64],
) -> Result<Vec<u8>, PublicationError> {
    let bytes = content.canonical()?;
    let mut carrier = CborWriter::default();
    carrier.array(2).bytes(&bytes).bytes(signature);
    Ok(carrier.into_bytes())
}

/// Canonical borrowed event; decoding alone does not establish authentication.
#[derive(Clone, Debug)]
pub struct PublicationEvent<'a> {
    content: PublicationContent<'a>,
    signing_bytes: &'a [u8],
    signature: [u8; 64],
    wire: &'a [u8],
}

/// Pure refusal; errors never represent empty authority.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PublicationError {
    /// Invalid, truncated, nonminimal or trailing CBOR.
    #[error(transparent)]
    Contract(#[from] crate::account::AccountError),
    /// Measured encoded event or snapshot exceeds its byte ceiling.
    #[error("publication encoded byte bound exceeded")]
    Bounds,
    /// Unsupported schema, discriminant or invalid required field.
    #[error("invalid publication field")]
    Field,
    /// Signed issuer differs from the externally trusted issuer.
    #[error("publication issuer mismatch")]
    Issuer,
    /// Signed recipient differs from the expected recipient.
    #[error("publication recipient mismatch")]
    Recipient,
    /// Served realm and scope are not an authorized pair.
    #[error("publication scope mismatch")]
    Scope,
    /// Future issue or actual exclusive expiry.
    #[error("publication outside signed validity")]
    Validity,
    /// Domain-separated signature is invalid.
    #[error("invalid publication signature")]
    Signature,
    /// A known owned kind is partial rather than complete.
    #[error("incomplete publication")]
    Incomplete,
    /// Equal or lower version within the exact accepted key.
    #[error("stale or replayed publication version")]
    Stale,
    /// Snapshot keys are duplicated or not in strictly increasing order.
    #[error("publication snapshot keys out of order")]
    Order,
}

crate::account::contract_error!(PublicationError);

/// Consumer action. Only replacement, withdrawal and typed failure advance state.
#[derive(Debug)]
pub enum PublicationDecision<'a> {
    /// Atomically replace this exact scope/kind after owning-family validation.
    Replace(PublicationEvent<'a>),
    /// Explicit complete empty authority, retaining the accepted version tombstone.
    Withdraw(PublicationEvent<'a>),
    /// Authenticated ACL failure: deny immediately and retain the accepted version.
    FetchFailed(PublicationEvent<'a>),
    /// No event for the queried kind; retain current state, including absence.
    Absent,
    /// Authenticated future kind; no state change.
    UnknownKind(PublicationEvent<'a>),
    /// The known kind belongs to another channel; no state change.
    ChannelMismatch(PublicationEvent<'a>),
    /// Invalid event; no state change.
    Refused(PublicationError),
    /// Oversized received stream event: no replacement, terminate and reconnect.
    TerminateStream,
}

/// Kind ownership in the candidate profile; unknown pairs confer no authority.
#[must_use]
pub fn publication_channel(family: u64, kind: &str) -> Option<PublicationChannel> {
    match (family, kind) {
        (1, "own-node")
        | (6, "resource-authority")
        | (7, "public-edge")
        | (8, "identity-classes")
        | (9, "usage-profile")
        | (10, "node-control-profile")
        | (11, "policy-version") => Some(PublicationChannel::Stream),
        (2, "realm-peers")
        | (3, "egress-grants")
        | (4, "exit-grants")
        | (4, "subnet-routes")
        | (4, "provider-mappings")
        | (5, "payer-bindings")
        | (8, "directory")
        | (11, "node-l3") => Some(PublicationChannel::Snapshot),
        _ => None,
    }
}

impl<'a> PublicationEvent<'a> {
    /// Decodes without variable allocation, checking measured length first.
    /// Every declared string length is checked before borrowing its input slice.
    ///
    /// # Errors
    /// Rejects over-ceiling input, malformed encoding and invalid signed fields.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, PublicationError> {
        if bytes.len() > MAX_PUBLICATION_BYTES {
            return Err(PublicationError::Bounds);
        }
        let mut carrier = CborReader::new(bytes, MAX_PUBLICATION_BYTES)?;
        carrier.array(2)?;
        let signing_bytes = carrier.bytes_up_to(bytes.len())?;
        let signature = carrier.fixed_bytes()?;
        carrier.finish()?;
        let mut reader = CborReader::new(signing_bytes, bytes.len())?;
        reader.array(14)?;
        if reader.uint()? != 1 {
            return Err(PublicationError::Field);
        }
        let key = PublicationKey {
            issuer: IdentityKey::from_bytes(&reader.fixed_bytes()?)
                .map_err(|_| PublicationError::Field)?,
            recipient: IdentityKey::from_bytes(&reader.fixed_bytes()?)
                .map_err(|_| PublicationError::Field)?,
            served_realm: reader
                .text_up_to(26)?
                .parse()
                .map_err(|_| PublicationError::Field)?,
            scope: reader.text_up_to(MAX_TEXT_BYTES)?,
            family: reader.uint()?,
            kind: reader.text_up_to(MAX_TEXT_BYTES)?,
        };
        let channel = match reader.uint()? {
            0 => PublicationChannel::Stream,
            1 => PublicationChannel::Snapshot,
            _ => return Err(PublicationError::Field),
        };
        let complete = reader.boolean()?;
        let version = reader.uint()?;
        let issued_seconds = reader.uint()?;
        let expires_seconds = reader.uint()?;
        let outcome = match reader.uint()? {
            0 => PublicationOutcome::Data,
            1 => PublicationOutcome::FetchFailed,
            _ => return Err(PublicationError::Field),
        };
        let payload = reader.bytes_up_to(bytes.len())?;
        reader.finish()?;
        if !is_token(key.scope)
            || key.kind.is_empty()
            || version == 0
            || issued_seconds >= expires_seconds
            || (outcome == PublicationOutcome::FetchFailed
                && (key.family != 11 || key.kind != "node-l3" || payload.is_empty()))
        {
            return Err(PublicationError::Field);
        }
        Ok(Self {
            content: PublicationContent {
                key,
                channel,
                complete,
                version,
                issued_seconds,
                expires_seconds,
                outcome,
                payload,
            },
            signing_bytes,
            signature,
            wire: bytes,
        })
    }

    /// Canonical signed bytes, borrowed without encoding or payload copies.
    #[must_use]
    pub const fn canonical(&self) -> &'a [u8] {
        self.wire
    }

    /// Immutable signed fields, bound to the exact signature input.
    #[must_use]
    pub const fn content(&self) -> &PublicationContent<'a> {
        &self.content
    }

    /// Exact signature input, without re-encoding or establishing authenticity.
    #[must_use]
    pub fn signing_input(&self) -> Vec<u8> {
        signing_input(PUBLICATION_DOMAIN, self.signing_bytes)
    }

    /// Exact received signature; decoding alone does not authenticate it.
    #[must_use]
    pub const fn signature(&self) -> &[u8; 64] {
        &self.signature
    }

    /// Maps nonempty profile kinds to their owning typed catalogue.
    /// Empty payloads and other kinds return None; decoding establishes no authority.
    /// Callers must compare independently accepted reporter or membership context.
    /// # Errors
    /// Refuses malformed profile payloads and reporter/recipient disagreement.
    pub fn decode_profile_payload(
        &self,
    ) -> Result<
        Option<crate::account::usage::ProfilePublicationPayload>,
        crate::account::AccountError,
    > {
        use crate::{
            account::usage::NodeControlProfilePublication,
            account::usage::ProfilePublicationPayload, account::usage::UsageProfilePublication,
        };
        let content = self.content();
        if content.payload.is_empty() {
            return Ok(None);
        }
        match (content.key.family, content.key.kind) {
            (9, "usage-profile") => {
                let value = UsageProfilePublication::decode(content.payload)?;
                value.validate_reporter(content.key.recipient)?;
                Ok(Some(ProfilePublicationPayload::Usage(value)))
            }
            (10, "node-control-profile") => Ok(Some(ProfilePublicationPayload::NodeControl(
                NodeControlProfilePublication::decode(content.payload)?,
            ))),
            _ => Ok(None),
        }
    }

    /// Decodes only provider grant kinds, comparing signed envelope facts.
    /// Empty withdrawal and unrelated kinds return None.
    /// # Errors
    /// Refuses wrong payload types, recipients, issuers, families or revisions.
    pub fn decode_grant_payload(
        &self,
    ) -> Result<Option<crate::account::grants::GrantPublication>, PublicationError> {
        let content = self.content();
        if !matches!(
            (content.key.family, content.key.kind),
            (3, "egress-grants") | (4, "exit-grants")
        ) || content.payload.is_empty()
        {
            return Ok(None);
        }
        let value = crate::account::grants::GrantPublication::decode(content.payload)
            .map_err(|_| PublicationError::Field)?;
        if value.family != content.key.family
            || value.issuer != content.key.issuer
            || value.recipient != content.key.recipient
            || value.revision != content.version
        {
            return Err(PublicationError::Field);
        }
        Ok(Some(value))
    }

    /// Decodes only the standalone client route kind, never provider grants.
    /// Empty withdrawal and unrelated kinds return None.
    /// # Errors
    /// Refuses malformed routes or disagreement with event recipient/revision.
    pub fn decode_subnet_payload(
        &self,
    ) -> Result<Option<crate::account::subnet::SubnetPublication>, PublicationError> {
        let content = self.content();
        if (content.key.family, content.key.kind) != (4, "subnet-routes")
            || content.payload.is_empty()
        {
            return Ok(None);
        }
        let value = crate::account::subnet::SubnetPublication::decode(content.payload)
            .map_err(|_| PublicationError::Field)?;
        if value.recipient != *content.key.recipient.as_bytes() || value.revision != content.version
        {
            return Err(PublicationError::Field);
        }
        Ok(Some(value))
    }

    /// Decodes only the provider inventory kind; decoding conveys no authority.
    /// Empty carrier withdrawals and unrelated kinds return None.
    /// # Errors
    /// Refuses malformed or noncanonical mapping payloads.
    pub fn decode_provider_mapping_payload(
        &self,
    ) -> Result<Option<crate::account::subnet::ProviderMappings>, PublicationError> {
        let content = self.content();
        if (content.key.family, content.key.kind) != (4, "provider-mappings")
            || content.payload.is_empty()
        {
            return Ok(None);
        }
        crate::account::subnet::ProviderMappings::decode(content.payload)
            .map(Some)
            .map_err(|_| PublicationError::Field)
    }

    /// Compares routing collections against independently accepted identity and membership.
    /// Source signatures and pending delivery still require the source decision API.
    /// Empty withdrawals retain the same recipient, Network and source-scope fences.
    /// # Errors
    /// Refuses unrelated kinds, mismatched context, wrong scopes or invalid payloads.
    pub fn validate_routing_context(
        &self,
        recipient: IdentityKey,
        membership: &crate::account::control::exchange::MembershipScope,
    ) -> Result<(), PublicationError> {
        let content = self.content();
        let scope = match (content.key.family, content.key.kind) {
            (3, "egress-grants") => "egress",
            (4, "exit-grants" | "subnet-routes" | "provider-mappings") => "nodes",
            _ => return Err(PublicationError::Field),
        };
        if content.key.recipient != recipient {
            return Err(PublicationError::Recipient);
        }
        if content.key.scope != scope
            || content.key.served_realm != RealmId::from_bytes(membership.network_id)
        {
            return Err(PublicationError::Scope);
        }
        self.decode_provider_mapping_payload()?;
        if let Some(value) = self.decode_subnet_payload()?
            && (value.recipient != *recipient.as_bytes()
                || value.nsd_id != membership.nsd_id
                || value.network_id != membership.network_id)
        {
            return Err(PublicationError::Scope);
        }
        if let Some(value) = self.decode_grant_payload()?
            && value.grants.iter().any(|grant| {
                grant.resource.nsd_id != membership.nsd_id
                    || grant.resource.network_id != membership.network_id
            })
        {
            return Err(PublicationError::Scope);
        }
        Ok(())
    }

    fn authenticate(&self, expected: &PublicationExpectation<'_>) -> Result<(), PublicationError> {
        let content = &self.content;
        if content.key.issuer != expected.issuer {
            return Err(PublicationError::Issuer);
        }
        if content.key.recipient != expected.recipient {
            return Err(PublicationError::Recipient);
        }
        if !expected.scopes.contains(&PublicationScope {
            served_realm: content.key.served_realm,
            scope: content.key.scope,
        }) {
            return Err(PublicationError::Scope);
        }
        if expected.now_seconds < content.issued_seconds
            || expected.now_seconds >= content.expires_seconds
        {
            return Err(PublicationError::Validity);
        }
        verify(
            expected.issuer,
            PUBLICATION_DOMAIN,
            self.signing_bytes,
            &self.signature,
        )
        .map_err(|_| PublicationError::Signature)
    }
}

/// Decides from externally retained per-key versions, received bytes and clock.
/// No state is mutated; commit only accepted action versions atomically.
#[must_use]
pub fn decide_publication<'a>(
    last: &[AcceptedPublication<'_>],
    presented: Option<&'a [u8]>,
    expected: &PublicationExpectation<'_>,
) -> PublicationDecision<'a> {
    let Some(bytes) = presented else {
        return PublicationDecision::Absent;
    };
    if bytes.len() > MAX_PUBLICATION_BYTES && expected.channel == PublicationChannel::Stream {
        return PublicationDecision::TerminateStream;
    }
    let event = match PublicationEvent::decode(bytes) {
        Ok(event) => event,
        Err(error) => return PublicationDecision::Refused(error),
    };
    if let Err(error) = event.authenticate(expected) {
        return PublicationDecision::Refused(error);
    }
    let content = event.content();
    let Some(channel) = publication_channel(content.key.family, content.key.kind) else {
        return PublicationDecision::UnknownKind(event);
    };
    if content.channel != channel || expected.channel != channel {
        return PublicationDecision::ChannelMismatch(event);
    }
    if !content.complete {
        return PublicationDecision::Refused(PublicationError::Incomplete);
    }
    if last
        .iter()
        .any(|state| state.key == content.key && state.version >= content.version)
    {
        return PublicationDecision::Refused(PublicationError::Stale);
    }
    if event.decode_profile_payload().is_err()
        || event.decode_grant_payload().is_err()
        || event.decode_subnet_payload().is_err()
        || event.decode_provider_mapping_payload().is_err()
    {
        return PublicationDecision::Refused(PublicationError::Field);
    }
    if content.outcome == PublicationOutcome::FetchFailed {
        PublicationDecision::FetchFailed(event)
    } else if content.payload.is_empty() {
        PublicationDecision::Withdraw(event)
    } else {
        PublicationDecision::Replace(event)
    }
}

/// Low-level plain publication container; not a config.snapshot response validator.
/// No M6 type is redefined.
/// No decisions are available until every event has passed validation.
pub struct PublicationSnapshot<'a, 's> {
    bytes: &'a [u8],
    reader: CborReader<'a>,
    count: usize,
    last: &'s [AcceptedPublication<'s>],
    expected: &'s PublicationExpectation<'s>,
}

impl std::fmt::Debug for PublicationSnapshot<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PublicationSnapshot")
            .field("count", &self.count)
            .finish_non_exhaustive()
    }
}

impl<'a> PublicationSnapshot<'a, '_> {
    /// Exact canonical container bytes, borrowed from the validated input.
    #[must_use]
    pub const fn canonical(&self) -> &'a [u8] {
        self.bytes
    }

    /// Consumes the validated container, yielding decisions without a collection.
    pub fn decisions(mut self) -> impl Iterator<Item = PublicationDecision<'a>> {
        (0..self.count).map(move |_| match self.reader.bytes_up_to(MAX_CONTROL_BODY) {
            Ok(bytes) => decide_publication(self.last, Some(bytes), self.expected),
            Err(error) => PublicationDecision::Refused(error.into()),
        })
    }
}

fn snapshot_reader(bytes: &[u8]) -> Result<(CborReader<'_>, usize), PublicationError> {
    if bytes.len() > MAX_CONTROL_BODY {
        return Err(PublicationError::Bounds);
    }
    let mut reader = CborReader::new(bytes, MAX_CONTROL_BODY)?;
    reader.array(2)?;
    if reader.uint()? != 1 {
        return Err(PublicationError::Field);
    }
    let count = reader.array_up_to(bytes.len())?;
    Ok((reader, count))
}

/// Validates low-level plain snapshot events, including ordering.
/// This codec is not a config.snapshot response validator; use
/// PublicationSnapshotRequest::response for the source-bound carrier.
/// Missing keys retain their current state, and an empty container is valid.
///
/// # Errors
/// Rejects the whole snapshot on one malformed, unauthenticated, stale,
/// incomplete, oversized or wrongly scoped event, or unordered/duplicate key.
pub fn decide_publication_snapshot<'a, 's>(
    last: &'s [AcceptedPublication<'s>],
    bytes: &'a [u8],
    expected: &'s PublicationExpectation<'s>,
) -> Result<PublicationSnapshot<'a, 's>, PublicationError> {
    if expected.channel != PublicationChannel::Snapshot {
        return Err(PublicationError::Field);
    }
    let (mut reader, count) = snapshot_reader(bytes)?;
    let mut previous = None;
    for _ in 0..count {
        let bytes = reader.bytes_up_to(MAX_CONTROL_BODY)?;
        let decision = decide_publication(last, Some(bytes), expected);
        let event = match decision {
            PublicationDecision::Replace(event)
            | PublicationDecision::Withdraw(event)
            | PublicationDecision::FetchFailed(event)
            | PublicationDecision::UnknownKind(event)
            | PublicationDecision::ChannelMismatch(event) => event,
            PublicationDecision::Refused(error) => return Err(error),
            PublicationDecision::Absent | PublicationDecision::TerminateStream => {
                return Err(PublicationError::Field);
            }
        };
        let key = event.content().key;
        if previous.is_some_and(|previous| previous >= key) {
            return Err(PublicationError::Order);
        }
        previous = Some(key);
    }
    reader.finish()?;
    let (reader, _) = snapshot_reader(bytes)?;
    Ok(PublicationSnapshot {
        bytes,
        reader,
        count,
        last,
        expected,
    })
}
