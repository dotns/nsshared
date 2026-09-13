use crate::{KeyBinding, NameRecord, ObservedAddr, RelayIdentifier, Revocation, codec::CborReader};
use blake2::{
    Blake2s,
    digest::{Digest, consts::U16},
};
use serde::{Serialize, ser::SerializeTuple};
use std::collections::BTreeSet;

/// Version of every keynet v1 in-band control record (§§13.6-13.7).
pub const CONTROL_VERSION: u8 = 1;
/// Inner UDP port consumed by the in-band control adapter (§§13.6-13.7).
pub const IN_BAND_CONTROL_PORT: u16 = 47_900;
/// Maximum in-band UDP payload size (§§13.6-13.7).
pub const MAX_CONTROL_DATAGRAM_BYTES: usize = 1_200;
/// Maximum endpoint candidates in either endpoint record (§§13.6-13.7).
pub const MAX_ENDPOINT_CANDIDATES: usize = 8;
/// Maximum relay names in either endpoint record (§§13.6-13.7).
pub const MAX_ENDPOINT_RELAYS: usize = 4;
/// Maximum simultaneously unacknowledged state records per peer (§13.6).
pub const MAX_UNACKNOWLEDGED_CONTROL_RECORDS: usize = 4;
/// Fixed acknowledged-record retransmission schedule in seconds (§13.6).
pub const CONTROL_RETRANSMISSION_SECONDS: [u64; 3] = [1, 2, 4];
/// Default maximum simultaneous relay sessions held by one node (§13.6).
pub const DEFAULT_RELAY_SESSIONS_PER_NODE: usize = 8;
/// First durable ordered-endpoint revision (§13.6).
pub const INITIAL_ENDPOINT_REVISION: u64 = 1;
/// Probe nonce width (§13.6).
pub const PROBE_NONCE_BYTES: usize = 32;
/// Exclusive probe request deadline in milliseconds (§13.6).
pub const PROBE_REQUEST_DEADLINE_MS: u64 = 1_000;
/// Minimum spacing between generated probes for one candidate (§13.6).
pub const PROBE_CANDIDATE_INTERVAL_MS: u64 = 250;
/// Maximum hole-punching round length and minimum next-round spacing (§13.6).
pub const PROBE_ROUND_SECONDS: u64 = 30;
/// Maximum live candidate probes retained per peer (§13.6).
pub const MAX_LIVE_PROBES_PER_PEER: usize = 8;
/// Maximum live candidate probes retained per node (§13.6).
pub const MAX_LIVE_PROBES_PER_NODE: usize = 4_096;
/// Generated probe-request rate and burst per node (§13.6).
pub const PROBE_REQUESTS_PER_SECOND: u32 = 256;
/// Generated probe-request burst per node (§13.6).
pub const PROBE_REQUEST_BURST_PER_NODE: u32 = 256;
/// Probe-reply rate and burst per authenticated peer (§13.6).
pub const PROBE_REPLIES_PER_SECOND_PER_PEER: u32 = 32;
/// Probe-reply burst per authenticated peer (§13.6).
pub const PROBE_REPLY_BURST_PER_PEER: u32 = 32;
/// Probe-reply rate and burst per node (§13.6).
pub const PROBE_REPLIES_PER_SECOND_PER_NODE: u32 = 256;
/// Probe-reply burst per node (§13.6).
pub const PROBE_REPLY_BURST_PER_NODE: u32 = 256;
/// Minimum scheduled binding-rotation lead (§13.6).
pub const MIN_ROTATION_LEAD_SECONDS: u64 = 300;
/// Default scheduled binding-rotation lead (§13.6).
pub const DEFAULT_ROTATION_LEAD_SECONDS: u64 = 300;
/// Default new-binding lifetime after cutover (§13.6).
pub const DEFAULT_NEW_BINDING_LIFETIME_SECONDS: u64 = 2_592_000;
/// Minimum new-binding validity remaining at cutover (§13.6).
pub const MIN_BINDING_REMAINING_AT_CUTOVER_SECONDS: u64 = 600;
/// Ordinary minimum previous-binding overlap after cutover (§13.6).
pub const MIN_PREVIOUS_BINDING_OVERLAP_SECONDS: u64 = 240;
/// Version-one old data-key grace period (§13.6).
pub const OLD_DATA_KEY_GRACE_SECONDS: u64 = 0;
/// Maximum imported current-binding record length (§13.6).
pub const MAX_CURRENT_BINDING_IMPORT_BYTES: usize = 512;

/// An in-band control record type tag (§13.7).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ControlType {
    /// ACK.
    Ack = 0,
    /// Legacy unordered ENDPOINTS.
    Endpoints = 1,
    /// BINDING.
    Binding = 2,
    /// REVOCATION.
    Revocation = 3,
    /// NAME.
    Name = 4,
    /// Durable ORDERED_ENDPOINTS snapshot.
    OrderedEndpoints = 5,
    /// Direct-path PROBE_REQUEST.
    ProbeRequest = 6,
    /// Direct-path PROBE_REPLY.
    ProbeReply = 7,
}

impl TryFrom<u8> for ControlType {
    type Error = ControlDecodeError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Ack),
            1 => Ok(Self::Endpoints),
            2 => Ok(Self::Binding),
            3 => Ok(Self::Revocation),
            4 => Ok(Self::Name),
            5 => Ok(Self::OrderedEndpoints),
            6 => Ok(Self::ProbeRequest),
            7 => Ok(Self::ProbeReply),
            _ => Err(ControlDecodeError::UnsupportedType),
        }
    }
}

/// A state-record type that uses the generic ACK/retry rule (§13.7).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AcknowledgedControlType {
    /// Legacy ENDPOINTS.
    Endpoints = 1,
    /// BINDING.
    Binding = 2,
    /// REVOCATION.
    Revocation = 3,
    /// NAME.
    Name = 4,
    /// ORDERED_ENDPOINTS.
    OrderedEndpoints = 5,
}

impl TryFrom<u8> for AcknowledgedControlType {
    type Error = ControlDecodeError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Endpoints),
            2 => Ok(Self::Binding),
            3 => Ok(Self::Revocation),
            4 => Ok(Self::Name),
            5 => Ok(Self::OrderedEndpoints),
            _ => Err(ControlDecodeError::InvalidBody),
        }
    }
}

/// Candidate provenance tag (§13.7).
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum EndpointKind {
    /// Local interface address.
    LocalInterface = 0,
    /// Address reflected by a relay.
    Reflected = 1,
    /// Explicitly configured address.
    Configured = 2,
}

impl TryFrom<u8> for EndpointKind {
    type Error = ControlDecodeError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::LocalInterface),
            1 => Ok(Self::Reflected),
            2 => Ok(Self::Configured),
            _ => Err(ControlDecodeError::InvalidBody),
        }
    }
}

/// One direct-path candidate in an endpoint record (§13.7).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EndpointCandidate {
    /// Raw IPv4/IPv6 address and nonzero UDP port.
    pub address: ObservedAddr,
    /// How the candidate was learned.
    pub kind: EndpointKind,
}

/// ACK body fields (§13.7).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControlAck {
    /// Acknowledged state-record type.
    pub type_in: AcknowledgedControlType,
    /// Unkeyed BLAKE2s-16 of the complete acknowledged datagram.
    pub hash: [u8; 16],
}

/// Legacy unordered ENDPOINTS body (§13.7).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyEndpoints {
    /// At most eight direct candidates.
    pub candidates: Vec<EndpointCandidate>,
    /// At most four legacy v0.6 relay-name strings.
    pub relays: Vec<String>,
}

/// BINDING body (§13.7).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BindingControl {
    /// Complete signed KeyBinding.
    pub binding: KeyBinding,
    /// Required cutover, exactly equal to `binding.not_before`.
    pub cutover: u64,
}

/// Durable complete ordered endpoint snapshot (§13.7).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrderedEndpoints {
    /// Durable, nonzero, strictly increasing caller-owned revision.
    pub revision: u64,
    /// Canonically ordered direct candidates.
    pub candidates: Vec<EndpointCandidate>,
    /// Bounded canonical relay identifiers in selected preference order.
    pub relays: Vec<RelayIdentifier>,
}

/// One exact version-one in-band control datagram (§13.7).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ControlRecord {
    /// Type 0 ACK.
    Ack(ControlAck),
    /// Type 1 legacy ENDPOINTS.
    Endpoints(LegacyEndpoints),
    /// Type 2 BINDING.
    Binding(BindingControl),
    /// Type 3 REVOCATION.
    Revocation(Revocation),
    /// Type 4 NAME.
    Name(NameRecord),
    /// Type 5 ORDERED_ENDPOINTS.
    OrderedEndpoints(OrderedEndpoints),
    /// Type 6 PROBE_REQUEST.
    ProbeRequest([u8; PROBE_NONCE_BYTES]),
    /// Type 7 PROBE_REPLY.
    ProbeReply([u8; PROBE_NONCE_BYTES]),
}

/// A control-record construction or serialization failure (§13.7).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlEncodeError {
    /// A body field, enum, list, relay text, ordering rule, or binding equality is invalid.
    InvalidBody,
    /// The complete UDP payload exceeds 1200 bytes.
    DatagramTooLarge,
    /// Canonical serialization unexpectedly failed.
    Serialization,
}

/// A strict control-record decoding failure (§§13.1, 13.7).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlDecodeError {
    /// The payload is empty or exceeds 1200 bytes.
    InvalidLength,
    /// The outer version is not one.
    UnsupportedVersion,
    /// The type is outside zero through seven.
    UnsupportedType,
    /// The body shape, width, value, count, order, or nested record is invalid.
    InvalidBody,
    /// The input is not the exact canonical encoding or contains trailing data.
    NonCanonical,
}

/// Result of deterministic ordered-snapshot selection (§13.7).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrderedEndpointSelection {
    /// The complete selected snapshot.
    pub snapshot: OrderedEndpoints,
    /// Number of valid input candidates omitted by count or datagram caps.
    pub omitted_candidates: usize,
    /// Number of valid input relay identifiers omitted by count or datagram caps.
    pub omitted_relays: usize,
}

/// Failure to advance the durable ordered-endpoint revision (§13.7).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndpointRevisionError {
    /// A present durable revision was zero even though revisions start at one.
    InvalidCurrent,
    /// The durable revision reached `u64::MAX` and must never wrap.
    Exhausted,
}

impl ControlRecord {
    /// Returns this record's fixed type tag.
    #[must_use]
    pub fn message_type(&self) -> ControlType {
        match self {
            Self::Ack(_) => ControlType::Ack,
            Self::Endpoints(_) => ControlType::Endpoints,
            Self::Binding(_) => ControlType::Binding,
            Self::Revocation(_) => ControlType::Revocation,
            Self::Name(_) => ControlType::Name,
            Self::OrderedEndpoints(_) => ControlType::OrderedEndpoints,
            Self::ProbeRequest(_) => ControlType::ProbeRequest,
            Self::ProbeReply(_) => ControlType::ProbeReply,
        }
    }

    /// Encodes exactly one canonical bounded `[ver,type,body]` datagram (§13.7).
    pub fn encode(&self) -> Result<Vec<u8>, ControlEncodeError> {
        validate_record(self)?;
        let mut output = Vec::new();
        ciborium::ser::into_writer(&ControlWire(self), &mut output)
            .map_err(|_| ControlEncodeError::Serialization)?;
        if output.len() > MAX_CONTROL_DATAGRAM_BYTES {
            return Err(ControlEncodeError::DatagramTooLarge);
        }
        Ok(output)
    }

    /// Decodes canonical structure and all bounds before any nested authentication (§13.7).
    pub fn decode(encoded: &[u8]) -> Result<Self, ControlDecodeError> {
        if encoded.is_empty() || encoded.len() > MAX_CONTROL_DATAGRAM_BYTES {
            return Err(ControlDecodeError::InvalidLength);
        }
        let mut reader = CborReader::new(encoded);
        reader.array(3).map_err(decode_body)?;
        let version = u8::try_from(reader.uint().map_err(decode_body)?)
            .map_err(|_| ControlDecodeError::InvalidBody)?;
        if version != CONTROL_VERSION {
            return Err(ControlDecodeError::UnsupportedVersion);
        }
        let message_type = u8::try_from(reader.uint().map_err(decode_body)?)
            .map_err(|_| ControlDecodeError::UnsupportedType)?;
        let message_type = ControlType::try_from(message_type)?;
        let record = decode_record_body(message_type, &mut reader)?;
        if !reader.finished() {
            return Err(ControlDecodeError::NonCanonical);
        }
        let canonical = record
            .encode()
            .map_err(|_| ControlDecodeError::InvalidBody)?;
        if canonical != encoded {
            return Err(ControlDecodeError::NonCanonical);
        }
        Ok(record)
    }
}

/// Computes the unkeyed BLAKE2s-16 ACK hash of exact datagram bytes (§13.7).
#[must_use]
pub fn control_ack_hash(datagram: &[u8]) -> [u8; 16] {
    Blake2s::<U16>::digest(datagram).into()
}

/// Returns revision one for new state or strictly advances without wrapping (§13.7).
pub fn next_endpoint_revision(current: Option<u64>) -> Result<u64, EndpointRevisionError> {
    match current {
        None => Ok(INITIAL_ENDPOINT_REVISION),
        Some(0) => Err(EndpointRevisionError::InvalidCurrent),
        Some(value) => value.checked_add(1).ok_or(EndpointRevisionError::Exhausted),
    }
}

/// Sorts candidates by width, raw IP, numeric port, and kind (§13.7).
pub fn sort_endpoint_candidates(candidates: &mut [EndpointCandidate]) {
    candidates.sort_by_key(|candidate| candidate_key(*candidate));
}

/// Selects one deterministic count- and byte-bounded ordered snapshot (§13.7).
pub fn select_ordered_endpoints(
    revision: u64,
    candidates: &[EndpointCandidate],
    relays: &[RelayIdentifier],
    home_relay: Option<&RelayIdentifier>,
) -> Result<OrderedEndpointSelection, ControlEncodeError> {
    if revision < INITIAL_ENDPOINT_REVISION {
        return Err(ControlEncodeError::InvalidBody);
    }
    let mut ordered_candidates = candidates.to_vec();
    if ordered_candidates
        .iter()
        .any(|candidate| !valid_candidate(*candidate))
    {
        return Err(ControlEncodeError::InvalidBody);
    }
    sort_endpoint_candidates(&mut ordered_candidates);
    ordered_candidates.dedup();
    let candidate_total = ordered_candidates.len();

    let mut ordered_relays = relays.to_vec();
    ordered_relays.sort();
    ordered_relays.dedup();
    if let Some(home) = home_relay
        && let Some(index) = ordered_relays.iter().position(|relay| relay == home)
    {
        let home = ordered_relays.remove(index);
        ordered_relays.insert(0, home);
    }
    let relay_total = ordered_relays.len();
    let mut snapshot = OrderedEndpoints {
        revision,
        candidates: Vec::new(),
        relays: Vec::new(),
    };
    for candidate in ordered_candidates.into_iter().take(MAX_ENDPOINT_CANDIDATES) {
        let mut next = snapshot.clone();
        next.candidates.push(candidate);
        if ControlRecord::OrderedEndpoints(next.clone())
            .encode()
            .is_ok()
        {
            snapshot = next;
        } else {
            break;
        }
    }
    for relay in ordered_relays.into_iter().take(MAX_ENDPOINT_RELAYS) {
        let mut next = snapshot.clone();
        next.relays.push(relay);
        if ControlRecord::OrderedEndpoints(next.clone())
            .encode()
            .is_ok()
        {
            snapshot = next;
        } else {
            break;
        }
    }
    Ok(OrderedEndpointSelection {
        omitted_candidates: candidate_total.saturating_sub(snapshot.candidates.len()),
        omitted_relays: relay_total.saturating_sub(snapshot.relays.len()),
        snapshot,
    })
}

fn validate_record(record: &ControlRecord) -> Result<(), ControlEncodeError> {
    match record {
        ControlRecord::Ack(_) | ControlRecord::ProbeRequest(_) | ControlRecord::ProbeReply(_) => {
            Ok(())
        }
        ControlRecord::Endpoints(value) => {
            validate_endpoints(&value.candidates, value.relays.len()).and_then(|()| {
                if value
                    .relays
                    .iter()
                    .all(|relay| !relay.is_empty() && relay.len() <= 255)
                {
                    Ok(())
                } else {
                    Err(ControlEncodeError::InvalidBody)
                }
            })
        }
        ControlRecord::Binding(value) => {
            if value.binding.ver == 1 && value.cutover == value.binding.not_before {
                Ok(())
            } else {
                Err(ControlEncodeError::InvalidBody)
            }
        }
        ControlRecord::Revocation(value) => {
            if value.ver == 1 {
                Ok(())
            } else {
                Err(ControlEncodeError::InvalidBody)
            }
        }
        ControlRecord::Name(value) => value
            .encode()
            .map(|_| ())
            .map_err(|_| ControlEncodeError::InvalidBody),
        ControlRecord::OrderedEndpoints(value) => {
            validate_endpoints(&value.candidates, value.relays.len())?;
            if value.revision == 0
                || !candidates_are_ordered(&value.candidates)
                || value.relays.iter().collect::<BTreeSet<_>>().len() != value.relays.len()
                || !value
                    .relays
                    .get(1..)
                    .unwrap_or_default()
                    .windows(2)
                    .all(|pair| pair[0] < pair[1])
            {
                return Err(ControlEncodeError::InvalidBody);
            }
            Ok(())
        }
    }
}

fn validate_endpoints(
    candidates: &[EndpointCandidate],
    relay_count: usize,
) -> Result<(), ControlEncodeError> {
    if candidates.len() > MAX_ENDPOINT_CANDIDATES
        || relay_count > MAX_ENDPOINT_RELAYS
        || candidates
            .iter()
            .any(|candidate| !valid_candidate(*candidate))
    {
        Err(ControlEncodeError::InvalidBody)
    } else {
        Ok(())
    }
}

fn valid_candidate(candidate: EndpointCandidate) -> bool {
    match candidate.address {
        ObservedAddr::V4(_, port) | ObservedAddr::V6(_, port) => port != 0,
    }
}

fn candidate_key(candidate: EndpointCandidate) -> (u8, [u8; 16], u16, EndpointKind) {
    match candidate.address {
        ObservedAddr::V4(ip, port) => {
            let mut bytes = [0; 16];
            bytes[..4].copy_from_slice(&ip);
            (4, bytes, port, candidate.kind)
        }
        ObservedAddr::V6(ip, port) => (16, ip, port, candidate.kind),
    }
}

fn candidates_are_ordered(candidates: &[EndpointCandidate]) -> bool {
    candidates
        .windows(2)
        .all(|pair| candidate_key(pair[0]) < candidate_key(pair[1]))
}

fn decode_record_body(
    message_type: ControlType,
    reader: &mut CborReader<'_>,
) -> Result<ControlRecord, ControlDecodeError> {
    match message_type {
        ControlType::Ack => {
            reader.array(2).map_err(decode_body)?;
            Ok(ControlRecord::Ack(ControlAck {
                type_in: AcknowledgedControlType::try_from(read_u8(reader)?)?,
                hash: reader.fixed_bytes().map_err(decode_body)?,
            }))
        }
        ControlType::Endpoints => {
            let (candidates, relays) = decode_legacy_endpoints(reader)?;
            Ok(ControlRecord::Endpoints(LegacyEndpoints {
                candidates,
                relays,
            }))
        }
        ControlType::Binding => {
            reader.array(2).map_err(decode_body)?;
            let binding = reader.binding().map_err(decode_body)?;
            let cutover = reader.uint().map_err(decode_body)?;
            Ok(ControlRecord::Binding(BindingControl { binding, cutover }))
        }
        ControlType::Revocation => {
            reader.array(1).map_err(decode_body)?;
            Ok(ControlRecord::Revocation(
                reader.revocation().map_err(decode_body)?,
            ))
        }
        ControlType::Name => {
            reader.array(1).map_err(decode_body)?;
            Ok(ControlRecord::Name(
                reader.name_record().map_err(decode_body)?,
            ))
        }
        ControlType::OrderedEndpoints => {
            reader.array(3).map_err(decode_body)?;
            let revision = reader.uint().map_err(decode_body)?;
            let candidates = decode_candidates(reader)?;
            let relays = decode_ordered_relays(reader)?;
            Ok(ControlRecord::OrderedEndpoints(OrderedEndpoints {
                revision,
                candidates,
                relays,
            }))
        }
        ControlType::ProbeRequest => {
            reader.array(1).map_err(decode_body)?;
            Ok(ControlRecord::ProbeRequest(
                reader.fixed_bytes().map_err(decode_body)?,
            ))
        }
        ControlType::ProbeReply => {
            reader.array(1).map_err(decode_body)?;
            Ok(ControlRecord::ProbeReply(
                reader.fixed_bytes().map_err(decode_body)?,
            ))
        }
    }
}

fn decode_legacy_endpoints(
    reader: &mut CborReader<'_>,
) -> Result<(Vec<EndpointCandidate>, Vec<String>), ControlDecodeError> {
    reader.array(2).map_err(decode_body)?;
    let candidates = decode_candidates(reader)?;
    let count = usize::try_from(reader.array_len().map_err(decode_body)?)
        .map_err(|_| ControlDecodeError::InvalidBody)?;
    if count > MAX_ENDPOINT_RELAYS {
        return Err(ControlDecodeError::InvalidBody);
    }
    let mut relays = Vec::with_capacity(count);
    for _ in 0..count {
        let relay = reader.text().map_err(decode_body)?;
        if relay.is_empty() || relay.len() > 255 {
            return Err(ControlDecodeError::InvalidBody);
        }
        relays.push(relay);
    }
    Ok((candidates, relays))
}

fn decode_candidates(
    reader: &mut CborReader<'_>,
) -> Result<Vec<EndpointCandidate>, ControlDecodeError> {
    let count = usize::try_from(reader.array_len().map_err(decode_body)?)
        .map_err(|_| ControlDecodeError::InvalidBody)?;
    if count > MAX_ENDPOINT_CANDIDATES {
        return Err(ControlDecodeError::InvalidBody);
    }
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        reader.array(3).map_err(decode_body)?;
        let address = match reader.peek() {
            Some(0x44) => ObservedAddr::V4(reader.fixed_bytes().map_err(decode_body)?, 0),
            Some(0x50) => ObservedAddr::V6(reader.fixed_bytes().map_err(decode_body)?, 0),
            _ => return Err(ControlDecodeError::InvalidBody),
        };
        let port = u16::try_from(reader.uint().map_err(decode_body)?)
            .ok()
            .filter(|port| *port != 0)
            .ok_or(ControlDecodeError::InvalidBody)?;
        let address = match address {
            ObservedAddr::V4(ip, _) => ObservedAddr::V4(ip, port),
            ObservedAddr::V6(ip, _) => ObservedAddr::V6(ip, port),
        };
        values.push(EndpointCandidate {
            address,
            kind: EndpointKind::try_from(read_u8(reader)?)?,
        });
    }
    Ok(values)
}

fn decode_ordered_relays(
    reader: &mut CborReader<'_>,
) -> Result<Vec<RelayIdentifier>, ControlDecodeError> {
    let count = usize::try_from(reader.array_len().map_err(decode_body)?)
        .map_err(|_| ControlDecodeError::InvalidBody)?;
    if count > MAX_ENDPOINT_RELAYS {
        return Err(ControlDecodeError::InvalidBody);
    }
    (0..count)
        .map(|_| {
            RelayIdentifier::parse(&reader.text().map_err(decode_body)?)
                .map_err(|_| ControlDecodeError::InvalidBody)
        })
        .collect()
}

fn read_u8(reader: &mut CborReader<'_>) -> Result<u8, ControlDecodeError> {
    u8::try_from(reader.uint().map_err(decode_body)?).map_err(|_| ControlDecodeError::InvalidBody)
}

fn decode_body(_: crate::codec::CborError) -> ControlDecodeError {
    ControlDecodeError::InvalidBody
}

struct ControlWire<'a>(&'a ControlRecord);
struct CandidateWire(EndpointCandidate);

impl Serialize for ControlWire<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut outer = serializer.serialize_tuple(3)?;
        outer.serialize_element(&CONTROL_VERSION)?;
        outer.serialize_element(&(self.0.message_type() as u8))?;
        match self.0 {
            ControlRecord::Ack(value) => outer
                .serialize_element(&(value.type_in as u8, serde_bytes::Bytes::new(&value.hash)))?,
            ControlRecord::Endpoints(value) => {
                outer.serialize_element(&LegacyEndpointsWire(value))?
            }
            ControlRecord::Binding(value) => outer.serialize_element(&BindingWire(value))?,
            ControlRecord::Revocation(value) => {
                outer.serialize_element(&(NestedRevocation(value),))?
            }
            ControlRecord::Name(value) => outer.serialize_element(&(NestedName(value),))?,
            ControlRecord::OrderedEndpoints(value) => {
                outer.serialize_element(&OrderedEndpointsWire(value))?
            }
            ControlRecord::ProbeRequest(nonce) | ControlRecord::ProbeReply(nonce) => {
                outer.serialize_element(&(serde_bytes::Bytes::new(nonce),))?
            }
        }
        outer.end()
    }
}

struct LegacyEndpointsWire<'a>(&'a LegacyEndpoints);
struct BindingWire<'a>(&'a BindingControl);
struct OrderedEndpointsWire<'a>(&'a OrderedEndpoints);
struct NestedBinding<'a>(&'a KeyBinding);
struct NestedRevocation<'a>(&'a Revocation);
struct NestedName<'a>(&'a NameRecord);

impl Serialize for CandidateWire {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut tuple = serializer.serialize_tuple(3)?;
        match self.0.address {
            ObservedAddr::V4(ip, port) => {
                tuple.serialize_element(serde_bytes::Bytes::new(&ip))?;
                tuple.serialize_element(&port)?;
            }
            ObservedAddr::V6(ip, port) => {
                tuple.serialize_element(serde_bytes::Bytes::new(&ip))?;
                tuple.serialize_element(&port)?;
            }
        }
        tuple.serialize_element(&(self.0.kind as u8))?;
        tuple.end()
    }
}

impl Serialize for LegacyEndpointsWire<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut tuple = serializer.serialize_tuple(2)?;
        tuple.serialize_element(
            &self
                .0
                .candidates
                .iter()
                .copied()
                .map(CandidateWire)
                .collect::<Vec<_>>(),
        )?;
        tuple.serialize_element(&self.0.relays)?;
        tuple.end()
    }
}

impl Serialize for OrderedEndpointsWire<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut tuple = serializer.serialize_tuple(3)?;
        tuple.serialize_element(&self.0.revision)?;
        tuple.serialize_element(
            &self
                .0
                .candidates
                .iter()
                .copied()
                .map(CandidateWire)
                .collect::<Vec<_>>(),
        )?;
        tuple.serialize_element(
            &self
                .0
                .relays
                .iter()
                .map(RelayIdentifier::as_str)
                .collect::<Vec<_>>(),
        )?;
        tuple.end()
    }
}

impl Serialize for BindingWire<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut tuple = serializer.serialize_tuple(2)?;
        tuple.serialize_element(&NestedBinding(&self.0.binding))?;
        tuple.serialize_element(&self.0.cutover)?;
        tuple.end()
    }
}

macro_rules! serialize_nested {
    ($name:ident, $encode:expr) => {
        impl Serialize for $name<'_> {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                let bytes = ($encode)(self.0);
                let value: ciborium::value::Value = ciborium::de::from_reader(bytes.as_slice())
                    .map_err(serde::ser::Error::custom)?;
                value.serialize(serializer)
            }
        }
    };
}

serialize_nested!(NestedBinding, |value: &KeyBinding| value.encode());
serialize_nested!(NestedRevocation, |value: &Revocation| value.encode());
impl Serialize for NestedName<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let bytes = self
            .0
            .encode()
            .map_err(|_| serde::ser::Error::custom("invalid name record"))?;
        let value: ciborium::value::Value =
            ciborium::de::from_reader(bytes.as_slice()).map_err(serde::ser::Error::custom)?;
        value.serialize(serializer)
    }
}
