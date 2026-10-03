//! In-tunnel control channel messages, ACK hashing, ENDPOINTS selection and acceptance,
//! RECORD handling and probe correlation (quick-v2 §9, quick-protocol §12.7).

use crate::{
    codec::{CborError, CborReader, CborWriter},
    constants::{MAX_CONTROL_MESSAGE_BYTES, MAX_ENDPOINT_CANDIDATES, MAX_ENDPOINT_RELAYS},
    identifier::{RelayId, RelayIdError},
    identity::Identity,
    record::{NodeRecord, NodeRecordError, RecordDecision, RecordMarks},
};
use blake2::{Blake2s128, Digest};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use thiserror::Error;

/// Control message format version `ver` (quick-v2 §9).
pub const CONTROL_VERSION: u8 = 2;
/// ACK hash length in bytes (quick-v2 §9).
pub const ACK_HASH_BYTES: usize = 16;
/// Probe nonce length in bytes (quick-v2 §9).
pub const PROBE_NONCE_BYTES: usize = 32;
/// First ENDPOINTS revision (quick-v2 §9, quick-protocol §12.7).
pub const INITIAL_ENDPOINT_REVISION: u64 = 1;
/// Retransmission schedule in seconds for unacknowledged ENDPOINTS and RECORD (quick-v2 §9).
pub const CONTROL_RETRANSMIT_SECONDS: [u64; 3] = [1, 2, 4];
/// Maximum unacknowledged ENDPOINTS and RECORD messages per peer (quick-v2 §9).
pub const MAX_UNACKNOWLEDGED_CONTROL_MESSAGES: usize = 4;
/// Minimum spacing between probe requests to one candidate, in milliseconds (quick-v2 §9).
pub const PROBE_CANDIDATE_INTERVAL_MS: u64 = 250;
/// Probe request deadline in milliseconds; the deadline itself is excluded (quick-v2 §9).
pub const PROBE_DEADLINE_MS: u64 = 1_000;
/// Probe round length and minimum spacing between round starts, in seconds (quick-v2 §9).
pub const PROBE_ROUND_SECONDS: u64 = 30;
/// Unanswered non-keepalive outbound traffic time after which the direct path is lost, in
/// seconds of monotonic time (quick-v2 §9).
pub const DIRECT_LOSS_SECONDS: u64 = 15;

/// A probe nonce (quick-v2 §9).
pub type ProbeNonce = [u8; PROBE_NONCE_BYTES];

/// A control message type (quick-v2 §9).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ControlType {
    /// 0 ACK.
    Ack = 0,
    /// 1 ENDPOINTS.
    Endpoints = 1,
    /// 2 RECORD.
    Record = 2,
    /// 3 PROBE_REQUEST.
    ProbeRequest = 3,
    /// 4 PROBE_REPLY.
    ProbeReply = 4,
}

/// A message type that is acknowledged and retransmitted until ACKed (quick-v2 §9).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AckedType {
    /// 1 ENDPOINTS.
    Endpoints = 1,
    /// 2 RECORD.
    Record = 2,
}

/// An ACK body `[type_in, hash]` (quick-v2 §9).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ack {
    /// The acknowledged message type.
    pub type_in: AckedType,
    /// Unkeyed BLAKE2s-128 of the exact acknowledged datagram bytes.
    pub hash: [u8; ACK_HASH_BYTES],
}

/// Endpoint candidate provenance `kind` (quick-v2 §9).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum EndpointKind {
    /// 0 local interface address.
    Local = 0,
    /// 1 address reflected by a relay.
    Reflected = 1,
    /// 2 configured address.
    Configured = 2,
}

/// One direct-path candidate `[ip, port, kind]` (quick-v2 §9).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct EndpointCandidate {
    /// The IP address; IPv4 encodes as bytes4 and IPv6 as bytes16.
    pub ip: IpAddr,
    /// The UDP port, 1..=65535.
    pub port: u16,
    /// How the candidate was learned.
    pub kind: EndpointKind,
}

/// An ENDPOINTS body `[revision, candidates, relays]`, one atomic snapshot (quick-v2 §9).
///
/// Encodable snapshots are canonical: `revision >= 1`, at most eight candidates in strictly
/// increasing canonical order, at most four distinct relays where all but the first (the
/// home relay when active) are in strictly increasing byte order (quick-protocol §12.7).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Endpoints {
    /// The sender's persistent, strictly increasing revision.
    pub revision: u64,
    /// Direct-path candidates.
    pub candidates: Vec<EndpointCandidate>,
    /// Relays on which the sender holds an active slot.
    pub relays: Vec<RelayId>,
}

/// One control message (quick-v2 §9).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ControlMessage {
    /// Type 0 ACK.
    Ack(Ack),
    /// Type 1 ENDPOINTS.
    Endpoints(Endpoints),
    /// Type 2 RECORD, the sender's own valid NodeRecord.
    Record(NodeRecord),
    /// Type 3 PROBE_REQUEST.
    ProbeRequest(ProbeNonce),
    /// Type 4 PROBE_REPLY.
    ProbeReply(ProbeNonce),
}

/// A rejected control message (quick-v2 §9, §12.1).
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ControlError {
    /// The datagram exceeds 1200 bytes.
    #[error("control message of {0} bytes exceeds {MAX_CONTROL_MESSAGE_BYTES} bytes")]
    TooLarge(usize),
    /// The input is not canonical CBOR of the message shape, including wrong arity and
    /// trailing bytes (quick-v2 §12.1).
    #[error("non-canonical control message: {0}")]
    Cbor(#[from] CborError),
    /// `ver` is not 2.
    #[error("unknown control message version {0}")]
    Version(u64),
    /// `type` is not 0..=4.
    #[error("unknown control message type {0}")]
    UnknownType(u64),
    /// ACK `type_in` is not an acknowledged type (1 or 2).
    #[error("ACK type_in {0} is not an acknowledged type")]
    AckType(u64),
    /// ENDPOINTS `revision` is 0; revisions start at 1.
    #[error("ENDPOINTS revision must start at 1")]
    ZeroRevision,
    /// More than eight candidates.
    #[error("ENDPOINTS lists {0} candidates, at most {MAX_ENDPOINT_CANDIDATES} allowed")]
    TooManyCandidates(usize),
    /// More than four relays.
    #[error("ENDPOINTS lists {0} relays, at most {MAX_ENDPOINT_RELAYS} allowed")]
    TooManyRelays(usize),
    /// A candidate `ip` is neither 4 nor 16 bytes.
    #[error("candidate IP of {0} bytes, expected 4 or 16")]
    CandidateIpLength(usize),
    /// A candidate `port` is outside 1..=65535.
    #[error("candidate port {0} is outside 1..=65535")]
    CandidatePort(u64),
    /// A candidate `kind` is not 0, 1 or 2.
    #[error("unknown candidate kind {0}")]
    CandidateKind(u64),
    /// Candidates are not in strictly increasing canonical order (quick-protocol §12.7).
    #[error("ENDPOINTS candidates are not in canonical order")]
    CandidateOrder,
    /// Relays repeat, or those after the first are not in strictly increasing byte order
    /// (quick-protocol §12.7).
    #[error("ENDPOINTS relays are not in canonical order")]
    RelayOrder,
    /// A relay entry is not a canonical relay identifier (quick-v2 §8.6).
    #[error("invalid relay identifier: {0}")]
    RelayId(#[from] RelayIdError),
    /// The nested NodeRecord is malformed or invalid (quick-v2 §3.2).
    #[error("invalid nested node record: {0}")]
    Record(#[from] NodeRecordError),
}

impl ControlMessage {
    /// Returns the message type (quick-v2 §9).
    #[must_use]
    pub const fn message_type(&self) -> ControlType {
        match self {
            Self::Ack(_) => ControlType::Ack,
            Self::Endpoints(_) => ControlType::Endpoints,
            Self::Record(_) => ControlType::Record,
            Self::ProbeRequest(_) => ControlType::ProbeRequest,
            Self::ProbeReply(_) => ControlType::ProbeReply,
        }
    }

    /// Encodes the canonical datagram `[ver = 2, type, body]` (quick-v2 §9, §12.1).
    ///
    /// # Errors
    ///
    /// For ENDPOINTS, [`ControlError::ZeroRevision`], a count, port or order violation, or
    /// [`ControlError::TooLarge`] when the datagram exceeds 1200 bytes.
    pub fn encode(&self) -> Result<Vec<u8>, ControlError> {
        let mut writer = CborWriter::with_capacity(MAX_CONTROL_MESSAGE_BYTES);
        writer
            .array(3)
            .uint(u64::from(CONTROL_VERSION))
            .uint(self.message_type() as u64);
        match self {
            Self::Ack(ack) => {
                writer.array(2).uint(ack.type_in as u64).bytes(&ack.hash);
            }
            Self::Endpoints(endpoints) => {
                check_endpoints(endpoints)?;
                writer.array(3).uint(endpoints.revision);
                writer.array(endpoints.candidates.len());
                for candidate in &endpoints.candidates {
                    writer.array(3);
                    match candidate.ip {
                        IpAddr::V4(ip) => writer.bytes(&ip.octets()),
                        IpAddr::V6(ip) => writer.bytes(&ip.octets()),
                    };
                    writer
                        .uint(u64::from(candidate.port))
                        .uint(candidate.kind as u64);
                }
                writer.array(endpoints.relays.len());
                for relay in &endpoints.relays {
                    writer.text(relay.as_str());
                }
            }
            Self::Record(_) => {
                writer.array(1);
            }
            Self::ProbeRequest(nonce) | Self::ProbeReply(nonce) => {
                writer.array(1).bytes(nonce);
            }
        }
        let mut encoded = writer.into_bytes();
        if let Self::Record(record) = self {
            encoded.extend_from_slice(record.as_bytes());
        }
        if encoded.len() > MAX_CONTROL_MESSAGE_BYTES {
            return Err(ControlError::TooLarge(encoded.len()));
        }
        Ok(encoded)
    }

    /// Decodes and validates one datagram (quick-v2 §9, §12.1).
    ///
    /// Size, canonical CBOR, version, type, arity, every body bound and trailing bytes are
    /// checked before the nested NodeRecord signature. The record is the final item, so
    /// bytes after it are rejected by [`NodeRecord::decode`] as trailing bytes.
    ///
    /// # Errors
    ///
    /// [`ControlError`] naming the first violated rule.
    pub fn decode(datagram: &[u8]) -> Result<Self, ControlError> {
        if datagram.len() > MAX_CONTROL_MESSAGE_BYTES {
            return Err(ControlError::TooLarge(datagram.len()));
        }
        let mut reader = CborReader::new(datagram, MAX_CONTROL_MESSAGE_BYTES)?;
        reader.array(3)?;
        let version = reader.uint()?;
        if version != u64::from(CONTROL_VERSION) {
            return Err(ControlError::Version(version));
        }
        let message = match reader.uint()? {
            0 => {
                reader.array(2)?;
                let type_in = match reader.uint()? {
                    1 => AckedType::Endpoints,
                    2 => AckedType::Record,
                    other => return Err(ControlError::AckType(other)),
                };
                let hash = reader.fixed_bytes::<ACK_HASH_BYTES>()?;
                Self::Ack(Ack { type_in, hash })
            }
            1 => Self::Endpoints(decode_endpoints(&mut reader)?),
            2 => {
                reader.array(1)?;
                let rest = datagram.get(reader.consumed().len()..).unwrap_or_default();
                return Ok(Self::Record(NodeRecord::decode(rest)?));
            }
            3 => {
                reader.array(1)?;
                Self::ProbeRequest(reader.fixed_bytes()?)
            }
            4 => {
                reader.array(1)?;
                Self::ProbeReply(reader.fixed_bytes()?)
            }
            other => return Err(ControlError::UnknownType(other)),
        };
        reader.finish()?;
        Ok(message)
    }
}

fn decode_endpoints(reader: &mut CborReader<'_>) -> Result<Endpoints, ControlError> {
    reader.array(3)?;
    let revision = reader.uint()?;
    let count = reader.array_up_to(MAX_CONTROL_MESSAGE_BYTES)?;
    if count > MAX_ENDPOINT_CANDIDATES {
        return Err(ControlError::TooManyCandidates(count));
    }
    let mut candidates = Vec::with_capacity(count);
    for _ in 0..count {
        reader.array(3)?;
        let raw = reader.bytes_up_to(MAX_CONTROL_MESSAGE_BYTES)?;
        let ip = if let Ok(octets) = <[u8; 4]>::try_from(raw) {
            IpAddr::V4(Ipv4Addr::from(octets))
        } else if let Ok(octets) = <[u8; 16]>::try_from(raw) {
            IpAddr::V6(Ipv6Addr::from(octets))
        } else {
            return Err(ControlError::CandidateIpLength(raw.len()));
        };
        let port = reader.uint()?;
        let port = u16::try_from(port)
            .ok()
            .filter(|port| *port != 0)
            .ok_or(ControlError::CandidatePort(port))?;
        let kind = match reader.uint()? {
            0 => EndpointKind::Local,
            1 => EndpointKind::Reflected,
            2 => EndpointKind::Configured,
            other => return Err(ControlError::CandidateKind(other)),
        };
        candidates.push(EndpointCandidate { ip, port, kind });
    }
    let count = reader.array_up_to(MAX_CONTROL_MESSAGE_BYTES)?;
    if count > MAX_ENDPOINT_RELAYS {
        return Err(ControlError::TooManyRelays(count));
    }
    let mut relays = Vec::with_capacity(count);
    for _ in 0..count {
        relays.push(RelayId::parse(
            reader.text_up_to(MAX_CONTROL_MESSAGE_BYTES)?,
        )?);
    }
    let endpoints = Endpoints {
        revision,
        candidates,
        relays,
    };
    check_endpoints(&endpoints)?;
    Ok(endpoints)
}

fn check_endpoints(endpoints: &Endpoints) -> Result<(), ControlError> {
    if endpoints.revision < INITIAL_ENDPOINT_REVISION {
        return Err(ControlError::ZeroRevision);
    }
    if endpoints.candidates.len() > MAX_ENDPOINT_CANDIDATES {
        return Err(ControlError::TooManyCandidates(endpoints.candidates.len()));
    }
    if endpoints.relays.len() > MAX_ENDPOINT_RELAYS {
        return Err(ControlError::TooManyRelays(endpoints.relays.len()));
    }
    check_ports(&endpoints.candidates)?;
    if !endpoints
        .candidates
        .windows(2)
        .all(|pair| matches!(pair, [a, b] if candidate_key(a) < candidate_key(b)))
    {
        return Err(ControlError::CandidateOrder);
    }
    let rest_ordered = endpoints
        .relays
        .get(1..)
        .unwrap_or_default()
        .windows(2)
        .all(|pair| matches!(pair, [a, b] if a < b));
    let home_distinct = endpoints
        .relays
        .split_first()
        .is_none_or(|(home, rest)| !rest.contains(home));
    if !rest_ordered || !home_distinct {
        return Err(ControlError::RelayOrder);
    }
    Ok(())
}

fn check_ports(candidates: &[EndpointCandidate]) -> Result<(), ControlError> {
    match candidates.iter().find(|candidate| candidate.port == 0) {
        Some(_) => Err(ControlError::CandidatePort(0)),
        None => Ok(()),
    }
}

/// Canonical candidate order: address-family width, raw IP bytes, numeric port, kind
/// (quick-protocol §12.7).
fn candidate_key(candidate: &EndpointCandidate) -> (u8, [u8; 16], u16, EndpointKind) {
    let (width, bytes) = match candidate.ip {
        IpAddr::V4(ip) => {
            let mut bytes = [0; 16];
            bytes[..4].copy_from_slice(&ip.octets());
            (4, bytes)
        }
        IpAddr::V6(ip) => (16, ip.octets()),
    };
    (width, bytes, candidate.port, candidate.kind)
}

/// Returns the unkeyed BLAKE2s-128 of the exact datagram bytes, used by ACK and as the
/// persisted ENDPOINTS snapshot hash (quick-v2 §9).
#[must_use]
pub fn ack_hash(datagram: &[u8]) -> [u8; ACK_HASH_BYTES] {
    Blake2s128::digest(datagram).into()
}

impl Ack {
    /// Builds the ACK for a received datagram of type `type_in` (quick-v2 §9).
    #[must_use]
    pub fn for_datagram(type_in: AckedType, datagram: &[u8]) -> Self {
        Self {
            type_in,
            hash: ack_hash(datagram),
        }
    }

    /// Returns true when this ACK acknowledges the pending datagram of type `type_in`
    /// (quick-v2 §9).
    #[must_use]
    pub fn acknowledges(&self, type_in: AckedType, pending: &[u8]) -> bool {
        self.type_in == type_in && self.hash == ack_hash(pending)
    }
}

/// The ENDPOINTS revision space is used up; ordered publication for this identity is
/// terminal and reports `endpoint_revision_exhausted` (quick-protocol §12.7).
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("endpoint_revision_exhausted")]
pub struct EndpointRevisionExhausted;

/// Returns the next ENDPOINTS revision after the persisted `last`, 1 before the first
/// snapshot; never wraps (quick-v2 §9, quick-protocol §12.7).
///
/// # Errors
///
/// [`EndpointRevisionExhausted`] when `last` is `u64::MAX`.
pub fn next_endpoint_revision(last: Option<u64>) -> Result<u64, EndpointRevisionExhausted> {
    match last {
        None => Ok(INITIAL_ENDPOINT_REVISION),
        Some(last) => last.checked_add(1).ok_or(EndpointRevisionExhausted),
    }
}

/// A selected ENDPOINTS snapshot, its exact datagram and the omitted local entries
/// (quick-protocol §12.7).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndpointSelection {
    /// The selected snapshot, sent unchanged to every peer at this revision.
    pub endpoints: Endpoints,
    /// The encoded datagram, at most 1200 bytes.
    pub datagram: Vec<u8>,
    /// Deduplicated candidates that did not fit, in canonical order.
    pub omitted_candidates: Vec<EndpointCandidate>,
    /// Deduplicated relays that did not fit, in selection order.
    pub omitted_relays: Vec<RelayId>,
}

/// Selects the canonical ENDPOINTS snapshot for `revision` (quick-protocol §12.7).
///
/// Candidates are sorted by address-family width, raw IP bytes, port and kind; relays by
/// byte order with `home_relay` first when it is active (the caller passes it only then)
/// and listed. Both lists are deduplicated, then filled greedily under the simultaneous
/// limits of eight candidates, four relays and a 1200-byte datagram: every complete entry
/// that does not fit the remaining budget is omitted and the scan continues. The result is
/// independent of input order, so every peer receives the same subset.
///
/// # Errors
///
/// [`ControlError::ZeroRevision`] or [`ControlError::CandidatePort`] for invalid input.
pub fn select_endpoints(
    revision: u64,
    candidates: &[EndpointCandidate],
    relays: &[RelayId],
    home_relay: Option<&RelayId>,
) -> Result<EndpointSelection, ControlError> {
    if revision < INITIAL_ENDPOINT_REVISION {
        return Err(ControlError::ZeroRevision);
    }
    check_ports(candidates)?;
    let mut ordered_candidates = candidates.to_vec();
    ordered_candidates.sort_by_key(candidate_key);
    ordered_candidates.dedup();
    let mut ordered_relays = relays.to_vec();
    ordered_relays.sort();
    ordered_relays.dedup();
    if let Some(home) = home_relay
        && let Some(index) = ordered_relays.iter().position(|relay| relay == home)
    {
        let home = ordered_relays.remove(index);
        ordered_relays.insert(0, home);
    }

    let mut endpoints = Endpoints {
        revision,
        candidates: Vec::new(),
        relays: Vec::new(),
    };
    let mut datagram = ControlMessage::Endpoints(endpoints.clone()).encode()?;
    let mut omitted_candidates = Vec::new();
    for candidate in ordered_candidates {
        if endpoints.candidates.len() == MAX_ENDPOINT_CANDIDATES {
            omitted_candidates.push(candidate);
            continue;
        }
        endpoints.candidates.push(candidate);
        match ControlMessage::Endpoints(endpoints.clone()).encode() {
            Ok(encoded) => datagram = encoded,
            Err(_) => {
                endpoints.candidates.pop();
                omitted_candidates.push(candidate);
            }
        }
    }
    let mut omitted_relays = Vec::new();
    for relay in ordered_relays {
        if endpoints.relays.len() == MAX_ENDPOINT_RELAYS {
            omitted_relays.push(relay);
            continue;
        }
        endpoints.relays.push(relay);
        match ControlMessage::Endpoints(endpoints.clone()).encode() {
            Ok(encoded) => datagram = encoded,
            Err(_) => {
                if let Some(relay) = endpoints.relays.pop() {
                    omitted_relays.push(relay);
                }
            }
        }
    }
    Ok(EndpointSelection {
        endpoints,
        datagram,
        omitted_candidates,
        omitted_relays,
    })
}

/// The receiver's persisted ENDPOINTS state for one peer: the largest accepted revision
/// and the hash of its exact datagram (quick-v2 §9).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EndpointState {
    /// The largest accepted revision.
    pub revision: u64,
    /// [`ack_hash`] of the accepted datagram.
    pub snapshot_hash: [u8; ACK_HASH_BYTES],
}

/// The outcome of receiving a valid ENDPOINTS datagram (quick-v2 §9, quick-protocol §12.7).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EndpointAcceptance {
    /// Lower revision than the persisted one: ignored, no ACK, state unchanged.
    Stale,
    /// Same revision and identical bytes: idempotent ACK, state unchanged; after a restart
    /// the runtime reapplies `endpoints` to its in-memory path state once.
    Duplicate {
        /// The snapshot, identical to the accepted one.
        endpoints: Endpoints,
        /// The ACK to send.
        ack: Ack,
    },
    /// Same revision, different bytes: report `endpoint_state_conflict`, keep the last
    /// accepted paths, no ACK, state unchanged.
    Conflict,
    /// Higher revision (or no state): atomically replace both lists, possibly with empty
    /// ones, persist `state`, then send `ack`.
    Replaced {
        /// The new snapshot.
        endpoints: Endpoints,
        /// The state to persist.
        state: EndpointState,
        /// The ACK to send.
        ack: Ack,
    },
}

impl EndpointAcceptance {
    /// Returns the ACK to send, if any (quick-v2 §9).
    #[must_use]
    pub const fn ack(&self) -> Option<&Ack> {
        match self {
            Self::Duplicate { ack, .. } | Self::Replaced { ack, .. } => Some(ack),
            Self::Stale | Self::Conflict => None,
        }
    }
}

/// A received control datagram that is not handled; it gets no ACK (quick-v2 §9).
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ControlReceiveError {
    /// The datagram is malformed or its nested record invalid.
    #[error("malformed control message: {0}")]
    Malformed(#[from] ControlError),
    /// The datagram is valid but of another type than the handler expects.
    #[error("unexpected control message type {0:?}")]
    UnexpectedType(ControlType),
    /// RECORD `record.I` differs from the peer identity.
    #[error("RECORD identity differs from the peer identity")]
    PeerIdentity,
}

/// Decides how to handle a received ENDPOINTS datagram against the persisted state, `None`
/// before the first accepted snapshot; pure, the caller persists (quick-v2 §9,
/// quick-protocol §12.7).
///
/// # Errors
///
/// [`ControlReceiveError`] for a malformed or non-ENDPOINTS datagram; no ACK.
pub fn accept_endpoints(
    state: Option<&EndpointState>,
    datagram: &[u8],
) -> Result<EndpointAcceptance, ControlReceiveError> {
    let endpoints = match ControlMessage::decode(datagram)? {
        ControlMessage::Endpoints(endpoints) => endpoints,
        other => return Err(ControlReceiveError::UnexpectedType(other.message_type())),
    };
    let ack = Ack::for_datagram(AckedType::Endpoints, datagram);
    let acceptance = match state {
        Some(state) if endpoints.revision < state.revision => EndpointAcceptance::Stale,
        Some(state) if endpoints.revision == state.revision => {
            if ack.hash == state.snapshot_hash {
                EndpointAcceptance::Duplicate { endpoints, ack }
            } else {
                EndpointAcceptance::Conflict
            }
        }
        _ => EndpointAcceptance::Replaced {
            state: EndpointState {
                revision: endpoints.revision,
                snapshot_hash: ack.hash,
            },
            endpoints,
            ack,
        },
    };
    Ok(acceptance)
}

/// A RECORD handled against the peer's ordering state (quick-v2 §9, §3.3).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordReceipt {
    /// The valid received record.
    pub record: NodeRecord,
    /// The §3.3 decision; the caller applies it with [`RecordMarks::apply`].
    pub decision: RecordDecision,
    /// The ACK to send: present for accepted and idempotent records, absent for rejected
    /// (`Stale`) and conflicting ones.
    pub ack: Option<Ack>,
}

/// Handles a received RECORD datagram from the peer whose ordering state is `peer`; pure,
/// state is not changed (quick-v2 §9, §3.3).
///
/// # Errors
///
/// [`ControlReceiveError`] for a malformed datagram or record, another message type, or a
/// record whose `I` is not the peer's; none of them gets an ACK.
pub fn receive_record(
    peer: &RecordMarks,
    datagram: &[u8],
) -> Result<RecordReceipt, ControlReceiveError> {
    let record = match ControlMessage::decode(datagram)? {
        ControlMessage::Record(record) => record,
        other => return Err(ControlReceiveError::UnexpectedType(other.message_type())),
    };
    let decision = peer
        .evaluate(&record)
        .map_err(|_| ControlReceiveError::PeerIdentity)?;
    let ack = match decision {
        RecordDecision::Advanced | RecordDecision::Refreshed | RecordDecision::Unchanged => {
            Some(Ack::for_datagram(AckedType::Record, datagram))
        }
        RecordDecision::Stale | RecordDecision::Conflict => None,
    };
    Ok(RecordReceipt {
        record,
        decision,
        ack,
    })
}

/// One outstanding probe attempt to a candidate (quick-v2 §9, quick-protocol §12.7).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProbeAttempt {
    /// The complete peer identity `I`.
    pub peer: Identity,
    /// The caller's local WireGuard session identifier.
    pub session: u64,
    /// The candidate IP and port the request was sent to.
    pub candidate: SocketAddr,
    /// The active nonce.
    pub nonce: ProbeNonce,
    /// Monotonic send time in milliseconds.
    pub sent_at_ms: u64,
}

/// An authenticated PROBE_REPLY as observed by the caller (quick-v2 §9).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProbeReplyObservation {
    /// The identity of the peer whose session decrypted the reply.
    pub peer: Identity,
    /// The local WireGuard session that decrypted the reply.
    pub session: u64,
    /// The outer source IP and port of the reply.
    pub source: SocketAddr,
    /// The echoed nonce.
    pub nonce: ProbeNonce,
    /// Monotonic receive time in milliseconds.
    pub received_at_ms: u64,
}

/// Why a PROBE_REPLY does not correlate with an attempt (quick-protocol §12.7).
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProbeMismatch {
    /// Decrypted under another peer.
    #[error("probe reply from another peer")]
    Peer,
    /// Decrypted under another session.
    #[error("probe reply under another session")]
    Session,
    /// Not directly from the exact attempted candidate.
    #[error("probe reply from another source")]
    Source,
    /// Does not echo the active nonce.
    #[error("probe reply nonce is not the active nonce")]
    Nonce,
    /// Arrived at or after the 1 s deadline.
    #[error("probe reply after the deadline")]
    Deadline,
}

impl ProbeAttempt {
    /// Returns the exclusive deadline `sent_at_ms + 1000` (quick-v2 §9).
    #[must_use]
    pub const fn deadline_ms(&self) -> u64 {
        self.sent_at_ms.saturating_add(PROBE_DEADLINE_MS)
    }

    /// Checks that `reply` correlates with this attempt: same peer and session, directly
    /// from the exact candidate, echoing the active nonce, strictly before the deadline
    /// (quick-v2 §9, quick-protocol §12.7).
    ///
    /// # Errors
    ///
    /// [`ProbeMismatch`] naming the first failed condition.
    pub fn correlate(&self, reply: &ProbeReplyObservation) -> Result<(), ProbeMismatch> {
        if reply.peer != self.peer {
            Err(ProbeMismatch::Peer)
        } else if reply.session != self.session {
            Err(ProbeMismatch::Session)
        } else if reply.source != self.candidate {
            Err(ProbeMismatch::Source)
        } else if reply.nonce != self.nonce {
            Err(ProbeMismatch::Nonce)
        } else if reply.received_at_ms >= self.deadline_ms() {
            Err(ProbeMismatch::Deadline)
        } else {
            Ok(())
        }
    }
}
