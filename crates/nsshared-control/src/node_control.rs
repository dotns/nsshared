//! The pure Node-control message codec (quick-v2 §9, §12.1).
//!
//! Implements account registry family [`crate::account::publication::FamilyId::NodeControl`].
//! ACK means at least accepted; persistence before ACK is conforming.
//! Transport, persistence, retransmission and sessions remain consumer-owned.
//!
//! A message is the canonical CBOR array `[ver = 2, type, body]` of at most
//! [`MAX_MESSAGE_BYTES`]. Decoding rejects oversize input, non-canonical CBOR, an unknown
//! version or type, malformed bodies and trailing bytes; nothing is returned on error, so
//! a rejected message never reaches any state.

use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use blake2::{Blake2s, Digest, digest::consts::U16};
use nsshared_codec::cbor::{CborError, CborReader, CborWriter};
use nsshared_identity::{
    constants::MAX_NODE_RECORD_BYTES,
    record::{MAX_NODE_RECORD_RELAYS, NodeRecord, NodeRecordError},
    relay_id::{RelayId, RelayIdError},
};

/// The control message version.
pub const VERSION: u8 = 2;
/// The UDP port of the control channel at both ends.
pub const CONTROL_PORT: u16 = 47_900;
/// The largest encoded message.
pub const MAX_MESSAGE_BYTES: usize = 1200;
/// The most candidates in an `ENDPOINTS` message.
pub const MAX_CANDIDATES: usize = 8;
/// The most relays in an `ENDPOINTS` message.
pub const MAX_RELAYS: usize = 4;

const MAX_RELAY_ID_BYTES: usize = 255;

/// Message type numbers.
pub mod kind {
    /// `ACK`.
    pub const ACK: u8 = 0;
    /// `ENDPOINTS`, acknowledged.
    pub const ENDPOINTS: u8 = 1;
    /// `RECORD`, acknowledged.
    pub const RECORD: u8 = 2;
    /// `PROBE_REQUEST`.
    pub const PROBE_REQUEST: u8 = 3;
    /// `PROBE_REPLY`.
    pub const PROBE_REPLY: u8 = 4;
}

/// The 16-byte unkeyed BLAKE2s of a message's bytes, carried by its `ACK`.
pub type AckHash = [u8; 16];

/// Returns the [`AckHash`] of the encoded message `bytes`.
#[must_use]
pub fn ack_hash(bytes: &[u8]) -> AckHash {
    let mut hash = Blake2s::<U16>::new();
    Digest::update(&mut hash, bytes);
    hash.finalize().into()
}

/// How a candidate was learned.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CandidateKind {
    /// A local interface address.
    Local = 0,
    /// The address a relay observed.
    Reflected = 1,
    /// A configured address.
    Configured = 2,
}

/// A direct UDP endpoint of the sender.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Candidate {
    /// The address; the port is never 0.
    pub addr: SocketAddr,
    /// How it was learned.
    pub kind: CandidateKind,
}

impl Candidate {
    /// Canonical order: IPv4 before IPv6, then IP bytes, port and kind.
    fn sort_key(&self) -> (usize, Vec<u8>, u16, CandidateKind) {
        let ip = match self.addr.ip() {
            IpAddr::V4(ip) => ip.octets().to_vec(),
            IpAddr::V6(ip) => ip.octets().to_vec(),
        };
        (ip.len(), ip, self.addr.port(), self.kind)
    }
}

/// An `ENDPOINTS` snapshot: the sender's candidates and the relays it holds an active
/// slot on.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Endpoints {
    /// The sender's persistent, strictly increasing revision.
    pub revision: u64,
    /// At most [`MAX_CANDIDATES`] candidates.
    pub candidates: Vec<Candidate>,
    /// At most [`MAX_RELAYS`] relays.
    pub relays: Vec<RelayId>,
}

impl Endpoints {
    /// Builds the canonical snapshot of revision `revision` (quick-protocol §12.7):
    /// candidates deduplicated and sorted by address family, IP bytes, port and kind;
    /// relays deduplicated, `home` first when listed, the rest in byte order. Entries are
    /// taken greedily in that order while they fit the count limits and the message
    /// budget. Returns the snapshot and the number of omitted input entries.
    #[must_use]
    pub fn select(
        revision: u64,
        home: Option<&RelayId>,
        candidates: &[Candidate],
        relays: &[RelayId],
    ) -> (Self, usize) {
        let mut candidates = candidates.to_vec();
        candidates.sort_by_key(Candidate::sort_key);
        candidates.dedup();
        let mut relays = relays.to_vec();
        relays.sort_by(|a, b| a.as_str().as_bytes().cmp(b.as_str().as_bytes()));
        relays.dedup();
        if let Some(position) = home.and_then(|home| relays.iter().position(|relay| relay == home))
        {
            let home = relays.remove(position);
            relays.insert(0, home);
        }
        let mut snapshot = Self {
            revision,
            candidates: Vec::new(),
            relays: Vec::new(),
        };
        let mut omitted = 0;
        for candidate in candidates {
            snapshot.candidates.push(candidate);
            if snapshot.candidates.len() > MAX_CANDIDATES || !snapshot.fits() {
                snapshot.candidates.pop();
                omitted += 1;
            }
        }
        for relay in relays {
            snapshot.relays.push(relay);
            if snapshot.relays.len() > MAX_RELAYS || !snapshot.fits() {
                snapshot.relays.pop();
                omitted += 1;
            }
        }
        (snapshot, omitted)
    }

    fn fits(&self) -> bool {
        Message::Endpoints(self.clone()).encode().is_ok()
    }
}

/// A control message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Message {
    /// Acknowledges at least acceptance of type `type_in` whose bytes hash to `hash`.
    Ack {
        /// The acknowledged message type.
        type_in: u8,
        /// The [`AckHash`] of the acknowledged message.
        hash: AckHash,
    },
    /// The sender's endpoints.
    Endpoints(Endpoints),
    /// The sender's own node record.
    Record(NodeRecord),
    /// A direct-path probe.
    ProbeRequest([u8; 32]),
    /// The echo of a probe's nonce.
    ProbeReply([u8; 32]),
}

/// A message that cannot be encoded or decoded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CodecError {
    /// The encoding exceeds [`MAX_MESSAGE_BYTES`].
    TooLarge(usize),
    /// Non-canonical or malformed CBOR.
    Cbor(CborError),
    /// `ver` is not 2.
    Version(u64),
    /// An unknown message type.
    Type(u64),
    /// More than [`MAX_CANDIDATES`] candidates or [`MAX_RELAYS`] relays.
    TooMany,
    /// A candidate with an IP of neither 4 nor 16 bytes, port 0 or an unknown kind.
    Candidate,
    /// An invalid relay identifier.
    Relay(RelayIdError),
    /// An invalid node record.
    Record(NodeRecordError),
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge(length) => write!(
                f,
                "control message of {length} bytes exceeds {MAX_MESSAGE_BYTES} bytes"
            ),
            Self::Cbor(error) => write!(f, "non-canonical control message: {error}"),
            Self::Version(version) => write!(f, "unknown control message version {version}"),
            Self::Type(kind) => write!(f, "unknown control message type {kind}"),
            Self::TooMany => f.write_str("too many candidates or relays"),
            Self::Candidate => f.write_str("invalid candidate"),
            Self::Relay(error) => write!(f, "invalid relay: {error}"),
            Self::Record(error) => write!(f, "invalid record: {error}"),
        }
    }
}

impl std::error::Error for CodecError {}

impl From<CborError> for CodecError {
    fn from(error: CborError) -> Self {
        Self::Cbor(error)
    }
}

impl Message {
    /// The message type number.
    #[must_use]
    pub const fn kind(&self) -> u8 {
        match self {
            Self::Ack { .. } => kind::ACK,
            Self::Endpoints(_) => kind::ENDPOINTS,
            Self::Record(_) => kind::RECORD,
            Self::ProbeRequest(_) => kind::PROBE_REQUEST,
            Self::ProbeReply(_) => kind::PROBE_REPLY,
        }
    }

    /// Encodes the message canonically.
    ///
    /// # Errors
    ///
    /// [`CodecError::TooMany`] or [`CodecError::Candidate`] for an invalid `ENDPOINTS`,
    /// [`CodecError::TooLarge`] beyond [`MAX_MESSAGE_BYTES`].
    pub fn encode(&self) -> Result<Vec<u8>, CodecError> {
        let mut writer = CborWriter::with_capacity(128);
        writer
            .array(3)
            .uint(u64::from(VERSION))
            .uint(u64::from(self.kind()));
        let mut tail: &[u8] = &[];
        match self {
            Self::Ack { type_in, hash } => {
                writer.array(2).uint(u64::from(*type_in)).bytes(hash);
            }
            Self::Endpoints(endpoints) => encode_endpoints(&mut writer, endpoints)?,
            Self::Record(record) => {
                // The record is the last item: append its canonical encoding as is.
                writer.array(1);
                tail = record.as_bytes();
            }
            Self::ProbeRequest(nonce) | Self::ProbeReply(nonce) => {
                writer.array(1).bytes(nonce);
            }
        }
        let mut bytes = writer.into_bytes();
        bytes.extend_from_slice(tail);
        if bytes.len() > MAX_MESSAGE_BYTES {
            return Err(CodecError::TooLarge(bytes.len()));
        }
        Ok(bytes)
    }

    /// Decodes one message.
    ///
    /// # Errors
    ///
    /// [`CodecError`] naming the first violated rule.
    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        if bytes.len() > MAX_MESSAGE_BYTES {
            return Err(CodecError::TooLarge(bytes.len()));
        }
        let mut reader = CborReader::new(bytes, MAX_MESSAGE_BYTES)?;
        reader.array(3)?;
        let version = reader.uint()?;
        if version != u64::from(VERSION) {
            return Err(CodecError::Version(version));
        }
        let kind = reader.uint()?;
        let message = match u8::try_from(kind) {
            Ok(kind::ACK) => {
                reader.array(2)?;
                let type_in = u8::try_from(reader.uint()?).map_err(|_| CodecError::Type(kind))?;
                Self::Ack {
                    type_in,
                    hash: reader.fixed_bytes()?,
                }
            }
            Ok(kind::ENDPOINTS) => Self::Endpoints(decode_endpoints(&mut reader)?),
            Ok(kind::RECORD) => {
                reader.array(1)?;
                let start = reader.consumed().len();
                skip_record(&mut reader)?;
                let record = bytes
                    .get(start..reader.consumed().len())
                    .ok_or(CodecError::Cbor(CborError::Truncated))?;
                Self::Record(NodeRecord::decode(record).map_err(CodecError::Record)?)
            }
            Ok(kind::PROBE_REQUEST) => {
                reader.array(1)?;
                Self::ProbeRequest(reader.fixed_bytes()?)
            }
            Ok(kind::PROBE_REPLY) => {
                reader.array(1)?;
                Self::ProbeReply(reader.fixed_bytes()?)
            }
            _ => return Err(CodecError::Type(kind)),
        };
        reader.finish()?;
        Ok(message)
    }
}

fn encode_endpoints(writer: &mut CborWriter, endpoints: &Endpoints) -> Result<(), CodecError> {
    if endpoints.candidates.len() > MAX_CANDIDATES || endpoints.relays.len() > MAX_RELAYS {
        return Err(CodecError::TooMany);
    }
    writer
        .array(3)
        .uint(endpoints.revision)
        .array(endpoints.candidates.len());
    for candidate in &endpoints.candidates {
        if candidate.addr.port() == 0 {
            return Err(CodecError::Candidate);
        }
        writer.array(3);
        match candidate.addr.ip() {
            IpAddr::V4(ip) => writer.bytes(&ip.octets()),
            IpAddr::V6(ip) => writer.bytes(&ip.octets()),
        };
        writer
            .uint(u64::from(candidate.addr.port()))
            .uint(candidate.kind as u64);
    }
    writer.array(endpoints.relays.len());
    for relay in &endpoints.relays {
        writer.text(relay.as_str());
    }
    Ok(())
}

fn decode_endpoints(reader: &mut CborReader<'_>) -> Result<Endpoints, CodecError> {
    reader.array(3)?;
    let revision = reader.uint()?;
    let count = reader
        .array_up_to(MAX_CANDIDATES)
        .map_err(|_| CodecError::TooMany)?;
    let mut candidates = Vec::with_capacity(count);
    for _ in 0..count {
        reader.array(3)?;
        let ip = match reader.bytes_up_to(16)? {
            &[a, b, c, d] => IpAddr::V4(Ipv4Addr::new(a, b, c, d)),
            bytes => IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(bytes).map_err(|_| CodecError::Candidate)?,
            )),
        };
        let port = u16::try_from(reader.uint()?)
            .ok()
            .filter(|port| *port != 0)
            .ok_or(CodecError::Candidate)?;
        let kind = match reader.uint()? {
            0 => CandidateKind::Local,
            1 => CandidateKind::Reflected,
            2 => CandidateKind::Configured,
            _ => return Err(CodecError::Candidate),
        };
        candidates.push(Candidate {
            addr: SocketAddr::new(ip, port),
            kind,
        });
    }
    let count = reader
        .array_up_to(MAX_RELAYS)
        .map_err(|_| CodecError::TooMany)?;
    let mut relays = Vec::with_capacity(count);
    for _ in 0..count {
        relays.push(
            RelayId::parse(reader.text_up_to(MAX_RELAY_ID_BYTES)?).map_err(CodecError::Relay)?,
        );
    }
    Ok(Endpoints {
        revision,
        candidates,
        relays,
    })
}

/// Reads over one `NodeRecord` array (quick-v2 §3.1) so its bytes can be handed to
/// [`NodeRecord::decode`].
fn skip_record(reader: &mut CborReader<'_>) -> Result<(), CborError> {
    reader.array(8)?;
    reader.uint()?;
    reader.fixed_bytes::<32>()?;
    reader.fixed_bytes::<32>()?;
    reader.uint()?;
    reader.uint()?;
    reader.uint()?;
    for _ in 0..reader.array_up_to(MAX_NODE_RECORD_RELAYS)? {
        reader.text_up_to(MAX_NODE_RECORD_BYTES)?;
    }
    reader.fixed_bytes::<64>()?;
    Ok(())
}
