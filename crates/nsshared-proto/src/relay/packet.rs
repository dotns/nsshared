//! Relay packet header and the eight body types (quick-v2 §8.1-§8.2, quick-protocol §12.5).

use crate::{
    codec::{CborError, CborReader, CborWriter},
    constants::{
        MAX_PRESENCE_TTL_SECONDS, MAX_RELAY_CONTROL_BYTES, MAX_RELAY_DATA_BODY_BYTES,
        MAX_RELAY_PACKET_BYTES, MIN_PRESENCE_TTL_SECONDS, MIN_RELAY_DATA_BODY_BYTES, NODE_ID_BYTES,
        NODE_RECORD_VERSION, RELAY_HEADER_BYTES, RELAY_MAGIC, RELAY_REGISTER_CONTEXT,
    },
    identifier::{MAX_RELAY_ID_BYTES, RelayId},
    identity::{Identity, NodeId},
    record::{MAX_NODE_RECORD_RELAYS, NodeRecord},
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use thiserror::Error;

/// The all-zero slot that names the relay itself (quick-v2 §8.1).
pub const RELAY_SLOT: NodeId = NodeId::from_bytes([0; NODE_ID_BYTES]);
/// Maximum REGISTER `relay_name` length in bytes (quick-v2 §8.6, quick-protocol §12.5).
pub const MAX_RELAY_NAME_BYTES: usize = MAX_RELAY_ID_BYTES;

/// A relay packet type byte (quick-v2 §8.2).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum RelayType {
    /// REGISTER, node to relay.
    Register = 1,
    /// REGISTERED, relay to node.
    Registered = 2,
    /// PRESENCE, node to relay.
    Presence = 3,
    /// REFLECT, node to relay.
    Reflect = 4,
    /// REFLECTED, relay to node.
    Reflected = 5,
    /// DATA, node to relay to node.
    Data = 6,
    /// STATUS, relay to node.
    Status = 7,
    /// REVOKE, node to relay.
    Revoke = 8,
}

/// The src / dst slot rule of a relay packet type (quick-v2 §8.2).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelayDirection {
    /// Node to relay: src non-zero, dst zero.
    ToRelay,
    /// Relay to node: src zero, dst non-zero.
    FromRelay,
    /// Node to node through the relay: src and dst non-zero.
    NodeToNode,
}

impl RelayType {
    /// Parses a type byte; `None` for an unknown type, which the relay answers with
    /// STATUS 5 (quick-v2 §8.2).
    #[must_use]
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Register),
            2 => Some(Self::Registered),
            3 => Some(Self::Presence),
            4 => Some(Self::Reflect),
            5 => Some(Self::Reflected),
            6 => Some(Self::Data),
            7 => Some(Self::Status),
            8 => Some(Self::Revoke),
            _ => None,
        }
    }

    /// Returns the type byte (quick-v2 §8.2).
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Returns the src / dst slot rule of this type (quick-v2 §8.2).
    #[must_use]
    pub const fn direction(self) -> RelayDirection {
        match self {
            Self::Register | Self::Presence | Self::Reflect | Self::Revoke => {
                RelayDirection::ToRelay
            }
            Self::Registered | Self::Reflected | Self::Status => RelayDirection::FromRelay,
            Self::Data => RelayDirection::NodeToNode,
        }
    }

    /// Returns the maximum whole packet length of this type: 2048 bytes for DATA, 1200
    /// bytes otherwise (quick-v2 §8.1).
    #[must_use]
    pub const fn max_packet_bytes(self) -> usize {
        match self {
            Self::Data => MAX_RELAY_PACKET_BYTES,
            _ => MAX_RELAY_CONTROL_BYTES,
        }
    }
}

/// A rejected relay packet (quick-v2 §8.1-§8.2, §12.1, quick-protocol §12.5).
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum RelayPacketError {
    /// The packet is shorter than the 29-byte header (quick-v2 §8.1).
    #[error("relay packet of {0} bytes is shorter than the {RELAY_HEADER_BYTES}-byte header")]
    TooShort(usize),
    /// The packet exceeds 2048 bytes, or 1200 bytes for a non-DATA type (quick-v2 §8.1).
    #[error("relay packet of {length} bytes exceeds the {maximum}-byte limit")]
    TooLarge {
        /// Packet length in bytes.
        length: usize,
        /// Applicable maximum in bytes.
        maximum: usize,
    },
    /// The magic is not `NSR2` (quick-v2 §8.1).
    #[error("relay packet magic is not NSR2")]
    BadMagic,
    /// The type byte is not 1..=8; the relay answers STATUS 5 (quick-v2 §8.2).
    #[error("unknown relay packet type {0}")]
    UnknownType(u8),
    /// The src / dst slots violate the direction rule of the type (quick-v2 §8.2).
    #[error("src / dst slots violate the {0:?} direction rule")]
    Direction(RelayType),
    /// A DATA body is empty or longer than 2019 bytes (quick-v2 §8.2).
    #[error("DATA body of {0} bytes is outside 1..={MAX_RELAY_DATA_BODY_BYTES}")]
    DataLength(usize),
    /// The body is not canonical CBOR of the fixed array shape: wrong arity, widths,
    /// item types or trailing bytes (quick-v2 §8.2, §12.1).
    #[error("non-canonical relay body: {0}")]
    Body(#[from] CborError),
    /// The nested REGISTER record has a version other than 2 (quick-v2 §3.2, §12.1).
    #[error("nested node record has unknown version {0}")]
    RecordVersion(u64),
    /// The REGISTER `relay_name` is not 1..=255 bytes (quick-protocol §12.5).
    #[error("relay_name of {0} bytes is outside 1..={MAX_RELAY_NAME_BYTES}")]
    RelayNameLength(usize),
    /// The STATUS `type_in` does not fit in a u8 (quick-v2 §8.2).
    #[error("STATUS type_in {0} does not fit in u8")]
    TypeIn(u64),
    /// The REGISTERED `presence_ttl_s` is outside 30..=3600 (quick-v2 §8.3 rule 5).
    #[error(
        "presence_ttl_s {0} is outside {MIN_PRESENCE_TTL_SECONDS}..={MAX_PRESENCE_TTL_SECONDS}"
    )]
    PresenceTtl(u64),
    /// REGISTERED carries capabilities with `ack_seq != 0` (quick-v2 §8.2).
    #[error("capabilities are only allowed when ack_seq = 0, got ack_seq {0}")]
    CapabilitiesNotProvisional(u64),
    /// A node control `seq` or REFLECTED echo is 0; sequences start at 1
    /// (quick-v2 §8.3 rule 5, quick-protocol §12.5 rule 7).
    #[error("seq must be at least 1")]
    ZeroSeq,
    /// The STATUS code is not 1..=6 (quick-v2 §8.2).
    #[error("unknown STATUS code {0}")]
    StatusCode(u64),
    /// The REVOKE reason is not 0 or 1 (quick-v2 §8.2).
    #[error("unknown REVOKE reason {0}")]
    RevokeReason(u64),
    /// The `observed_addr` IP is neither 4 nor 16 bytes (quick-v2 §8.2).
    #[error("observed_addr IP of {0} bytes is neither 4 nor 16")]
    ObservedIp(usize),
    /// The `observed_addr` port is not 1..=65535 (quick-protocol §12.5).
    #[error("observed_addr port {0} is outside 1..=65535")]
    ObservedPort(u64),
}

/// The 29-byte relay packet header (quick-v2 §8.1).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RelayHeader {
    /// The packet type.
    pub packet_type: RelayType,
    /// The sender slot: the sender's raw node ID, or [`RELAY_SLOT`].
    pub src: NodeId,
    /// The destination slot: the receiver's raw node ID, or [`RELAY_SLOT`].
    pub dst: NodeId,
}

impl RelayHeader {
    /// Checks the src / dst rule of the type (quick-v2 §8.2).
    ///
    /// # Errors
    ///
    /// [`RelayPacketError::Direction`].
    pub fn check_direction(&self) -> Result<(), RelayPacketError> {
        let valid = match self.packet_type.direction() {
            RelayDirection::ToRelay => !self.src.is_zero() && self.dst.is_zero(),
            RelayDirection::FromRelay => self.src.is_zero() && !self.dst.is_zero(),
            RelayDirection::NodeToNode => !self.src.is_zero() && !self.dst.is_zero(),
        };
        if valid {
            Ok(())
        } else {
            Err(RelayPacketError::Direction(self.packet_type))
        }
    }

    /// Encodes the header `NSR2 ‖ type ‖ src ‖ dst` (quick-v2 §8.1).
    ///
    /// # Errors
    ///
    /// [`RelayPacketError::Direction`].
    pub fn encode(&self) -> Result<[u8; RELAY_HEADER_BYTES], RelayPacketError> {
        self.check_direction()?;
        let mut output = [0; RELAY_HEADER_BYTES];
        let parts: [&[u8]; 4] = [
            &RELAY_MAGIC,
            &[self.packet_type.as_u8()],
            self.src.as_bytes(),
            self.dst.as_bytes(),
        ];
        for (slot, byte) in output.iter_mut().zip(parts.into_iter().flatten()) {
            *slot = *byte;
        }
        Ok(output)
    }

    /// Parses the header of a whole packet in the order length, magic, type, direction,
    /// per-type size limit; the body is not inspected (quick-v2 §8.1-§8.2).
    ///
    /// # Errors
    ///
    /// [`RelayPacketError::TooShort`], [`RelayPacketError::TooLarge`],
    /// [`RelayPacketError::BadMagic`], [`RelayPacketError::UnknownType`] or
    /// [`RelayPacketError::Direction`].
    pub fn parse(packet: &[u8]) -> Result<Self, RelayPacketError> {
        split_packet(packet).map(|(header, _)| header)
    }
}

/// Splits and checks the header, returning it with the raw body (quick-v2 §8.1).
fn split_packet(packet: &[u8]) -> Result<(RelayHeader, &[u8]), RelayPacketError> {
    let too_short = RelayPacketError::TooShort(packet.len());
    if packet.len() > MAX_RELAY_PACKET_BYTES {
        return Err(RelayPacketError::TooLarge {
            length: packet.len(),
            maximum: MAX_RELAY_PACKET_BYTES,
        });
    }
    let (magic, rest) = packet.split_first_chunk::<4>().ok_or(too_short)?;
    let (&[type_byte], rest) = rest.split_first_chunk::<1>().ok_or(too_short)?;
    let (src, rest) = rest.split_first_chunk::<NODE_ID_BYTES>().ok_or(too_short)?;
    let (dst, body) = rest.split_first_chunk::<NODE_ID_BYTES>().ok_or(too_short)?;
    if *magic != RELAY_MAGIC {
        return Err(RelayPacketError::BadMagic);
    }
    let packet_type =
        RelayType::from_u8(type_byte).ok_or(RelayPacketError::UnknownType(type_byte))?;
    let header = RelayHeader {
        packet_type,
        src: NodeId::from_bytes(*src),
        dst: NodeId::from_bytes(*dst),
    };
    header.check_direction()?;
    let maximum = packet_type.max_packet_bytes();
    if packet.len() > maximum {
        return Err(RelayPacketError::TooLarge {
            length: packet.len(),
            maximum,
        });
    }
    Ok((header, body))
}

/// A UDP source observed by the relay, `[ip bytes4|bytes16, port u16]` (quick-v2 §8.2).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ObservedAddr {
    /// The IP address; IPv4 is encoded as 4 bytes, IPv6 as 16 bytes.
    pub ip: IpAddr,
    /// The UDP port, 1..=65535.
    pub port: u16,
}

impl From<ObservedAddr> for SocketAddr {
    fn from(value: ObservedAddr) -> Self {
        Self::new(value.ip, value.port)
    }
}

/// REGISTER body `[record, incarnation, ts, node_ephemeral, relay_name, sig]`
/// (quick-v2 §8.2-§8.3).
///
/// The record is kept as its exact nested canonical array; it is only structurally
/// checked here, its validity and signature are checked by [`crate::relay::check_register`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Register {
    record: Vec<u8>,
    identity: Identity,
    incarnation: u64,
    ts: u64,
    node_ephemeral: [u8; 32],
    relay_name: String,
    signature: [u8; 64],
}

/// The REGISTER signer is not the record identity `I` (quick-v2 §8.3).
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("REGISTER signer is not the record identity")]
pub struct SignerMismatch;

/// The REGISTER signature does not strictly verify under `record.I` (quick-v2 §8.3, §12.2).
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("REGISTER signature does not verify")]
pub struct BadRegisterSignature;

impl Register {
    /// Builds and signs a REGISTER:
    /// `sig = Ed25519_I("ns/relay-register/v2" ‖ CBOR([record, incarnation, ts,
    /// node_ephemeral, relay_name]))` (quick-v2 §8.3).
    ///
    /// # Errors
    ///
    /// [`SignerMismatch`] when `signer` is not the identity of `record`.
    pub fn sign(
        signer: &SigningKey,
        record: &NodeRecord,
        incarnation: u64,
        ts: u64,
        node_ephemeral: [u8; 32],
        relay_name: &RelayId,
    ) -> Result<Self, SignerMismatch> {
        if signer.verifying_key().as_bytes() != record.identity() {
            return Err(SignerMismatch);
        }
        let mut register = Self {
            record: record.as_bytes().to_vec(),
            identity: *record.identity(),
            incarnation,
            ts,
            node_ephemeral,
            relay_name: relay_name.as_str().to_owned(),
            signature: [0; 64],
        };
        register.signature = signer.sign(&register.signed_message()).to_bytes();
        Ok(register)
    }

    /// Assembles a REGISTER from raw parts without signing or verifying, e.g. to relay
    /// a received body or build test inputs (quick-v2 §8.2).
    ///
    /// # Errors
    ///
    /// [`RelayPacketError`] when `record` is not one canonical record-shaped array or
    /// `relay_name` is not 1..=255 bytes.
    pub fn from_parts(
        record: &[u8],
        incarnation: u64,
        ts: u64,
        node_ephemeral: [u8; 32],
        relay_name: &str,
        signature: [u8; 64],
    ) -> Result<Self, RelayPacketError> {
        let mut reader = CborReader::new(record, MAX_RELAY_CONTROL_BYTES)?;
        let identity = read_record_shape(&mut reader)?;
        reader.finish()?;
        check_relay_name(relay_name)?;
        Ok(Self {
            record: record.to_vec(),
            identity,
            incarnation,
            ts,
            node_ephemeral,
            relay_name: relay_name.to_owned(),
            signature,
        })
    }

    /// Returns the exact nested record array bytes (quick-v2 §8.2).
    #[must_use]
    pub fn record(&self) -> &[u8] {
        &self.record
    }

    /// Returns `record.I`, read structurally from the nested record (quick-v2 §8.3).
    #[must_use]
    pub const fn identity(&self) -> &Identity {
        &self.identity
    }

    /// Returns the node ID of `record.I`, the expected REGISTER src (quick-v2 §8.3).
    #[must_use]
    pub fn node_id(&self) -> NodeId {
        NodeId::derive(&self.identity)
    }

    /// Returns `incarnation` (quick-v2 §8.2).
    #[must_use]
    pub const fn incarnation(&self) -> u64 {
        self.incarnation
    }

    /// Returns `ts` in Unix seconds (quick-v2 §8.2).
    #[must_use]
    pub const fn ts(&self) -> u64 {
        self.ts
    }

    /// Returns the node X25519 ephemeral public key (quick-v2 §8.2).
    #[must_use]
    pub const fn node_ephemeral(&self) -> &[u8; 32] {
        &self.node_ephemeral
    }

    /// Returns `relay_name` exactly as signed (quick-v2 §8.2).
    #[must_use]
    pub fn relay_name(&self) -> &str {
        &self.relay_name
    }

    /// Returns `sig` (quick-v2 §8.2).
    #[must_use]
    pub const fn signature(&self) -> &[u8; 64] {
        &self.signature
    }

    /// Encodes the six-field REGISTER body (quick-v2 §8.2).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        self.encode_array(true)
    }

    /// Returns `reg_hash = SHA-256(CBOR(six-field REGISTER body))` (quick-v2 §8.3).
    #[must_use]
    pub fn reg_hash(&self) -> [u8; 32] {
        Sha256::digest(self.encode()).into()
    }

    /// Strictly verifies `sig` under `record.I` (quick-v2 §8.3, §12.2).
    ///
    /// # Errors
    ///
    /// [`BadRegisterSignature`], also for an invalid or small-order `I`.
    pub fn verify_signature(&self) -> Result<(), BadRegisterSignature> {
        let key = VerifyingKey::from_bytes(&self.identity).map_err(|_| BadRegisterSignature)?;
        if key.is_weak() {
            return Err(BadRegisterSignature);
        }
        key.verify_strict(
            &self.signed_message(),
            &Signature::from_bytes(&self.signature),
        )
        .map_err(|_| BadRegisterSignature)
    }

    /// `"ns/relay-register/v2" ‖ CBOR(first five fields)` (quick-v2 §8.3, §12.2).
    fn signed_message(&self) -> Vec<u8> {
        let mut message = RELAY_REGISTER_CONTEXT.to_vec();
        message.extend_from_slice(&self.encode_array(false));
        message
    }

    /// The five unsigned fields, followed by `sig` when `signed`; the record is nested
    /// as its own array, not wrapped in a byte string.
    fn encode_array(&self, signed: bool) -> Vec<u8> {
        let mut head = CborWriter::with_capacity(1);
        head.array(if signed { 6 } else { 5 });
        let mut output = head.into_bytes();
        output.extend_from_slice(&self.record);
        let mut tail = CborWriter::with_capacity(MAX_RELAY_CONTROL_BYTES);
        tail.uint(self.incarnation)
            .uint(self.ts)
            .bytes(&self.node_ephemeral)
            .text(&self.relay_name);
        if signed {
            tail.bytes(&self.signature);
        }
        output.extend_from_slice(&tail.into_bytes());
        output
    }
}

/// REGISTERED body `[incarnation, relay_ephemeral, presence_ttl_s, observed_addr, ack_seq,
/// capabilities, mac]` (quick-v2 §8.2).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Registered {
    /// The echoed REGISTER incarnation.
    pub incarnation: u64,
    /// The relay X25519 ephemeral public key.
    pub relay_ephemeral: [u8; 32],
    /// The presence TTL in seconds, 30..=3600.
    pub presence_ttl_s: u32,
    /// The observed UDP source, `None` on WSS.
    pub observed_addr: Option<ObservedAddr>,
    /// 0 for the provisional reply, otherwise the acknowledged PRESENCE `seq`.
    pub ack_seq: u64,
    /// Opaque capability tokens (rendezvous §3.1); non-empty only when `ack_seq = 0`.
    pub capabilities: Vec<String>,
    /// The reply MAC under `sk`.
    pub mac: [u8; 32],
}

/// PRESENCE body `[incarnation, seq, mac]` (quick-v2 §8.2).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Presence {
    /// The session incarnation.
    pub incarnation: u64,
    /// The control sequence, starting at 1.
    pub seq: u64,
    /// The control MAC under `sk`.
    pub mac: [u8; 32],
}

/// REFLECT body `[incarnation, seq, nonce, mac]` (quick-v2 §8.2).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Reflect {
    /// The session incarnation.
    pub incarnation: u64,
    /// The control sequence, starting at 1.
    pub seq: u64,
    /// The 16-byte reflection nonce.
    pub nonce: [u8; 16],
    /// The control MAC under `sk`.
    pub mac: [u8; 32],
}

/// REFLECTED body `[incarnation, seq, nonce, observed_addr, mac]` (quick-v2 §8.2).
///
/// REFLECT runs only on UDP sessions (quick-v2 §8.3 rule 7), so `observed_addr` is
/// always present, as in v1 (quick-protocol §12.5).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Reflected {
    /// The session incarnation.
    pub incarnation: u64,
    /// The echoed REFLECT `seq`.
    pub seq: u64,
    /// The echoed REFLECT nonce.
    pub nonce: [u8; 16],
    /// The observed UDP source.
    pub observed_addr: ObservedAddr,
    /// The reply MAC under `sk`.
    pub mac: [u8; 32],
}

/// A STATUS code (quick-v2 §8.2).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
#[non_exhaustive]
pub enum StatusCode {
    /// 1: no destination.
    NoDestination = 1,
    /// 2: rate limited.
    RateLimited = 2,
    /// 3: too large.
    TooLarge = 3,
    /// 4: stale generation or incarnation.
    Stale = 4,
    /// 5: unsupported type.
    UnsupportedType = 5,
    /// 6: sender not registered or source mismatch.
    NotRegistered = 6,
}

impl StatusCode {
    /// Parses a STATUS code 1..=6 (quick-v2 §8.2).
    #[must_use]
    pub const fn from_u64(value: u64) -> Option<Self> {
        match value {
            1 => Some(Self::NoDestination),
            2 => Some(Self::RateLimited),
            3 => Some(Self::TooLarge),
            4 => Some(Self::Stale),
            5 => Some(Self::UnsupportedType),
            6 => Some(Self::NotRegistered),
            _ => None,
        }
    }
}

/// STATUS body `[type_in, destination, status]` (quick-v2 §8.2).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Status {
    /// The type byte of the triggering packet, possibly unknown.
    pub type_in: u8,
    /// The dst slot of the triggering packet.
    pub destination: NodeId,
    /// The status code.
    pub status: StatusCode,
}

/// A REVOKE reason (quick-v2 §8.2).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum RevokeReason {
    /// 0: rotation.
    Rotation = 0,
    /// 1: close.
    Close = 1,
}

/// REVOKE body `[incarnation, seq, reason, mac]` (quick-v2 §8.2).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Revoke {
    /// The session incarnation.
    pub incarnation: u64,
    /// The control sequence, starting at 1.
    pub seq: u64,
    /// The revocation reason.
    pub reason: RevokeReason,
    /// The control MAC under `sk`.
    pub mac: [u8; 32],
}

/// A typed relay packet body (quick-v2 §8.2).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RelayBody {
    /// Type 1.
    Register(Register),
    /// Type 2.
    Registered(Registered),
    /// Type 3.
    Presence(Presence),
    /// Type 4.
    Reflect(Reflect),
    /// Type 5.
    Reflected(Reflected),
    /// Type 6: a raw WireGuard packet of 1..=2019 bytes, not CBOR.
    Data(Vec<u8>),
    /// Type 7.
    Status(Status),
    /// Type 8.
    Revoke(Revoke),
}

impl RelayBody {
    /// Returns the packet type of this body (quick-v2 §8.2).
    #[must_use]
    pub const fn packet_type(&self) -> RelayType {
        match self {
            Self::Register(_) => RelayType::Register,
            Self::Registered(_) => RelayType::Registered,
            Self::Presence(_) => RelayType::Presence,
            Self::Reflect(_) => RelayType::Reflect,
            Self::Reflected(_) => RelayType::Reflected,
            Self::Data(_) => RelayType::Data,
            Self::Status(_) => RelayType::Status,
            Self::Revoke(_) => RelayType::Revoke,
        }
    }

    /// Checks the value rules shared by encoding and decoding (quick-v2 §8.2).
    fn validate(&self) -> Result<(), RelayPacketError> {
        match self {
            Self::Register(_) => Ok(()),
            Self::Registered(value) => {
                let ttl = u64::from(value.presence_ttl_s);
                if !(MIN_PRESENCE_TTL_SECONDS..=MAX_PRESENCE_TTL_SECONDS).contains(&ttl) {
                    return Err(RelayPacketError::PresenceTtl(ttl));
                }
                if !value.capabilities.is_empty() && value.ack_seq != 0 {
                    return Err(RelayPacketError::CapabilitiesNotProvisional(value.ack_seq));
                }
                value.observed_addr.map_or(Ok(()), check_observed)
            }
            Self::Presence(Presence { seq, .. })
            | Self::Reflect(Reflect { seq, .. })
            | Self::Revoke(Revoke { seq, .. }) => check_seq(*seq),
            Self::Reflected(value) => {
                check_seq(value.seq)?;
                check_observed(value.observed_addr)
            }
            Self::Data(data) => {
                if (MIN_RELAY_DATA_BODY_BYTES..=MAX_RELAY_DATA_BODY_BYTES).contains(&data.len()) {
                    Ok(())
                } else {
                    Err(RelayPacketError::DataLength(data.len()))
                }
            }
            Self::Status(_) => Ok(()),
        }
    }

    /// Writes the array of a MAC-carrying body (types 2-5 and 8): with its trailing `mac`
    /// for the wire, or without it as `U` of the MAC input (quick-v2 §8.3). Returns false
    /// and writes nothing for the other types.
    pub(crate) fn write_mac_body(&self, writer: &mut CborWriter, with_mac: bool) -> bool {
        let extra = usize::from(with_mac);
        let mac = match self {
            Self::Registered(value) => {
                writer
                    .array(6 + extra)
                    .uint(value.incarnation)
                    .bytes(&value.relay_ephemeral)
                    .uint(u64::from(value.presence_ttl_s));
                match value.observed_addr {
                    Some(address) => write_observed(writer, address),
                    None => writer.null(),
                };
                writer.uint(value.ack_seq).array(value.capabilities.len());
                for capability in &value.capabilities {
                    writer.text(capability);
                }
                &value.mac
            }
            Self::Presence(value) => {
                writer
                    .array(2 + extra)
                    .uint(value.incarnation)
                    .uint(value.seq);
                &value.mac
            }
            Self::Reflect(value) => {
                writer
                    .array(3 + extra)
                    .uint(value.incarnation)
                    .uint(value.seq)
                    .bytes(&value.nonce);
                &value.mac
            }
            Self::Reflected(value) => {
                writer
                    .array(4 + extra)
                    .uint(value.incarnation)
                    .uint(value.seq)
                    .bytes(&value.nonce);
                write_observed(writer, value.observed_addr);
                &value.mac
            }
            Self::Revoke(value) => {
                writer
                    .array(3 + extra)
                    .uint(value.incarnation)
                    .uint(value.seq)
                    .uint(u64::from(value.reason as u8));
                &value.mac
            }
            Self::Register(_) | Self::Data(_) | Self::Status(_) => return false,
        };
        if with_mac {
            writer.bytes(mac);
        }
        true
    }

    /// Returns the `mac` of a MAC-carrying body (quick-v2 §8.3).
    pub(crate) const fn mac(&self) -> Option<&[u8; 32]> {
        match self {
            Self::Registered(Registered { mac, .. })
            | Self::Presence(Presence { mac, .. })
            | Self::Reflect(Reflect { mac, .. })
            | Self::Reflected(Reflected { mac, .. })
            | Self::Revoke(Revoke { mac, .. }) => Some(mac),
            Self::Register(_) | Self::Data(_) | Self::Status(_) => None,
        }
    }

    /// Returns a mutable reference to the `mac` of a MAC-carrying body (quick-v2 §8.3).
    pub(crate) fn mac_mut(&mut self) -> Option<&mut [u8; 32]> {
        match self {
            Self::Registered(Registered { mac, .. })
            | Self::Presence(Presence { mac, .. })
            | Self::Reflect(Reflect { mac, .. })
            | Self::Reflected(Reflected { mac, .. })
            | Self::Revoke(Revoke { mac, .. }) => Some(mac),
            Self::Register(_) | Self::Data(_) | Self::Status(_) => None,
        }
    }

    fn encode(&self) -> Vec<u8> {
        match self {
            Self::Register(value) => value.encode(),
            Self::Data(data) => data.clone(),
            Self::Status(value) => {
                let mut writer = CborWriter::with_capacity(32);
                writer
                    .array(3)
                    .uint(u64::from(value.type_in))
                    .bytes(value.destination.as_bytes())
                    .uint(u64::from(value.status as u8));
                writer.into_bytes()
            }
            Self::Registered(_)
            | Self::Presence(_)
            | Self::Reflect(_)
            | Self::Reflected(_)
            | Self::Revoke(_) => {
                let mut writer = CborWriter::with_capacity(MAX_RELAY_CONTROL_BYTES);
                self.write_mac_body(&mut writer, true);
                writer.into_bytes()
            }
        }
    }

    fn decode(packet_type: RelayType, body: &[u8]) -> Result<Self, RelayPacketError> {
        if packet_type == RelayType::Data {
            let data = Self::Data(body.to_vec());
            data.validate()?;
            return Ok(data);
        }
        let mut reader = CborReader::new(body, MAX_RELAY_CONTROL_BYTES)?;
        let value = match packet_type {
            RelayType::Register => Self::Register(read_register(&mut reader)?),
            RelayType::Registered => {
                reader.array(7)?;
                let incarnation = reader.uint()?;
                let relay_ephemeral = reader.fixed_bytes::<32>()?;
                let ttl = reader.uint()?;
                let presence_ttl_s = u32::try_from(ttl)
                    .ok()
                    .filter(|ttl| {
                        (MIN_PRESENCE_TTL_SECONDS..=MAX_PRESENCE_TTL_SECONDS)
                            .contains(&u64::from(*ttl))
                    })
                    .ok_or(RelayPacketError::PresenceTtl(ttl))?;
                let observed_addr = if reader.take_null() {
                    None
                } else {
                    Some(read_observed(&mut reader)?)
                };
                let ack_seq = reader.uint()?;
                let count = reader.array_up_to(MAX_RELAY_CONTROL_BYTES)?;
                let mut capabilities = Vec::with_capacity(count);
                for _ in 0..count {
                    capabilities.push(reader.text_up_to(MAX_RELAY_CONTROL_BYTES)?.to_owned());
                }
                Self::Registered(Registered {
                    incarnation,
                    relay_ephemeral,
                    presence_ttl_s,
                    observed_addr,
                    ack_seq,
                    capabilities,
                    mac: reader.fixed_bytes()?,
                })
            }
            RelayType::Presence => {
                reader.array(3)?;
                Self::Presence(Presence {
                    incarnation: reader.uint()?,
                    seq: reader.uint()?,
                    mac: reader.fixed_bytes()?,
                })
            }
            RelayType::Reflect => {
                reader.array(4)?;
                Self::Reflect(Reflect {
                    incarnation: reader.uint()?,
                    seq: reader.uint()?,
                    nonce: reader.fixed_bytes()?,
                    mac: reader.fixed_bytes()?,
                })
            }
            RelayType::Reflected => {
                reader.array(5)?;
                Self::Reflected(Reflected {
                    incarnation: reader.uint()?,
                    seq: reader.uint()?,
                    nonce: reader.fixed_bytes()?,
                    observed_addr: read_observed(&mut reader)?,
                    mac: reader.fixed_bytes()?,
                })
            }
            RelayType::Status => {
                reader.array(3)?;
                let type_in = reader.uint()?;
                let type_in =
                    u8::try_from(type_in).map_err(|_| RelayPacketError::TypeIn(type_in))?;
                let destination = NodeId::from_bytes(reader.fixed_bytes()?);
                let status = reader.uint()?;
                Self::Status(Status {
                    type_in,
                    destination,
                    status: StatusCode::from_u64(status)
                        .ok_or(RelayPacketError::StatusCode(status))?,
                })
            }
            RelayType::Revoke => {
                reader.array(4)?;
                let incarnation = reader.uint()?;
                let seq = reader.uint()?;
                let reason = match reader.uint()? {
                    0 => RevokeReason::Rotation,
                    1 => RevokeReason::Close,
                    other => return Err(RelayPacketError::RevokeReason(other)),
                };
                Self::Revoke(Revoke {
                    incarnation,
                    seq,
                    reason,
                    mac: reader.fixed_bytes()?,
                })
            }
            RelayType::Data => return Err(RelayPacketError::DataLength(body.len())),
        };
        reader.finish()?;
        value.validate()?;
        Ok(value)
    }
}

/// A whole relay packet: header slots and a typed body (quick-v2 §8.1-§8.2).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayPacket {
    /// The sender slot, or [`RELAY_SLOT`].
    pub src: NodeId,
    /// The destination slot, or [`RELAY_SLOT`].
    pub dst: NodeId,
    /// The body; its variant fixes the type byte.
    pub body: RelayBody,
}

impl RelayPacket {
    /// Returns the header of this packet (quick-v2 §8.1).
    #[must_use]
    pub const fn header(&self) -> RelayHeader {
        RelayHeader {
            packet_type: self.body.packet_type(),
            src: self.src,
            dst: self.dst,
        }
    }

    /// Encodes the whole packet (quick-v2 §8.1-§8.2).
    ///
    /// # Errors
    ///
    /// [`RelayPacketError`] for a direction violation, a body value rule or a size limit.
    pub fn encode(&self) -> Result<Vec<u8>, RelayPacketError> {
        let header = self.header().encode()?;
        self.body.validate()?;
        let body = self.body.encode();
        let length = RELAY_HEADER_BYTES + body.len();
        let maximum = self.body.packet_type().max_packet_bytes();
        if length > maximum {
            return Err(RelayPacketError::TooLarge { length, maximum });
        }
        let mut output = Vec::with_capacity(length);
        output.extend_from_slice(&header);
        output.extend_from_slice(&body);
        Ok(output)
    }

    /// Decodes a whole packet: length, magic, type, direction and size limits, then the
    /// canonical body schema; no signature or MAC is checked (quick-v2 §8.1-§8.2, §12.1).
    ///
    /// # Errors
    ///
    /// [`RelayPacketError`] naming the first violated rule.
    pub fn decode(packet: &[u8]) -> Result<Self, RelayPacketError> {
        let (header, body) = split_packet(packet)?;
        Ok(Self {
            src: header.src,
            dst: header.dst,
            body: RelayBody::decode(header.packet_type, body)?,
        })
    }
}

fn check_seq(seq: u64) -> Result<(), RelayPacketError> {
    if seq == 0 {
        Err(RelayPacketError::ZeroSeq)
    } else {
        Ok(())
    }
}

fn check_observed(address: ObservedAddr) -> Result<(), RelayPacketError> {
    if address.port == 0 {
        Err(RelayPacketError::ObservedPort(0))
    } else {
        Ok(())
    }
}

fn check_relay_name(name: &str) -> Result<(), RelayPacketError> {
    if (1..=MAX_RELAY_NAME_BYTES).contains(&name.len()) {
        Ok(())
    } else {
        Err(RelayPacketError::RelayNameLength(name.len()))
    }
}

fn write_observed(writer: &mut CborWriter, address: ObservedAddr) -> &mut CborWriter {
    writer.array(2);
    match address.ip {
        IpAddr::V4(ip) => writer.bytes(&ip.octets()),
        IpAddr::V6(ip) => writer.bytes(&ip.octets()),
    };
    writer.uint(u64::from(address.port))
}

fn read_observed(reader: &mut CborReader<'_>) -> Result<ObservedAddr, RelayPacketError> {
    reader.array(2)?;
    let raw = reader.bytes_up_to(16)?;
    let ip = if let Ok(octets) = <[u8; 4]>::try_from(raw) {
        IpAddr::V4(Ipv4Addr::from(octets))
    } else if let Ok(octets) = <[u8; 16]>::try_from(raw) {
        IpAddr::V6(Ipv6Addr::from(octets))
    } else {
        return Err(RelayPacketError::ObservedIp(raw.len()));
    };
    let port = reader.uint()?;
    let port = u16::try_from(port)
        .ok()
        .filter(|port| *port != 0)
        .ok_or(RelayPacketError::ObservedPort(port))?;
    Ok(ObservedAddr { ip, port })
}

/// Reads the nested eight-field record array structurally and returns `I`; validity and
/// the record signature are checked later (quick-v2 §3.1, §8.3 rule 1).
fn read_record_shape(reader: &mut CborReader<'_>) -> Result<Identity, RelayPacketError> {
    reader.array(8)?;
    let version = reader.uint()?;
    if version != u64::from(NODE_RECORD_VERSION) {
        return Err(RelayPacketError::RecordVersion(version));
    }
    let identity = reader.fixed_bytes::<32>()?;
    reader.fixed_bytes::<32>()?;
    reader.uint()?;
    reader.uint()?;
    reader.uint()?;
    let relays = reader.array_up_to(MAX_NODE_RECORD_RELAYS)?;
    for _ in 0..relays {
        reader.text_up_to(MAX_RELAY_ID_BYTES)?;
    }
    reader.fixed_bytes::<64>()?;
    Ok(identity)
}

fn read_register(reader: &mut CborReader<'_>) -> Result<Register, RelayPacketError> {
    reader.array(6)?;
    let start = reader.consumed().len();
    let identity = read_record_shape(reader)?;
    let record = reader.consumed().get(start..).unwrap_or_default().to_vec();
    let incarnation = reader.uint()?;
    let ts = reader.uint()?;
    let node_ephemeral = reader.fixed_bytes()?;
    let relay_name = reader.text_up_to(MAX_RELAY_CONTROL_BYTES)?;
    check_relay_name(relay_name)?;
    Ok(Register {
        record,
        identity,
        incarnation,
        ts,
        node_ephemeral,
        relay_name: relay_name.to_owned(),
        signature: reader.fixed_bytes()?,
    })
}
