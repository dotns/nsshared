//! Region frame envelope, the bodies of types 1-9, the per-channel frame size limits and
//! the channel rules (quick-v2 §8.5, quick-protocol §12.8).

use crate::{
    codec::{CborError, CborReader, CborWriter},
    constants::{MAX_REGION_RENDEZVOUS_FRAME_BYTES, MAX_RELAY_PACKET_BYTES},
    identifier::{MAX_RELAY_ID_BYTES, RelayId, RelayIdError},
    identity::{Identity, NodeId},
    record::WireGuardKey,
    relay::{RelayPacket, RelayPacketError, RelayType},
};
use thiserror::Error;

/// Region frame version `ver` (quick-v2 §8.5).
pub const REGION_FRAME_VERSION: u8 = 2;
/// Length of the big-endian frame length prefix in bytes (quick-protocol §12.8).
pub const REGION_FRAME_PREFIX_BYTES: usize = 4;
/// Maximum encoded frame array length in bytes, prefix excluded, of every frame except
/// types 10 and 11 on the control connection, which may reach
/// [`MAX_REGION_RENDEZVOUS_FRAME_BYTES`] (quick-v2 §8.5, quick-protocol §12.8).
pub const MAX_REGION_FRAME_BYTES: usize = 4096;
/// Maximum FORWARD datagram length: one whole relay packet (quick-v2 §8.5,
/// quick-protocol §12.8).
pub const MAX_REGION_FORWARD_DATAGRAM_BYTES: usize = MAX_RELAY_PACKET_BYTES;
/// Maximum combined presence and mark entries in one SNAPSHOT chunk (quick-protocol §12.8).
pub const MAX_REGION_SNAPSHOT_ENTRIES: usize = 256;
/// Smallest region member id (quick-protocol §12.8).
pub const MIN_REGION_MEMBER_ID: u8 = 1;
/// Largest region member id (quick-protocol §12.8).
pub const MAX_REGION_MEMBER_ID: u8 = 16;

/// A region frame type byte, including the reserved types 10-12 (quick-v2 §8.5,
/// quick-protocol §12.8).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum RegionFrameType {
    /// 1 HELLO, the first frame in both directions on both connections.
    Hello = 1,
    /// 2 SNAPSHOT, one chunk of presence and retained marks.
    Snapshot = 2,
    /// 3 PRESENT, a source session became active or changed.
    Present = 3,
    /// 4 GONE, a source session was retired.
    Gone = 4,
    /// 5 MARKS, a retained mark update.
    Marks = 5,
    /// 6 FORWARD, a relay DATA packet for the exit member.
    Forward = 6,
    /// 7 MISS, the exit member could not deliver a FORWARD.
    Miss = 7,
    /// 8 PING, control liveness probe.
    Ping = 8,
    /// 9 PONG, control liveness answer.
    Pong = 9,
    /// 10 RENDEZVOUS_REQUEST, control connection only, up to
    /// [`MAX_REGION_RENDEZVOUS_FRAME_BYTES`]; the body is defined by the rendezvous v2
    /// messages (`nsshared_rendezvous::region`) and [`RegionFrame::decode`] refuses it as an
    /// unknown type (quick-v2 §8.5).
    RendezvousRequest = 10,
    /// 11 RENDEZVOUS_RESPONSE, control connection only, up to
    /// [`MAX_REGION_RENDEZVOUS_FRAME_BYTES`]; the body is defined by the rendezvous v2
    /// messages (`nsshared_rendezvous::region`) and [`RegionFrame::decode`] refuses it as an
    /// unknown type (quick-v2 §8.5).
    RendezvousResponse = 11,
    /// 12 REGISTRY_RECORD, control connection only, up to [`MAX_REGION_FRAME_BYTES`]; the
    /// body is defined by the rendezvous v2 messages (`nsshared_rendezvous::region`) and
    /// [`RegionFrame::decode`] refuses it as an unknown type (quick-v2 §7.1, §8.5).
    RegistryRecord = 12,
}

impl RegionFrameType {
    /// Parses a type byte, reserved types included; `None` for any other value
    /// (quick-v2 §8.5).
    #[must_use]
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Hello),
            2 => Some(Self::Snapshot),
            3 => Some(Self::Present),
            4 => Some(Self::Gone),
            5 => Some(Self::Marks),
            6 => Some(Self::Forward),
            7 => Some(Self::Miss),
            8 => Some(Self::Ping),
            9 => Some(Self::Pong),
            10 => Some(Self::RendezvousRequest),
            11 => Some(Self::RendezvousResponse),
            12 => Some(Self::RegistryRecord),
            _ => None,
        }
    }

    /// Returns the type byte (quick-v2 §8.5).
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Returns true for the types 10-12, whose bodies are defined by the rendezvous v2
    /// messages rather than by [`RegionFrame`] (quick-v2 §8.5).
    #[must_use]
    pub const fn is_reserved(self) -> bool {
        matches!(
            self,
            Self::RendezvousRequest | Self::RendezvousResponse | Self::RegistryRecord
        )
    }
}

/// A mesh connection kind, HELLO `channel_kind` (quick-protocol §12.8).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum RegionChannel {
    /// 0 control connection.
    Control = 0,
    /// 1 data connection.
    Data = 1,
}

/// A frame that may not be sent on a connection in its current phase
/// (quick-v2 §8.5, quick-protocol §12.8).
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RegionChannelError {
    /// The first frame of a connection is not HELLO.
    #[error("{0:?} before HELLO")]
    HelloRequired(RegionFrameType),
    /// A second HELLO on an established connection.
    #[error("HELLO after the connection was established")]
    DuplicateHello,
    /// The type is not carried on this connection kind.
    #[error("{frame_type:?} is not carried on the {channel:?} connection")]
    WrongChannel {
        /// The frame type.
        frame_type: RegionFrameType,
        /// The connection kind.
        channel: RegionChannel,
    },
}

/// Checks that `frame_type` may appear on a `channel` connection: one HELLO first, then the
/// control connection carries SNAPSHOT, PRESENT, GONE, MARKS, MISS, PING, PONG and the
/// rendezvous types 10, 11 and 12, and the data connection carries only FORWARD
/// (quick-v2 §7.1, §8.5, quick-protocol §12.8).
///
/// `established` is true once the connection's HELLO has been received.
///
/// # Errors
///
/// [`RegionChannelError`] naming the violated rule.
pub const fn check_region_channel(
    channel: RegionChannel,
    established: bool,
    frame_type: RegionFrameType,
) -> Result<(), RegionChannelError> {
    match (established, frame_type) {
        (false, RegionFrameType::Hello) => Ok(()),
        (false, other) => Err(RegionChannelError::HelloRequired(other)),
        (true, RegionFrameType::Hello) => Err(RegionChannelError::DuplicateHello),
        (true, frame_type) => {
            let data_only = matches!(frame_type, RegionFrameType::Forward);
            let on_data = matches!(channel, RegionChannel::Data);
            if data_only == on_data {
                Ok(())
            } else {
                Err(RegionChannelError::WrongChannel {
                    frame_type,
                    channel,
                })
            }
        }
    }
}

/// PRESENT `carrier`, the source's committed node carrier (quick-protocol §12.8).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum RegionCarrier {
    /// 0 UDP.
    Udp = 0,
    /// 1 WSS.
    Wss = 1,
}

/// GONE `reason` (quick-protocol §12.8).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum RegionGoneReason {
    /// 0 expired.
    Expired = 0,
    /// 1 revoked.
    Revoked = 1,
    /// 2 superseded; mesh only, never a node packet (quick-protocol §12.8 rule 1).
    Superseded = 2,
    /// 3 closed.
    Closed = 3,
}

/// MISS `status` (quick-protocol §12.8).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum RegionMissStatus {
    /// 1 no eligible local destination.
    NoEligibleDestination = 1,
    /// 2 destination admission or output exhausted.
    Exhausted = 2,
}

/// HELLO body `[region_name, member_id, boot_epoch, channel_kind, conn_gen]`
/// (quick-protocol §12.8).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegionHello {
    /// The canonical advertised region identifier, compared bytewise.
    pub region_name: RelayId,
    /// The sender's member id, 1..=16.
    pub member_id: u8,
    /// The sender's process boot epoch.
    pub boot_epoch: u64,
    /// The connection kind being established.
    pub channel: RegionChannel,
    /// The non-zero connection generation owned by the lower member id.
    pub conn_gen: u32,
}

/// PRESENT body, also a SNAPSHOT presence entry
/// `[slot, I, gen, incarnation, carrier, boot_epoch, revision]` (quick-v2 §8.5).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RegionPresent {
    /// The relay slot; must equal `NodeId(I)`.
    pub slot: NodeId,
    /// The owner identity `I`.
    pub identity: Identity,
    /// The committed generation.
    pub generation: u64,
    /// The session incarnation.
    pub incarnation: u64,
    /// The source's committed node carrier.
    pub carrier: RegionCarrier,
    /// The source's boot epoch.
    pub boot_epoch: u64,
    /// The non-zero source presence revision.
    pub revision: u64,
}

/// GONE body `[slot, I, gen, incarnation, reason, boot_epoch, revision]` (quick-v2 §8.5).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RegionGone {
    /// The relay slot; must equal `NodeId(I)`.
    pub slot: NodeId,
    /// The owner identity `I`.
    pub identity: Identity,
    /// The committed generation.
    pub generation: u64,
    /// The retired session incarnation.
    pub incarnation: u64,
    /// The retirement reason.
    pub reason: RegionGoneReason,
    /// The source's boot epoch.
    pub boot_epoch: u64,
    /// The non-zero source presence revision.
    pub revision: u64,
}

/// MARKS body, also a SNAPSHOT mark entry
/// `[I, committed_gen, committed_K, conflicted, incarnation_high_water]` (quick-v2 §8.5).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RegionMarks {
    /// The owner identity `I`.
    pub identity: Identity,
    /// The committed generation.
    pub committed_gen: u64,
    /// The committed WireGuard key `K`; for a conflicted generation the lexicographically
    /// smaller key, a deterministic representative and never an authorised winner.
    pub committed_key: WireGuardKey,
    /// Whether the committed generation is latched as conflicted.
    pub conflicted: bool,
    /// The highest session incarnation seen in the committed generation.
    pub incarnation_high_water: u64,
}

/// SNAPSHOT body `[snapshot_id, base_revision, marks_revision, chunk_index,
/// presence_entries, mark_entries, more]` (quick-v2 §8.5, quick-protocol §12.8).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegionSnapshot {
    /// The non-zero sender snapshot counter.
    pub snapshot_id: u64,
    /// The presence revision of the cut.
    pub base_revision: u64,
    /// The sender's durable marks revision of the cut.
    pub marks_revision: u64,
    /// The chunk index, contiguous from 0.
    pub chunk_index: u32,
    /// Presence entries, each a PRESENT body.
    pub presence: Vec<RegionPresent>,
    /// Mark entries, each a MARKS body.
    pub marks: Vec<RegionMarks>,
    /// False only on the last chunk.
    pub more: bool,
}

/// FORWARD body `[forward_id, source_owner, datagram]` (quick-v2 §8.5).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegionForward {
    /// The non-zero per-direction forward id.
    pub forward_id: u64,
    /// The source owner `I`; `NodeId(I)` must equal the packet src.
    pub source_owner: Identity,
    /// The exact original relay DATA packet, header included, at most 2048 bytes.
    pub datagram: Vec<u8>,
}

/// MISS body `[data_conn_gen, forward_id, status]` (quick-protocol §12.8).
///
/// Zero, stale or unknown correlation values are well-formed and ignored by the ingress
/// (quick-protocol §12.8 rule 3).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RegionMiss {
    /// The data connection generation captured when the FORWARD was consumed.
    pub data_conn_gen: u32,
    /// The forward id of the missed FORWARD.
    pub forward_id: u64,
    /// The miss status.
    pub status: RegionMissStatus,
}

/// PING and PONG body `[nonce, data_conn_gen, consumed_forward_id]`
/// (quick-protocol §12.8 rule 5).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RegionLiveness {
    /// The non-zero per-control-connection PING counter; PONG echoes it.
    pub nonce: u64,
    /// The current data connection generation, 0 without one.
    pub data_conn_gen: u32,
    /// The highest fully consumed forward id; 0 when none, and always 0 without a data
    /// connection.
    pub consumed_forward_id: u64,
}

/// A typed region frame of types 1-9 (quick-v2 §8.5, quick-protocol §12.8).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegionFrame {
    /// Type 1.
    Hello(RegionHello),
    /// Type 2.
    Snapshot(RegionSnapshot),
    /// Type 3.
    Present(RegionPresent),
    /// Type 4.
    Gone(RegionGone),
    /// Type 5.
    Marks(RegionMarks),
    /// Type 6.
    Forward(RegionForward),
    /// Type 7.
    Miss(RegionMiss),
    /// Type 8.
    Ping(RegionLiveness),
    /// Type 9.
    Pong(RegionLiveness),
}

/// The largest frame of any type a `channel` connection accepts, prefix excluded: 20480
/// bytes on control, where types 10 and 11 may exceed 4096, and 4096 bytes on data
/// (quick-v2 §8.5, quick-protocol §12.8).
#[must_use]
pub const fn max_region_frame_bytes(channel: RegionChannel) -> usize {
    match channel {
        RegionChannel::Control => MAX_REGION_RENDEZVOUS_FRAME_BYTES,
        RegionChannel::Data => MAX_REGION_FRAME_BYTES,
    }
}

/// The largest frame of type byte `frame_type` on a `channel` connection, prefix excluded:
/// [`MAX_REGION_RENDEZVOUS_FRAME_BYTES`] for types 10 and 11 on control, otherwise
/// [`MAX_REGION_FRAME_BYTES`] (quick-v2 §8.5, quick-protocol §12.8).
#[must_use]
pub const fn max_region_frame_bytes_for(channel: RegionChannel, frame_type: u8) -> usize {
    let rendezvous = frame_type == RegionFrameType::RendezvousRequest.as_u8()
        || frame_type == RegionFrameType::RendezvousResponse.as_u8();
    if rendezvous && matches!(channel, RegionChannel::Control) {
        MAX_REGION_RENDEZVOUS_FRAME_BYTES
    } else {
        MAX_REGION_FRAME_BYTES
    }
}

/// A rejected region frame (quick-v2 §8.5, §12.1, quick-protocol §12.8).
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum RegionFrameError {
    /// The length prefix is 0 or exceeds the channel limit of [`max_region_frame_bytes`];
    /// rejected before allocating.
    #[error("frame length prefix {0} is 0 or above the channel limit")]
    FrameLength(u32),
    /// The input ends inside the length prefix or before the declared length.
    #[error("prefixed frame is truncated")]
    Truncated,
    /// Bytes follow the frame declared by the length prefix.
    #[error("bytes follow the prefixed frame")]
    TrailingFrameBytes,
    /// The encoded frame array exceeds the limit of its channel and type, see
    /// [`max_region_frame_bytes_for`].
    #[error("frame of {0} bytes exceeds the limit of its channel and type")]
    TooLarge(usize),
    /// Not canonical CBOR of the frame shape: wrong arity, field types or widths of
    /// strings, or trailing bytes (quick-v2 §12.1).
    #[error("non-canonical region frame: {0}")]
    Cbor(#[from] CborError),
    /// `ver` is not 2.
    #[error("unknown region frame version {0}")]
    Version(u64),
    /// The type is not 1..=9; [`RegionFrame`] refuses the rendezvous types 10-12 as well
    /// (quick-v2 §8.5).
    #[error("unknown region frame type {0}")]
    UnknownType(u64),
    /// An integer field exceeds its u8 / u32 width.
    #[error("{field} {value} exceeds its field width")]
    FieldWidth {
        /// The field name.
        field: &'static str,
        /// The decoded value.
        value: u64,
    },
    /// HELLO `region_name` is not a canonical relay identifier.
    #[error("invalid region name: {0}")]
    RegionName(RelayIdError),
    /// HELLO `member_id` is outside 1..=16.
    #[error("member id {0} is outside {MIN_REGION_MEMBER_ID}..={MAX_REGION_MEMBER_ID}")]
    MemberId(u64),
    /// HELLO `channel_kind` is not 0 or 1.
    #[error("unknown channel kind {0}")]
    ChannelKind(u64),
    /// HELLO `conn_gen` is 0.
    #[error("HELLO conn_gen must not be 0")]
    ZeroConnGen,
    /// PRESENT `carrier` is not 0 or 1.
    #[error("unknown carrier {0}")]
    Carrier(u64),
    /// GONE `reason` is not 0..=3.
    #[error("unknown GONE reason {0}")]
    GoneReason(u64),
    /// MISS `status` is not 1 or 2.
    #[error("unknown MISS status {0}")]
    MissStatus(u64),
    /// A PRESENT or GONE slot is not `NodeId(I)`.
    #[error("slot is not the node ID of I")]
    SlotMismatch,
    /// A PRESENT or GONE event revision is 0.
    #[error("event revision must not be 0")]
    ZeroRevision,
    /// SNAPSHOT `snapshot_id` is 0.
    #[error("snapshot_id must not be 0")]
    ZeroSnapshotId,
    /// A SNAPSHOT chunk holds more than 256 combined entries.
    #[error("snapshot chunk holds {0} entries, at most {MAX_REGION_SNAPSHOT_ENTRIES}")]
    TooManyEntries(usize),
    /// A snapshot presence entry revision exceeds `base_revision`.
    #[error("presence entry revision {revision} exceeds base_revision {base_revision}")]
    EntryAfterCut {
        /// The entry revision.
        revision: u64,
        /// The chunk `base_revision`.
        base_revision: u64,
    },
    /// An owner appears twice in one entry list of a snapshot.
    #[error("owner appears twice in the snapshot {0} entries")]
    DuplicateOwner(&'static str),
    /// FORWARD `forward_id` is 0.
    #[error("forward_id must not be 0")]
    ZeroForwardId,
    /// FORWARD `datagram` exceeds 2048 bytes.
    #[error("FORWARD datagram of {0} bytes exceeds {MAX_REGION_FORWARD_DATAGRAM_BYTES} bytes")]
    DatagramTooLarge(usize),
    /// FORWARD `datagram` is not a valid relay packet.
    #[error("FORWARD datagram is not a valid relay packet: {0}")]
    Datagram(RelayPacketError),
    /// FORWARD `datagram` is a relay packet of a type other than DATA.
    #[error("FORWARD datagram is a {0:?} packet, not DATA")]
    DatagramNotData(RelayType),
    /// FORWARD `NodeId(source_owner)` is not the packet src.
    #[error("FORWARD source_owner does not derive the packet src")]
    SourceOwnerMismatch,
    /// PING / PONG `nonce` is 0; the counter starts at 1.
    #[error("liveness nonce must not be 0")]
    ZeroNonce,
    /// PING / PONG report consumed progress without a data connection.
    #[error("consumed_forward_id {0} reported with data_conn_gen 0")]
    ProgressWithoutDataConnection(u64),
}

/// A checked frame envelope `[ver = 2, type, body]` with the raw body bytes
/// (quick-v2 §8.5).
///
/// The extension point for the rendezvous types 10-12: the body is the exact remaining bytes
/// of the frame, not yet checked; a body decoder must consume it as one canonical CBOR item
/// with no trailing bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegionEnvelope<'a> {
    /// The type byte; any value 0..=255.
    pub frame_type: u8,
    /// The raw body bytes.
    pub body: &'a [u8],
}

/// Decodes the envelope of an unprefixed frame received on a `channel` connection: the
/// channel size limit, canonical array head, `ver = 2`, a u8 type, then the size limit of
/// that type on that channel; the body is returned raw (quick-v2 §8.5, §12.1).
///
/// A frame above 4096 bytes is accepted only for types 10 and 11 on control.
///
/// # Errors
///
/// [`RegionFrameError::TooLarge`], [`RegionFrameError::Cbor`],
/// [`RegionFrameError::Version`] or [`RegionFrameError::UnknownType`] for a type above 255.
pub fn decode_region_envelope(
    frame: &[u8],
    channel: RegionChannel,
) -> Result<RegionEnvelope<'_>, RegionFrameError> {
    let maximum = max_region_frame_bytes(channel);
    if frame.len() > maximum {
        return Err(RegionFrameError::TooLarge(frame.len()));
    }
    let mut reader = CborReader::new(frame, maximum)?;
    reader.array(3)?;
    let version = reader.uint()?;
    if version != u64::from(REGION_FRAME_VERSION) {
        return Err(RegionFrameError::Version(version));
    }
    let frame_type = reader.uint()?;
    let frame_type =
        u8::try_from(frame_type).map_err(|_| RegionFrameError::UnknownType(frame_type))?;
    if frame.len() > max_region_frame_bytes_for(channel, frame_type) {
        return Err(RegionFrameError::TooLarge(frame.len()));
    }
    let body = frame.get(reader.consumed().len()..).unwrap_or_default();
    if body.is_empty() {
        return Err(CborError::Truncated.into());
    }
    Ok(RegionEnvelope { frame_type, body })
}

/// Encodes an unprefixed frame `[ver = 2, frame_type, body]` from a raw body, for bodies
/// defined outside this module, to be sent on a `channel` connection (quick-v2 §8.5).
///
/// `body` must be exactly one canonical CBOR item; it is not inspected.
///
/// # Errors
///
/// [`RegionFrameError::TooLarge`] when the frame exceeds
/// [`max_region_frame_bytes_for`] `(channel, frame_type)`.
pub fn encode_region_envelope(
    frame_type: u8,
    body: &[u8],
    channel: RegionChannel,
) -> Result<Vec<u8>, RegionFrameError> {
    let mut writer = CborWriter::with_capacity(body.len().saturating_add(4));
    writer
        .array(3)
        .uint(u64::from(REGION_FRAME_VERSION))
        .uint(u64::from(frame_type));
    let mut encoded = writer.into_bytes();
    encoded.extend_from_slice(body);
    if encoded.len() > max_region_frame_bytes_for(channel, frame_type) {
        return Err(RegionFrameError::TooLarge(encoded.len()));
    }
    Ok(encoded)
}

/// Reads a 4-byte big-endian length prefix on a `channel` connection and returns the frame
/// length, rejecting 0 and values above [`max_region_frame_bytes`] (20480 on control, 4096
/// on data) before any allocation (quick-v2 §8.5, quick-protocol §12.8).
///
/// The type is not known yet: [`decode_region_envelope`] applies the per-type limit once it
/// is.
///
/// # Errors
///
/// [`RegionFrameError::FrameLength`].
pub fn region_frame_length(
    prefix: [u8; REGION_FRAME_PREFIX_BYTES],
    channel: RegionChannel,
) -> Result<usize, RegionFrameError> {
    let length = u32::from_be_bytes(prefix);
    usize::try_from(length)
        .ok()
        .filter(|length| (1..=max_region_frame_bytes(channel)).contains(length))
        .ok_or(RegionFrameError::FrameLength(length))
}

/// Prepends the 4-byte big-endian length prefix to an encoded frame to be sent on a
/// `channel` connection (quick-v2 §8.5, quick-protocol §12.8).
///
/// A frame above 4096 bytes must be a type 10 or 11 envelope on control; its envelope head
/// is decoded to check that.
///
/// # Errors
///
/// [`RegionFrameError::FrameLength`] for an empty frame, [`RegionFrameError::TooLarge`]
/// above the limit of its channel and type, or an envelope error of
/// [`decode_region_envelope`] for a frame above 4096 bytes.
pub fn prefix_region_frame(
    frame: &[u8],
    channel: RegionChannel,
) -> Result<Vec<u8>, RegionFrameError> {
    if frame.len() > MAX_REGION_FRAME_BYTES {
        decode_region_envelope(frame, channel)?;
    }
    let length = u32::try_from(frame.len()).map_err(|_| RegionFrameError::TooLarge(frame.len()))?;
    if length == 0 {
        return Err(RegionFrameError::FrameLength(0));
    }
    let mut output = Vec::with_capacity(REGION_FRAME_PREFIX_BYTES + frame.len());
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(frame);
    Ok(output)
}

/// Splits exactly one length-prefixed frame received on a `channel` connection from `wire`
/// and returns the frame bytes; the length is checked by [`region_frame_length`]
/// (quick-protocol §12.8).
///
/// # Errors
///
/// [`RegionFrameError::Truncated`], [`RegionFrameError::FrameLength`] or
/// [`RegionFrameError::TrailingFrameBytes`].
pub fn split_region_frame(wire: &[u8], channel: RegionChannel) -> Result<&[u8], RegionFrameError> {
    let (prefix, rest) = wire
        .split_first_chunk::<REGION_FRAME_PREFIX_BYTES>()
        .ok_or(RegionFrameError::Truncated)?;
    let length = region_frame_length(*prefix, channel)?;
    let (frame, trailing) = rest
        .split_at_checked(length)
        .ok_or(RegionFrameError::Truncated)?;
    if trailing.is_empty() {
        Ok(frame)
    } else {
        Err(RegionFrameError::TrailingFrameBytes)
    }
}

impl RegionFrame {
    /// Returns the frame type (quick-v2 §8.5).
    #[must_use]
    pub const fn frame_type(&self) -> RegionFrameType {
        match self {
            Self::Hello(_) => RegionFrameType::Hello,
            Self::Snapshot(_) => RegionFrameType::Snapshot,
            Self::Present(_) => RegionFrameType::Present,
            Self::Gone(_) => RegionFrameType::Gone,
            Self::Marks(_) => RegionFrameType::Marks,
            Self::Forward(_) => RegionFrameType::Forward,
            Self::Miss(_) => RegionFrameType::Miss,
            Self::Ping(_) => RegionFrameType::Ping,
            Self::Pong(_) => RegionFrameType::Pong,
        }
    }

    /// Checks every per-field rule of the body (quick-v2 §8.5, quick-protocol §12.8).
    ///
    /// # Errors
    ///
    /// [`RegionFrameError`] naming the first violated rule.
    pub fn validate(&self) -> Result<(), RegionFrameError> {
        match self {
            Self::Hello(hello) => {
                if !(MIN_REGION_MEMBER_ID..=MAX_REGION_MEMBER_ID).contains(&hello.member_id) {
                    return Err(RegionFrameError::MemberId(u64::from(hello.member_id)));
                }
                if hello.conn_gen == 0 {
                    return Err(RegionFrameError::ZeroConnGen);
                }
                Ok(())
            }
            Self::Snapshot(snapshot) => snapshot.validate(),
            Self::Present(present) => present.validate(),
            Self::Gone(gone) => check_event(&gone.slot, &gone.identity, gone.revision),
            Self::Marks(_) | Self::Miss(_) => Ok(()),
            Self::Forward(forward) => forward.validate(),
            Self::Ping(liveness) | Self::Pong(liveness) => {
                if liveness.nonce == 0 {
                    return Err(RegionFrameError::ZeroNonce);
                }
                if liveness.data_conn_gen == 0 && liveness.consumed_forward_id != 0 {
                    return Err(RegionFrameError::ProgressWithoutDataConnection(
                        liveness.consumed_forward_id,
                    ));
                }
                Ok(())
            }
        }
    }

    /// Encodes the unprefixed frame array `[ver = 2, type, body]` (quick-v2 §8.5, §12.1).
    ///
    /// # Errors
    ///
    /// [`RegionFrameError`] for a body rule, or [`RegionFrameError::TooLarge`] above 4096
    /// bytes.
    pub fn encode(&self) -> Result<Vec<u8>, RegionFrameError> {
        self.validate()?;
        let mut writer = CborWriter::with_capacity(MAX_REGION_FRAME_BYTES);
        writer
            .array(3)
            .uint(u64::from(REGION_FRAME_VERSION))
            .uint(u64::from(self.frame_type().as_u8()));
        match self {
            Self::Hello(hello) => {
                writer
                    .array(5)
                    .text(hello.region_name.as_str())
                    .uint(u64::from(hello.member_id))
                    .uint(hello.boot_epoch)
                    .uint(hello.channel as u64)
                    .uint(u64::from(hello.conn_gen));
            }
            Self::Snapshot(snapshot) => {
                writer
                    .array(7)
                    .uint(snapshot.snapshot_id)
                    .uint(snapshot.base_revision)
                    .uint(snapshot.marks_revision)
                    .uint(u64::from(snapshot.chunk_index))
                    .array(snapshot.presence.len());
                for present in &snapshot.presence {
                    write_present(&mut writer, present);
                }
                writer.array(snapshot.marks.len());
                for marks in &snapshot.marks {
                    write_marks(&mut writer, marks);
                }
                writer.boolean(snapshot.more);
            }
            Self::Present(present) => write_present(&mut writer, present),
            Self::Gone(gone) => {
                writer
                    .array(7)
                    .bytes(gone.slot.as_bytes())
                    .bytes(&gone.identity)
                    .uint(gone.generation)
                    .uint(gone.incarnation)
                    .uint(gone.reason as u64)
                    .uint(gone.boot_epoch)
                    .uint(gone.revision);
            }
            Self::Marks(marks) => write_marks(&mut writer, marks),
            Self::Forward(forward) => {
                writer
                    .array(3)
                    .uint(forward.forward_id)
                    .bytes(&forward.source_owner)
                    .bytes(&forward.datagram);
            }
            Self::Miss(miss) => {
                writer
                    .array(3)
                    .uint(u64::from(miss.data_conn_gen))
                    .uint(miss.forward_id)
                    .uint(miss.status as u64);
            }
            Self::Ping(liveness) | Self::Pong(liveness) => {
                writer
                    .array(3)
                    .uint(liveness.nonce)
                    .uint(u64::from(liveness.data_conn_gen))
                    .uint(liveness.consumed_forward_id);
            }
        }
        let encoded = writer.into_bytes();
        if encoded.len() > MAX_REGION_FRAME_BYTES {
            return Err(RegionFrameError::TooLarge(encoded.len()));
        }
        Ok(encoded)
    }

    /// Encodes the frame with its 4-byte length prefix (quick-protocol §12.8).
    ///
    /// Types 1-9 are at most 4096 bytes on either channel.
    ///
    /// # Errors
    ///
    /// As [`RegionFrame::encode`].
    pub fn encode_prefixed(&self) -> Result<Vec<u8>, RegionFrameError> {
        prefix_region_frame(&self.encode()?, RegionChannel::Data)
    }

    /// Decodes an unprefixed frame array: envelope, canonical body schema and trailing
    /// bytes first, then every per-field rule (quick-v2 §8.5, §12.1, quick-protocol §12.8).
    ///
    /// # Errors
    ///
    /// [`RegionFrameError`] naming the first violated rule; a frame above 4096 bytes yields
    /// [`RegionFrameError::TooLarge`] and the rendezvous types 10-12 yield
    /// [`RegionFrameError::UnknownType`].
    pub fn decode(frame: &[u8]) -> Result<Self, RegionFrameError> {
        // Types 1-9 are at most 4096 bytes on either channel: the data limit applies.
        let envelope = decode_region_envelope(frame, RegionChannel::Data)?;
        let frame_type = RegionFrameType::from_u8(envelope.frame_type)
            .filter(|frame_type| !frame_type.is_reserved())
            .ok_or(RegionFrameError::UnknownType(u64::from(
                envelope.frame_type,
            )))?;
        let mut reader = CborReader::new(envelope.body, MAX_REGION_FRAME_BYTES)?;
        let decoded = match frame_type {
            RegionFrameType::Hello => Self::Hello(read_hello(&mut reader)?),
            RegionFrameType::Snapshot => Self::Snapshot(read_snapshot(&mut reader)?),
            RegionFrameType::Present => Self::Present(read_present(&mut reader)?),
            RegionFrameType::Gone => Self::Gone(read_gone(&mut reader)?),
            RegionFrameType::Marks => Self::Marks(read_marks(&mut reader)?),
            RegionFrameType::Forward => {
                reader.array(3)?;
                let forward_id = reader.uint()?;
                let source_owner = reader.fixed_bytes()?;
                let datagram = reader.bytes_up_to(MAX_REGION_FRAME_BYTES)?;
                if datagram.len() > MAX_REGION_FORWARD_DATAGRAM_BYTES {
                    return Err(RegionFrameError::DatagramTooLarge(datagram.len()));
                }
                Self::Forward(RegionForward {
                    forward_id,
                    source_owner,
                    datagram: datagram.to_vec(),
                })
            }
            RegionFrameType::Miss => {
                reader.array(3)?;
                let data_conn_gen = read_u32(&mut reader, "data_conn_gen")?;
                let forward_id = reader.uint()?;
                let status = match reader.uint()? {
                    1 => RegionMissStatus::NoEligibleDestination,
                    2 => RegionMissStatus::Exhausted,
                    other => return Err(RegionFrameError::MissStatus(other)),
                };
                Self::Miss(RegionMiss {
                    data_conn_gen,
                    forward_id,
                    status,
                })
            }
            RegionFrameType::Ping => Self::Ping(read_liveness(&mut reader)?),
            RegionFrameType::Pong => Self::Pong(read_liveness(&mut reader)?),
            RegionFrameType::RendezvousRequest
            | RegionFrameType::RendezvousResponse
            | RegionFrameType::RegistryRecord => {
                return Err(RegionFrameError::UnknownType(u64::from(
                    envelope.frame_type,
                )));
            }
        };
        reader.finish()?;
        decoded.validate()?;
        Ok(decoded)
    }

    /// Decodes exactly one length-prefixed frame of types 1-9, whose prefix may not exceed
    /// 4096 on either channel (quick-protocol §12.8).
    ///
    /// # Errors
    ///
    /// As [`split_region_frame`] and [`RegionFrame::decode`].
    pub fn decode_prefixed(wire: &[u8]) -> Result<Self, RegionFrameError> {
        Self::decode(split_region_frame(wire, RegionChannel::Data)?)
    }
}

impl RegionPresent {
    /// Checks `slot = NodeId(I)` and a non-zero revision (quick-v2 §8.5,
    /// quick-protocol §12.8 rule 6).
    ///
    /// # Errors
    ///
    /// [`RegionFrameError::SlotMismatch`] or [`RegionFrameError::ZeroRevision`].
    pub fn validate(&self) -> Result<(), RegionFrameError> {
        check_event(&self.slot, &self.identity, self.revision)
    }

    /// Checks a snapshot presence entry: [`RegionPresent::validate`] and a revision not
    /// greater than the chunk `base_revision` (quick-protocol §12.8).
    ///
    /// # Errors
    ///
    /// As [`RegionPresent::validate`], or [`RegionFrameError::EntryAfterCut`].
    pub fn validate_entry(&self, base_revision: u64) -> Result<(), RegionFrameError> {
        self.validate()?;
        if self.revision > base_revision {
            return Err(RegionFrameError::EntryAfterCut {
                revision: self.revision,
                base_revision,
            });
        }
        Ok(())
    }
}

impl RegionSnapshot {
    /// Checks the per-chunk rules: non-zero `snapshot_id`, at most 256 combined entries,
    /// valid presence entries no later than `base_revision`, and each owner at most once per
    /// entry list (quick-protocol §12.8).
    ///
    /// # Errors
    ///
    /// [`RegionFrameError`] naming the first violated rule.
    pub fn validate(&self) -> Result<(), RegionFrameError> {
        if self.snapshot_id == 0 {
            return Err(RegionFrameError::ZeroSnapshotId);
        }
        let entries = self.presence.len().saturating_add(self.marks.len());
        if entries > MAX_REGION_SNAPSHOT_ENTRIES {
            return Err(RegionFrameError::TooManyEntries(entries));
        }
        for present in &self.presence {
            present.validate_entry(self.base_revision)?;
        }
        if has_duplicate(self.presence.iter().map(|present| present.identity)) {
            return Err(RegionFrameError::DuplicateOwner("presence"));
        }
        if has_duplicate(self.marks.iter().map(|marks| marks.identity)) {
            return Err(RegionFrameError::DuplicateOwner("mark"));
        }
        Ok(())
    }
}

impl RegionForward {
    /// Checks a non-zero `forward_id` and that `datagram` is a whole, valid relay DATA packet
    /// of at most 2048 bytes whose src is `NodeId(source_owner)` (quick-v2 §8.5,
    /// quick-protocol §12.8 rule 3).
    ///
    /// # Errors
    ///
    /// [`RegionFrameError`] naming the first violated rule.
    pub fn validate(&self) -> Result<(), RegionFrameError> {
        if self.forward_id == 0 {
            return Err(RegionFrameError::ZeroForwardId);
        }
        if self.datagram.len() > MAX_REGION_FORWARD_DATAGRAM_BYTES {
            return Err(RegionFrameError::DatagramTooLarge(self.datagram.len()));
        }
        let packet = RelayPacket::decode(&self.datagram).map_err(RegionFrameError::Datagram)?;
        let packet_type = packet.body.packet_type();
        if packet_type != RelayType::Data {
            return Err(RegionFrameError::DatagramNotData(packet_type));
        }
        if packet.src != NodeId::derive(&self.source_owner) {
            return Err(RegionFrameError::SourceOwnerMismatch);
        }
        Ok(())
    }
}

/// Encoded length of a PRESENT body in bytes (quick-v2 §8.5).
pub(super) fn present_len(present: &RegionPresent) -> usize {
    let mut writer = CborWriter::with_capacity(128);
    write_present(&mut writer, present);
    writer.into_bytes().len()
}

/// Encoded length of a MARKS body in bytes (quick-v2 §8.5).
pub(super) fn marks_len(marks: &RegionMarks) -> usize {
    let mut writer = CborWriter::with_capacity(128);
    write_marks(&mut writer, marks);
    writer.into_bytes().len()
}

fn check_event(slot: &NodeId, identity: &Identity, revision: u64) -> Result<(), RegionFrameError> {
    if *slot != NodeId::derive(identity) {
        return Err(RegionFrameError::SlotMismatch);
    }
    if revision == 0 {
        return Err(RegionFrameError::ZeroRevision);
    }
    Ok(())
}

fn has_duplicate(identities: impl Iterator<Item = Identity>) -> bool {
    let mut identities: Vec<Identity> = identities.collect();
    identities.sort_unstable();
    identities
        .windows(2)
        .any(|pair| matches!(pair, [a, b] if a == b))
}

fn write_present(writer: &mut CborWriter, present: &RegionPresent) {
    writer
        .array(7)
        .bytes(present.slot.as_bytes())
        .bytes(&present.identity)
        .uint(present.generation)
        .uint(present.incarnation)
        .uint(present.carrier as u64)
        .uint(present.boot_epoch)
        .uint(present.revision);
}

fn write_marks(writer: &mut CborWriter, marks: &RegionMarks) {
    writer
        .array(5)
        .bytes(&marks.identity)
        .uint(marks.committed_gen)
        .bytes(&marks.committed_key)
        .boolean(marks.conflicted)
        .uint(marks.incarnation_high_water);
}

fn read_u32(reader: &mut CborReader<'_>, field: &'static str) -> Result<u32, RegionFrameError> {
    let value = reader.uint()?;
    u32::try_from(value).map_err(|_| RegionFrameError::FieldWidth { field, value })
}

fn read_hello(reader: &mut CborReader<'_>) -> Result<RegionHello, RegionFrameError> {
    reader.array(5)?;
    let region_name = RelayId::parse(reader.text_up_to(MAX_RELAY_ID_BYTES)?)
        .map_err(RegionFrameError::RegionName)?;
    let member_id = reader.uint()?;
    let member_id = u8::try_from(member_id)
        .ok()
        .filter(|id| (MIN_REGION_MEMBER_ID..=MAX_REGION_MEMBER_ID).contains(id))
        .ok_or(RegionFrameError::MemberId(member_id))?;
    let boot_epoch = reader.uint()?;
    let channel = match reader.uint()? {
        0 => RegionChannel::Control,
        1 => RegionChannel::Data,
        other => return Err(RegionFrameError::ChannelKind(other)),
    };
    let conn_gen = read_u32(reader, "conn_gen")?;
    Ok(RegionHello {
        region_name,
        member_id,
        boot_epoch,
        channel,
        conn_gen,
    })
}

fn read_present(reader: &mut CborReader<'_>) -> Result<RegionPresent, RegionFrameError> {
    reader.array(7)?;
    let slot = NodeId::from_bytes(reader.fixed_bytes()?);
    let identity = reader.fixed_bytes()?;
    let generation = reader.uint()?;
    let incarnation = reader.uint()?;
    let carrier = match reader.uint()? {
        0 => RegionCarrier::Udp,
        1 => RegionCarrier::Wss,
        other => return Err(RegionFrameError::Carrier(other)),
    };
    Ok(RegionPresent {
        slot,
        identity,
        generation,
        incarnation,
        carrier,
        boot_epoch: reader.uint()?,
        revision: reader.uint()?,
    })
}

fn read_gone(reader: &mut CborReader<'_>) -> Result<RegionGone, RegionFrameError> {
    reader.array(7)?;
    let slot = NodeId::from_bytes(reader.fixed_bytes()?);
    let identity = reader.fixed_bytes()?;
    let generation = reader.uint()?;
    let incarnation = reader.uint()?;
    let reason = match reader.uint()? {
        0 => RegionGoneReason::Expired,
        1 => RegionGoneReason::Revoked,
        2 => RegionGoneReason::Superseded,
        3 => RegionGoneReason::Closed,
        other => return Err(RegionFrameError::GoneReason(other)),
    };
    Ok(RegionGone {
        slot,
        identity,
        generation,
        incarnation,
        reason,
        boot_epoch: reader.uint()?,
        revision: reader.uint()?,
    })
}

fn read_marks(reader: &mut CborReader<'_>) -> Result<RegionMarks, RegionFrameError> {
    reader.array(5)?;
    Ok(RegionMarks {
        identity: reader.fixed_bytes()?,
        committed_gen: reader.uint()?,
        committed_key: reader.fixed_bytes()?,
        conflicted: reader.boolean()?,
        incarnation_high_water: reader.uint()?,
    })
}

fn read_snapshot(reader: &mut CborReader<'_>) -> Result<RegionSnapshot, RegionFrameError> {
    reader.array(7)?;
    let snapshot_id = reader.uint()?;
    let base_revision = reader.uint()?;
    let marks_revision = reader.uint()?;
    let chunk_index = read_u32(reader, "chunk_index")?;
    let presence_count = reader.array_up_to(MAX_REGION_FRAME_BYTES)?;
    if presence_count > MAX_REGION_SNAPSHOT_ENTRIES {
        return Err(RegionFrameError::TooManyEntries(presence_count));
    }
    let mut presence = Vec::with_capacity(presence_count);
    for _ in 0..presence_count {
        presence.push(read_present(reader)?);
    }
    let marks_count = reader.array_up_to(MAX_REGION_FRAME_BYTES)?;
    let entries = presence_count.saturating_add(marks_count);
    if entries > MAX_REGION_SNAPSHOT_ENTRIES {
        return Err(RegionFrameError::TooManyEntries(entries));
    }
    let mut marks = Vec::with_capacity(marks_count);
    for _ in 0..marks_count {
        marks.push(read_marks(reader)?);
    }
    Ok(RegionSnapshot {
        snapshot_id,
        base_revision,
        marks_revision,
        chunk_index,
        presence,
        marks,
        more: reader.boolean()?,
    })
}

fn read_liveness(reader: &mut CborReader<'_>) -> Result<RegionLiveness, RegionFrameError> {
    reader.array(3)?;
    Ok(RegionLiveness {
        nonce: reader.uint()?,
        data_conn_gen: read_u32(reader, "data_conn_gen")?,
        consumed_forward_id: reader.uint()?,
    })
}
