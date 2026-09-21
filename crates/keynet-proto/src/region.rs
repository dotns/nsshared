//! Canonical inter-member relay-region frames from design section 13.8.

use crate::{Identity, NetworkId, RelayIdentifier, SlotId, codec::CborReader};

/// The sole supported region-frame version.
pub const REGION_FRAME_VERSION: u8 = 1;
/// The largest encoded CBOR frame body, excluding its four-byte prefix.
pub const MAX_REGION_FRAME_BYTES: usize = 4096;
/// The largest forwarded node datagram retained as opaque frame data.
pub const MAX_REGION_FORWARD_DATAGRAM_BYTES: usize = 2048;
/// The maximum combined number of nested presence and mark records in a snapshot.
pub const MAX_REGION_SNAPSHOT_ENTRIES: usize = 256;

/// Frame types permitted on a control connection.
pub const CONTROL_REGION_FRAME_TYPES: &[RegionFrameType] = &[
    RegionFrameType::Hello,
    RegionFrameType::Snapshot,
    RegionFrameType::Present,
    RegionFrameType::Gone,
    RegionFrameType::Marks,
    RegionFrameType::Miss,
    RegionFrameType::Ping,
    RegionFrameType::Pong,
];
/// Frame types permitted on a data connection, including its HELLO setup frame.
pub const DATA_REGION_FRAME_TYPES: &[RegionFrameType] =
    &[RegionFrameType::Hello, RegionFrameType::Forward];
/// Frame types permitted on a data connection after HELLO completes.
pub const DATA_POST_HELLO_REGION_FRAME_TYPES: &[RegionFrameType] = &[RegionFrameType::Forward];

/// A mesh transport channel.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RegionChannel {
    /// The control channel carries membership, snapshot, mark, and liveness frames.
    Control = 0,
    /// The data channel carries HELLO followed by forwarded datagrams.
    Data = 1,
}

impl RegionChannel {
    /// Returns whether `frame_type` is permitted on this channel before handshake state is applied.
    #[must_use]
    pub const fn permits(self, frame_type: RegionFrameType) -> bool {
        match self {
            Self::Control => !matches!(frame_type, RegionFrameType::Forward),
            Self::Data => matches!(
                frame_type,
                RegionFrameType::Hello | RegionFrameType::Forward
            ),
        }
    }

    /// Returns whether `frame_type` is permitted after this channel's initial HELLO exchange.
    #[must_use]
    pub const fn permits_after_hello(self, frame_type: RegionFrameType) -> bool {
        match self {
            Self::Control => !matches!(
                frame_type,
                RegionFrameType::Hello | RegionFrameType::Forward
            ),
            Self::Data => matches!(frame_type, RegionFrameType::Forward),
        }
    }
}

impl TryFrom<u8> for RegionChannel {
    type Error = RegionDecodeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Control),
            1 => Ok(Self::Data),
            _ => Err(RegionDecodeError::InvalidEncoding),
        }
    }
}

/// A carrier used by an origin member's committed node session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RegionCarrier {
    /// The node session uses UDP.
    Udp = 0,
    /// The node session uses WSS.
    Wss = 1,
}

impl TryFrom<u8> for RegionCarrier {
    type Error = RegionDecodeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Udp),
            1 => Ok(Self::Wss),
            _ => Err(RegionDecodeError::InvalidEncoding),
        }
    }
}

/// A reason that an origin member retired a presence record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RegionGoneReason {
    /// The session expired.
    Expired = 0,
    /// The session was revoked.
    Revoked = 1,
    /// A newer session superseded the record.
    Superseded = 2,
    /// The origin member shut down.
    Shutdown = 3,
}

impl TryFrom<u8> for RegionGoneReason {
    type Error = RegionDecodeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Expired),
            1 => Ok(Self::Revoked),
            2 => Ok(Self::Superseded),
            3 => Ok(Self::Shutdown),
            _ => Err(RegionDecodeError::InvalidEncoding),
        }
    }
}

/// A reason an exit member could not deliver a forwarded datagram.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RegionMissStatus {
    /// No eligible local destination existed.
    NoEligibleDestination = 1,
    /// Destination admission or output capacity was exhausted.
    DestinationExhausted = 2,
}

impl TryFrom<u8> for RegionMissStatus {
    type Error = RegionDecodeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::NoEligibleDestination),
            2 => Ok(Self::DestinationExhausted),
            _ => Err(RegionDecodeError::InvalidEncoding),
        }
    }
}

/// A region-frame envelope type tag.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RegionFrameType {
    /// A channel setup HELLO frame.
    Hello = 1,
    /// A chunk of initial presence and mark state.
    Snapshot = 2,
    /// A local active-session announcement.
    Present = 3,
    /// A local active-session retirement announcement.
    Gone = 4,
    /// A retained-owner mark update.
    Marks = 5,
    /// A datagram forwarded to a destination member.
    Forward = 6,
    /// A destination-member failure for a forwarded datagram.
    Miss = 7,
    /// A control-channel liveness probe.
    Ping = 8,
    /// A control-channel liveness response.
    Pong = 9,
}

impl RegionFrameType {
    /// Returns whether this frame type is permitted on `channel` before handshake state is applied.
    #[must_use]
    pub const fn is_legal_on(self, channel: RegionChannel) -> bool {
        channel.permits(self)
    }

    /// Returns whether this type is permitted after HELLO completes on `channel`.
    #[must_use]
    pub const fn is_legal_after_hello_on(self, channel: RegionChannel) -> bool {
        channel.permits_after_hello(self)
    }
}

impl TryFrom<u8> for RegionFrameType {
    type Error = RegionDecodeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Hello),
            2 => Ok(Self::Snapshot),
            3 => Ok(Self::Present),
            4 => Ok(Self::Gone),
            5 => Ok(Self::Marks),
            6 => Ok(Self::Forward),
            7 => Ok(Self::Miss),
            8 => Ok(Self::Ping),
            9 => Ok(Self::Pong),
            _ => Err(RegionDecodeError::UnsupportedType),
        }
    }
}

/// The HELLO frame body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegionHello {
    /// The canonical advertised region identifier.
    pub region_name: String,
    /// The configured member identifier in the inclusive range 1 through 16.
    pub member_id: u8,
    /// The fresh epoch allocated when the member process started.
    pub boot_epoch: u64,
    /// The channel this HELLO establishes.
    pub channel: RegionChannel,
    /// The nonzero per-channel connection generation.
    pub conn_gen: u32,
}

/// A complete owner identifier used in a forwarded source owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegionOwner {
    /// The wire scope identifier.
    pub network_id: NetworkId,
    /// The owner identity public key.
    pub identity: Identity,
}

/// A nested PRESENT body or a top-level PRESENT frame body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegionPresence {
    /// The active relay slot.
    pub slot: SlotId,
    /// The wire scope identifier.
    pub network_id: NetworkId,
    /// The owner identity public key.
    pub identity: Identity,
    /// The committed generation.
    pub generation: u64,
    /// The active-session incarnation.
    pub incarnation: u64,
    /// The origin member's node carrier.
    pub carrier: RegionCarrier,
    /// The origin member process epoch.
    pub boot_epoch: u64,
    /// The origin member's event revision.
    pub revision: u64,
}

/// A GONE frame body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegionGone {
    /// The retired relay slot.
    pub slot: SlotId,
    /// The wire scope identifier.
    pub network_id: NetworkId,
    /// The owner identity public key.
    pub identity: Identity,
    /// The committed generation.
    pub generation: u64,
    /// The retired-session incarnation.
    pub incarnation: u64,
    /// The retirement reason.
    pub reason: RegionGoneReason,
    /// The origin member process epoch.
    pub boot_epoch: u64,
    /// The origin member's event revision.
    pub revision: u64,
}

/// A nested MARKS body or a top-level MARKS frame body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegionMarks {
    /// The wire scope identifier.
    pub network_id: NetworkId,
    /// The owner identity public key.
    pub identity: Identity,
    /// The committed generation.
    pub committed_generation: u64,
    /// The committed public key.
    pub committed_key: [u8; 32],
    /// Whether a same-generation key conflict is latched.
    pub conflicted: bool,
    /// The optional generation revocation floor.
    pub revoked_through: Option<u64>,
    /// The greatest retained session incarnation.
    pub incarnation_high_water: u64,
}

/// The side-effect-free result of joining two retained marks for one owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegionMarksJoin {
    /// The monotonic mark state produced by the join.
    pub state: RegionMarks,
    /// Whether `state` differs from the caller's current mark state.
    pub changed: bool,
}

/// A failure to join retained marks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegionMarksJoinError {
    /// The inputs name different retained owners.
    ScopeMismatch,
}

/// Joins two retained marks for the same owner without applying persistence or other effects.
///
/// The returned `changed` flag compares the joined state with `current`, so a caller can persist
/// an updated state before any dependent route change or publication.
pub fn join_region_marks(
    current: RegionMarks,
    incoming: RegionMarks,
) -> Result<RegionMarksJoin, RegionMarksJoinError> {
    if current.network_id != incoming.network_id || current.identity != incoming.identity {
        return Err(RegionMarksJoinError::ScopeMismatch);
    }

    let revoked_through = match (current.revoked_through, incoming.revoked_through) {
        (Some(current), Some(incoming)) => Some(current.max(incoming)),
        (Some(current), None) => Some(current),
        (None, Some(incoming)) => Some(incoming),
        (None, None) => None,
    };
    let (committed_generation, committed_key, conflicted, incarnation_high_water) =
        if current.committed_generation > incoming.committed_generation {
            (
                current.committed_generation,
                current.committed_key,
                current.conflicted,
                current.incarnation_high_water,
            )
        } else if current.committed_generation < incoming.committed_generation {
            (
                incoming.committed_generation,
                incoming.committed_key,
                incoming.conflicted,
                incoming.incarnation_high_water,
            )
        } else {
            let keys_differ = current.committed_key != incoming.committed_key;
            (
                current.committed_generation,
                current.committed_key.min(incoming.committed_key),
                current.conflicted || incoming.conflicted || keys_differ,
                current
                    .incarnation_high_water
                    .max(incoming.incarnation_high_water),
            )
        };
    let state = RegionMarks {
        network_id: current.network_id,
        identity: current.identity,
        committed_generation,
        committed_key,
        conflicted,
        revoked_through,
        incarnation_high_water,
    };
    Ok(RegionMarksJoin {
        changed: state != current,
        state,
    })
}

/// A SNAPSHOT frame body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegionSnapshot {
    /// The snapshot identifier.
    pub snapshot_id: u64,
    /// The presence revision at which this snapshot was cut.
    pub base_revision: u64,
    /// The durable marks revision represented by this chunk.
    pub marks_revision: u64,
    /// The zero-based chunk index.
    pub chunk_index: u32,
    /// Nested PRESENT bodies without envelopes.
    pub presence_entries: Vec<RegionPresence>,
    /// Nested MARKS bodies without envelopes.
    pub mark_entries: Vec<RegionMarks>,
    /// Whether another chunk follows this one.
    pub more: bool,
}

/// A FORWARD frame body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegionForward {
    /// The sender's monotonically assigned forwarding identifier.
    pub forward_id: u64,
    /// The owner that supplied the original node datagram.
    pub source_owner: RegionOwner,
    /// The unchanged opaque node datagram, validated by the caller at the node layer.
    pub datagram: Vec<u8>,
}

/// A MISS frame body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegionMiss {
    /// The data-channel connection generation of the failed forward.
    pub data_conn_gen: u32,
    /// The failed forwarding identifier.
    pub forward_id: u64,
    /// The reason delivery failed.
    pub status: RegionMissStatus,
}

/// A PING frame body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegionPing {
    /// The liveness nonce.
    pub nonce: u64,
    /// The observed data-channel connection generation.
    pub data_conn_gen: u32,
    /// The greatest consumed forwarding identifier.
    pub consumed_forward_id: u64,
}

/// A PONG frame body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegionPong {
    /// The echoed liveness nonce.
    pub nonce: u64,
    /// The observed data-channel connection generation.
    pub data_conn_gen: u32,
    /// The greatest consumed forwarding identifier.
    pub consumed_forward_id: u64,
}

/// One complete region-frame envelope and typed body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegionFrame {
    /// A HELLO frame.
    Hello(RegionHello),
    /// A SNAPSHOT frame.
    Snapshot(RegionSnapshot),
    /// A PRESENT frame.
    Present(RegionPresence),
    /// A GONE frame.
    Gone(RegionGone),
    /// A MARKS frame.
    Marks(RegionMarks),
    /// A FORWARD frame.
    Forward(RegionForward),
    /// A MISS frame.
    Miss(RegionMiss),
    /// A PING frame.
    Ping(RegionPing),
    /// A PONG frame.
    Pong(RegionPong),
}

/// A failure to encode a region frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegionEncodeError {
    /// A field, enum, channel association, or snapshot count violates the frame contract.
    InvalidFrame,
    /// The encoded CBOR envelope exceeds the region frame limit.
    FrameTooLarge,
}

/// A failure to decode a region frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegionDecodeError {
    /// Fewer than four prefix bytes were available.
    IncompletePrefix,
    /// The prefix declared zero bytes or more than the frame limit.
    InvalidPrefix,
    /// The supplied input did not contain exactly the prefix-declared body length.
    InvalidLength,
    /// A CBOR field, shape, width, enum, text value, or trailing byte was invalid.
    InvalidEncoding,
    /// The envelope version was not one.
    UnsupportedVersion,
    /// The envelope type was not one of the nine region frame types.
    UnsupportedType,
    /// The frame type or HELLO channel does not match the supplied transport channel.
    WrongChannel,
}

impl RegionFrame {
    /// Returns this envelope's type tag.
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

    /// Encodes this frame with a four-byte big-endian length prefix for `channel`.
    pub fn encode(&self, channel: RegionChannel) -> Result<Vec<u8>, RegionEncodeError> {
        validate_frame(self, channel)?;

        let mut body = Vec::new();
        write_array(&mut body, 3);
        write_uint(&mut body, u64::from(REGION_FRAME_VERSION));
        write_uint(&mut body, u64::from(self.frame_type() as u8));
        encode_body(&mut body, self)?;
        if body.len() > MAX_REGION_FRAME_BYTES {
            return Err(RegionEncodeError::FrameTooLarge);
        }

        let length = u32::try_from(body.len()).map_err(|_| RegionEncodeError::FrameTooLarge)?;
        let capacity = body
            .len()
            .checked_add(4)
            .ok_or(RegionEncodeError::FrameTooLarge)?;
        let mut framed = Vec::with_capacity(capacity);
        framed.extend_from_slice(&length.to_be_bytes());
        framed.extend_from_slice(&body);
        Ok(framed)
    }

    /// Decodes exactly one prefixed canonical region frame received on `channel`.
    pub fn decode(input: &[u8], channel: RegionChannel) -> Result<Self, RegionDecodeError> {
        if input.len() < 4 {
            return Err(RegionDecodeError::IncompletePrefix);
        }
        let prefix = [input[0], input[1], input[2], input[3]];
        let body_length = decode_region_frame_prefix(prefix)?;
        let expected_length = body_length
            .checked_add(4)
            .ok_or(RegionDecodeError::InvalidLength)?;
        if input.len() != expected_length {
            return Err(RegionDecodeError::InvalidLength);
        }

        let mut reader = CborReader::new(&input[4..]);
        expect_array(&mut reader, 3)?;
        if read_u8(&mut reader)? != REGION_FRAME_VERSION {
            return Err(RegionDecodeError::UnsupportedVersion);
        }
        let frame_type = RegionFrameType::try_from(read_u8(&mut reader)?)?;
        if !frame_type.is_legal_on(channel) {
            return Err(RegionDecodeError::WrongChannel);
        }
        let frame = decode_body(&mut reader, frame_type)?;
        if !reader.finished() {
            return Err(RegionDecodeError::InvalidEncoding);
        }
        if let RegionFrame::Hello(hello) = &frame
            && hello.channel != channel
        {
            return Err(RegionDecodeError::WrongChannel);
        }
        validate_frame(&frame, channel).map_err(|_| RegionDecodeError::InvalidEncoding)?;
        Ok(frame)
    }
}

/// Decodes and validates a four-byte big-endian region-frame length prefix.
///
/// This function performs no body allocation and is suitable for bounded stream assembly.
pub fn decode_region_frame_prefix(prefix: [u8; 4]) -> Result<usize, RegionDecodeError> {
    let length = usize::try_from(u32::from_be_bytes(prefix))
        .map_err(|_| RegionDecodeError::InvalidPrefix)?;
    if length == 0 || length > MAX_REGION_FRAME_BYTES {
        return Err(RegionDecodeError::InvalidPrefix);
    }
    Ok(length)
}

fn validate_frame(frame: &RegionFrame, channel: RegionChannel) -> Result<(), RegionEncodeError> {
    if !frame.frame_type().is_legal_on(channel) {
        return Err(RegionEncodeError::InvalidFrame);
    }
    if let RegionFrame::Hello(hello) = frame
        && hello.channel != channel
    {
        return Err(RegionEncodeError::InvalidFrame);
    }
    match frame {
        RegionFrame::Hello(hello) => validate_hello(hello),
        RegionFrame::Snapshot(snapshot) => validate_snapshot(snapshot),
        RegionFrame::Present(_) | RegionFrame::Gone(_) | RegionFrame::Marks(_) => Ok(()),
        RegionFrame::Forward(forward) => {
            if forward.datagram.len() > MAX_REGION_FORWARD_DATAGRAM_BYTES {
                Err(RegionEncodeError::InvalidFrame)
            } else {
                Ok(())
            }
        }
        RegionFrame::Miss(_) | RegionFrame::Ping(_) | RegionFrame::Pong(_) => Ok(()),
    }
}

fn validate_hello(hello: &RegionHello) -> Result<(), RegionEncodeError> {
    if !(1..=255).contains(&hello.region_name.len())
        || !(1..=16).contains(&hello.member_id)
        || hello.conn_gen == 0
        || RelayIdentifier::parse(&hello.region_name).is_err()
    {
        return Err(RegionEncodeError::InvalidFrame);
    }
    Ok(())
}

fn validate_snapshot(snapshot: &RegionSnapshot) -> Result<(), RegionEncodeError> {
    let entries = snapshot
        .presence_entries
        .len()
        .checked_add(snapshot.mark_entries.len())
        .ok_or(RegionEncodeError::InvalidFrame)?;
    if entries > MAX_REGION_SNAPSHOT_ENTRIES {
        return Err(RegionEncodeError::InvalidFrame);
    }
    Ok(())
}

fn encode_body(output: &mut Vec<u8>, frame: &RegionFrame) -> Result<(), RegionEncodeError> {
    match frame {
        RegionFrame::Hello(hello) => {
            write_array(output, 5);
            write_text(output, &hello.region_name);
            write_uint(output, u64::from(hello.member_id));
            write_uint(output, hello.boot_epoch);
            write_uint(output, u64::from(hello.channel as u8));
            write_uint(output, u64::from(hello.conn_gen));
        }
        RegionFrame::Snapshot(snapshot) => {
            write_array(output, 7);
            write_uint(output, snapshot.snapshot_id);
            write_uint(output, snapshot.base_revision);
            write_uint(output, snapshot.marks_revision);
            write_uint(output, u64::from(snapshot.chunk_index));
            write_array(
                output,
                u64::try_from(snapshot.presence_entries.len())
                    .map_err(|_| RegionEncodeError::InvalidFrame)?,
            );
            for presence in &snapshot.presence_entries {
                encode_presence(output, presence);
            }
            write_array(
                output,
                u64::try_from(snapshot.mark_entries.len())
                    .map_err(|_| RegionEncodeError::InvalidFrame)?,
            );
            for marks in &snapshot.mark_entries {
                encode_marks(output, marks);
            }
            write_boolean(output, snapshot.more);
        }
        RegionFrame::Present(presence) => encode_presence(output, presence),
        RegionFrame::Gone(gone) => {
            write_array(output, 8);
            write_bytes(output, &gone.slot);
            write_bytes(output, &gone.network_id);
            write_bytes(output, &gone.identity);
            write_uint(output, gone.generation);
            write_uint(output, gone.incarnation);
            write_uint(output, u64::from(gone.reason as u8));
            write_uint(output, gone.boot_epoch);
            write_uint(output, gone.revision);
        }
        RegionFrame::Marks(marks) => encode_marks(output, marks),
        RegionFrame::Forward(forward) => {
            write_array(output, 3);
            write_uint(output, forward.forward_id);
            write_array(output, 2);
            write_bytes(output, &forward.source_owner.network_id);
            write_bytes(output, &forward.source_owner.identity);
            write_bytes(output, &forward.datagram);
        }
        RegionFrame::Miss(miss) => {
            write_array(output, 3);
            write_uint(output, u64::from(miss.data_conn_gen));
            write_uint(output, miss.forward_id);
            write_uint(output, u64::from(miss.status as u8));
        }
        RegionFrame::Ping(ping) => encode_ping(
            output,
            ping.nonce,
            ping.data_conn_gen,
            ping.consumed_forward_id,
        ),
        RegionFrame::Pong(pong) => encode_ping(
            output,
            pong.nonce,
            pong.data_conn_gen,
            pong.consumed_forward_id,
        ),
    }
    Ok(())
}

fn encode_presence(output: &mut Vec<u8>, presence: &RegionPresence) {
    write_array(output, 8);
    write_bytes(output, &presence.slot);
    write_bytes(output, &presence.network_id);
    write_bytes(output, &presence.identity);
    write_uint(output, presence.generation);
    write_uint(output, presence.incarnation);
    write_uint(output, u64::from(presence.carrier as u8));
    write_uint(output, presence.boot_epoch);
    write_uint(output, presence.revision);
}

fn encode_marks(output: &mut Vec<u8>, marks: &RegionMarks) {
    write_array(output, 7);
    write_bytes(output, &marks.network_id);
    write_bytes(output, &marks.identity);
    write_uint(output, marks.committed_generation);
    write_bytes(output, &marks.committed_key);
    write_boolean(output, marks.conflicted);
    match marks.revoked_through {
        Some(value) => write_uint(output, value),
        None => output.push(0xf6),
    }
    write_uint(output, marks.incarnation_high_water);
}

fn encode_ping(output: &mut Vec<u8>, nonce: u64, data_conn_gen: u32, consumed_forward_id: u64) {
    write_array(output, 3);
    write_uint(output, nonce);
    write_uint(output, u64::from(data_conn_gen));
    write_uint(output, consumed_forward_id);
}

fn decode_body(
    reader: &mut CborReader<'_>,
    frame_type: RegionFrameType,
) -> Result<RegionFrame, RegionDecodeError> {
    match frame_type {
        RegionFrameType::Hello => {
            expect_array(reader, 5)?;
            let hello = RegionHello {
                region_name: reader
                    .text_with_maximum(255)
                    .map_err(|_| RegionDecodeError::InvalidEncoding)?,
                member_id: read_u8(reader)?,
                boot_epoch: read_uint(reader)?,
                channel: RegionChannel::try_from(read_u8(reader)?)?,
                conn_gen: read_u32(reader)?,
            };
            Ok(RegionFrame::Hello(hello))
        }
        RegionFrameType::Snapshot => {
            expect_array(reader, 7)?;
            let snapshot_id = read_uint(reader)?;
            let base_revision = read_uint(reader)?;
            let marks_revision = read_uint(reader)?;
            let chunk_index = read_u32(reader)?;
            let presence_entries = decode_presence_entries(reader)?;
            let mark_entries = decode_mark_entries(reader, presence_entries.len())?;
            let more = reader
                .boolean()
                .map_err(|_| RegionDecodeError::InvalidEncoding)?;
            Ok(RegionFrame::Snapshot(RegionSnapshot {
                snapshot_id,
                base_revision,
                marks_revision,
                chunk_index,
                presence_entries,
                mark_entries,
                more,
            }))
        }
        RegionFrameType::Present => Ok(RegionFrame::Present(decode_presence(reader)?)),
        RegionFrameType::Gone => {
            expect_array(reader, 8)?;
            Ok(RegionFrame::Gone(RegionGone {
                slot: fixed_bytes(reader)?,
                network_id: fixed_bytes(reader)?,
                identity: fixed_bytes(reader)?,
                generation: read_uint(reader)?,
                incarnation: read_uint(reader)?,
                reason: RegionGoneReason::try_from(read_u8(reader)?)?,
                boot_epoch: read_uint(reader)?,
                revision: read_uint(reader)?,
            }))
        }
        RegionFrameType::Marks => Ok(RegionFrame::Marks(decode_marks(reader)?)),
        RegionFrameType::Forward => {
            expect_array(reader, 3)?;
            let forward_id = read_uint(reader)?;
            expect_array(reader, 2)?;
            let source_owner = RegionOwner {
                network_id: fixed_bytes(reader)?,
                identity: fixed_bytes(reader)?,
            };
            let datagram = reader
                .bytes_with_maximum(MAX_REGION_FORWARD_DATAGRAM_BYTES)
                .map_err(|_| RegionDecodeError::InvalidEncoding)?;
            Ok(RegionFrame::Forward(RegionForward {
                forward_id,
                source_owner,
                datagram,
            }))
        }
        RegionFrameType::Miss => {
            expect_array(reader, 3)?;
            Ok(RegionFrame::Miss(RegionMiss {
                data_conn_gen: read_u32(reader)?,
                forward_id: read_uint(reader)?,
                status: RegionMissStatus::try_from(read_u8(reader)?)?,
            }))
        }
        RegionFrameType::Ping => {
            let (nonce, data_conn_gen, consumed_forward_id) = decode_ping(reader)?;
            Ok(RegionFrame::Ping(RegionPing {
                nonce,
                data_conn_gen,
                consumed_forward_id,
            }))
        }
        RegionFrameType::Pong => {
            let (nonce, data_conn_gen, consumed_forward_id) = decode_ping(reader)?;
            Ok(RegionFrame::Pong(RegionPong {
                nonce,
                data_conn_gen,
                consumed_forward_id,
            }))
        }
    }
}

fn decode_presence(reader: &mut CborReader<'_>) -> Result<RegionPresence, RegionDecodeError> {
    expect_array(reader, 8)?;
    Ok(RegionPresence {
        slot: fixed_bytes(reader)?,
        network_id: fixed_bytes(reader)?,
        identity: fixed_bytes(reader)?,
        generation: read_uint(reader)?,
        incarnation: read_uint(reader)?,
        carrier: RegionCarrier::try_from(read_u8(reader)?)?,
        boot_epoch: read_uint(reader)?,
        revision: read_uint(reader)?,
    })
}

fn decode_marks(reader: &mut CborReader<'_>) -> Result<RegionMarks, RegionDecodeError> {
    expect_array(reader, 7)?;
    Ok(RegionMarks {
        network_id: fixed_bytes(reader)?,
        identity: fixed_bytes(reader)?,
        committed_generation: read_uint(reader)?,
        committed_key: fixed_bytes(reader)?,
        conflicted: reader
            .boolean()
            .map_err(|_| RegionDecodeError::InvalidEncoding)?,
        revoked_through: reader
            .optional_uint()
            .map_err(|_| RegionDecodeError::InvalidEncoding)?,
        incarnation_high_water: read_uint(reader)?,
    })
}

fn decode_presence_entries(
    reader: &mut CborReader<'_>,
) -> Result<Vec<RegionPresence>, RegionDecodeError> {
    let count = read_entry_count(reader, 0)?;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        entries.push(decode_presence(reader)?);
    }
    Ok(entries)
}

fn decode_mark_entries(
    reader: &mut CborReader<'_>,
    presence_count: usize,
) -> Result<Vec<RegionMarks>, RegionDecodeError> {
    let count = read_entry_count(reader, presence_count)?;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        entries.push(decode_marks(reader)?);
    }
    Ok(entries)
}

fn read_entry_count(
    reader: &mut CborReader<'_>,
    existing: usize,
) -> Result<usize, RegionDecodeError> {
    let count = reader
        .array_len()
        .map_err(|_| RegionDecodeError::InvalidEncoding)?;
    let count = usize::try_from(count).map_err(|_| RegionDecodeError::InvalidEncoding)?;
    if existing
        .checked_add(count)
        .is_none_or(|total| total > MAX_REGION_SNAPSHOT_ENTRIES)
    {
        return Err(RegionDecodeError::InvalidEncoding);
    }
    Ok(count)
}

fn decode_ping(reader: &mut CborReader<'_>) -> Result<(u64, u32, u64), RegionDecodeError> {
    expect_array(reader, 3)?;
    Ok((read_uint(reader)?, read_u32(reader)?, read_uint(reader)?))
}

fn expect_array(reader: &mut CborReader<'_>, expected: u64) -> Result<(), RegionDecodeError> {
    reader
        .array(expected)
        .map_err(|_| RegionDecodeError::InvalidEncoding)
}

fn read_uint(reader: &mut CborReader<'_>) -> Result<u64, RegionDecodeError> {
    reader
        .uint()
        .map_err(|_| RegionDecodeError::InvalidEncoding)
}

fn read_u8(reader: &mut CborReader<'_>) -> Result<u8, RegionDecodeError> {
    u8::try_from(read_uint(reader)?).map_err(|_| RegionDecodeError::InvalidEncoding)
}

fn read_u32(reader: &mut CborReader<'_>) -> Result<u32, RegionDecodeError> {
    u32::try_from(read_uint(reader)?).map_err(|_| RegionDecodeError::InvalidEncoding)
}

fn fixed_bytes<const N: usize>(reader: &mut CborReader<'_>) -> Result<[u8; N], RegionDecodeError> {
    reader
        .fixed_bytes()
        .map_err(|_| RegionDecodeError::InvalidEncoding)
}

fn write_array(output: &mut Vec<u8>, length: u64) {
    write_head(output, 4, length);
}

fn write_uint(output: &mut Vec<u8>, value: u64) {
    write_head(output, 0, value);
}

fn write_bytes(output: &mut Vec<u8>, value: &[u8]) {
    write_head(output, 2, value.len() as u64);
    output.extend_from_slice(value);
}

fn write_text(output: &mut Vec<u8>, value: &str) {
    write_head(output, 3, value.len() as u64);
    output.extend_from_slice(value.as_bytes());
}

fn write_boolean(output: &mut Vec<u8>, value: bool) {
    output.push(if value { 0xf5 } else { 0xf4 });
}

fn write_head(output: &mut Vec<u8>, major: u8, value: u64) {
    match value {
        0..=23 => output.push((major << 5) | value as u8),
        24..=255 => {
            output.push((major << 5) | 24);
            output.push(value as u8);
        }
        256..=65_535 => {
            output.push((major << 5) | 25);
            output.extend_from_slice(&(value as u16).to_be_bytes());
        }
        65_536..=4_294_967_295 => {
            output.push((major << 5) | 26);
            output.extend_from_slice(&(value as u32).to_be_bytes());
        }
        _ => {
            output.push((major << 5) | 27);
            output.extend_from_slice(&value.to_be_bytes());
        }
    }
}
