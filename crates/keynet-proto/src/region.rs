//! Canonical inter-member relay-region frames from design section 13.8.

use crate::{Identity, NetworkId, RelayIdentifier, SlotId, codec::CborReader, derive_slot_id};
use sha2::{Digest, Sha256};

/// The sole supported region-frame version.
pub const REGION_FRAME_VERSION: u8 = 1;
/// The largest encoded CBOR frame body, excluding its four-byte prefix.
pub const MAX_REGION_FRAME_BYTES: usize = 4096;
/// The largest forwarded node datagram retained as opaque frame data.
pub const MAX_REGION_FORWARD_DATAGRAM_BYTES: usize = 2048;
/// The maximum combined number of nested presence and mark records in a snapshot.
pub const MAX_REGION_SNAPSHOT_ENTRIES: usize = 256;
/// The protocol limit for retained incoming snapshot mark staging per origin.
pub const MAX_REGION_SNAPSHOT_MARK_STAGING_BYTES: usize = 64 * 1024;
/// The protocol limit for the retained full-owner mark union on one member.
pub const MAX_REGION_RETAINED_MARK_OWNERS: usize = 1_000_000;

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
    RegionFrameType::Settled,
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
    /// A cumulative final-decision watermark for forwarded datagrams.
    Settled = 10,
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
            10 => Ok(Self::Settled),
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
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
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

/// An authenticated origin identity for one region-member process epoch.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RegionPresenceOrigin {
    /// The configured member identifier for the authenticated mesh peer.
    pub member_id: u8,
    /// The peer process epoch authenticated by the current mesh stream.
    pub boot_epoch: u64,
}

/// A presence session together with its authenticated origin identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegionPresenceSession {
    /// The authenticated member and process epoch that own this session.
    pub origin: RegionPresenceOrigin,
    /// The origin-owned session announced in a PRESENT frame.
    pub presence: RegionPresence,
}

/// A retained origin-owned presence entry and its current routing eligibility.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegionPresenceRecord {
    /// The origin-owned relay session.
    pub session: RegionPresenceSession,
    /// Whether the session is currently usable for routing.
    pub eligible: bool,
    /// Whether the entry is being retained only during a disconnected-peer grace period.
    pub grace_cached: bool,
}

/// The scalar revision and synchronization state retained for one origin epoch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegionPresenceOriginState {
    /// The authenticated origin epoch described by this state.
    pub origin: RegionPresenceOrigin,
    /// The greatest accepted PRESENT or GONE revision from this origin epoch.
    pub revision_high_water: u64,
    /// Whether a completed snapshot is required before the epoch can supply usable routes.
    pub snapshot_required: bool,
}

/// The complete explicit input and output table for region-presence decisions.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RegionPresenceTable {
    /// The one selected presence record for each full owner.
    pub entries: Vec<RegionPresenceRecord>,
    /// The per-member origin epoch and revision state.
    pub origins: Vec<RegionPresenceOriginState>,
}

/// The authenticated-stream status supplied to a region-presence decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegionPresenceStream {
    /// The authenticated member and boot epoch for the event source.
    pub origin: RegionPresenceOrigin,
    /// Whether this stream is still the current authenticated stream for its origin.
    pub is_current: bool,
}

/// The two mesh channels required for a peer's presence to be forwardable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegionPresenceChannels {
    /// The member and boot epoch of the current authenticated channel pair.
    pub origin: RegionPresenceOrigin,
    /// Whether the current control channel is up.
    pub control_up: bool,
    /// Whether the current data channel is up.
    pub data_up: bool,
}

/// The explicit retained-presence capacity applied by a decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegionPresenceCapacity {
    /// The maximum number of retained selected presence entries.
    pub maximum_entries: usize,
}

/// An event accepted from an authenticated region control stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegionPresenceEvent {
    /// A current active session announcement.
    Present(RegionPresence),
    /// An exact active-session retirement announcement.
    Gone(RegionGone),
}

impl RegionPresenceEvent {
    const fn boot_epoch(self) -> u64 {
        match self {
            Self::Present(presence) => presence.boot_epoch,
            Self::Gone(gone) => gone.boot_epoch,
        }
    }

    const fn revision(self) -> u64 {
        match self {
            Self::Present(presence) => presence.revision,
            Self::Gone(gone) => gone.revision,
        }
    }
}

/// The explicit inputs that constrain a region-presence decision.
pub struct RegionPresenceInput<'a> {
    /// The current authenticated stream that delivered the event.
    pub stream: RegionPresenceStream,
    /// The complete retained durable mark union used to filter presence.
    pub durable_marks: &'a [RegionMarks],
    /// The current control/data state for each authenticated member pair.
    pub channel_states: &'a [RegionPresenceChannels],
    /// The retained-presence capacity available to the decision.
    pub capacity: RegionPresenceCapacity,
    /// The local member identifier, used only to emit local supersession effects.
    pub local_member_id: u8,
    /// The next local presence revision available for a mesh-only superseding GONE.
    pub local_gone_revision: Option<u64>,
}

/// The result category for a pure region-presence decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegionPresenceDisposition {
    /// The event was applied to the returned table.
    Applied,
    /// The authenticated origin member identifier was outside the configured range.
    IgnoredInvalidOrigin,
    /// The event did not arrive from the origin's current authenticated stream.
    IgnoredStaleStream,
    /// The event revision was zero or did not exceed the origin high-water revision.
    IgnoredStaleRevision,
    /// The origin has no completed snapshot and cannot yet supply a usable route.
    AwaitingSnapshot,
    /// A different boot epoch invalidated the prior origin routes and now needs a snapshot.
    ReplacedEpoch,
    /// A new selected presence would exceed the explicit capacity.
    CapacityExhausted,
    /// Local supersession could not emit a strictly newer mesh-only GONE.
    MissingLocalRetirementRevision,
}

/// A local action required after deterministic presence supersession.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegionPresenceEffect {
    /// Stop authenticated acknowledgments for the retired local session.
    StopAuthenticatedAcknowledgments(RegionPresenceSession),
    /// Stop forwarding through the retired local session.
    StopForwarding(RegionPresenceSession),
    /// Drop output queued for the retired local session.
    DropQueuedOutput(RegionPresenceSession),
    /// Publish a mesh-only GONE with reason superseded; this is not a node STATUS or WSS close.
    EmitMeshGone(RegionGone),
}

/// The replacement table, ordered local effects, and disposition of one presence event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegionPresenceDecision {
    /// The complete next presence table.
    pub table: RegionPresenceTable,
    /// The local effects required by the decision, in execution order.
    pub effects: Vec<RegionPresenceEffect>,
    /// Whether and how the event changed the table.
    pub disposition: RegionPresenceDisposition,
}

/// Applies one authenticated presence event without I/O, persistence, or hidden mutable state.
///
/// The caller supplies the current table, authenticated origin, durable marks, channel state,
/// capacity, and local retirement revision. The result retains only selected presence entries;
/// durable marks are read-only inputs and are never removed by a presence decision.
#[must_use]
pub fn decide_region_presence(
    table: &RegionPresenceTable,
    event: RegionPresenceEvent,
    input: RegionPresenceInput<'_>,
) -> RegionPresenceDecision {
    if !valid_region_member(input.stream.origin.member_id) {
        return unchanged_presence_decision(table, RegionPresenceDisposition::IgnoredInvalidOrigin);
    }
    let mut next = table.clone();
    refresh_presence_eligibility(&mut next, input.durable_marks, input.channel_states);
    if !input.stream.is_current || event.boot_epoch() != input.stream.origin.boot_epoch {
        return RegionPresenceDecision {
            table: next,
            effects: Vec::new(),
            disposition: RegionPresenceDisposition::IgnoredStaleStream,
        };
    }

    if next.origins.iter().any(|state| {
        state.origin.member_id == input.stream.origin.member_id
            && state.origin.boot_epoch != input.stream.origin.boot_epoch
    }) {
        next.entries
            .retain(|entry| entry.session.origin.member_id != input.stream.origin.member_id);
        next.origins
            .retain(|state| state.origin.member_id != input.stream.origin.member_id);
        next.origins.push(RegionPresenceOriginState {
            origin: input.stream.origin,
            revision_high_water: 0,
            snapshot_required: true,
        });
        return RegionPresenceDecision {
            table: next,
            effects: Vec::new(),
            disposition: RegionPresenceDisposition::ReplacedEpoch,
        };
    }

    let Some(origin_index) = next
        .origins
        .iter()
        .position(|state| state.origin == input.stream.origin)
    else {
        next.origins.push(RegionPresenceOriginState {
            origin: input.stream.origin,
            revision_high_water: 0,
            snapshot_required: true,
        });
        return RegionPresenceDecision {
            table: next,
            effects: Vec::new(),
            disposition: RegionPresenceDisposition::AwaitingSnapshot,
        };
    };
    if next.origins[origin_index].snapshot_required {
        return RegionPresenceDecision {
            table: next,
            effects: Vec::new(),
            disposition: RegionPresenceDisposition::AwaitingSnapshot,
        };
    }
    if event.revision() == 0 || event.revision() <= next.origins[origin_index].revision_high_water {
        return RegionPresenceDecision {
            table: next,
            effects: Vec::new(),
            disposition: RegionPresenceDisposition::IgnoredStaleRevision,
        };
    }

    let refreshed_table = next.clone();
    next.origins[origin_index].revision_high_water = event.revision();

    match event {
        RegionPresenceEvent::Gone(gone) => {
            next.entries
                .retain(|entry| !matches_exact_gone(*entry, input.stream.origin, gone));
            RegionPresenceDecision {
                table: next,
                effects: Vec::new(),
                disposition: RegionPresenceDisposition::Applied,
            }
        }
        RegionPresenceEvent::Present(presence) => {
            let candidate = RegionPresenceRecord {
                session: RegionPresenceSession {
                    origin: input.stream.origin,
                    presence,
                },
                eligible: presence_is_eligible(
                    RegionPresenceSession {
                        origin: input.stream.origin,
                        presence,
                    },
                    &next.origins,
                    input.durable_marks,
                    input.channel_states,
                ),
                grace_cached: false,
            };
            let existing_index = next
                .entries
                .iter()
                .position(|entry| same_presence_owner(entry.session.presence, presence));
            let Some(existing_index) = existing_index else {
                if next.entries.len() >= input.capacity.maximum_entries {
                    next.origins[origin_index].snapshot_required = true;
                    refresh_presence_eligibility(
                        &mut next,
                        input.durable_marks,
                        input.channel_states,
                    );
                    return RegionPresenceDecision {
                        table: next,
                        effects: Vec::new(),
                        disposition: RegionPresenceDisposition::CapacityExhausted,
                    };
                }
                next.entries.push(candidate);
                return RegionPresenceDecision {
                    table: next,
                    effects: Vec::new(),
                    disposition: RegionPresenceDisposition::Applied,
                };
            };

            let existing = next.entries[existing_index];
            match select_presence(existing, candidate, input.durable_marks) {
                PresenceSelection::Candidate => {
                    let effects = if existing.session.origin.member_id == input.local_member_id {
                        let Some(effects) = local_retirement_effects(
                            &mut next,
                            existing.session,
                            input.local_gone_revision,
                        ) else {
                            return unchanged_presence_decision(
                                &refreshed_table,
                                RegionPresenceDisposition::MissingLocalRetirementRevision,
                            );
                        };
                        effects
                    } else {
                        Vec::new()
                    };
                    next.entries[existing_index] = candidate;
                    RegionPresenceDecision {
                        table: next,
                        effects,
                        disposition: RegionPresenceDisposition::Applied,
                    }
                }
                PresenceSelection::Existing => {
                    let effects = if candidate.session.origin.member_id == input.local_member_id {
                        let Some(effects) = local_retirement_effects(
                            &mut next,
                            candidate.session,
                            input.local_gone_revision,
                        ) else {
                            return unchanged_presence_decision(
                                &refreshed_table,
                                RegionPresenceDisposition::MissingLocalRetirementRevision,
                            );
                        };
                        effects
                    } else {
                        Vec::new()
                    };
                    RegionPresenceDecision {
                        table: next,
                        effects,
                        disposition: RegionPresenceDisposition::Applied,
                    }
                }
                PresenceSelection::EqualIneligible => RegionPresenceDecision {
                    table: next,
                    effects: Vec::new(),
                    disposition: RegionPresenceDisposition::Applied,
                },
            }
        }
    }
}

fn unchanged_presence_decision(
    table: &RegionPresenceTable,
    disposition: RegionPresenceDisposition,
) -> RegionPresenceDecision {
    RegionPresenceDecision {
        table: table.clone(),
        effects: Vec::new(),
        disposition,
    }
}

fn valid_region_member(member_id: u8) -> bool {
    (1..=16).contains(&member_id)
}

fn refresh_presence_eligibility(
    table: &mut RegionPresenceTable,
    durable_marks: &[RegionMarks],
    channel_states: &[RegionPresenceChannels],
) {
    for entry in &mut table.entries {
        entry.eligible =
            presence_is_eligible(entry.session, &table.origins, durable_marks, channel_states);
    }
}

fn presence_is_eligible(
    session: RegionPresenceSession,
    origins: &[RegionPresenceOriginState],
    durable_marks: &[RegionMarks],
    channel_states: &[RegionPresenceChannels],
) -> bool {
    origin_is_ready(origins, session.origin)
        && has_live_channel_pair(channel_states, session.origin)
        && marks_are_compatible(durable_marks, session.presence)
}

fn origin_is_ready(origins: &[RegionPresenceOriginState], origin: RegionPresenceOrigin) -> bool {
    let mut matching = None;
    for state in origins {
        if state.origin == origin && matching.replace(!state.snapshot_required).is_some() {
            return false;
        }
    }
    matching.unwrap_or(false)
}

fn has_live_channel_pair(
    channel_states: &[RegionPresenceChannels],
    origin: RegionPresenceOrigin,
) -> bool {
    let mut matching = None;
    for state in channel_states {
        if state.origin == origin
            && matching
                .replace(state.control_up && state.data_up)
                .is_some()
        {
            return false;
        }
    }
    matching.unwrap_or(false)
}

fn marks_are_compatible(durable_marks: &[RegionMarks], presence: RegionPresence) -> bool {
    let mut matching = None;
    for marks in durable_marks {
        if marks.network_id == presence.network_id
            && marks.identity == presence.identity
            && matching.replace(marks).is_some()
        {
            return false;
        }
    }
    let Some(marks) = matching else {
        return false;
    };
    if presence.generation != marks.committed_generation
        || marks
            .revoked_through
            .is_some_and(|revoked| presence.generation <= revoked)
    {
        return false;
    }
    !marks.conflicted && presence.incarnation >= marks.incarnation_high_water
}

fn same_presence_owner(left: RegionPresence, right: RegionPresence) -> bool {
    left.network_id == right.network_id && left.identity == right.identity
}

fn matches_exact_gone(
    entry: RegionPresenceRecord,
    origin: RegionPresenceOrigin,
    gone: RegionGone,
) -> bool {
    let presence = entry.session.presence;
    entry.session.origin == origin
        && presence.slot == gone.slot
        && presence.network_id == gone.network_id
        && presence.identity == gone.identity
        && presence.generation == gone.generation
        && presence.incarnation == gone.incarnation
        && presence.boot_epoch == gone.boot_epoch
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PresenceSelection {
    Candidate,
    Existing,
    EqualIneligible,
}

fn select_presence(
    existing: RegionPresenceRecord,
    candidate: RegionPresenceRecord,
    durable_marks: &[RegionMarks],
) -> PresenceSelection {
    let existing_presence = existing.session.presence;
    let candidate_presence = candidate.session.presence;
    if candidate_presence.generation != existing_presence.generation {
        return if candidate_presence.generation > existing_presence.generation {
            PresenceSelection::Candidate
        } else {
            PresenceSelection::Existing
        };
    }
    if candidate_presence.incarnation != existing_presence.incarnation {
        return if candidate_presence.incarnation > existing_presence.incarnation {
            PresenceSelection::Candidate
        } else {
            PresenceSelection::Existing
        };
    }
    if existing.session.origin == candidate.session.origin {
        return PresenceSelection::Candidate;
    }

    match (
        marks_are_compatible(durable_marks, existing_presence),
        marks_are_compatible(durable_marks, candidate_presence),
    ) {
        (true, true) => {
            if candidate.session.origin.member_id < existing.session.origin.member_id {
                PresenceSelection::Candidate
            } else {
                PresenceSelection::Existing
            }
        }
        (true, false) => PresenceSelection::Existing,
        (false, true) => PresenceSelection::Candidate,
        (false, false) => PresenceSelection::EqualIneligible,
    }
}

fn local_retirement_effects(
    table: &mut RegionPresenceTable,
    session: RegionPresenceSession,
    revision: Option<u64>,
) -> Option<Vec<RegionPresenceEffect>> {
    let revision = revision?;
    if revision == 0 {
        return None;
    }
    let state = table
        .origins
        .iter_mut()
        .find(|state| state.origin == session.origin)?;
    if revision <= state.revision_high_water {
        return None;
    }
    state.revision_high_water = revision;
    let presence = session.presence;
    let gone = RegionGone {
        slot: presence.slot,
        network_id: presence.network_id,
        identity: presence.identity,
        generation: presence.generation,
        incarnation: presence.incarnation,
        reason: RegionGoneReason::Superseded,
        boot_epoch: presence.boot_epoch,
        revision,
    };
    Some(vec![
        RegionPresenceEffect::StopAuthenticatedAcknowledgments(session),
        RegionPresenceEffect::StopForwarding(session),
        RegionPresenceEffect::DropQueuedOutput(session),
        RegionPresenceEffect::EmitMeshGone(gone),
    ])
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

/// The two authenticated boot epochs that scope a local incoming snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegionSnapshotPair {
    /// The remote member and boot epoch that supplied the snapshot.
    pub origin: RegionPresenceOrigin,
    /// The local member process epoch that owns the durable store assertion.
    pub local_boot_epoch: u64,
}

/// An authenticated control-stream identity used only by the local decision API.
///
/// This is not a wire field and a peer cannot assert it. The integration layer supplies it after
/// authenticating the control connection and changes it for every replacement connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegionSnapshotControl {
    /// The authenticated remote stream state.
    pub stream: RegionPresenceStream,
    /// The local member process epoch paired with the remote epoch.
    pub local_boot_epoch: u64,
    /// The opaque nonzero identity of the current authenticated control connection.
    pub control_stream_id: u64,
}

impl RegionSnapshotControl {
    /// Returns the pair identity bound into snapshot persistence evidence.
    #[must_use]
    pub const fn pair(self) -> RegionSnapshotPair {
        RegionSnapshotPair {
            origin: self.stream.origin,
            local_boot_epoch: self.local_boot_epoch,
        }
    }
}

/// An opaque local durable-store lineage.
///
/// This value is supplied by trusted local storage. It is neither transmitted by a peer nor
/// encoded in a region frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegionSnapshotStoreLineage {
    /// The stable local-store lineage identifier.
    pub bytes: [u8; 16],
}

/// The monotonic local durable-store state supplied with a pure decision.
///
/// The decision can compare this evidence but cannot independently prove a false storage claim.
/// Integrations must derive it from their trusted durable store, not from peer input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegionSnapshotDurableStore {
    /// The trusted storage lineage.
    pub lineage: RegionSnapshotStoreLineage,
    /// The local durable revision after the asserted transaction.
    pub durable_revision: u64,
}

/// A deterministic commitment to one exact snapshot chunk and its mark batch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegionSnapshotBatchCommitment {
    /// The SHA-256 commitment bytes.
    pub digest: [u8; 32],
}

/// A deterministic commitment to every accepted chunk in one named snapshot cut.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegionSnapshotCutCommitment {
    /// The SHA-256 commitment bytes.
    pub digest: [u8; 32],
}

/// A locally persisted snapshot mark batch described by a staging effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegionSnapshotDurableBatch {
    /// The authenticated control stream that received the batch.
    pub control: RegionSnapshotControl,
    /// The sender-owned snapshot identifier.
    pub snapshot_id: u64,
    /// The captured presence cut.
    pub base_revision: u64,
    /// The captured mark cut.
    pub marks_revision: u64,
    /// The exact chunk that supplied the batch.
    pub chunk_index: u32,
    /// The contiguous accepted progress represented by this batch.
    pub accepted_through: u32,
    /// The exact batch commitment that the local transaction must acknowledge.
    pub commitment: RegionSnapshotBatchCommitment,
    /// The changed joins that must be durably committed before another mark batch is accepted.
    pub joins: Vec<RegionMarks>,
}

/// Caller-owned evidence that one requested durable snapshot batch committed locally.
///
/// This evidence is an integration boundary, not a peer claim or a wire field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegionSnapshotDurableBatchAcknowledgment {
    /// The authenticated control stream that received the batch.
    pub control: RegionSnapshotControl,
    /// The sender-owned snapshot identifier.
    pub snapshot_id: u64,
    /// The captured presence cut.
    pub base_revision: u64,
    /// The captured mark cut.
    pub marks_revision: u64,
    /// The committed chunk index.
    pub chunk_index: u32,
    /// The contiguous accepted progress proved by this acknowledgment.
    pub accepted_through: u32,
    /// The exact batch commitment returned by the staging effect.
    pub commitment: RegionSnapshotBatchCommitment,
    /// The trusted local store state after the batch transaction.
    pub durable_store: RegionSnapshotDurableStore,
}

/// Caller-owned evidence that the whole named cut remains durable locally.
///
/// The receipt is deliberately not a peer assertion and is never serialized. It records what a
/// trusted local storage implementation proved after all batch transactions drained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegionSnapshotDurableCutReceipt {
    /// The authenticated control stream that received the cut.
    pub control: RegionSnapshotControl,
    /// The sender-owned snapshot identifier.
    pub snapshot_id: u64,
    /// The captured presence cut.
    pub base_revision: u64,
    /// The captured mark cut.
    pub marks_revision: u64,
    /// The final contiguous chunk index included by the receipt.
    pub accepted_through: u32,
    /// The commitment to every accepted chunk in the cut.
    pub cut_commitment: RegionSnapshotCutCommitment,
    /// The final changed mark-batch commitment, or `None` when no write was required.
    pub final_batch_commitment: Option<RegionSnapshotBatchCommitment>,
    /// The trusted local store state that still contains the complete cut.
    pub durable_store: RegionSnapshotDurableStore,
}

/// An exact scoped request to the caller's durable, bounded owner index.
///
/// The caller must atomically test and reserve all listed owners in the request scope. The index
/// is exact and store-backed; probabilistic membership is not sufficient. Its scope ends when
/// the matching stage leaves the staging table, at which point the caller discards the index.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegionSnapshotOwnerValidationRequest {
    /// The authenticated control stream that scopes the index entry.
    pub control: RegionSnapshotControl,
    /// The sender-owned snapshot identifier.
    pub snapshot_id: u64,
    /// The captured presence cut.
    pub base_revision: u64,
    /// The captured mark cut.
    pub marks_revision: u64,
    /// The chunk whose owners are being reserved.
    pub chunk_index: u32,
    /// The contiguous progress that would result from accepting the chunk.
    pub accepted_through: u32,
    /// The exact batch commitment.
    pub commitment: RegionSnapshotBatchCommitment,
    /// The exact scoped owner count before this batch is atomically reserved.
    pub previous_indexed_owner_count: usize,
    /// The deterministic scoped index bytes before this batch is atomically reserved.
    pub previous_indexed_bytes: usize,
    /// The complete current-batch owner list to test and reserve exactly.
    pub owners: Vec<RegionOwner>,
    /// The retained-union owner limit enforced by the store-backed index.
    pub maximum_owners: usize,
    /// The maximum retained index bytes derived from the retained-union limit.
    pub maximum_index_bytes: usize,
}

/// The result returned by an exact store-backed owner-index operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegionSnapshotOwnerIndexOutcome {
    /// Every owner was unique and atomically reserved in the scoped index.
    Unique {
        /// The exact scoped owner count after reservation.
        indexed_owner_count: usize,
        /// The deterministic retained-index bytes after reservation, including allocation accounting.
        indexed_bytes: usize,
    },
    /// At least one owner was already reserved by an earlier accepted batch.
    Duplicate,
    /// The bounded index could not reserve the requested owners.
    CapacityExhausted,
}

/// A typed exact owner-index result supplied to a pure decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegionSnapshotOwnerValidation {
    /// The original request, returned unchanged by the local index.
    pub request: RegionSnapshotOwnerValidationRequest,
    /// The exact index outcome.
    pub outcome: RegionSnapshotOwnerIndexOutcome,
}

/// A mark batch waiting for a trusted local durable acknowledgment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegionSnapshotPendingMarkBatch {
    /// The chunk index that produced these marks.
    pub chunk_index: u32,
    /// The exact batch commitment.
    pub commitment: RegionSnapshotBatchCommitment,
    /// Whether this batch contained a changed join and must advance the local durable revision.
    pub requires_revision_advance: bool,
    /// The full batch retained only until local durable acknowledgment.
    pub marks: Vec<RegionMarks>,
}

/// A bounded chunk awaiting exact cross-batch owner validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegionSnapshotPendingOwnerValidation {
    /// The validated but not yet accepted chunk.
    pub snapshot: RegionSnapshot,
    /// The exact commitment to the pending chunk.
    pub commitment: RegionSnapshotBatchCommitment,
}

/// One bounded incoming snapshot that has not yet replaced published presence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegionSnapshotStage {
    /// The authenticated origin that owns this transfer.
    pub origin: RegionPresenceOrigin,
    /// The exact authenticated control stream that owns the active transfer.
    pub control: RegionSnapshotControl,
    /// The sender-owned identifier shared by every chunk.
    pub snapshot_id: u64,
    /// The origin presence revision captured by the sender.
    pub base_revision: u64,
    /// The durable-mark revision captured by the sender.
    pub marks_revision: u64,
    /// The only index accepted for the next unvalidated or unaccepted chunk.
    pub next_chunk_index: u32,
    /// The greatest contiguous accepted index, if any.
    pub accepted_through: Option<u32>,
    /// Presence records retained until durable completion.
    pub presence_entries: Vec<RegionPresence>,
    /// The exact scoped owner count confirmed by the store-backed index.
    pub indexed_owner_count: usize,
    /// The accounted scoped owner-index bytes confirmed by the local index.
    pub indexed_owner_bytes: usize,
    /// The single bounded mark batch awaiting durable acknowledgment.
    pub pending_mark_batch: Option<RegionSnapshotPendingMarkBatch>,
    /// The single bounded chunk awaiting exact cross-batch owner validation.
    pub pending_owner_validation: Option<RegionSnapshotPendingOwnerValidation>,
    /// The commitment to every accepted chunk in this cut.
    pub cut_commitment: RegionSnapshotCutCommitment,
    /// The final changed batch commitment, retained as metadata after that batch drains.
    pub final_batch_commitment: Option<RegionSnapshotBatchCommitment>,
    /// The final chunk index, present only after `more = false` was accepted.
    pub final_chunk_index: Option<u32>,
    /// The highest trusted local store state observed for this stage.
    pub durable_store: RegionSnapshotDurableStore,
    /// Whether the final chunk has arrived and awaits durable completion.
    pub final_received: bool,
}

impl RegionSnapshotStage {
    /// Returns the retained bytes charged to the incoming mark-staging budget.
    #[must_use]
    pub fn mark_staging_bytes(&self) -> Option<usize> {
        if let Some(batch) = &self.pending_mark_batch {
            return snapshot_mark_staging_bytes(
                batch.marks.capacity(),
                core::mem::size_of::<RegionSnapshotPendingMarkBatch>(),
            );
        }
        if let Some(pending) = &self.pending_owner_validation {
            return snapshot_mark_staging_bytes(
                pending.snapshot.mark_entries.capacity(),
                core::mem::size_of::<RegionSnapshotPendingOwnerValidation>(),
            );
        }
        Some(0)
    }
}

/// The greatest consumed snapshot identifier retained independently from active staging.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegionSnapshotCursor {
    /// The authenticated pair epoch that consumed the identifier.
    pub pair: RegionSnapshotPair,
    /// The greatest consumed snapshot identifier for that pair epoch.
    pub snapshot_id: u64,
}

/// Explicit caller-owned state for all incoming snapshot transfers.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RegionSnapshotStagingTable {
    /// At most one active or final-awaiting stage per authenticated pair.
    pub stages: Vec<RegionSnapshotStage>,
    /// Replay fences that remain after a stage drains, fails, or is interrupted.
    pub cursors: Vec<RegionSnapshotCursor>,
}

/// Bounded staging limits supplied by the caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegionSnapshotStagingCapacity {
    /// The greatest number of actively staged origins; replay fences do not consume this bound.
    pub maximum_origins: usize,
    /// The greatest count of staged presence records per origin.
    pub maximum_entries: usize,
    /// The caller-supplied retained-union limit, capped by the protocol owner bound.
    pub maximum_mark_owners: usize,
    /// The greatest retained single-batch mark bytes per origin, capped at the protocol maximum.
    pub maximum_mark_staging_bytes: usize,
}

/// Inputs for accepting one incoming SNAPSHOT chunk.
pub struct RegionSnapshotStagingInput<'a> {
    /// The current authenticated control stream that supplied the chunk.
    pub control: RegionSnapshotControl,
    /// The currently durable mark union used to prepare this chunk's joins.
    pub durable_marks: &'a [RegionMarks],
    /// The trusted local durable-store state observed for this decision.
    pub durable_store: RegionSnapshotDurableStore,
    /// Explicit bounds for caller-owned staging allocations.
    pub capacity: RegionSnapshotStagingCapacity,
}

/// Inputs for applying an exact scoped owner-index result.
pub struct RegionSnapshotOwnerValidationInput<'a> {
    /// The current authenticated control stream that owns the pending validation.
    pub control: RegionSnapshotControl,
    /// The exact result returned by the trusted local owner index.
    pub validation: &'a RegionSnapshotOwnerValidation,
    /// The current durable mark union used to prepare durable joins.
    pub durable_marks: &'a [RegionMarks],
    /// The trusted local durable-store state observed for this decision.
    pub durable_store: RegionSnapshotDurableStore,
    /// Explicit bounds for the pending durable batch.
    pub capacity: RegionSnapshotStagingCapacity,
}

/// Inputs for accepting a caller-owned durable batch acknowledgment.
pub struct RegionSnapshotDurableBatchAcknowledgmentInput<'a> {
    /// The current authenticated control stream that owns the pending batch.
    pub control: RegionSnapshotControl,
    /// The typed local storage acknowledgment.
    pub acknowledgment: RegionSnapshotDurableBatchAcknowledgment,
    /// The current durable mark union after the acknowledged transaction.
    pub durable_marks: &'a [RegionMarks],
    /// The trusted local durable-store state observed for this decision.
    pub durable_store: RegionSnapshotDurableStore,
}

/// Inputs for finishing a staged snapshot after all durable batches drain.
pub struct RegionSnapshotCompletionInput<'a> {
    /// The current authenticated control stream that owns the completion callback.
    pub control: RegionSnapshotControl,
    /// The snapshot identifier captured with the completion callback.
    pub snapshot_id: u64,
    /// The trusted complete-cut receipt; missing evidence fails closed.
    pub durable_cut_receipt: Option<RegionSnapshotDurableCutReceipt>,
    /// The mark union used to filter staged presence after receipt validation.
    pub durable_marks: &'a [RegionMarks],
    /// The trusted local durable-store state observed for this decision.
    pub durable_store: RegionSnapshotDurableStore,
    /// The current paired-channel state used for route eligibility.
    pub channel_states: &'a [RegionPresenceChannels],
    /// The published-presence capacity available to the replacement decision.
    pub capacity: RegionPresenceCapacity,
}

/// A local action requested by a snapshot decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegionSnapshotEffect {
    /// Atomically validate and reserve this batch's owners in the scoped exact local index.
    ValidateSnapshotOwners(RegionSnapshotOwnerValidationRequest),
    /// Durably apply the changed joins in this exact batch before accepting another mark batch.
    PersistDurableBatch(RegionSnapshotDurableBatch),
}

/// The documented outcome of one snapshot staging or completion decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegionSnapshotDisposition {
    /// A fresh control stream discarded any partial stage for its origin.
    ControlStarted,
    /// A non-final chunk was retained without publishing presence.
    Staged,
    /// The final chunk is retained and must wait for durable mark persistence.
    AwaitingDurableMarks,
    /// A mark-bearing chunk was refused until the prior batch becomes durable.
    DurableMarkBatchPending,
    /// A bounded mark chunk awaits exact cross-batch owner validation.
    AwaitingOwnerValidation,
    /// The final stage passed durable-floor validation and replaced one origin's presence.
    Completed,
    /// No final stage is available for completion.
    MissingSnapshot,
    /// A stage is still awaiting another chunk with `more = false`.
    IncompleteSnapshot,
    /// The authenticated member identifier was outside the configured range.
    IgnoredInvalidOrigin,
    /// The chunk did not arrive from the current authenticated stream.
    IgnoredStaleStream,
    /// A durable completion callback named a different active snapshot.
    IgnoredStaleSnapshotCompletion,
    /// Owner-index evidence did not match the exact pending batch.
    InvalidOwnerValidation,
    /// Durable batch evidence was missing, mismatched, stale, or rolled back.
    InvalidDurableBatchAcknowledgment,
    /// A local durable-store lineage or revision moved backwards.
    InvalidDurableStore,
    /// The final durable-cut receipt was missing, mismatched, stale, or incomplete.
    InvalidDurableCutReceipt,
    /// A sender supplied the reserved zero snapshot identifier.
    InvalidSnapshotId,
    /// The first chunk did not start at index zero.
    InvalidInitialChunkIndex,
    /// A prior chunk index was repeated.
    DuplicateChunkIndex,
    /// A chunk index skipped one or more required chunks.
    SkippedChunkIndex,
    /// Continuing the snapshot would wrap the u32 chunk index.
    ChunkIndexExhausted,
    /// A later chunk changed the snapshot identifier while a stage was active.
    UnexpectedSnapshotId,
    /// A later chunk changed either captured revision cut.
    ChangedSnapshotCuts,
    /// A previously accepted snapshot identifier was used again.
    ChunkAfterCompletion,
    /// A snapshot identifier preceded a completed identifier for the epoch.
    StaleSnapshotId,
    /// A chunk exceeded the per-frame nested-record bound.
    ChunkEntryLimit,
    /// A full owner occurred twice in staged presence records.
    DuplicatePresenceOwner,
    /// A full owner occurred twice in staged mark records.
    DuplicateMarkOwner,
    /// A nested presence record named a different boot epoch.
    InvalidPresenceEpoch,
    /// A nested presence revision was zero or exceeded the captured cut.
    InvalidPresenceRevision,
    /// A nested presence slot did not match its full owner.
    InvalidPresenceSlot,
    /// The captured presence cut preceded the accepted origin revision.
    CutRegression,
    /// A mark union could not be uniquely joined from the supplied durable state.
    InvalidDurableMarks,
    /// The caller had not yet persisted every requested durable mark join.
    DurableMarksNotPersisted,
    /// A staged presence record did not match the resulting durable floors.
    IncompatiblePresence,
    /// An explicit staging or published-presence capacity was exhausted.
    CapacityExhausted,
    /// A channel interruption discarded partial staging and invalidated synchronization.
    Interrupted,
}

/// The replacement tables, durable actions, and disposition for a snapshot decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegionSnapshotDecision {
    /// The next published presence table.
    pub table: RegionPresenceTable,
    /// The next caller-owned snapshot staging state.
    pub staging: RegionSnapshotStagingTable,
    /// Durable mark joins requested by this accepted chunk; never a route or acknowledgment.
    pub effects: Vec<RegionSnapshotEffect>,
    /// The one outcome selected for the input.
    pub disposition: RegionSnapshotDisposition,
}

/// Starts a fresh authenticated control stream and discards only its active partial stage.
#[must_use]
pub fn begin_region_snapshot_control(
    table: &RegionPresenceTable,
    staging: &RegionSnapshotStagingTable,
    control: RegionSnapshotControl,
) -> RegionSnapshotDecision {
    if validate_snapshot_control(control).is_none() {
        return unchanged_snapshot_decision(table, staging, snapshot_control_failure(control));
    }

    let pair = control.pair();
    let mut next_table = table.clone();
    let mut next_staging = staging.clone();
    clear_other_snapshot_epochs(&mut next_staging, pair);
    next_staging
        .stages
        .retain(|stage| stage.control.pair() != pair);
    require_snapshot(&mut next_table, pair.origin);
    RegionSnapshotDecision {
        table: next_table,
        staging: next_staging,
        effects: Vec::new(),
        disposition: RegionSnapshotDisposition::ControlStarted,
    }
}

/// Discards the current control stream's partial snapshot while retaining caller-owned marks.
#[must_use]
pub fn interrupt_region_snapshot(
    table: &RegionPresenceTable,
    staging: &RegionSnapshotStagingTable,
    control: RegionSnapshotControl,
) -> RegionSnapshotDecision {
    if validate_snapshot_control(control).is_none() {
        return unchanged_snapshot_decision(table, staging, snapshot_control_failure(control));
    }
    let pair = control.pair();
    if staging
        .stages
        .iter()
        .any(|stage| stage.control.pair() == pair && stage.control != control)
    {
        return unchanged_snapshot_decision(
            table,
            staging,
            RegionSnapshotDisposition::IgnoredStaleStream,
        );
    }
    invalidate_snapshot(table, staging, pair, RegionSnapshotDisposition::Interrupted)
}

/// Stages one incoming SNAPSHOT chunk without publishing any staged presence.
#[must_use]
pub fn stage_region_snapshot(
    table: &RegionPresenceTable,
    staging: &RegionSnapshotStagingTable,
    snapshot: RegionSnapshot,
    input: RegionSnapshotStagingInput<'_>,
) -> RegionSnapshotDecision {
    let control = input.control;
    if validate_snapshot_control(control).is_none() {
        return unchanged_snapshot_decision(table, staging, snapshot_control_failure(control));
    }

    let pair = control.pair();
    let mut next_table = table.clone();
    let mut next_staging = staging.clone();
    clear_other_snapshot_epochs(&mut next_staging, pair);
    require_snapshot(&mut next_table, pair.origin);

    if snapshot.snapshot_id == 0 {
        return invalidate_snapshot(
            &next_table,
            &next_staging,
            pair,
            RegionSnapshotDisposition::InvalidSnapshotId,
        );
    }
    if snapshot
        .presence_entries
        .len()
        .checked_add(snapshot.mark_entries.len())
        .is_none_or(|count| count > MAX_REGION_SNAPSHOT_ENTRIES)
    {
        return invalidate_snapshot(
            &next_table,
            &next_staging,
            pair,
            RegionSnapshotDisposition::ChunkEntryLimit,
        );
    }

    let active_stage = next_staging
        .stages
        .iter()
        .position(|stage| stage.control.pair() == pair);
    let stage_index = match active_stage {
        Some(index) => {
            let Some(stage) = next_staging.stages.get(index) else {
                return invalidate_snapshot(
                    &next_table,
                    &next_staging,
                    pair,
                    RegionSnapshotDisposition::Interrupted,
                );
            };
            if stage.control != control {
                return unchanged_snapshot_decision(
                    table,
                    staging,
                    RegionSnapshotDisposition::IgnoredStaleStream,
                );
            }
            if stage.snapshot_id != snapshot.snapshot_id {
                if snapshot.snapshot_id > stage.snapshot_id
                    && !record_snapshot_cursor(&mut next_staging, pair, snapshot.snapshot_id)
                {
                    return invalidate_snapshot(
                        &next_table,
                        &next_staging,
                        pair,
                        RegionSnapshotDisposition::CapacityExhausted,
                    );
                }
                return invalidate_snapshot(
                    &next_table,
                    &next_staging,
                    pair,
                    RegionSnapshotDisposition::UnexpectedSnapshotId,
                );
            }
            if stage.final_received {
                return invalidate_snapshot(
                    &next_table,
                    &next_staging,
                    pair,
                    RegionSnapshotDisposition::ChunkAfterCompletion,
                );
            }
            if stage.base_revision != snapshot.base_revision
                || stage.marks_revision != snapshot.marks_revision
            {
                return invalidate_snapshot(
                    &next_table,
                    &next_staging,
                    pair,
                    RegionSnapshotDisposition::ChangedSnapshotCuts,
                );
            }
            if snapshot.chunk_index < stage.next_chunk_index {
                return invalidate_snapshot(
                    &next_table,
                    &next_staging,
                    pair,
                    RegionSnapshotDisposition::DuplicateChunkIndex,
                );
            }
            if snapshot.chunk_index > stage.next_chunk_index {
                return invalidate_snapshot(
                    &next_table,
                    &next_staging,
                    pair,
                    RegionSnapshotDisposition::SkippedChunkIndex,
                );
            }
            index
        }
        None => {
            if let Some(cursor) = snapshot_cursor(&next_staging, pair) {
                if snapshot.snapshot_id == cursor.snapshot_id {
                    return invalidate_snapshot(
                        &next_table,
                        &next_staging,
                        pair,
                        RegionSnapshotDisposition::ChunkAfterCompletion,
                    );
                }
                if snapshot.snapshot_id < cursor.snapshot_id {
                    return invalidate_snapshot(
                        &next_table,
                        &next_staging,
                        pair,
                        RegionSnapshotDisposition::StaleSnapshotId,
                    );
                }
            }
            if !record_snapshot_cursor(&mut next_staging, pair, snapshot.snapshot_id) {
                return invalidate_snapshot(
                    &next_table,
                    &next_staging,
                    pair,
                    RegionSnapshotDisposition::CapacityExhausted,
                );
            }
            if snapshot.chunk_index != 0 {
                return invalidate_snapshot(
                    &next_table,
                    &next_staging,
                    pair,
                    RegionSnapshotDisposition::InvalidInitialChunkIndex,
                );
            }
            if next_staging.stages.len() >= input.capacity.maximum_origins {
                return invalidate_snapshot(
                    &next_table,
                    &next_staging,
                    pair,
                    RegionSnapshotDisposition::CapacityExhausted,
                );
            }
            if next_staging.stages.try_reserve_exact(1).is_err() {
                return invalidate_snapshot(
                    &next_table,
                    &next_staging,
                    pair,
                    RegionSnapshotDisposition::CapacityExhausted,
                );
            }
            next_staging.stages.push(RegionSnapshotStage {
                origin: pair.origin,
                control,
                snapshot_id: snapshot.snapshot_id,
                base_revision: snapshot.base_revision,
                marks_revision: snapshot.marks_revision,
                next_chunk_index: 0,
                accepted_through: None,
                presence_entries: Vec::new(),
                indexed_owner_count: 0,
                indexed_owner_bytes: 0,
                pending_mark_batch: None,
                pending_owner_validation: None,
                cut_commitment: initial_snapshot_cut_commitment(control, &snapshot),
                final_batch_commitment: None,
                final_chunk_index: None,
                durable_store: input.durable_store,
                final_received: false,
            });
            next_staging.stages.len() - 1
        }
    };

    let Some(stage) = next_staging.stages.get(stage_index) else {
        return invalidate_snapshot(
            &next_table,
            &next_staging,
            pair,
            RegionSnapshotDisposition::Interrupted,
        );
    };
    if !durable_store_advances(stage.durable_store, input.durable_store) {
        return invalidate_snapshot(
            &next_table,
            &next_staging,
            pair,
            RegionSnapshotDisposition::InvalidDurableStore,
        );
    }
    if let Err(disposition) = validate_snapshot_chunk(&next_table, stage, &snapshot, input.capacity)
    {
        return invalidate_snapshot(&next_table, &next_staging, pair, disposition);
    }
    if let Some(pending) = &stage.pending_owner_validation {
        if pending.snapshot != snapshot {
            return invalidate_snapshot(
                &next_table,
                &next_staging,
                pair,
                RegionSnapshotDisposition::InvalidOwnerValidation,
            );
        }
        return RegionSnapshotDecision {
            table: next_table,
            staging: next_staging,
            effects: Vec::new(),
            disposition: RegionSnapshotDisposition::AwaitingOwnerValidation,
        };
    }
    if stage.pending_mark_batch.is_some() {
        return RegionSnapshotDecision {
            table: next_table,
            staging: next_staging,
            effects: Vec::new(),
            disposition: RegionSnapshotDisposition::DurableMarkBatchPending,
        };
    }

    if snapshot.mark_entries.is_empty() {
        let result = {
            let Some(stage) = next_staging.stages.get_mut(stage_index) else {
                return invalidate_snapshot(
                    &next_table,
                    &next_staging,
                    pair,
                    RegionSnapshotDisposition::Interrupted,
                );
            };
            accept_snapshot_chunk(
                stage,
                snapshot,
                input.durable_marks,
                input.durable_store,
                input.capacity,
            )
        };
        return match result {
            Ok((effects, disposition)) => RegionSnapshotDecision {
                table: next_table,
                staging: next_staging,
                effects,
                disposition,
            },
            Err(disposition) => invalidate_snapshot(&next_table, &next_staging, pair, disposition),
        };
    }

    let commitment = snapshot_batch_commitment(control, &snapshot);
    let Some(request) = snapshot_owner_validation_request(
        control,
        &snapshot,
        commitment,
        stage.indexed_owner_count,
        stage.indexed_owner_bytes,
        input.capacity,
    ) else {
        return invalidate_snapshot(
            &next_table,
            &next_staging,
            pair,
            RegionSnapshotDisposition::CapacityExhausted,
        );
    };
    let Some(pending_snapshot) = try_clone_snapshot(&snapshot) else {
        return invalidate_snapshot(
            &next_table,
            &next_staging,
            pair,
            RegionSnapshotDisposition::CapacityExhausted,
        );
    };
    let Some(stage) = next_staging.stages.get_mut(stage_index) else {
        return invalidate_snapshot(
            &next_table,
            &next_staging,
            pair,
            RegionSnapshotDisposition::Interrupted,
        );
    };
    stage.pending_owner_validation = Some(RegionSnapshotPendingOwnerValidation {
        snapshot: pending_snapshot,
        commitment,
    });
    RegionSnapshotDecision {
        table: next_table,
        staging: next_staging,
        effects: vec![RegionSnapshotEffect::ValidateSnapshotOwners(request)],
        disposition: RegionSnapshotDisposition::AwaitingOwnerValidation,
    }
}

/// Applies one exact result from the scoped local snapshot-owner index.
#[must_use]
pub fn validate_region_snapshot_owners(
    table: &RegionPresenceTable,
    staging: &RegionSnapshotStagingTable,
    input: RegionSnapshotOwnerValidationInput<'_>,
) -> RegionSnapshotDecision {
    let control = input.control;
    if validate_snapshot_control(control).is_none() {
        return unchanged_snapshot_decision(table, staging, snapshot_control_failure(control));
    }
    let pair = control.pair();
    let Some(stage_index) = staging
        .stages
        .iter()
        .position(|stage| stage.control.pair() == pair)
    else {
        return unchanged_snapshot_decision(
            table,
            staging,
            RegionSnapshotDisposition::MissingSnapshot,
        );
    };
    let Some(stage) = staging.stages.get(stage_index) else {
        return unchanged_snapshot_decision(
            table,
            staging,
            RegionSnapshotDisposition::MissingSnapshot,
        );
    };
    if stage.control != control {
        return unchanged_snapshot_decision(
            table,
            staging,
            RegionSnapshotDisposition::IgnoredStaleSnapshotCompletion,
        );
    }
    if !durable_store_advances(stage.durable_store, input.durable_store) {
        return invalidate_snapshot(
            table,
            staging,
            pair,
            RegionSnapshotDisposition::InvalidDurableStore,
        );
    }
    let Some(pending) = stage.pending_owner_validation.as_ref() else {
        return unchanged_snapshot_decision(
            table,
            staging,
            RegionSnapshotDisposition::IgnoredStaleSnapshotCompletion,
        );
    };
    let Some(expected) = snapshot_owner_validation_request(
        control,
        &pending.snapshot,
        pending.commitment,
        stage.indexed_owner_count,
        stage.indexed_owner_bytes,
        input.capacity,
    ) else {
        return invalidate_snapshot(
            table,
            staging,
            pair,
            RegionSnapshotDisposition::CapacityExhausted,
        );
    };
    if input.validation.request != expected {
        return invalidate_snapshot(
            table,
            staging,
            pair,
            RegionSnapshotDisposition::InvalidOwnerValidation,
        );
    }
    let (indexed_owner_count, indexed_bytes) = match input.validation.outcome {
        RegionSnapshotOwnerIndexOutcome::Duplicate => {
            return invalidate_snapshot(
                table,
                staging,
                pair,
                RegionSnapshotDisposition::DuplicateMarkOwner,
            );
        }
        RegionSnapshotOwnerIndexOutcome::CapacityExhausted => {
            return invalidate_snapshot(
                table,
                staging,
                pair,
                RegionSnapshotDisposition::CapacityExhausted,
            );
        }
        RegionSnapshotOwnerIndexOutcome::Unique {
            indexed_owner_count,
            indexed_bytes,
        } => {
            let Some(expected_owner_count) = expected
                .previous_indexed_owner_count
                .checked_add(expected.owners.len())
            else {
                return invalidate_snapshot(
                    table,
                    staging,
                    pair,
                    RegionSnapshotDisposition::CapacityExhausted,
                );
            };
            let Some(expected_indexed_bytes) = snapshot_owner_index_bytes(expected_owner_count)
            else {
                return invalidate_snapshot(
                    table,
                    staging,
                    pair,
                    RegionSnapshotDisposition::CapacityExhausted,
                );
            };
            if indexed_owner_count != expected_owner_count
                || indexed_owner_count > expected.maximum_owners
                || indexed_bytes != expected_indexed_bytes
                || indexed_bytes > expected.maximum_index_bytes
            {
                return invalidate_snapshot(
                    table,
                    staging,
                    pair,
                    RegionSnapshotDisposition::InvalidOwnerValidation,
                );
            }
            (indexed_owner_count, indexed_bytes)
        }
    };

    let next_table = table.clone();
    let mut next_staging = staging.clone();
    let Some(stage) = next_staging.stages.get_mut(stage_index) else {
        return invalidate_snapshot(table, staging, pair, RegionSnapshotDisposition::Interrupted);
    };
    let Some(pending) = stage.pending_owner_validation.take() else {
        return invalidate_snapshot(
            table,
            staging,
            pair,
            RegionSnapshotDisposition::InvalidOwnerValidation,
        );
    };
    stage.indexed_owner_count = indexed_owner_count;
    stage.indexed_owner_bytes = indexed_bytes;
    match accept_snapshot_chunk(
        stage,
        pending.snapshot,
        input.durable_marks,
        input.durable_store,
        input.capacity,
    ) {
        Ok((effects, disposition)) => RegionSnapshotDecision {
            table: next_table,
            staging: next_staging,
            effects,
            disposition,
        },
        Err(disposition) => invalidate_snapshot(table, staging, pair, disposition),
    }
}

/// Accepts a trusted local durable acknowledgment for the one pending mark batch.
#[must_use]
pub fn acknowledge_region_snapshot_durable_batch(
    table: &RegionPresenceTable,
    staging: &RegionSnapshotStagingTable,
    input: RegionSnapshotDurableBatchAcknowledgmentInput<'_>,
) -> RegionSnapshotDecision {
    let control = input.control;
    if validate_snapshot_control(control).is_none() {
        return unchanged_snapshot_decision(table, staging, snapshot_control_failure(control));
    }
    let pair = control.pair();
    let Some(stage_index) = staging
        .stages
        .iter()
        .position(|stage| stage.control.pair() == pair)
    else {
        return unchanged_snapshot_decision(
            table,
            staging,
            RegionSnapshotDisposition::MissingSnapshot,
        );
    };
    let Some(stage) = staging.stages.get(stage_index) else {
        return unchanged_snapshot_decision(
            table,
            staging,
            RegionSnapshotDisposition::MissingSnapshot,
        );
    };
    if stage.control != control {
        return unchanged_snapshot_decision(
            table,
            staging,
            RegionSnapshotDisposition::IgnoredStaleSnapshotCompletion,
        );
    }
    let Some(batch) = stage.pending_mark_batch.as_ref() else {
        return unchanged_snapshot_decision(
            table,
            staging,
            RegionSnapshotDisposition::IgnoredStaleSnapshotCompletion,
        );
    };
    let acknowledgment = input.acknowledgment;
    if acknowledgment.control != control
        || acknowledgment.snapshot_id != stage.snapshot_id
        || acknowledgment.base_revision != stage.base_revision
        || acknowledgment.marks_revision != stage.marks_revision
        || acknowledgment.chunk_index != batch.chunk_index
        || acknowledgment.accepted_through != batch.chunk_index
        || acknowledgment.commitment != batch.commitment
        || (batch.requires_revision_advance
            && acknowledgment.durable_store.durable_revision
                == stage.durable_store.durable_revision)
        || !durable_store_advances(stage.durable_store, acknowledgment.durable_store)
        || acknowledgment.durable_store.lineage != input.durable_store.lineage
        || acknowledgment.durable_store.durable_revision > input.durable_store.durable_revision
    {
        return invalidate_snapshot(
            table,
            staging,
            pair,
            RegionSnapshotDisposition::InvalidDurableBatchAcknowledgment,
        );
    }
    if !snapshot_marks_are_durable(&batch.marks, input.durable_marks) {
        return invalidate_snapshot(
            table,
            staging,
            pair,
            RegionSnapshotDisposition::DurableMarksNotPersisted,
        );
    }

    let next_table = table.clone();
    let mut next_staging = staging.clone();
    let disposition = {
        let Some(stage) = next_staging.stages.get_mut(stage_index) else {
            return invalidate_snapshot(
                table,
                staging,
                pair,
                RegionSnapshotDisposition::Interrupted,
            );
        };
        stage.pending_mark_batch = None;
        stage.durable_store = input.durable_store;
        if stage.final_received {
            RegionSnapshotDisposition::AwaitingDurableMarks
        } else {
            RegionSnapshotDisposition::Staged
        }
    };
    RegionSnapshotDecision {
        table: next_table,
        staging: next_staging,
        effects: Vec::new(),
        disposition,
    }
}

/// Completes a final stage only after a trusted local receipt proves the complete cut remains durable.
#[must_use]
pub fn complete_region_snapshot(
    table: &RegionPresenceTable,
    staging: &RegionSnapshotStagingTable,
    input: RegionSnapshotCompletionInput<'_>,
) -> RegionSnapshotDecision {
    let control = input.control;
    if validate_snapshot_control(control).is_none() {
        return unchanged_snapshot_decision(table, staging, snapshot_control_failure(control));
    }
    let pair = control.pair();
    let Some(stage_index) = staging
        .stages
        .iter()
        .position(|stage| stage.control.pair() == pair)
    else {
        return unchanged_snapshot_decision(
            table,
            staging,
            RegionSnapshotDisposition::MissingSnapshot,
        );
    };
    let Some(stage) = staging.stages.get(stage_index) else {
        return unchanged_snapshot_decision(
            table,
            staging,
            RegionSnapshotDisposition::MissingSnapshot,
        );
    };
    if stage.control != control || stage.snapshot_id != input.snapshot_id {
        return unchanged_snapshot_decision(
            table,
            staging,
            RegionSnapshotDisposition::IgnoredStaleSnapshotCompletion,
        );
    }
    if !stage.final_received {
        return unchanged_snapshot_decision(
            table,
            staging,
            RegionSnapshotDisposition::IncompleteSnapshot,
        );
    }
    if stage.pending_owner_validation.is_some() || stage.pending_mark_batch.is_some() {
        return invalidate_snapshot(
            table,
            staging,
            pair,
            RegionSnapshotDisposition::DurableMarksNotPersisted,
        );
    }
    if !durable_store_advances(stage.durable_store, input.durable_store) {
        return invalidate_snapshot(
            table,
            staging,
            pair,
            RegionSnapshotDisposition::InvalidDurableCutReceipt,
        );
    }
    let Some(final_chunk_index) = stage.final_chunk_index else {
        return invalidate_snapshot(
            table,
            staging,
            pair,
            RegionSnapshotDisposition::InvalidDurableCutReceipt,
        );
    };
    let Some(receipt) = input.durable_cut_receipt else {
        return invalidate_snapshot(
            table,
            staging,
            pair,
            RegionSnapshotDisposition::InvalidDurableCutReceipt,
        );
    };
    if receipt.control != control
        || receipt.snapshot_id != stage.snapshot_id
        || receipt.base_revision != stage.base_revision
        || receipt.marks_revision != stage.marks_revision
        || receipt.accepted_through != final_chunk_index
        || receipt.cut_commitment != stage.cut_commitment
        || receipt.final_batch_commitment != stage.final_batch_commitment
        || receipt.durable_store != input.durable_store
        || !durable_store_advances(stage.durable_store, receipt.durable_store)
    {
        return invalidate_snapshot(
            table,
            staging,
            pair,
            RegionSnapshotDisposition::InvalidDurableCutReceipt,
        );
    }
    if table.origins.iter().any(|state| {
        state.origin.member_id == pair.origin.member_id
            && state.origin.boot_epoch != pair.origin.boot_epoch
    }) {
        return unchanged_snapshot_decision(
            table,
            staging,
            RegionSnapshotDisposition::IgnoredStaleStream,
        );
    }
    if stage
        .presence_entries
        .iter()
        .any(|presence| !marks_are_compatible(input.durable_marks, *presence))
    {
        return invalidate_snapshot(
            table,
            staging,
            pair,
            RegionSnapshotDisposition::IncompatiblePresence,
        );
    }

    let mut next_table = table.clone();
    require_snapshot(&mut next_table, pair.origin);
    let Some(state) = next_table
        .origins
        .iter_mut()
        .find(|state| state.origin == pair.origin)
    else {
        return invalidate_snapshot(table, staging, pair, RegionSnapshotDisposition::Interrupted);
    };
    if stage.base_revision < state.revision_high_water {
        return invalidate_snapshot(
            table,
            staging,
            pair,
            RegionSnapshotDisposition::CutRegression,
        );
    }
    state.revision_high_water = stage.base_revision;
    state.snapshot_required = false;
    next_table
        .entries
        .retain(|entry| entry.session.origin != pair.origin);
    for presence in &stage.presence_entries {
        let candidate = RegionPresenceRecord {
            session: RegionPresenceSession {
                origin: pair.origin,
                presence: *presence,
            },
            eligible: false,
            grace_cached: false,
        };
        let Some(existing_index) = next_table
            .entries
            .iter()
            .position(|entry| same_presence_owner(entry.session.presence, *presence))
        else {
            if next_table.entries.len() >= input.capacity.maximum_entries {
                return invalidate_snapshot(
                    table,
                    staging,
                    pair,
                    RegionSnapshotDisposition::CapacityExhausted,
                );
            }
            if next_table.entries.try_reserve_exact(1).is_err() {
                return invalidate_snapshot(
                    table,
                    staging,
                    pair,
                    RegionSnapshotDisposition::CapacityExhausted,
                );
            }
            next_table.entries.push(candidate);
            continue;
        };
        if matches!(
            select_presence(
                next_table.entries[existing_index],
                candidate,
                input.durable_marks
            ),
            PresenceSelection::Candidate
        ) {
            next_table.entries[existing_index] = candidate;
        }
    }
    refresh_presence_eligibility(&mut next_table, input.durable_marks, input.channel_states);

    let mut next_staging = staging.clone();
    next_staging.stages.remove(stage_index);
    RegionSnapshotDecision {
        table: next_table,
        staging: next_staging,
        effects: Vec::new(),
        disposition: RegionSnapshotDisposition::Completed,
    }
}

fn validate_snapshot_control(control: RegionSnapshotControl) -> Option<()> {
    if valid_region_member(control.stream.origin.member_id)
        && control.stream.is_current
        && control.control_stream_id != 0
    {
        Some(())
    } else {
        None
    }
}

fn snapshot_control_failure(control: RegionSnapshotControl) -> RegionSnapshotDisposition {
    if !valid_region_member(control.stream.origin.member_id) {
        RegionSnapshotDisposition::IgnoredInvalidOrigin
    } else {
        RegionSnapshotDisposition::IgnoredStaleStream
    }
}

fn unchanged_snapshot_decision(
    table: &RegionPresenceTable,
    staging: &RegionSnapshotStagingTable,
    disposition: RegionSnapshotDisposition,
) -> RegionSnapshotDecision {
    RegionSnapshotDecision {
        table: table.clone(),
        staging: staging.clone(),
        effects: Vec::new(),
        disposition,
    }
}

fn invalidate_snapshot(
    table: &RegionPresenceTable,
    staging: &RegionSnapshotStagingTable,
    pair: RegionSnapshotPair,
    disposition: RegionSnapshotDisposition,
) -> RegionSnapshotDecision {
    let mut next_table = table.clone();
    let mut next_staging = staging.clone();
    next_staging
        .stages
        .retain(|stage| stage.control.pair() != pair);
    if next_table.origins.iter().any(|state| {
        state.origin.member_id == pair.origin.member_id
            && state.origin.boot_epoch != pair.origin.boot_epoch
    }) {
        return RegionSnapshotDecision {
            table: next_table,
            staging: next_staging,
            effects: Vec::new(),
            disposition,
        };
    }
    require_snapshot(&mut next_table, pair.origin);
    RegionSnapshotDecision {
        table: next_table,
        staging: next_staging,
        effects: Vec::new(),
        disposition,
    }
}

fn clear_other_snapshot_epochs(staging: &mut RegionSnapshotStagingTable, pair: RegionSnapshotPair) {
    staging.stages.retain(|stage| {
        stage.origin.member_id != pair.origin.member_id || stage.control.pair() == pair
    });
    staging.cursors.retain(|cursor| {
        cursor.pair.origin.member_id != pair.origin.member_id || cursor.pair == pair
    });
}

fn snapshot_cursor(
    staging: &RegionSnapshotStagingTable,
    pair: RegionSnapshotPair,
) -> Option<RegionSnapshotCursor> {
    staging
        .cursors
        .iter()
        .copied()
        .find(|cursor| cursor.pair == pair)
}

fn record_snapshot_cursor(
    staging: &mut RegionSnapshotStagingTable,
    pair: RegionSnapshotPair,
    snapshot_id: u64,
) -> bool {
    if let Some(cursor) = staging
        .cursors
        .iter_mut()
        .find(|cursor| cursor.pair == pair)
    {
        cursor.snapshot_id = cursor.snapshot_id.max(snapshot_id);
        return true;
    }
    if staging.cursors.try_reserve_exact(1).is_err() {
        return false;
    }
    staging
        .cursors
        .push(RegionSnapshotCursor { pair, snapshot_id });
    true
}

fn require_snapshot(table: &mut RegionPresenceTable, origin: RegionPresenceOrigin) {
    let replaced_epoch = table.origins.iter().any(|state| {
        state.origin.member_id == origin.member_id && state.origin.boot_epoch != origin.boot_epoch
    });
    if replaced_epoch {
        table
            .entries
            .retain(|entry| entry.session.origin.member_id != origin.member_id);
        table
            .origins
            .retain(|state| state.origin.member_id != origin.member_id);
    }
    if let Some(state) = table
        .origins
        .iter_mut()
        .find(|state| state.origin == origin)
    {
        state.snapshot_required = true;
    } else {
        table.origins.push(RegionPresenceOriginState {
            origin,
            revision_high_water: 0,
            snapshot_required: true,
        });
    }
    for entry in &mut table.entries {
        if entry.session.origin == origin {
            entry.eligible = false;
        }
    }
}

fn durable_store_advances(
    previous: RegionSnapshotDurableStore,
    current: RegionSnapshotDurableStore,
) -> bool {
    previous.lineage == current.lineage && previous.durable_revision <= current.durable_revision
}

fn same_region_owner(
    left_network: NetworkId,
    left_identity: Identity,
    right_network: NetworkId,
    right_identity: Identity,
) -> bool {
    left_network == right_network && left_identity == right_identity
}

fn snapshot_mark_staging_bytes(
    mark_entry_capacity: usize,
    retained_overhead: usize,
) -> Option<usize> {
    let mark_entry_bytes = mark_entry_capacity.checked_mul(core::mem::size_of::<RegionMarks>())?;
    mark_entry_bytes.checked_add(retained_overhead)
}

fn maximum_snapshot_mark_staging_bytes(capacity: RegionSnapshotStagingCapacity) -> usize {
    capacity
        .maximum_mark_staging_bytes
        .min(MAX_REGION_SNAPSHOT_MARK_STAGING_BYTES)
}

fn maximum_snapshot_mark_owners(capacity: RegionSnapshotStagingCapacity) -> usize {
    capacity
        .maximum_mark_owners
        .min(MAX_REGION_RETAINED_MARK_OWNERS)
}

fn snapshot_owner_index_bytes(owner_count: usize) -> Option<usize> {
    if owner_count == 0 {
        return Some(0);
    }
    let per_owner =
        core::mem::size_of::<RegionOwner>().checked_add(core::mem::size_of::<usize>())?;
    owner_count
        .checked_mul(per_owner)?
        .checked_add(core::mem::size_of::<Vec<RegionOwner>>())
}

fn maximum_snapshot_owner_index_bytes(maximum_owners: usize) -> Option<usize> {
    snapshot_owner_index_bytes(maximum_owners)
}

fn validate_snapshot_chunk(
    table: &RegionPresenceTable,
    stage: &RegionSnapshotStage,
    snapshot: &RegionSnapshot,
    capacity: RegionSnapshotStagingCapacity,
) -> Result<(), RegionSnapshotDisposition> {
    let Some(origin_state) = table
        .origins
        .iter()
        .find(|state| state.origin == stage.origin)
    else {
        return Err(RegionSnapshotDisposition::Interrupted);
    };
    if snapshot.base_revision < origin_state.revision_high_water {
        return Err(RegionSnapshotDisposition::CutRegression);
    }
    let Some(staged_presence_count) = stage
        .presence_entries
        .len()
        .checked_add(snapshot.presence_entries.len())
    else {
        return Err(RegionSnapshotDisposition::CapacityExhausted);
    };
    if staged_presence_count > capacity.maximum_entries {
        return Err(RegionSnapshotDisposition::CapacityExhausted);
    }
    if snapshot.mark_entries.len() > maximum_snapshot_mark_owners(capacity) {
        return Err(RegionSnapshotDisposition::CapacityExhausted);
    }
    if !snapshot.mark_entries.is_empty() {
        let Some(mark_staging_bytes) = snapshot_mark_staging_bytes(
            snapshot.mark_entries.len(),
            core::mem::size_of::<RegionSnapshotPendingOwnerValidation>(),
        ) else {
            return Err(RegionSnapshotDisposition::CapacityExhausted);
        };
        if mark_staging_bytes > maximum_snapshot_mark_staging_bytes(capacity) {
            return Err(RegionSnapshotDisposition::CapacityExhausted);
        }
    }
    for presence in &snapshot.presence_entries {
        if presence.boot_epoch != stage.origin.boot_epoch {
            return Err(RegionSnapshotDisposition::InvalidPresenceEpoch);
        }
        if presence.revision == 0 || presence.revision > snapshot.base_revision {
            return Err(RegionSnapshotDisposition::InvalidPresenceRevision);
        }
        let Ok(slot) = derive_slot_id(&presence.network_id, &presence.identity) else {
            return Err(RegionSnapshotDisposition::InvalidPresenceSlot);
        };
        if presence.slot != slot {
            return Err(RegionSnapshotDisposition::InvalidPresenceSlot);
        }
        if stage
            .presence_entries
            .iter()
            .chain(snapshot.presence_entries.iter())
            .filter(|candidate| {
                same_region_owner(
                    candidate.network_id,
                    candidate.identity,
                    presence.network_id,
                    presence.identity,
                )
            })
            .count()
            > 1
        {
            return Err(RegionSnapshotDisposition::DuplicatePresenceOwner);
        }
    }
    for (index, marks) in snapshot.mark_entries.iter().enumerate() {
        if snapshot.mark_entries[..index].iter().any(|candidate| {
            same_region_owner(
                candidate.network_id,
                candidate.identity,
                marks.network_id,
                marks.identity,
            )
        }) {
            return Err(RegionSnapshotDisposition::DuplicateMarkOwner);
        }
    }
    if snapshot.more && snapshot.chunk_index == u32::MAX {
        return Err(RegionSnapshotDisposition::ChunkIndexExhausted);
    }
    Ok(())
}

fn try_clone_snapshot(snapshot: &RegionSnapshot) -> Option<RegionSnapshot> {
    let mut presence_entries = Vec::new();
    if presence_entries
        .try_reserve_exact(snapshot.presence_entries.len())
        .is_err()
    {
        return None;
    }
    presence_entries.extend_from_slice(&snapshot.presence_entries);
    let mut mark_entries = Vec::new();
    if mark_entries
        .try_reserve_exact(snapshot.mark_entries.len())
        .is_err()
    {
        return None;
    }
    mark_entries.extend_from_slice(&snapshot.mark_entries);
    Some(RegionSnapshot {
        snapshot_id: snapshot.snapshot_id,
        base_revision: snapshot.base_revision,
        marks_revision: snapshot.marks_revision,
        chunk_index: snapshot.chunk_index,
        presence_entries,
        mark_entries,
        more: snapshot.more,
    })
}

fn snapshot_owner_validation_request(
    control: RegionSnapshotControl,
    snapshot: &RegionSnapshot,
    commitment: RegionSnapshotBatchCommitment,
    previous_indexed_owner_count: usize,
    previous_indexed_bytes: usize,
    capacity: RegionSnapshotStagingCapacity,
) -> Option<RegionSnapshotOwnerValidationRequest> {
    let maximum_owners = maximum_snapshot_mark_owners(capacity);
    let maximum_index_bytes = maximum_snapshot_owner_index_bytes(maximum_owners)?;
    let mut owners = Vec::new();
    if owners
        .try_reserve_exact(snapshot.mark_entries.len())
        .is_err()
    {
        return None;
    }
    for marks in &snapshot.mark_entries {
        owners.push(RegionOwner {
            network_id: marks.network_id,
            identity: marks.identity,
        });
    }
    Some(RegionSnapshotOwnerValidationRequest {
        control,
        snapshot_id: snapshot.snapshot_id,
        base_revision: snapshot.base_revision,
        marks_revision: snapshot.marks_revision,
        chunk_index: snapshot.chunk_index,
        accepted_through: snapshot.chunk_index,
        commitment,
        previous_indexed_owner_count,
        previous_indexed_bytes,
        owners,
        maximum_owners,
        maximum_index_bytes,
    })
}

fn accept_snapshot_chunk(
    stage: &mut RegionSnapshotStage,
    snapshot: RegionSnapshot,
    durable_marks: &[RegionMarks],
    durable_store: RegionSnapshotDurableStore,
    capacity: RegionSnapshotStagingCapacity,
) -> Result<(Vec<RegionSnapshotEffect>, RegionSnapshotDisposition), RegionSnapshotDisposition> {
    if stage.pending_mark_batch.is_some() || stage.pending_owner_validation.is_some() {
        return Err(RegionSnapshotDisposition::DurableMarkBatchPending);
    }
    if !durable_store_advances(stage.durable_store, durable_store) {
        return Err(RegionSnapshotDisposition::InvalidDurableStore);
    }
    let commitment = snapshot_batch_commitment(stage.control, &snapshot);
    let joins = snapshot_mark_joins(&snapshot.mark_entries, durable_marks)?;
    let requires_revision_advance = !joins.is_empty();
    if !snapshot.mark_entries.is_empty() {
        let Some(mark_staging_bytes) = snapshot_mark_staging_bytes(
            snapshot.mark_entries.capacity(),
            core::mem::size_of::<RegionSnapshotPendingMarkBatch>(),
        ) else {
            return Err(RegionSnapshotDisposition::CapacityExhausted);
        };
        if mark_staging_bytes > maximum_snapshot_mark_staging_bytes(capacity) {
            return Err(RegionSnapshotDisposition::CapacityExhausted);
        }
    }
    if stage
        .presence_entries
        .try_reserve_exact(snapshot.presence_entries.len())
        .is_err()
    {
        return Err(RegionSnapshotDisposition::CapacityExhausted);
    }

    let RegionSnapshot {
        snapshot_id: _,
        base_revision: _,
        marks_revision: _,
        chunk_index,
        presence_entries,
        mark_entries,
        more,
    } = snapshot;
    stage.presence_entries.extend_from_slice(&presence_entries);
    stage.accepted_through = Some(chunk_index);
    stage.cut_commitment =
        extend_snapshot_cut_commitment(stage.cut_commitment, commitment, chunk_index);
    stage.durable_store = durable_store;
    if requires_revision_advance {
        stage.pending_mark_batch = Some(RegionSnapshotPendingMarkBatch {
            chunk_index,
            commitment,
            requires_revision_advance,
            marks: mark_entries,
        });
    }
    if more {
        let Some(next_chunk_index) = chunk_index.checked_add(1) else {
            return Err(RegionSnapshotDisposition::ChunkIndexExhausted);
        };
        stage.next_chunk_index = next_chunk_index;
    } else {
        stage.final_received = true;
        stage.final_chunk_index = Some(chunk_index);
        stage.final_batch_commitment = if requires_revision_advance {
            Some(commitment)
        } else {
            None
        };
    }

    let mut effects = Vec::new();
    if let Some(batch) = stage.pending_mark_batch.as_ref() {
        if effects.try_reserve_exact(1).is_err() {
            return Err(RegionSnapshotDisposition::CapacityExhausted);
        }
        effects.push(RegionSnapshotEffect::PersistDurableBatch(
            RegionSnapshotDurableBatch {
                control: stage.control,
                snapshot_id: stage.snapshot_id,
                base_revision: stage.base_revision,
                marks_revision: stage.marks_revision,
                chunk_index: batch.chunk_index,
                accepted_through: batch.chunk_index,
                commitment: batch.commitment,
                joins,
            },
        ));
    }
    Ok((
        effects,
        if stage.final_received {
            RegionSnapshotDisposition::AwaitingDurableMarks
        } else {
            RegionSnapshotDisposition::Staged
        },
    ))
}

fn snapshot_mark_joins(
    staged: &[RegionMarks],
    durable: &[RegionMarks],
) -> Result<Vec<RegionMarks>, RegionSnapshotDisposition> {
    let mut joins = Vec::new();
    if joins.try_reserve_exact(staged.len()).is_err() {
        return Err(RegionSnapshotDisposition::CapacityExhausted);
    }
    for incoming in staged {
        let mut current = None;
        for marks in durable {
            if same_region_owner(
                marks.network_id,
                marks.identity,
                incoming.network_id,
                incoming.identity,
            ) && current.replace(*marks).is_some()
            {
                return Err(RegionSnapshotDisposition::InvalidDurableMarks);
            }
        }
        let joined = match current {
            Some(current) => {
                join_region_marks(current, *incoming)
                    .map_err(|_| RegionSnapshotDisposition::InvalidDurableMarks)?
                    .state
            }
            None => *incoming,
        };
        if current != Some(joined) {
            joins.push(joined);
        }
    }
    Ok(joins)
}

fn snapshot_marks_are_durable(staged: &[RegionMarks], durable: &[RegionMarks]) -> bool {
    staged.iter().all(|incoming| {
        let mut current = None;
        for marks in durable {
            if same_region_owner(
                marks.network_id,
                marks.identity,
                incoming.network_id,
                incoming.identity,
            ) && current.replace(*marks).is_some()
            {
                return false;
            }
        }
        current.is_some_and(|current| {
            join_region_marks(current, *incoming).is_ok_and(|joined| joined.state == current)
        })
    })
}

fn snapshot_batch_commitment(
    control: RegionSnapshotControl,
    snapshot: &RegionSnapshot,
) -> RegionSnapshotBatchCommitment {
    let mut hasher = Sha256::new();
    hasher.update(b"keynet-region-snapshot-batch-v1");
    hash_snapshot_control(&mut hasher, control);
    hasher.update(snapshot.snapshot_id.to_be_bytes());
    hasher.update(snapshot.base_revision.to_be_bytes());
    hasher.update(snapshot.marks_revision.to_be_bytes());
    hasher.update(snapshot.chunk_index.to_be_bytes());
    hasher.update([u8::from(snapshot.more)]);
    let presence_entry_count =
        u64::try_from(snapshot.presence_entries.len()).map_or(u64::MAX, |count| count);
    hasher.update(presence_entry_count.to_be_bytes());
    for presence in &snapshot.presence_entries {
        hash_region_presence(&mut hasher, *presence);
    }
    let mark_entry_count =
        u64::try_from(snapshot.mark_entries.len()).map_or(u64::MAX, |count| count);
    hasher.update(mark_entry_count.to_be_bytes());
    for marks in &snapshot.mark_entries {
        hash_region_marks(&mut hasher, *marks);
    }
    RegionSnapshotBatchCommitment {
        digest: hasher.finalize().into(),
    }
}

fn initial_snapshot_cut_commitment(
    control: RegionSnapshotControl,
    snapshot: &RegionSnapshot,
) -> RegionSnapshotCutCommitment {
    let mut hasher = Sha256::new();
    hasher.update(b"keynet-region-snapshot-cut-v1");
    hash_snapshot_control(&mut hasher, control);
    hasher.update(snapshot.snapshot_id.to_be_bytes());
    hasher.update(snapshot.base_revision.to_be_bytes());
    hasher.update(snapshot.marks_revision.to_be_bytes());
    RegionSnapshotCutCommitment {
        digest: hasher.finalize().into(),
    }
}

fn extend_snapshot_cut_commitment(
    previous: RegionSnapshotCutCommitment,
    batch: RegionSnapshotBatchCommitment,
    chunk_index: u32,
) -> RegionSnapshotCutCommitment {
    let mut hasher = Sha256::new();
    hasher.update(b"keynet-region-snapshot-cut-step-v1");
    hasher.update(previous.digest);
    hasher.update(batch.digest);
    hasher.update(chunk_index.to_be_bytes());
    RegionSnapshotCutCommitment {
        digest: hasher.finalize().into(),
    }
}

fn hash_snapshot_control(hasher: &mut Sha256, control: RegionSnapshotControl) {
    hasher.update([control.stream.origin.member_id]);
    hasher.update(control.stream.origin.boot_epoch.to_be_bytes());
    hasher.update(control.local_boot_epoch.to_be_bytes());
    hasher.update(control.control_stream_id.to_be_bytes());
}

fn hash_region_presence(hasher: &mut Sha256, presence: RegionPresence) {
    hasher.update(presence.slot);
    hasher.update(presence.network_id);
    hasher.update(presence.identity);
    hasher.update(presence.generation.to_be_bytes());
    hasher.update(presence.incarnation.to_be_bytes());
    hasher.update([presence.carrier as u8]);
    hasher.update(presence.boot_epoch.to_be_bytes());
    hasher.update(presence.revision.to_be_bytes());
}

fn hash_region_marks(hasher: &mut Sha256, marks: RegionMarks) {
    hasher.update(marks.network_id);
    hasher.update(marks.identity);
    hasher.update(marks.committed_generation.to_be_bytes());
    hasher.update(marks.committed_key);
    hasher.update([u8::from(marks.conflicted)]);
    match marks.revoked_through {
        Some(revoked_through) => {
            hasher.update([1]);
            hasher.update(revoked_through.to_be_bytes());
        }
        None => hasher.update([0]),
    }
    hasher.update(marks.incarnation_high_water.to_be_bytes());
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

/// A SETTLED frame body.
///
/// The exit member has made its final decision (delivered, answered with MISS, or dropped) for
/// every forward on `data_conn_gen` whose identifier is at most `settled_forward_id`, and no MISS
/// for those identifiers follows.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegionSettled {
    /// The nonzero data-channel connection generation of the settled forwards.
    pub data_conn_gen: u32,
    /// The nonzero greatest forwarding identifier covered by the watermark.
    pub settled_forward_id: u64,
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
    /// A SETTLED frame.
    Settled(RegionSettled),
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
    /// The envelope type was not one of the ten region frame types.
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
            Self::Settled(_) => RegionFrameType::Settled,
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
        RegionFrame::Settled(settled) => {
            if settled.data_conn_gen == 0 || settled.settled_forward_id == 0 {
                Err(RegionEncodeError::InvalidFrame)
            } else {
                Ok(())
            }
        }
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
        RegionFrame::Settled(settled) => {
            write_array(output, 2);
            write_uint(output, u64::from(settled.data_conn_gen));
            write_uint(output, settled.settled_forward_id);
        }
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
        RegionFrameType::Settled => {
            expect_array(reader, 2)?;
            Ok(RegionFrame::Settled(RegionSettled {
                data_conn_gen: read_u32(reader)?,
                settled_forward_id: read_uint(reader)?,
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
