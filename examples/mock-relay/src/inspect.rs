//! Inspection hooks for tests: session snapshots and counters.

use crate::peer::{Carrier, Peer};
use nsshared_proto::{Identity, NodeId};
use std::collections::BTreeMap;

/// One provisional or confirmed registration, as returned by
/// [`crate::Relay::sessions`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionInfo {
    /// The slot: the node ID of `identity`.
    pub node_id: NodeId,
    /// The full identity `I`.
    pub identity: Identity,
    /// The exact source the registration is bound to.
    pub peer: Peer,
    /// The carrier of `peer`.
    pub carrier: Carrier,
    /// True for a confirmed session, false for a provisional registration.
    pub confirmed: bool,
    /// The REGISTER incarnation.
    pub incarnation: u64,
    /// The record generation `gen`.
    pub generation: u64,
}

/// Why a packet was dropped or answered with STATUS. Stable names for tests.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Reason {
    /// Bad magic, short, bad direction or non-canonical body; dropped silently.
    Malformed,
    /// Unknown type byte; STATUS 5 to a registered source, else dropped.
    UnknownType,
    /// Over the size limit of its type; STATUS 3 to a registered source, else dropped.
    Oversize,
    /// A STATUS, REGISTERED or REFLECTED sent to the relay; never answered.
    Unexpected,
    /// REGISTER `relay_name` is not this relay's identifier.
    RegisterRelayName,
    /// REGISTER `ts` is more than 120 s from now.
    RegisterTimestamp,
    /// The nested record is invalid or expired.
    RegisterRecord,
    /// The REGISTER signature does not verify.
    RegisterSignature,
    /// Any other REGISTER admission failure (src mismatch, all-zero shared secret).
    RegisterInvalid,
    /// Lower generation or a non-increasing incarnation within the same generation;
    /// STATUS 4 to the identity's active source, else dropped.
    Stale,
    /// The generation is latched as conflicted (quick-v2 §3.3).
    Conflict,
    /// The slot is held by a different identity (quick-v2 §8.1).
    SlotCollision,
    /// The per-IP provisional limit or the session limit is reached.
    Capacity,
    /// The sender has no session or is not its exact source; STATUS 6.
    NotRegistered,
    /// The DATA destination has no confirmed session; STATUS 1.
    NoDestination,
    /// A DATA, handshake-initiation or REFLECT budget is exhausted; STATUS 2.
    RateLimited,
    /// REFLECT on a WSS session; STATUS 5.
    ReflectOnWss,
    /// The control MAC does not verify; dropped silently.
    BadMac,
    /// The control `seq` is not above the high water; dropped silently.
    StaleSeq,
}

/// Running counters, as returned by [`crate::Relay::counters`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Counters {
    /// Packets passed to [`crate::Relay::handle`].
    pub received: u64,
    /// New provisional registrations answered with a tentative REGISTERED.
    pub registered: u64,
    /// Identical REGISTER retransmissions answered with the stored tentative reply.
    pub retransmitted: u64,
    /// Provisional registrations confirmed into sessions.
    pub confirmed: u64,
    /// PRESENCE packets acknowledged on a confirmed session.
    pub presence_acked: u64,
    /// REFLECTED replies sent.
    pub reflected: u64,
    /// DATA packets forwarded.
    pub forwarded: u64,
    /// Sessions removed by REVOKE.
    pub revoked: u64,
    /// Sessions removed by presence or record expiry.
    pub expired: u64,
    /// Sessions removed by [`crate::Relay::disconnect`].
    pub disconnected: u64,
    /// STATUS packets sent.
    pub status_sent: u64,
    /// Dropped or STATUS-answered packets by reason.
    pub rejected: BTreeMap<Reason, u64>,
}

impl Counters {
    /// Returns the count of `reason`.
    #[must_use]
    pub fn rejected(&self, reason: Reason) -> u64 {
        self.rejected.get(&reason).copied().unwrap_or(0)
    }

    pub(crate) fn reject(&mut self, reason: Reason) {
        *self.rejected.entry(reason).or_default() += 1;
    }
}
