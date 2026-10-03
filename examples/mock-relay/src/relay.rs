//! The relay v2 state machine (quick-v2 §8.2-§8.4, quick-protocol §12.5).

use crate::{
    bucket::TokenBucket,
    config::{ConfigError, Limits, PROVISIONAL_LIFETIME, RelayConfig},
    inspect::{Counters, Reason, SessionInfo},
    peer::{Carrier, Now, Peer, Transmit},
};
use nsshared_wire::{
    Identity, NODE_ID_BYTES, NodeId, NodeRecord, Presence, RELAY_HEADER_BYTES, RELAY_MAGIC,
    RELAY_SLOT, RecordDecision, RecordMarks, Reflect, Reflected, RegisterCandidate,
    RegisterRejection, Registered, RelayBody, RelayHeader, RelayPacket, RelayPacketError,
    SessionKey, Status, StatusCode, ephemeral_public, is_handshake_initiation,
};
use rand_core::CryptoRng;
use std::{collections::BTreeMap, time::Instant};

#[cfg(test)]
mod tests;

/// Offset of the src slot in the header (quick-v2 §8.1).
const SRC_OFFSET: usize = RELAY_MAGIC.len() + 1;
/// Offset of the dst slot in the header (quick-v2 §8.1).
const DST_OFFSET: usize = SRC_OFFSET + NODE_ID_BYTES;

/// The committed incarnation high water of one generation (quick-v2 §8.3 rule 4).
#[derive(Clone, Copy, Debug)]
struct IncarnationMark {
    generation: u64,
    incarnation: u64,
}

/// Per-identity state kept for the life of the relay: the slot owner, its record marks
/// and incarnation high water; it outlives sessions (quick-v2 §3.3, §8.1, §8.3 rule 4).
#[derive(Debug)]
struct Owner {
    identity: Identity,
    marks: RecordMarks,
    incarnation: Option<IncarnationMark>,
}

/// What both a provisional registration and a session are bound to (quick-v2 §8.3).
#[derive(Debug)]
struct Binding {
    node_id: NodeId,
    incarnation: u64,
    peer: Peer,
    key: SessionKey,
    relay_ephemeral: [u8; 32],
}

impl Binding {
    /// A REGISTERED for this binding: tentative with the announced capabilities when
    /// `ack_seq = 0`, otherwise acknowledging `ack_seq` (quick-v2 §8.2-§8.3).
    fn registered(&self, config: &RelayConfig, ack_seq: u64) -> Option<Vec<u8>> {
        let capabilities = if ack_seq == 0 {
            config
                .capabilities
                .as_slice()
                .iter()
                .map(|capability| capability.as_str().to_owned())
                .collect()
        } else {
            Vec::new()
        };
        self.seal(RelayBody::Registered(Registered {
            incarnation: self.incarnation,
            relay_ephemeral: self.relay_ephemeral,
            presence_ttl_s: config.presence_ttl_s,
            observed_addr: self.peer.observed_addr(),
            ack_seq,
            capabilities,
            mac: [0; 32],
        }))
    }

    /// A REFLECTED echoing `seq` and `nonce`; `None` on WSS (quick-v2 §8.2).
    fn reflected(&self, seq: u64, nonce: [u8; 16]) -> Option<Vec<u8>> {
        self.seal(RelayBody::Reflected(Reflected {
            incarnation: self.incarnation,
            seq,
            nonce,
            observed_addr: self.peer.observed_addr()?,
            mac: [0; 32],
        }))
    }

    fn seal(&self, body: RelayBody) -> Option<Vec<u8>> {
        let mut packet = RelayPacket {
            src: RELAY_SLOT,
            dst: self.node_id,
            body,
        };
        packet.seal(&self.key).ok()?;
        packet.encode().ok()
    }

    fn verifies(&self, packet: &RelayPacket) -> bool {
        packet.verify_mac(&self.key).is_ok()
    }
}

/// A provisional registration, keyed by the exact REGISTER bytes and source
/// (quick-v2 §8.3 rule 2).
#[derive(Debug)]
struct Provisional {
    binding: Binding,
    register: Vec<u8>,
    record: NodeRecord,
    reply: Vec<u8>,
    created: Instant,
}

/// A confirmed session (quick-v2 §8.3 rules 3 and 5).
#[derive(Debug)]
struct Session {
    binding: Binding,
    record: NodeRecord,
    /// The REGISTER and tentative reply, so a late identical retransmission is answered
    /// idempotently while the session lives (quick-protocol §12.5 rule 5).
    register: Vec<u8>,
    tentative_reply: Vec<u8>,
    seq: u64,
    last_control: Instant,
    last_reflect: Option<Instant>,
}

/// The per-sender DATA buckets (quick-protocol §5.2.1).
#[derive(Debug)]
struct SenderBudget {
    packets: TokenBucket,
    bytes: TokenBucket,
}

impl SenderBudget {
    fn new(limits: &Limits, now: Instant) -> Self {
        Self {
            packets: TokenBucket::new(limits.data_packets, now),
            bytes: TokenBucket::new(limits.data_bytes, now),
        }
    }
}

/// The header fields a STATUS echoes (quick-v2 §8.2, quick-protocol §12.5).
#[derive(Clone, Copy, Debug)]
struct Trigger {
    type_in: u8,
    src: NodeId,
    dst: NodeId,
    len: usize,
}

impl Trigger {
    fn of(header: RelayHeader, len: usize) -> Self {
        Self {
            type_in: header.packet_type.as_u8(),
            src: header.src,
            dst: header.dst,
            len,
        }
    }
}

/// A refused packet: the reason, and the STATUS code when one is sent.
#[derive(Clone, Copy, Debug)]
struct Refusal {
    status: Option<StatusCode>,
    reason: Reason,
}

impl Refusal {
    const fn status(status: StatusCode, reason: Reason) -> Self {
        Self {
            status: Some(status),
            reason,
        }
    }

    const fn silent(reason: Reason) -> Self {
        Self {
            status: None,
            reason,
        }
    }
}

/// A single-instance, in-memory relay v2 (quick-v2 §8).
///
/// Feed every received packet to [`Self::handle`] and send what it returns; call
/// [`Self::disconnect`] when a WSS connection closes and [`Self::tick`] periodically
/// (about once a second) to expire presence and provisional registrations. `R` supplies
/// the relay ephemeral of each REGISTER.
#[derive(Debug)]
pub struct Relay<R> {
    config: RelayConfig,
    rng: R,
    owners: BTreeMap<NodeId, Owner>,
    provisionals: Vec<Provisional>,
    sessions: BTreeMap<NodeId, Session>,
    data_budgets: BTreeMap<NodeId, SenderBudget>,
    handshake_budgets: BTreeMap<NodeId, TokenBucket>,
    counters: Counters,
}

impl<R: CryptoRng> Relay<R> {
    /// Creates a relay with no registrations.
    ///
    /// # Errors
    ///
    /// [`ConfigError`] for an invalid configuration.
    pub fn new(config: RelayConfig, rng: R) -> Result<Self, ConfigError> {
        config.validate()?;
        Ok(Self {
            config,
            rng,
            owners: BTreeMap::new(),
            provisionals: Vec::new(),
            sessions: BTreeMap::new(),
            data_budgets: BTreeMap::new(),
            handshake_budgets: BTreeMap::new(),
            counters: Counters::default(),
        })
    }

    /// Returns the configuration.
    #[must_use]
    pub const fn config(&self) -> &RelayConfig {
        &self.config
    }

    /// Returns the running counters.
    #[must_use]
    pub const fn counters(&self) -> &Counters {
        &self.counters
    }

    /// Returns every confirmed session and provisional registration, ordered by node ID,
    /// confirmed sessions first.
    #[must_use]
    pub fn sessions(&self) -> Vec<SessionInfo> {
        let info = |binding: &Binding, record: &NodeRecord, confirmed: bool| SessionInfo {
            node_id: binding.node_id,
            identity: *record.identity(),
            peer: binding.peer,
            carrier: binding.peer.carrier(),
            confirmed,
            incarnation: binding.incarnation,
            generation: record.generation(),
        };
        let mut sessions: Vec<_> = self
            .sessions
            .values()
            .map(|session| info(&session.binding, &session.record, true))
            .chain(
                self.provisionals
                    .iter()
                    .map(|provisional| info(&provisional.binding, &provisional.record, false)),
            )
            .collect();
        sessions.sort_by_key(|session| (session.node_id, !session.confirmed));
        sessions
    }

    /// Handles one received relay packet and returns the packets to send. Expiry runs
    /// first, as in [`Self::tick`].
    pub fn handle(&mut self, now: Now, from: Peer, packet: &[u8]) -> Vec<Transmit> {
        self.tick(now);
        self.counters.received += 1;
        let mut out = Vec::new();
        match RelayPacket::decode(packet) {
            Ok(decoded) => self.on_packet(now, from, packet, &decoded, &mut out),
            Err(error) => self.on_undecodable(from, packet, error, &mut out),
        }
        out
    }

    /// Removes every session and provisional registration bound to `peer`, e.g. a closed
    /// WSS connection; record marks are kept (quick-protocol §12.5).
    pub fn disconnect(&mut self, peer: &Peer) {
        self.provisionals
            .retain(|provisional| provisional.binding.peer != *peer);
        let before = self.sessions.len();
        self.sessions
            .retain(|_, session| session.binding.peer != *peer);
        self.counters.disconnected += (before - self.sessions.len()) as u64;
    }

    /// Drops provisional registrations older than 10 s and sessions past
    /// `min(last control + TTL, record.expires)`; record marks are kept
    /// (quick-v2 §8.3 rules 2 and 5).
    pub fn tick(&mut self, now: Now) {
        self.provisionals.retain(|provisional| {
            now.instant.saturating_duration_since(provisional.created) < PROVISIONAL_LIFETIME
        });
        let ttl = self.config.presence_ttl();
        let before = self.sessions.len();
        self.sessions.retain(|_, session| {
            now.instant.saturating_duration_since(session.last_control) < ttl
                && !session.record.is_expired(now.unix)
        });
        self.counters.expired += (before - self.sessions.len()) as u64;
    }

    fn on_packet(
        &mut self,
        now: Now,
        from: Peer,
        raw: &[u8],
        packet: &RelayPacket,
        out: &mut Vec<Transmit>,
    ) {
        let trigger = Trigger::of(packet.header(), raw.len());
        match &packet.body {
            RelayBody::Register(_) => self.on_register(now, from, raw, trigger, out),
            RelayBody::Presence(presence) => {
                self.on_presence(now, from, packet, trigger, presence, out);
            }
            RelayBody::Reflect(reflect) => {
                self.on_reflect(now, from, packet, trigger, reflect, out);
            }
            RelayBody::Revoke(revoke) => {
                if let Err(refusal) =
                    self.authenticate(from, packet, revoke.incarnation, revoke.seq)
                {
                    self.refuse(from, trigger, refusal, out);
                } else if self.sessions.remove(&packet.src).is_some() {
                    self.counters.revoked += 1;
                }
            }
            RelayBody::Data(data) => self.on_data(now, from, raw, trigger, data, out),
            RelayBody::Registered(_) | RelayBody::Reflected(_) | RelayBody::Status(_) => {
                self.counters.reject(Reason::Unexpected);
            }
        }
    }

    /// Unknown types get STATUS 5 and oversize packets STATUS 3, both only from the exact
    /// source of a session; everything else is dropped silently (quick-v2 §8.2,
    /// quick-protocol §12.5).
    fn on_undecodable(
        &mut self,
        from: Peer,
        raw: &[u8],
        error: RelayPacketError,
        out: &mut Vec<Transmit>,
    ) {
        let (trigger, refusal) = match error {
            RelayPacketError::UnknownType(type_in) => (
                unknown_type_slots(raw).map(|(src, dst)| Trigger {
                    type_in,
                    src,
                    dst,
                    len: raw.len(),
                }),
                Refusal::status(StatusCode::UnsupportedType, Reason::UnknownType),
            ),
            RelayPacketError::TooLarge { .. } => (
                raw.get(..RELAY_HEADER_BYTES)
                    .and_then(|header| RelayHeader::parse(header).ok())
                    .map(|header| Trigger::of(header, raw.len())),
                Refusal::status(StatusCode::TooLarge, Reason::Oversize),
            ),
            _ => (None, Refusal::silent(Reason::Malformed)),
        };
        match trigger {
            Some(trigger) if self.is_session_source(&trigger.src, &from) => {
                self.refuse(from, trigger, refusal, out);
            }
            _ => self.counters.reject(refusal.reason),
        }
    }

    /// REGISTER, quick-v2 §8.3 rules 1, 2 and 4.
    fn on_register(
        &mut self,
        now: Now,
        from: Peer,
        raw: &[u8],
        trigger: Trigger,
        out: &mut Vec<Transmit>,
    ) {
        let src = trigger.src;
        // Rule 2: an identical retransmission from the same source gets the same reply
        // and does not extend the lifetime.
        let stored = self
            .provisionals
            .iter()
            .find(|provisional| provisional.binding.peer == from && provisional.register == raw)
            .map(|provisional| provisional.reply.clone())
            .or_else(|| {
                self.sessions
                    .get(&src)
                    .filter(|session| session.binding.peer == from && session.register == raw)
                    .map(|session| session.tentative_reply.clone())
            });
        if let Some(reply) = stored {
            self.counters.retransmitted += 1;
            out.push(Transmit {
                to: from,
                packet: reply,
            });
            return;
        }
        // STATUS 4 is only addressable to the exact source of the identity's session.
        let stale = if self.is_session_source(&src, &from) {
            Refusal::status(StatusCode::Stale, Reason::Stale)
        } else {
            Refusal::silent(Reason::Stale)
        };
        let candidate = match RegisterCandidate::precheck(raw, &self.config.relay_id, now.unix) {
            Ok(candidate) => candidate,
            Err(rejection) => return self.counters.reject(register_reason(&rejection)),
        };
        let identity = *candidate.register().identity();
        let owner = self.owners.get(&src);
        if owner.is_some_and(|owner| owner.identity != identity) {
            return self.counters.reject(Reason::SlotCollision);
        }
        let from_ip = from.ip();
        let provisional_count = self
            .provisionals
            .iter()
            .filter(|provisional| provisional.binding.peer.ip() == from_ip)
            .count();
        if provisional_count >= self.config.limits.provisional_per_ip {
            return self.counters.reject(Reason::Capacity);
        }
        let record_bytes = candidate.register().record().to_vec();
        let fresh = RecordMarks::new(identity);
        let verified = match candidate.verify(owner.map_or(&fresh, |owner| &owner.marks)) {
            Ok(verified) => verified,
            Err(RegisterRejection::Conflict(_)) => {
                // Latch the same-generation key conflict (quick-v2 §3.3).
                if let (Some(owner), Ok(record)) =
                    (self.owners.get_mut(&src), NodeRecord::decode(&record_bytes))
                {
                    let _decision = owner.marks.apply(&record);
                }
                return self.counters.reject(Reason::Conflict);
            }
            Err(RegisterRejection::StaleGeneration { .. }) => {
                return self.refuse(from, trigger, stale, out);
            }
            Err(rejection) => return self.counters.reject(register_reason(&rejection)),
        };
        let record = verified.record().clone();
        let incarnation = verified.register().incarnation();
        if is_stale_incarnation(owner, &record, incarnation) {
            return self.refuse(from, trigger, stale, out);
        }
        if !self.sessions.contains_key(&src)
            && self.sessions.len() >= self.config.limits.max_sessions
        {
            return self.counters.reject(Reason::Capacity);
        }
        let mut secret = [0; 32];
        self.rng.fill_bytes(&mut secret);
        let Ok(key) = verified.relay_session_key(&secret) else {
            return self.counters.reject(Reason::RegisterInvalid);
        };
        let binding = Binding {
            node_id: src,
            incarnation,
            peer: from,
            key,
            relay_ephemeral: ephemeral_public(&secret),
        };
        let Some(reply) = binding.registered(&self.config, 0) else {
            return self.counters.reject(Reason::RegisterInvalid);
        };
        self.provisionals.push(Provisional {
            binding,
            register: raw.to_vec(),
            record,
            reply: reply.clone(),
            created: now.instant,
        });
        self.counters.registered += 1;
        out.push(Transmit {
            to: from,
            packet: reply,
        });
    }

    /// PRESENCE: confirms a provisional registration from its exact source, or refreshes
    /// a session (quick-v2 §8.3 rules 3 and 5).
    fn on_presence(
        &mut self,
        now: Now,
        from: Peer,
        packet: &RelayPacket,
        trigger: Trigger,
        presence: &Presence,
        out: &mut Vec<Transmit>,
    ) {
        let Presence {
            incarnation, seq, ..
        } = *presence;
        let mut matched = false;
        let confirming = self.provisionals.iter().position(|provisional| {
            let binding = &provisional.binding;
            let candidate = binding.node_id == packet.src
                && binding.peer == from
                && binding.incarnation == incarnation;
            matched |= candidate;
            candidate && binding.verifies(packet)
        });
        if let Some(index) = confirming {
            let provisional = self.provisionals.swap_remove(index);
            return self.confirm(now, provisional, seq, out);
        }
        if matched {
            return self.counters.reject(Reason::BadMac);
        }
        if let Err(refusal) = self.authenticate(from, packet, incarnation, seq) {
            return self.refuse(from, trigger, refusal, out);
        }
        let Some(session) = self.sessions.get_mut(&packet.src) else {
            return;
        };
        session.seq = seq;
        session.last_control = now.instant;
        if let Some(reply) = session.binding.registered(&self.config, seq) {
            self.counters.presence_acked += 1;
            out.push(Transmit {
                to: from,
                packet: reply,
            });
        }
    }

    /// Commits a confirmed registration after rechecking it, replacing any previous
    /// session of the identity, and acknowledges `seq` (quick-v2 §8.3 rules 3, 4 and 6).
    fn confirm(&mut self, now: Now, provisional: Provisional, seq: u64, out: &mut Vec<Transmit>) {
        let binding = &provisional.binding;
        let record = &provisional.record;
        let node_id = binding.node_id;
        if record.is_expired(now.unix) {
            return self.counters.reject(Reason::RegisterRecord);
        }
        let owner = self.owners.get(&node_id);
        let recheck = match owner {
            Some(owner) if owner.identity != *record.identity() => Err(Reason::SlotCollision),
            Some(owner) => check_marks(&owner.marks, record),
            None => Ok(()),
        };
        if let Err(reason) = recheck {
            return self.counters.reject(reason);
        }
        if is_stale_incarnation(owner, record, binding.incarnation) {
            return self.counters.reject(Reason::Stale);
        }
        if !self.sessions.contains_key(&node_id)
            && self.sessions.len() >= self.config.limits.max_sessions
        {
            return self.counters.reject(Reason::Capacity);
        }
        let owner = self.owners.entry(node_id).or_insert_with(|| Owner {
            identity: *record.identity(),
            marks: RecordMarks::new(*record.identity()),
            incarnation: None,
        });
        if owner.marks.apply(record).is_err() {
            return self.counters.reject(Reason::SlotCollision);
        }
        owner.incarnation = Some(IncarnationMark {
            generation: record.generation(),
            incarnation: binding.incarnation,
        });
        let reply = binding.registered(&self.config, seq);
        let peer = binding.peer;
        self.sessions.insert(
            node_id,
            Session {
                binding: provisional.binding,
                record: provisional.record,
                register: provisional.register,
                tentative_reply: provisional.reply,
                seq,
                last_control: now.instant,
                last_reflect: None,
            },
        );
        self.counters.confirmed += 1;
        if let Some(reply) = reply {
            out.push(Transmit {
                to: peer,
                packet: reply,
            });
        }
    }

    /// REFLECT, only on a confirmed UDP session and at most once per PRESENCE interval
    /// (quick-v2 §8.3 rule 7).
    fn on_reflect(
        &mut self,
        now: Now,
        from: Peer,
        packet: &RelayPacket,
        trigger: Trigger,
        reflect: &Reflect,
        out: &mut Vec<Transmit>,
    ) {
        let interval = self.config.presence_interval();
        let decision = self
            .authenticate(from, packet, reflect.incarnation, reflect.seq)
            .and_then(|()| {
                let session = self
                    .sessions
                    .get_mut(&packet.src)
                    .ok_or(Refusal::silent(Reason::NotRegistered))?;
                if session.binding.peer.carrier() == Carrier::Wss {
                    return Err(Refusal::status(
                        StatusCode::UnsupportedType,
                        Reason::ReflectOnWss,
                    ));
                }
                if session
                    .last_reflect
                    .is_some_and(|last| now.instant.saturating_duration_since(last) < interval)
                {
                    return Err(Refusal::status(
                        StatusCode::RateLimited,
                        Reason::RateLimited,
                    ));
                }
                session.seq = reflect.seq;
                session.last_control = now.instant;
                session.last_reflect = Some(now.instant);
                session
                    .binding
                    .reflected(reflect.seq, reflect.nonce)
                    .ok_or(Refusal::silent(Reason::ReflectOnWss))
            });
        match decision {
            Ok(reply) => {
                self.counters.reflected += 1;
                out.push(Transmit {
                    to: from,
                    packet: reply,
                });
            }
            Err(refusal) => self.refuse(from, trigger, refusal, out),
        }
    }

    /// DATA: src active from its exact source (else STATUS 6), dst active (else
    /// STATUS 1), budgets (else STATUS 2), then the bytes are forwarded unchanged
    /// (quick-v2 §8.4).
    fn on_data(
        &mut self,
        now: Now,
        from: Peer,
        raw: &[u8],
        trigger: Trigger,
        data: &[u8],
        out: &mut Vec<Transmit>,
    ) {
        if !self.is_session_source(&trigger.src, &from) {
            let refusal = Refusal::status(StatusCode::NotRegistered, Reason::NotRegistered);
            return self.refuse(from, trigger, refusal, out);
        }
        let Some(to) = self
            .sessions
            .get(&trigger.dst)
            .map(|session| session.binding.peer)
        else {
            let refusal = Refusal::status(StatusCode::NoDestination, Reason::NoDestination);
            return self.refuse(from, trigger, refusal, out);
        };
        let limits = &self.config.limits;
        let bytes = raw.len() as u64;
        let sender = self
            .data_budgets
            .entry(trigger.src)
            .or_insert_with(|| SenderBudget::new(limits, now.instant));
        let mut allowed =
            sender.packets.has(now.instant, 1) && sender.bytes.has(now.instant, bytes);
        // Only the first byte is read, to spot a WireGuard handshake initiation.
        let handshake = if is_handshake_initiation(data) {
            let bucket = self
                .handshake_budgets
                .entry(trigger.dst)
                .or_insert_with(|| TokenBucket::new(limits.handshake_initiations, now.instant));
            allowed &= bucket.has(now.instant, 1);
            Some(bucket)
        } else {
            None
        };
        if !allowed {
            let refusal = Refusal::status(StatusCode::RateLimited, Reason::RateLimited);
            return self.refuse(from, trigger, refusal, out);
        }
        sender.packets.take(1);
        sender.bytes.take(bytes);
        if let Some(bucket) = handshake {
            bucket.take(1);
        }
        self.counters.forwarded += 1;
        out.push(Transmit {
            to,
            packet: raw.to_vec(),
        });
    }

    /// Authenticates a node control packet against the session of its src: exact source
    /// (else STATUS 6), current incarnation (else STATUS 4), then MAC and `seq` above the
    /// high water (else dropped silently) (quick-v2 §8.3 rules 3 and 5).
    fn authenticate(
        &self,
        from: Peer,
        packet: &RelayPacket,
        incarnation: u64,
        seq: u64,
    ) -> Result<(), Refusal> {
        let session = self
            .sessions
            .get(&packet.src)
            .filter(|session| session.binding.peer == from)
            .ok_or(Refusal::status(
                StatusCode::NotRegistered,
                Reason::NotRegistered,
            ))?;
        if incarnation != session.binding.incarnation {
            return Err(Refusal::status(StatusCode::Stale, Reason::Stale));
        }
        if !session.binding.verifies(packet) {
            return Err(Refusal::silent(Reason::BadMac));
        }
        if seq <= session.seq {
            return Err(Refusal::silent(Reason::StaleSeq));
        }
        Ok(())
    }

    fn is_session_source(&self, src: &NodeId, from: &Peer) -> bool {
        self.sessions
            .get(src)
            .is_some_and(|session| session.binding.peer == *from)
    }

    /// Counts a refusal and sends its STATUS, if any, to `to`. The STATUS echoes the
    /// trigger's type and dst, is addressed to its src, and is never larger than the
    /// trigger (quick-v2 §8.2, quick-protocol §12.5).
    fn refuse(&mut self, to: Peer, trigger: Trigger, refusal: Refusal, out: &mut Vec<Transmit>) {
        self.counters.reject(refusal.reason);
        let Some(status) = refusal.status else {
            return;
        };
        let reply = RelayPacket {
            src: RELAY_SLOT,
            dst: trigger.src,
            body: RelayBody::Status(Status {
                type_in: trigger.type_in,
                destination: trigger.dst,
                status,
            }),
        };
        if let Ok(packet) = reply.encode()
            && packet.len() <= trigger.len
        {
            self.counters.status_sent += 1;
            out.push(Transmit { to, packet });
        }
    }
}

/// The §3.3 comparison at confirmation time: lower generation and latched or new
/// conflicts fail (quick-v2 §3.3, §8.3 rule 3).
fn check_marks(marks: &RecordMarks, record: &NodeRecord) -> Result<(), Reason> {
    match marks.evaluate(record) {
        Err(_) => Err(Reason::SlotCollision),
        Ok(RecordDecision::Stale) => Err(Reason::Stale),
        Ok(_) if marks.is_conflicted() && record.generation() == marks.committed_gen() => {
            Err(Reason::Conflict)
        }
        Ok(RecordDecision::Conflict) => Err(Reason::Conflict),
        Ok(_) => Ok(()),
    }
}

/// Within the committed generation a new session needs a larger incarnation; a higher
/// generation may reset it (quick-v2 §8.3 rule 4).
fn is_stale_incarnation(owner: Option<&Owner>, record: &NodeRecord, incarnation: u64) -> bool {
    owner
        .and_then(|owner| owner.incarnation)
        .is_some_and(|mark| {
            record.generation() < mark.generation
                || (record.generation() == mark.generation && incarnation <= mark.incarnation)
        })
}

fn register_reason(rejection: &RegisterRejection) -> Reason {
    match rejection {
        RegisterRejection::Packet(_) | RegisterRejection::NotRegister(_) => Reason::Malformed,
        RegisterRejection::SourceMismatch { .. } => Reason::RegisterInvalid,
        RegisterRejection::RelayName => Reason::RegisterRelayName,
        RegisterRejection::Timestamp { .. } => Reason::RegisterTimestamp,
        RegisterRejection::Record(_) | RegisterRejection::RecordExpired(_) => {
            Reason::RegisterRecord
        }
        RegisterRejection::Signature(_) => Reason::RegisterSignature,
        RegisterRejection::MarksIdentity => Reason::SlotCollision,
        RegisterRejection::StaleGeneration { .. } => Reason::Stale,
        RegisterRejection::Conflict(_) | RegisterRejection::ConflictLatched(_) => Reason::Conflict,
    }
}

/// Reads the slots of a packet whose type byte is unknown; [`RelayPacket::decode`] has
/// already checked its length and magic (quick-v2 §8.1).
fn unknown_type_slots(raw: &[u8]) -> Option<(NodeId, NodeId)> {
    let src = raw.get(SRC_OFFSET..DST_OFFSET)?.try_into().ok()?;
    let dst = raw.get(DST_OFFSET..RELAY_HEADER_BYTES)?.try_into().ok()?;
    Some((NodeId::from_bytes(src), NodeId::from_bytes(dst)))
}
