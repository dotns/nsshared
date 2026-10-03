//! Mailbox phase rules and broker state transitions (rendezvous §5.3, §6).
//!
//! Every check is pure and deterministic: the broker owns storage, clocks, randomness,
//! wake-ups and the digits index, and passes `now` in Unix seconds. A transition that
//! returns an error leaves the mailbox unchanged. No transition ever changes `expires`
//! (rendezvous §5.3).

use crate::{
    error::ErrorCode,
    limits::{
        CLOSING_GRACE_SECONDS, INACTIVITY_SECONDS, MAX_CANDIDATES, MAX_DATA_BYTES, MAX_INTRO_BYTES,
        MAX_MAILBOX_BYTES, MAX_MAILBOX_MESSAGES, MAX_MAILBOXES, MAX_MAILBOXES_PER_ACTOR,
        MAX_PEER_REJECTS, MAX_PENDING_RECV, MAX_PENDING_RECV_PER_CONNECTION, MAX_QUEUED_BYTES,
        MAX_REJECTED_ACTORS, MAX_TTL_SECONDS, MAX_UNACKED_BYTES, MAX_UNACKED_MESSAGES,
        MIN_CANDIDATES, MIN_TTL_SECONDS,
    },
    message::{
        Admission, Digits, Found, Kind, MailboxId, MailboxMessage, MailboxView, OpenRequest, Sent,
        Stage, Waiting,
    },
};
use std::collections::VecDeque;

/// An actor public key, the identity a `hello` authenticated (rendezvous §4).
pub type Actor = [u8; 32];

/// How the broker's digits lookup index changes after a transition (rendezvous §5.3).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum IndexChange {
    /// The index entry is unchanged.
    #[default]
    Unchanged,
    /// The digits become findable again (an evicted peer reopens the mailbox).
    Add,
    /// The digits are no longer findable.
    Remove,
}

/// What a successful transition changed, for the broker to act on (rendezvous §5.2, §5.3).
///
/// The requester gets its own reply and is never listed.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Outcome {
    /// Parties whose `recv` view changed; their pending `recv` is answered now.
    pub wake: Vec<Actor>,
    /// Parties that lost access to the mailbox (removed candidates, the evicted peer, or
    /// everyone on removal); a later request from them is refused.
    pub dropped: Vec<Actor>,
    /// Change to the digits lookup index.
    pub index: IndexChange,
    /// The mailbox must be removed now.
    pub remove: bool,
}

/// One direction's ordered queue of unacknowledged messages (rendezvous §5.1, §6).
#[derive(Clone, Debug, Eq, PartialEq)]
struct Queue {
    messages: VecDeque<MailboxMessage>,
    bytes: usize,
    next_seq: u64,
}

impl Queue {
    const fn new() -> Self {
        Self {
            messages: VecDeque::new(),
            bytes: 0,
            next_seq: 1,
        }
    }

    /// Deletes every message with `seq <= after`.
    fn acknowledge(&mut self, after: u64) {
        while let Some(front) = self.messages.front() {
            if front.seq > after {
                break;
            }
            self.bytes -= front.data.len();
            self.messages.pop_front();
        }
    }

    /// Clears the queue; sequence numbers keep counting so a stale `after` never
    /// acknowledges a later message.
    fn clear(&mut self) {
        self.messages.clear();
        self.bytes = 0;
    }
}

/// Who a requester is in a mailbox.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Role {
    Owner,
    Peer,
    Candidate,
}

/// A stored mailbox (rendezvous §5.1) with the broker bookkeeping of §5.3 and §6.
///
/// Built only by [`Mailbox::open`]; changed only by the transition methods.
#[derive(Clone, Debug)]
pub struct Mailbox {
    id: MailboxId,
    kind: Kind,
    owner: Actor,
    admission: Admission,
    candidates: u8,
    expires: u64,
    digits: Digits,
    intro: Vec<u8>,
    waiting: Vec<Waiting>,
    peer: Option<Actor>,
    rejects: u8,
    rejected: Vec<Actor>,
    to_peer: Queue,
    to_owner: Queue,
    stage: Stage,
    sent_messages: usize,
    sent_bytes: usize,
    owner_active: u64,
    peer_active: u64,
    closing: Option<Closing>,
}

/// `closing` bookkeeping (rendezvous §5.3).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Closing {
    by: Role,
    since: u64,
    drained: bool,
}

impl Mailbox {
    /// Validates an `open` request and builds the mailbox in stage `open` with
    /// `expires = now + ttl` (rendezvous §5.1-§5.3).
    ///
    /// # Errors
    ///
    /// [`ErrorCode::InvalidMessage`] when `ttl`, `admission`/`candidates` or `intro` break
    /// their rule.
    pub fn open(
        owner: Actor,
        request: &OpenRequest,
        id: MailboxId,
        digits: Digits,
        now: u64,
    ) -> Result<Self, ErrorCode> {
        if !(MIN_TTL_SECONDS..=MAX_TTL_SECONDS).contains(&request.ttl)
            || !(MIN_CANDIDATES..=MAX_CANDIDATES).contains(&request.candidates)
            || (request.admission == Admission::First && request.candidates != 1)
            || request.intro.len() > MAX_INTRO_BYTES
        {
            return Err(ErrorCode::InvalidMessage);
        }
        let expires = now
            .checked_add(request.ttl)
            .ok_or(ErrorCode::InvalidMessage)?;
        Ok(Self {
            id,
            kind: request.kind.clone(),
            owner,
            admission: request.admission,
            candidates: request.candidates,
            expires,
            digits,
            intro: request.intro.clone(),
            waiting: Vec::new(),
            peer: None,
            rejects: 0,
            rejected: Vec::new(),
            to_peer: Queue::new(),
            to_owner: Queue::new(),
            stage: Stage::Open,
            sent_messages: 0,
            sent_bytes: 0,
            owner_active: now,
            peer_active: now,
            closing: None,
        })
    }

    /// Mailbox id.
    #[must_use]
    pub const fn id(&self) -> MailboxId {
        self.id
    }

    /// Application label.
    #[must_use]
    pub const fn kind(&self) -> &Kind {
        &self.kind
    }

    /// The owner actor.
    #[must_use]
    pub const fn owner(&self) -> &Actor {
        &self.owner
    }

    /// Admission mode.
    #[must_use]
    pub const fn admission(&self) -> Admission {
        self.admission
    }

    /// Waiting-candidate limit.
    #[must_use]
    pub const fn candidates(&self) -> u8 {
        self.candidates
    }

    /// Absolute expiry, Unix seconds; fixed at open.
    #[must_use]
    pub const fn expires(&self) -> u64 {
        self.expires
    }

    /// Lookup digits; findable only while the stage is `open`.
    #[must_use]
    pub const fn digits(&self) -> &Digits {
        &self.digits
    }

    /// The owner's introduction payload.
    #[must_use]
    pub fn intro(&self) -> &[u8] {
        &self.intro
    }

    /// Waiting candidates.
    #[must_use]
    pub fn waiting(&self) -> &[Waiting] {
        &self.waiting
    }

    /// The admitted peer.
    #[must_use]
    pub const fn peer(&self) -> Option<&Actor> {
        self.peer.as_ref()
    }

    /// Number of peer evictions so far.
    #[must_use]
    pub const fn rejects(&self) -> u8 {
        self.rejects
    }

    /// Rejected candidates, who cannot join again.
    #[must_use]
    pub fn rejected(&self) -> &[Actor] {
        &self.rejected
    }

    /// Current stage.
    #[must_use]
    pub const fn stage(&self) -> Stage {
        self.stage
    }

    /// Bytes of unacknowledged messages in both queues, for the broker's global
    /// queued-bytes counter (rendezvous §6).
    #[must_use]
    pub const fn queued_bytes(&self) -> usize {
        self.to_peer.bytes + self.to_owner.bytes
    }

    /// The `found` reply, only while the stage is `open` and the mailbox is live
    /// (rendezvous §5.2, §5.3). A lookup never changes the mailbox.
    #[must_use]
    pub fn lookup_view(&self, now: u64) -> Option<Found> {
        (self.stage == Stage::Open && !self.removal_due(now)).then(|| Found {
            id: self.id,
            kind: self.kind.clone(),
            expires: self.expires,
            intro: self.intro.clone(),
        })
    }

    /// Whether the broker must remove the mailbox: absolute expiry, owner or peer
    /// inactive for 180 s, or the `closing` rules (rendezvous §5.3).
    #[must_use]
    pub fn removal_due(&self, now: u64) -> bool {
        let inactive = |since: u64| now.saturating_sub(since) >= INACTIVITY_SECONDS;
        now >= self.expires
            || inactive(self.owner_active)
            || (self.peer.is_some() && inactive(self.peer_active))
            || self.closing.is_some_and(|closing| {
                closing.drained || now.saturating_sub(closing.since) >= CLOSING_GRACE_SECONDS
            })
    }

    /// `join {id, intro}` (rendezvous §5.3).
    ///
    /// # Errors
    ///
    /// [`ErrorCode::UnknownMailbox`] once removal is due, [`ErrorCode::InvalidMessage`]
    /// for an oversize intro, [`ErrorCode::NotPermitted`] for the owner or a rejected
    /// actor, [`ErrorCode::Conflict`] for a waiting candidate or the peer,
    /// [`ErrorCode::WrongStage`] outside `open`, [`ErrorCode::Capacity`] when the
    /// waiting list is full.
    pub fn join(&mut self, actor: Actor, intro: Vec<u8>, now: u64) -> Result<Outcome, ErrorCode> {
        self.live(now)?;
        if intro.len() > MAX_INTRO_BYTES {
            return Err(ErrorCode::InvalidMessage);
        }
        if actor == self.owner || self.rejected.contains(&actor) {
            return Err(ErrorCode::NotPermitted);
        }
        if self.peer == Some(actor) || self.is_waiting(&actor) {
            return Err(ErrorCode::Conflict);
        }
        if self.stage != Stage::Open {
            return Err(ErrorCode::WrongStage);
        }
        let mut outcome = Outcome {
            wake: vec![self.owner],
            ..Outcome::default()
        };
        match self.admission {
            Admission::First => {
                self.make_peer(actor, now);
                outcome.index = IndexChange::Remove;
            }
            Admission::Owner => {
                if self.waiting.len() >= usize::from(self.candidates) {
                    return Err(ErrorCode::Capacity);
                }
                self.waiting.push(Waiting { actor, intro });
            }
        }
        Ok(outcome)
    }

    /// `admit {id, actor}`: the candidate becomes the peer and the other candidates are
    /// dropped (rendezvous §5.3).
    ///
    /// # Errors
    ///
    /// [`ErrorCode::UnknownMailbox`] once removal is due, [`ErrorCode::NotPermitted`]
    /// unless `by` is the owner and `actor` is waiting, [`ErrorCode::WrongStage`]
    /// outside `open`.
    pub fn admit(&mut self, by: &Actor, actor: &Actor, now: u64) -> Result<Outcome, ErrorCode> {
        self.live(now)?;
        if *by != self.owner {
            return Err(ErrorCode::NotPermitted);
        }
        if self.stage != Stage::Open {
            return Err(ErrorCode::WrongStage);
        }
        if !self.is_waiting(actor) {
            return Err(ErrorCode::NotPermitted);
        }
        self.owner_active = now;
        let dropped = self
            .waiting
            .drain(..)
            .map(|waiting| waiting.actor)
            .filter(|candidate| candidate != actor)
            .collect();
        self.make_peer(*actor, now);
        Ok(Outcome {
            wake: vec![*actor],
            dropped,
            index: IndexChange::Remove,
            remove: false,
        })
    }

    /// `reject {id, actor}`: removes and records a candidate, or evicts the admitted
    /// peer (rendezvous §5.3, §6).
    ///
    /// An evicted peer is not recorded as rejected and may join again.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::UnknownMailbox`] once removal is due, [`ErrorCode::NotPermitted`]
    /// unless `by` is the owner and `actor` is a candidate or the peer,
    /// [`ErrorCode::Capacity`] when the rejected set is full,
    /// [`ErrorCode::WrongStage`] for the peer of a `closing` mailbox.
    pub fn reject(&mut self, by: &Actor, actor: &Actor, now: u64) -> Result<Outcome, ErrorCode> {
        self.live(now)?;
        if *by != self.owner {
            return Err(ErrorCode::NotPermitted);
        }
        if let Some(index) = self.waiting_index(actor) {
            if self.rejected.len() >= MAX_REJECTED_ACTORS {
                return Err(ErrorCode::Capacity);
            }
            self.owner_active = now;
            self.waiting.remove(index);
            self.rejected.push(*actor);
            return Ok(Outcome {
                dropped: vec![*actor],
                ..Outcome::default()
            });
        }
        if self.peer.as_ref() != Some(actor) {
            return Err(ErrorCode::NotPermitted);
        }
        if self.stage != Stage::Admitted {
            return Err(ErrorCode::WrongStage);
        }
        self.owner_active = now;
        self.to_peer.clear();
        self.to_owner.clear();
        self.peer = None;
        self.rejects += 1;
        if self.rejects >= MAX_PEER_REJECTS {
            return Ok(Outcome {
                dropped: vec![*actor],
                remove: true,
                ..Outcome::default()
            });
        }
        self.stage = Stage::Open;
        Ok(Outcome {
            dropped: vec![*actor],
            index: IndexChange::Add,
            ..Outcome::default()
        })
    }

    /// `send {id, data}`: queues a message to the other side (rendezvous §5.3, §6).
    ///
    /// # Errors
    ///
    /// [`ErrorCode::UnknownMailbox`] once removal is due, [`ErrorCode::NotPermitted`]
    /// unless `by` is the owner or the peer, [`ErrorCode::WrongStage`] outside
    /// `admitted`, [`ErrorCode::InvalidMessage`] for oversize data,
    /// [`ErrorCode::QueueFull`] at a per-direction or per-mailbox limit.
    pub fn send(
        &mut self,
        by: &Actor,
        data: Vec<u8>,
        now: u64,
    ) -> Result<(Sent, Outcome), ErrorCode> {
        self.live(now)?;
        let role = match self.role(by) {
            Some(Role::Owner) => Role::Owner,
            Some(Role::Peer) => Role::Peer,
            Some(Role::Candidate) | None => return Err(ErrorCode::NotPermitted),
        };
        if self.stage != Stage::Admitted {
            return Err(ErrorCode::WrongStage);
        }
        let Some(peer) = self.peer else {
            return Err(ErrorCode::WrongStage);
        };
        if data.len() > MAX_DATA_BYTES {
            return Err(ErrorCode::InvalidMessage);
        }
        if self.sent_messages >= MAX_MAILBOX_MESSAGES
            || self.sent_bytes + data.len() > MAX_MAILBOX_BYTES
        {
            return Err(ErrorCode::QueueFull);
        }
        let (queue, recipient) = match role {
            Role::Owner => (&mut self.to_peer, peer),
            Role::Peer | Role::Candidate => (&mut self.to_owner, self.owner),
        };
        if queue.messages.len() >= MAX_UNACKED_MESSAGES
            || queue.bytes + data.len() > MAX_UNACKED_BYTES
        {
            return Err(ErrorCode::QueueFull);
        }
        let seq = queue.next_seq;
        queue.next_seq += 1;
        queue.bytes += data.len();
        self.sent_bytes += data.len();
        self.sent_messages += 1;
        queue.messages.push_back(MailboxMessage { seq, data });
        self.touch(role, now);
        Ok((
            Sent { seq },
            Outcome {
                wake: vec![recipient],
                ..Outcome::default()
            },
        ))
    }

    /// `recv {id, after, wait_ms}`: acknowledges and deletes the requester's messages
    /// with `seq <= after` and returns the view (rendezvous §5.2, §5.3).
    ///
    /// Candidates get no messages and only the owner sees `waiting`. In `closing`, the
    /// other side acknowledging its last message makes [`Mailbox::removal_due`] true.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::UnknownMailbox`] once removal is due, [`ErrorCode::NotPermitted`]
    /// unless `by` is the owner, a candidate or the peer, [`ErrorCode::InvalidMessage`]
    /// when `after` acknowledges a sequence number never assigned.
    pub fn recv(&mut self, by: &Actor, after: u64, now: u64) -> Result<MailboxView, ErrorCode> {
        self.live(now)?;
        let role = self.role(by).ok_or(ErrorCode::NotPermitted)?;
        let queue = match role {
            Role::Owner => &mut self.to_owner,
            Role::Peer => &mut self.to_peer,
            Role::Candidate => {
                return Ok(MailboxView {
                    stage: self.stage,
                    waiting: Vec::new(),
                    peer: self.peer,
                    messages: Vec::new(),
                });
            }
        };
        if after >= queue.next_seq {
            return Err(ErrorCode::InvalidMessage);
        }
        queue.acknowledge(after);
        let messages = queue.messages.iter().cloned().collect();
        let drained = queue.messages.is_empty();
        if let Some(closing) = self.closing.as_mut()
            && closing.by != role
            && drained
        {
            closing.drained = true;
        }
        self.touch(role, now);
        Ok(MailboxView {
            stage: self.stage,
            waiting: if role == Role::Owner {
                self.waiting.clone()
            } else {
                Vec::new()
            },
            peer: self.peer,
            messages,
        })
    }

    /// `close {id}` (rendezvous §5.3).
    ///
    /// A candidate leaves the waiting list. The owner of an `open` mailbox removes it,
    /// having no other side. Otherwise the owner or the peer moves the mailbox to
    /// `closing`; the other side's `close` removes it. A repeated `close` changes
    /// nothing.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::UnknownMailbox`] once removal is due, [`ErrorCode::NotPermitted`]
    /// unless `by` is the owner, a candidate or the peer.
    pub fn close(&mut self, by: &Actor, now: u64) -> Result<Outcome, ErrorCode> {
        self.live(now)?;
        let role = self.role(by).ok_or(ErrorCode::NotPermitted)?;
        match (role, self.stage, self.closing) {
            (Role::Candidate, _, _) => {
                self.waiting.retain(|waiting| waiting.actor != *by);
                Ok(Outcome {
                    wake: vec![self.owner],
                    ..Outcome::default()
                })
            }
            (_, Stage::Open, _) => Ok(Outcome {
                dropped: self.waiting.iter().map(|waiting| waiting.actor).collect(),
                index: IndexChange::Remove,
                remove: true,
                ..Outcome::default()
            }),
            (_, _, Some(closing)) if closing.by == role => Ok(Outcome::default()),
            (_, _, Some(_)) => Ok(Outcome {
                dropped: vec![self.other_side(role)],
                remove: true,
                ..Outcome::default()
            }),
            (_, _, None) => {
                self.touch(role, now);
                self.stage = Stage::Closing;
                self.closing = Some(Closing {
                    by: role,
                    since: now,
                    drained: false,
                });
                Ok(Outcome {
                    wake: vec![self.other_side(role)],
                    ..Outcome::default()
                })
            }
        }
    }

    fn live(&self, now: u64) -> Result<(), ErrorCode> {
        if self.removal_due(now) {
            Err(ErrorCode::UnknownMailbox)
        } else {
            Ok(())
        }
    }

    fn role(&self, actor: &Actor) -> Option<Role> {
        if *actor == self.owner {
            Some(Role::Owner)
        } else if self.peer.as_ref() == Some(actor) {
            Some(Role::Peer)
        } else if self.is_waiting(actor) {
            Some(Role::Candidate)
        } else {
            None
        }
    }

    fn other_side(&self, role: Role) -> Actor {
        match (role, self.peer) {
            (Role::Owner, Some(peer)) => peer,
            _ => self.owner,
        }
    }

    fn touch(&mut self, role: Role, now: u64) {
        match role {
            Role::Owner => self.owner_active = now,
            Role::Peer => self.peer_active = now,
            Role::Candidate => {}
        }
    }

    fn make_peer(&mut self, actor: Actor, now: u64) {
        self.peer = Some(actor);
        self.peer_active = now;
        self.stage = Stage::Admitted;
    }

    fn waiting_index(&self, actor: &Actor) -> Option<usize> {
        self.waiting
            .iter()
            .position(|waiting| waiting.actor == *actor)
    }

    fn is_waiting(&self, actor: &Actor) -> bool {
        self.waiting_index(actor).is_some()
    }
}

/// Checks the stored-mailbox limit before `open` (rendezvous §6).
///
/// # Errors
///
/// [`ErrorCode::Capacity`] when `stored` already reaches the limit.
pub const fn check_stored_mailboxes(stored: usize) -> Result<(), ErrorCode> {
    if stored >= MAX_MAILBOXES {
        Err(ErrorCode::Capacity)
    } else {
        Ok(())
    }
}

/// Checks the per-actor live-mailbox limit before the actor opens or joins one
/// (rendezvous §6).
///
/// # Errors
///
/// [`ErrorCode::Capacity`] when `active` already reaches the limit.
pub const fn check_actor_mailboxes(active: usize) -> Result<(), ErrorCode> {
    if active >= MAX_MAILBOXES_PER_ACTOR {
        Err(ErrorCode::Capacity)
    } else {
        Ok(())
    }
}

/// Checks the global queued-bytes limit before queuing `additional` bytes
/// (rendezvous §6).
///
/// # Errors
///
/// [`ErrorCode::QueueFull`] when the total would exceed the limit.
pub const fn check_queued_bytes(queued: usize, additional: usize) -> Result<(), ErrorCode> {
    match queued.checked_add(additional) {
        Some(total) if total <= MAX_QUEUED_BYTES => Ok(()),
        _ => Err(ErrorCode::QueueFull),
    }
}

/// Checks the pending-`recv` limits before a `recv` with a nonzero wait is held
/// (rendezvous §6).
///
/// # Errors
///
/// [`ErrorCode::Capacity`] when the connection or the broker already holds the limit.
pub const fn check_pending_recv(on_connection: usize, global: usize) -> Result<(), ErrorCode> {
    if on_connection >= MAX_PENDING_RECV_PER_CONNECTION || global >= MAX_PENDING_RECV {
        Err(ErrorCode::Capacity)
    } else {
        Ok(())
    }
}
