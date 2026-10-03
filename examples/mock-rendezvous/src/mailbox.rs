//! Mailbox broker state (rendezvous §5.1-§5.3, §6).
//!
//! [`MailboxBroker`] stores the mailboxes and the bookkeeping around them; every phase
//! rule, permission check and payload comes from `nsshared_proto::rendezvous::phase`. The
//! broker adds the digits lookup index, per-actor live-mailbox counts, the global
//! queued-byte total, id and digits allocation, removal and a per-mailbox change signal
//! for long polls. It is synchronous and meant to sit behind a `std::sync::Mutex`; it
//! does no I/O and reads no clock or OS randomness: callers pass `now` (Unix seconds)
//! and an RNG. Rate limits, pending-`recv` counting, the `recv` wait and the 10 s sweep
//! cadence are the server's job.

use crate::config::Limits;
use nsshared_proto::rendezvous::{
    error::ErrorCode,
    limits::{DIGITS_LEN, MAILBOX_ID_BYTES},
    message::{Digits, Found, MailboxId, MailboxView, OpenRequest, Opened, Sent},
    phase::{
        Actor, IndexChange, Mailbox, Outcome, check_actor_mailboxes_within,
        check_queued_bytes_within, check_stored_mailboxes_within,
    },
};
use rand_core::TryCryptoRng;
use std::collections::{HashMap, HashSet};
use tokio::sync::watch;

/// Id and digits draws per `open` before the RNG is considered broken. With at most
/// 10 000 stored mailboxes among 10^8 codes a working RNG never gets near it.
const MAX_ALLOCATION_ATTEMPTS: usize = 16;

/// A mailbox change signal: a generation counter bumped on every stage, queue or
/// waiting change, close, eviction and removal (rendezvous §5.2 `wait_ms`). The sender
/// is dropped on removal, after a final bump.
pub type ChangeReceiver = watch::Receiver<u64>;

/// A stored mailbox and its change signal.
#[derive(Debug)]
struct Entry {
    mailbox: Mailbox,
    changes: watch::Sender<u64>,
}

impl Entry {
    fn signal(&self) {
        self.changes
            .send_modify(|generation| *generation = generation.wrapping_add(1));
    }
}

/// Every stored mailbox with its indexes and counters (rendezvous §5, §6).
#[derive(Debug)]
pub struct MailboxBroker {
    limits: Limits,
    mailboxes: HashMap<MailboxId, Entry>,
    /// Findable digits, maintained from [`IndexChange`] outcomes.
    index: HashMap<Digits, MailboxId>,
    /// Digits of every stored mailbox: an evicted peer restores the same digits, so
    /// they stay reserved until removal.
    reserved: HashSet<Digits>,
    /// Live mailboxes per actor, as owner, waiting candidate or peer.
    actors: HashMap<Actor, usize>,
    queued_bytes: usize,
}

impl MailboxBroker {
    /// An empty broker enforcing `limits`.
    #[must_use]
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            mailboxes: HashMap::new(),
            index: HashMap::new(),
            reserved: HashSet::new(),
            actors: HashMap::new(),
            queued_bytes: 0,
        }
    }

    /// Number of stored mailboxes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.mailboxes.len()
    }

    /// Whether no mailbox is stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.mailboxes.is_empty()
    }

    /// Queued message bytes across all mailboxes (rendezvous §6).
    #[must_use]
    pub const fn queued_bytes(&self) -> usize {
        self.queued_bytes
    }

    /// Live mailboxes of `actor` as owner, waiting candidate or peer (rendezvous §6).
    #[must_use]
    pub fn actor_mailboxes(&self, actor: &Actor) -> usize {
        self.actors.get(actor).copied().unwrap_or(0)
    }

    /// `open`: allocates a random 16-byte id and random 8 digits not used by another
    /// stored mailbox, retrying on collision (rendezvous §5.2, §5.3, §6).
    ///
    /// # Errors
    ///
    /// [`ErrorCode::Capacity`] at the stored-mailbox or per-actor limit,
    /// [`ErrorCode::Randomness`] when the RNG fails or keeps colliding, and the
    /// validation errors of [`Mailbox::open`].
    pub fn open<R: TryCryptoRng + ?Sized>(
        &mut self,
        owner: Actor,
        request: &OpenRequest,
        now: u64,
        rng: &mut R,
    ) -> Result<Opened, ErrorCode> {
        check_stored_mailboxes_within(self.mailboxes.len(), self.limits.mailboxes)?;
        check_actor_mailboxes_within(
            self.actor_mailboxes(&owner),
            self.limits.mailboxes_per_actor,
        )?;
        let (id, digits) = self.allocate(rng)?;
        let mailbox = Mailbox::open(owner, request, id, digits.clone(), now)?;
        let opened = Opened {
            id,
            digits: digits.clone(),
            expires: mailbox.expires(),
        };
        self.reserved.insert(digits.clone());
        self.index.insert(digits, id);
        *self.actors.entry(owner).or_default() += 1;
        let (changes, _) = watch::channel(0);
        self.mailboxes.insert(id, Entry { mailbox, changes });
        Ok(opened)
    }

    /// `lookup`: the `found` reply while the digits are findable and the mailbox is
    /// live; never changes or extends a mailbox (rendezvous §5.2, §5.3).
    ///
    /// # Errors
    ///
    /// [`ErrorCode::InvalidCode`] when the digits do not locate a findable mailbox.
    pub fn lookup(&self, digits: &Digits, now: u64) -> Result<Found, ErrorCode> {
        self.index
            .get(digits)
            .and_then(|id| self.mailboxes.get(id))
            .and_then(|entry| entry.mailbox.lookup_view(now))
            .ok_or(ErrorCode::InvalidCode)
    }

    /// `join {id, intro}` by `actor` (rendezvous §5.2, §5.3, §6).
    ///
    /// # Errors
    ///
    /// [`ErrorCode::UnknownMailbox`], [`ErrorCode::Capacity`] at the per-actor limit,
    /// and the errors of [`Mailbox::join`].
    pub fn join(
        &mut self,
        actor: Actor,
        id: &MailboxId,
        intro: Vec<u8>,
        now: u64,
    ) -> Result<(), ErrorCode> {
        let entry = self.mailboxes.get(id).ok_or(ErrorCode::UnknownMailbox)?;
        if !participants(&entry.mailbox).contains(&actor) {
            check_actor_mailboxes_within(
                self.actor_mailboxes(&actor),
                self.limits.mailboxes_per_actor,
            )?;
        }
        self.apply(id, now, |mailbox| {
            mailbox.join(actor, intro, now).map(|outcome| ((), outcome))
        })
    }

    /// `admit {id, actor}` by `by` (rendezvous §5.2, §5.3).
    ///
    /// # Errors
    ///
    /// [`ErrorCode::UnknownMailbox`] and the errors of [`Mailbox::admit`].
    pub fn admit(
        &mut self,
        by: &Actor,
        id: &MailboxId,
        actor: &Actor,
        now: u64,
    ) -> Result<(), ErrorCode> {
        self.apply(id, now, |mailbox| {
            mailbox.admit(by, actor, now).map(|outcome| ((), outcome))
        })
    }

    /// `reject {id, actor}` by `by` (rendezvous §5.2, §5.3).
    ///
    /// # Errors
    ///
    /// [`ErrorCode::UnknownMailbox`] and the errors of [`Mailbox::reject`].
    pub fn reject(
        &mut self,
        by: &Actor,
        id: &MailboxId,
        actor: &Actor,
        now: u64,
    ) -> Result<(), ErrorCode> {
        self.apply(id, now, |mailbox| {
            mailbox.reject(by, actor, now).map(|outcome| ((), outcome))
        })
    }

    /// `send {id, data}` by `by` (rendezvous §5.2, §5.3, §6).
    ///
    /// # Errors
    ///
    /// [`ErrorCode::UnknownMailbox`], [`ErrorCode::QueueFull`] at the global
    /// queued-bytes limit, and the errors of [`Mailbox::send`].
    pub fn send(
        &mut self,
        by: &Actor,
        id: &MailboxId,
        data: Vec<u8>,
        now: u64,
    ) -> Result<Sent, ErrorCode> {
        if !self.mailboxes.contains_key(id) {
            return Err(ErrorCode::UnknownMailbox);
        }
        check_queued_bytes_within(self.queued_bytes, data.len(), self.limits.queued_bytes)?;
        self.apply(id, now, |mailbox| mailbox.send(by, data, now))
    }

    /// `recv {id, after}` by `by`, without waiting: acknowledges per `after` and returns
    /// the current view (rendezvous §5.2, §5.3). For a long poll the server subscribes
    /// first, calls this, and on an empty unchanged view waits on the
    /// [`ChangeReceiver`] and calls it again.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::UnknownMailbox`] and the errors of [`Mailbox::recv`].
    pub fn recv(
        &mut self,
        by: &Actor,
        id: &MailboxId,
        after: u64,
        now: u64,
    ) -> Result<MailboxView, ErrorCode> {
        self.apply(id, now, |mailbox| {
            mailbox
                .recv(by, after, now)
                .map(|view| (view, Outcome::default()))
        })
    }

    /// `close {id}` by `by` (rendezvous §5.2, §5.3).
    ///
    /// # Errors
    ///
    /// [`ErrorCode::UnknownMailbox`] and the errors of [`Mailbox::close`].
    pub fn close(&mut self, by: &Actor, id: &MailboxId, now: u64) -> Result<(), ErrorCode> {
        self.apply(id, now, |mailbox| {
            mailbox.close(by, now).map(|outcome| ((), outcome))
        })
    }

    /// The change signal of mailbox `id`, for a long-poll `recv` (rendezvous §5.2).
    ///
    /// # Errors
    ///
    /// [`ErrorCode::UnknownMailbox`].
    pub fn subscribe(&self, id: &MailboxId) -> Result<ChangeReceiver, ErrorCode> {
        self.mailboxes
            .get(id)
            .map(|entry| entry.changes.subscribe())
            .ok_or(ErrorCode::UnknownMailbox)
    }

    /// Removes every mailbox whose removal is due at `now` and signals its waiters
    /// (rendezvous §5.3). Returns the number removed.
    pub fn sweep(&mut self, now: u64) -> usize {
        let due: Vec<MailboxId> = self
            .mailboxes
            .iter()
            .filter(|(_, entry)| entry.mailbox.removal_due(now))
            .map(|(id, _)| *id)
            .collect();
        for id in &due {
            self.remove(id);
        }
        due.len()
    }

    /// Draws an id and digits that no stored mailbox uses.
    fn allocate<R: TryCryptoRng + ?Sized>(
        &self,
        rng: &mut R,
    ) -> Result<(MailboxId, Digits), ErrorCode> {
        for _ in 0..MAX_ALLOCATION_ATTEMPTS {
            let mut id = [0; MAILBOX_ID_BYTES];
            rng.try_fill_bytes(&mut id)
                .map_err(|_| ErrorCode::Randomness)?;
            let id = MailboxId(id);
            let digits = random_digits(rng)?;
            if !self.mailboxes.contains_key(&id) && !self.reserved.contains(&digits) {
                return Ok((id, digits));
            }
        }
        Err(ErrorCode::Randomness)
    }

    /// Runs one transition on mailbox `id` and applies its outcome to the indexes,
    /// counters and change signal; removes the mailbox when the outcome asks for it or
    /// its removal is due.
    fn apply<T>(
        &mut self,
        id: &MailboxId,
        now: u64,
        transition: impl FnOnce(&mut Mailbox) -> Result<(T, Outcome), ErrorCode>,
    ) -> Result<T, ErrorCode> {
        let entry = self
            .mailboxes
            .get_mut(id)
            .ok_or(ErrorCode::UnknownMailbox)?;
        let before = participants(&entry.mailbox);
        let queued_before = entry.mailbox.queued_bytes();
        let result = transition(&mut entry.mailbox);
        self.queued_bytes = self.queued_bytes - queued_before + entry.mailbox.queued_bytes();
        let due = entry.mailbox.removal_due(now);
        let value = match result {
            Ok((value, outcome)) => {
                let after = participants(&entry.mailbox);
                match outcome.index {
                    IndexChange::Unchanged => {}
                    IndexChange::Add => {
                        self.index.insert(entry.mailbox.digits().clone(), *id);
                    }
                    IndexChange::Remove => {
                        self.index.remove(entry.mailbox.digits());
                    }
                }
                if outcome != Outcome::default() {
                    entry.signal();
                }
                for actor in before.iter().filter(|actor| !after.contains(actor)) {
                    decrement(&mut self.actors, actor);
                }
                for actor in after.iter().filter(|actor| !before.contains(actor)) {
                    *self.actors.entry(*actor).or_default() += 1;
                }
                if outcome.remove {
                    self.remove(id);
                }
                Ok(value)
            }
            Err(code) => Err(code),
        };
        if due {
            self.remove(id);
        }
        value
    }

    /// Removes mailbox `id`: unindexes its digits, fixes the counters and signals its
    /// waiters, whose next request gets `unknown_mailbox`.
    fn remove(&mut self, id: &MailboxId) {
        let Some(entry) = self.mailboxes.remove(id) else {
            return;
        };
        let digits = entry.mailbox.digits();
        if self.index.get(digits) == Some(id) {
            self.index.remove(digits);
        }
        self.reserved.remove(digits);
        self.queued_bytes -= entry.mailbox.queued_bytes();
        for actor in participants(&entry.mailbox) {
            decrement(&mut self.actors, &actor);
        }
        entry.signal();
    }
}

/// The actors holding a live place in the mailbox: owner, waiting candidates and peer.
fn participants(mailbox: &Mailbox) -> Vec<Actor> {
    let mut actors = vec![*mailbox.owner()];
    actors.extend(mailbox.waiting().iter().map(|waiting| waiting.actor));
    actors.extend(mailbox.peer().copied());
    actors
}

fn decrement(actors: &mut HashMap<Actor, usize>, actor: &Actor) {
    if let Some(count) = actors.get_mut(actor) {
        *count -= 1;
        if *count == 0 {
            actors.remove(actor);
        }
    }
}

/// Uniform 8 decimal digits, leading zeros kept (rendezvous §5.1). The modulo bias of
/// 2^64 mod 10^8 is below 2^-36.
fn random_digits<R: TryCryptoRng + ?Sized>(rng: &mut R) -> Result<Digits, ErrorCode> {
    let mut value = rng.try_next_u64().map_err(|_| ErrorCode::Randomness)?;
    let mut text = [b'0'; DIGITS_LEN];
    for byte in text.iter_mut().rev() {
        *byte = b'0' + (value % 10) as u8;
        value /= 10;
    }
    std::str::from_utf8(&text)
        .ok()
        .and_then(|text| Digits::parse(text).ok())
        .ok_or(ErrorCode::Randomness)
}

#[cfg(test)]
mod tests {
    use super::MailboxBroker;
    use crate::config::Limits;
    use nsshared_proto::rendezvous::{
        error::ErrorCode,
        limits::{CLOSING_GRACE_SECONDS, INACTIVITY_SECONDS, MAX_DATA_BYTES},
        message::{Admission, Digits, Kind, MailboxId, OpenRequest, Stage},
        phase::Actor,
    };
    use rand_core::{Infallible, TryCryptoRng, TryRng};
    use std::collections::VecDeque;

    const NOW: u64 = 1_800_000_000;
    const OWNER: Actor = [1; 32];
    const ALICE: Actor = [2; 32];
    const BOB: Actor = [3; 32];

    /// Deterministic RNG: `next_u64` replays `words` (then counts up), `fill_bytes`
    /// writes a fresh counter byte so ids differ.
    struct TestRng {
        words: VecDeque<u64>,
        next_word: u64,
        next_byte: u8,
    }

    impl TestRng {
        fn new(words: &[u64]) -> Self {
            Self {
                words: words.iter().copied().collect(),
                next_word: 1000,
                next_byte: 0,
            }
        }
    }

    impl TryRng for TestRng {
        type Error = Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Infallible> {
            Ok(self.try_next_u64()? as u32)
        }

        fn try_next_u64(&mut self) -> Result<u64, Infallible> {
            Ok(self.words.pop_front().unwrap_or_else(|| {
                self.next_word += 1;
                self.next_word
            }))
        }

        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
            self.next_byte = self.next_byte.wrapping_add(1);
            dst.fill(self.next_byte);
            Ok(())
        }
    }

    impl TryCryptoRng for TestRng {}

    fn request(admission: Admission, candidates: u8, ttl: u64) -> OpenRequest {
        OpenRequest {
            kind: Kind::parse("pairing").unwrap(),
            ttl,
            admission,
            candidates,
            intro: b"owner intro".to_vec(),
        }
    }

    fn open(
        broker: &mut MailboxBroker,
        rng: &mut TestRng,
        admission: Admission,
    ) -> (MailboxId, Digits) {
        let candidates = if admission == Admission::First { 1 } else { 4 };
        let opened = broker
            .open(OWNER, &request(admission, candidates, 600), NOW, rng)
            .unwrap();
        (opened.id, opened.digits)
    }

    #[test]
    fn owner_admission_happy_path() {
        let mut broker = MailboxBroker::new(Limits::default());
        let mut rng = TestRng::new(&[42]);
        let (id, digits) = open(&mut broker, &mut rng, Admission::Owner);
        assert_eq!(digits.as_str(), "00000042");
        assert_eq!(broker.actor_mailboxes(&OWNER), 1);

        let found = broker.lookup(&digits, NOW).unwrap();
        assert_eq!(
            (found.id, found.intro.as_slice()),
            (id, b"owner intro".as_slice())
        );

        broker.join(ALICE, &id, b"alice".to_vec(), NOW).unwrap();
        broker.join(BOB, &id, b"bob".to_vec(), NOW).unwrap();
        assert_eq!(broker.actor_mailboxes(&BOB), 1);
        let view = broker.recv(&OWNER, &id, 0, NOW).unwrap();
        assert_eq!(view.waiting.len(), 2);

        broker.reject(&OWNER, &id, &BOB, NOW).unwrap();
        assert_eq!(broker.actor_mailboxes(&BOB), 0);
        broker.admit(&OWNER, &id, &ALICE, NOW).unwrap();
        assert_eq!(
            broker.lookup(&digits, NOW).unwrap_err(),
            ErrorCode::InvalidCode
        );

        assert_eq!(
            broker.send(&OWNER, &id, b"hi".to_vec(), NOW).unwrap().seq,
            1
        );
        assert_eq!(broker.queued_bytes(), 2);
        let view = broker.recv(&ALICE, &id, 0, NOW).unwrap();
        assert_eq!((view.stage, view.messages.len()), (Stage::Admitted, 1));
        broker.recv(&ALICE, &id, 1, NOW).unwrap();
        assert_eq!(broker.queued_bytes(), 0);

        // The owner has nothing left to drain: seeing `closing` removes the mailbox.
        broker.close(&ALICE, &id, NOW).unwrap();
        assert_eq!(
            broker.recv(&OWNER, &id, 0, NOW).unwrap().stage,
            Stage::Closing
        );
        assert!(broker.is_empty());
        assert_eq!(broker.actor_mailboxes(&OWNER), 0);
        assert_eq!(broker.actor_mailboxes(&ALICE), 0);
        assert_eq!(
            broker.recv(&OWNER, &id, 0, NOW).unwrap_err(),
            ErrorCode::UnknownMailbox
        );
    }

    #[test]
    fn first_admission_happy_path() {
        let mut broker = MailboxBroker::new(Limits::default());
        let mut rng = TestRng::new(&[]);
        let (id, digits) = open(&mut broker, &mut rng, Admission::First);
        assert_eq!(broker.lookup(&digits, NOW).unwrap().id, id);

        broker.join(ALICE, &id, Vec::new(), NOW).unwrap();
        assert_eq!(
            broker.lookup(&digits, NOW).unwrap_err(),
            ErrorCode::InvalidCode
        );
        assert_eq!(broker.recv(&OWNER, &id, 0, NOW).unwrap().peer, Some(ALICE));

        assert_eq!(broker.send(&ALICE, &id, b"x".to_vec(), NOW).unwrap().seq, 1);
        assert_eq!(broker.recv(&OWNER, &id, 0, NOW).unwrap().messages.len(), 1);

        // An evicted peer restores the same digits.
        broker.reject(&OWNER, &id, &ALICE, NOW).unwrap();
        assert_eq!(broker.queued_bytes(), 0);
        assert_eq!(broker.actor_mailboxes(&ALICE), 0);
        assert_eq!(broker.lookup(&digits, NOW).unwrap().id, id);

        broker.close(&OWNER, &id, NOW).unwrap();
        assert!(broker.is_empty());
        assert_eq!(
            broker.lookup(&digits, NOW).unwrap_err(),
            ErrorCode::InvalidCode
        );
    }

    #[test]
    fn digits_collision_is_retried() {
        let mut broker = MailboxBroker::new(Limits::default());
        let mut rng = TestRng::new(&[7, 100_000_007, 8]);
        let (_, first) = open(&mut broker, &mut rng, Admission::Owner);
        let (_, second) = open(&mut broker, &mut rng, Admission::First);
        assert_eq!(first.as_str(), "00000007");
        assert_eq!(second.as_str(), "00000008");
    }

    #[test]
    fn endless_collisions_are_a_randomness_error() {
        let mut broker = MailboxBroker::new(Limits::default());
        let mut rng = TestRng::new(&[7; 17]);
        open(&mut broker, &mut rng, Admission::Owner);
        assert_eq!(
            broker
                .open(ALICE, &request(Admission::First, 1, 600), NOW, &mut rng)
                .unwrap_err(),
            ErrorCode::Randomness
        );
    }

    #[test]
    fn per_actor_cap_is_capacity() {
        let limits = Limits {
            mailboxes_per_actor: 2,
            ..Limits::default()
        };
        let mut broker = MailboxBroker::new(limits);
        let mut rng = TestRng::new(&[]);
        let (a, _) = open(&mut broker, &mut rng, Admission::Owner);
        let (b, _) = open(&mut broker, &mut rng, Admission::Owner);
        assert_eq!(
            broker
                .open(OWNER, &request(Admission::Owner, 4, 600), NOW, &mut rng)
                .unwrap_err(),
            ErrorCode::Capacity
        );

        broker.join(ALICE, &a, Vec::new(), NOW).unwrap();
        broker.join(ALICE, &b, Vec::new(), NOW).unwrap();
        let c = broker
            .open(BOB, &request(Admission::Owner, 4, 600), NOW, &mut rng)
            .unwrap()
            .id;
        assert_eq!(
            broker.join(ALICE, &c, Vec::new(), NOW).unwrap_err(),
            ErrorCode::Capacity
        );

        // Leaving frees the place.
        broker.close(&ALICE, &a, NOW).unwrap();
        broker.join(ALICE, &c, Vec::new(), NOW).unwrap();
        assert_eq!(broker.actor_mailboxes(&ALICE), 2);
    }

    #[test]
    fn stored_mailbox_cap_is_capacity() {
        let limits = Limits {
            mailboxes: 1,
            ..Limits::default()
        };
        let mut broker = MailboxBroker::new(limits);
        let mut rng = TestRng::new(&[]);
        let (id, _) = open(&mut broker, &mut rng, Admission::Owner);
        assert_eq!(
            broker
                .open(ALICE, &request(Admission::First, 1, 600), NOW, &mut rng)
                .unwrap_err(),
            ErrorCode::Capacity
        );
        broker.close(&OWNER, &id, NOW).unwrap();
        broker
            .open(ALICE, &request(Admission::First, 1, 600), NOW, &mut rng)
            .unwrap();
    }

    #[test]
    fn global_queued_bytes_is_queue_full() {
        let limits = Limits {
            queued_bytes: MAX_DATA_BYTES + 1,
            ..Limits::default()
        };
        let mut broker = MailboxBroker::new(limits);
        let mut rng = TestRng::new(&[]);
        let (id, _) = open(&mut broker, &mut rng, Admission::First);
        broker.join(ALICE, &id, Vec::new(), NOW).unwrap();
        broker
            .send(&OWNER, &id, vec![0; MAX_DATA_BYTES], NOW)
            .unwrap();
        assert_eq!(
            broker.send(&ALICE, &id, vec![0; 2], NOW).unwrap_err(),
            ErrorCode::QueueFull
        );
        broker.send(&ALICE, &id, vec![0; 1], NOW).unwrap();
        assert_eq!(broker.queued_bytes(), MAX_DATA_BYTES + 1);

        broker.recv(&ALICE, &id, 1, NOW).unwrap();
        assert_eq!(broker.queued_bytes(), 1);
        broker.send(&OWNER, &id, vec![0; 2], NOW).unwrap();
    }

    #[test]
    fn sweep_removes_after_expiry() {
        let mut broker = MailboxBroker::new(Limits::default());
        let mut rng = TestRng::new(&[]);
        let opened = broker
            .open(OWNER, &request(Admission::First, 1, 60), NOW, &mut rng)
            .unwrap();
        broker.join(ALICE, &opened.id, Vec::new(), NOW).unwrap();
        broker
            .send(&ALICE, &opened.id, vec![1; 5], NOW + 30)
            .unwrap();
        broker.recv(&OWNER, &opened.id, 0, NOW + 30).unwrap();

        assert_eq!(broker.sweep(NOW + 59), 0);
        assert_eq!(broker.sweep(NOW + 60), 1);
        assert!(broker.is_empty());
        assert_eq!(broker.queued_bytes(), 0);
        assert_eq!(broker.actor_mailboxes(&OWNER), 0);
        assert_eq!(broker.actor_mailboxes(&ALICE), 0);
    }

    #[test]
    fn sweep_removes_after_inactivity() {
        let mut broker = MailboxBroker::new(Limits::default());
        let mut rng = TestRng::new(&[]);
        let (id, digits) = open(&mut broker, &mut rng, Admission::Owner);
        let (other, _) = open(&mut broker, &mut rng, Admission::Owner);
        broker.recv(&OWNER, &other, 0, NOW + 100).unwrap();

        assert_eq!(broker.sweep(NOW + INACTIVITY_SECONDS - 1), 0);
        assert_eq!(broker.sweep(NOW + INACTIVITY_SECONDS), 1);
        assert_eq!(broker.len(), 1);
        assert_eq!(
            broker
                .lookup(&digits, NOW + INACTIVITY_SECONDS)
                .unwrap_err(),
            ErrorCode::InvalidCode
        );
        assert_eq!(
            broker.subscribe(&id).unwrap_err(),
            ErrorCode::UnknownMailbox
        );
        assert_eq!(broker.actor_mailboxes(&OWNER), 1);
    }

    #[test]
    fn closing_grace_period_is_swept() {
        let mut broker = MailboxBroker::new(Limits::default());
        let mut rng = TestRng::new(&[]);
        let (id, _) = open(&mut broker, &mut rng, Admission::First);
        broker.join(ALICE, &id, Vec::new(), NOW).unwrap();
        broker.send(&OWNER, &id, vec![1], NOW).unwrap();
        broker.close(&OWNER, &id, NOW).unwrap();
        assert_eq!(broker.sweep(NOW + CLOSING_GRACE_SECONDS - 1), 0);
        assert_eq!(broker.sweep(NOW + CLOSING_GRACE_SECONDS), 1);
        assert_eq!(broker.queued_bytes(), 0);
    }

    #[test]
    fn change_signal_fires_on_changes() {
        let mut broker = MailboxBroker::new(Limits::default());
        let mut rng = TestRng::new(&[]);
        let (id, _) = open(&mut broker, &mut rng, Admission::Owner);
        let mut changes = broker.subscribe(&id).unwrap();
        assert!(!changes.has_changed().unwrap());

        broker.join(ALICE, &id, Vec::new(), NOW).unwrap();
        assert!(changes.has_changed().unwrap());
        changes.mark_unchanged();

        broker.recv(&OWNER, &id, 0, NOW).unwrap();
        assert!(!changes.has_changed().unwrap());

        broker.admit(&OWNER, &id, &ALICE, NOW).unwrap();
        assert!(changes.has_changed().unwrap());
        changes.mark_unchanged();

        broker.send(&ALICE, &id, b"x".to_vec(), NOW).unwrap();
        assert!(changes.has_changed().unwrap());
        changes.mark_unchanged();

        broker.close(&ALICE, &id, NOW).unwrap();
        assert!(changes.has_changed().unwrap());
        changes.mark_unchanged();

        // A repeated close changes nothing.
        broker.close(&ALICE, &id, NOW).unwrap();
        assert!(!changes.has_changed().unwrap());

        broker.sweep(NOW + CLOSING_GRACE_SECONDS);
        // The final bump is visible, then the sender is gone.
        assert_eq!(*changes.borrow_and_update(), 5);
        assert!(changes.has_changed().is_err());
    }

    #[test]
    fn drained_closing_is_removed_on_acknowledgement() {
        let mut broker = MailboxBroker::new(Limits::default());
        let mut rng = TestRng::new(&[]);
        let (id, _) = open(&mut broker, &mut rng, Admission::First);
        broker.join(ALICE, &id, Vec::new(), NOW).unwrap();
        broker.send(&OWNER, &id, vec![1, 2, 3], NOW).unwrap();
        broker.close(&OWNER, &id, NOW).unwrap();
        let changes = broker.subscribe(&id).unwrap();

        let view = broker.recv(&ALICE, &id, 0, NOW).unwrap();
        assert_eq!((view.stage, view.messages.len()), (Stage::Closing, 1));
        assert_eq!(broker.len(), 1);
        broker.recv(&ALICE, &id, 1, NOW).unwrap();
        assert!(broker.is_empty());
        assert_eq!(broker.queued_bytes(), 0);
        assert!(changes.has_changed().is_err());
    }

    #[test]
    fn unknown_ids() {
        let mut broker = MailboxBroker::new(Limits::default());
        let id = MailboxId([0; 16]);
        assert_eq!(
            broker.join(ALICE, &id, Vec::new(), NOW),
            Err(ErrorCode::UnknownMailbox)
        );
        assert_eq!(
            broker.admit(&OWNER, &id, &ALICE, NOW),
            Err(ErrorCode::UnknownMailbox)
        );
        assert_eq!(
            broker.reject(&OWNER, &id, &ALICE, NOW),
            Err(ErrorCode::UnknownMailbox)
        );
        assert_eq!(
            broker.send(&OWNER, &id, Vec::new(), NOW).unwrap_err(),
            ErrorCode::UnknownMailbox
        );
        assert_eq!(
            broker.recv(&OWNER, &id, 0, NOW).unwrap_err(),
            ErrorCode::UnknownMailbox
        );
        assert_eq!(
            broker.close(&OWNER, &id, NOW),
            Err(ErrorCode::UnknownMailbox)
        );
        assert_eq!(
            broker.subscribe(&id).unwrap_err(),
            ErrorCode::UnknownMailbox
        );
    }

    #[test]
    fn phase_errors_pass_through() {
        let mut broker = MailboxBroker::new(Limits::default());
        let mut rng = TestRng::new(&[]);
        let (id, _) = open(&mut broker, &mut rng, Admission::Owner);
        assert_eq!(
            broker.join(OWNER, &id, Vec::new(), NOW),
            Err(ErrorCode::NotPermitted)
        );
        assert_eq!(
            broker.admit(&ALICE, &id, &BOB, NOW),
            Err(ErrorCode::NotPermitted)
        );
        assert_eq!(
            broker.send(&OWNER, &id, Vec::new(), NOW).unwrap_err(),
            ErrorCode::WrongStage
        );
        assert_eq!(
            broker
                .open(OWNER, &request(Admission::First, 2, 600), NOW, &mut rng)
                .unwrap_err(),
            ErrorCode::InvalidMessage
        );
        assert_eq!(broker.len(), 1);
        assert_eq!(broker.actor_mailboxes(&OWNER), 1);
    }
}
