//! Mailbox model and phase rules: rendezvous §5.1-§5.3, §6.

#![allow(clippy::unwrap_used, reason = "test fixture helpers")]

use nsshared_proto::rendezvous::{
    error::ErrorCode,
    limits::{
        CLOSING_GRACE_SECONDS, INACTIVITY_SECONDS, MAX_DATA_BYTES, MAX_INTRO_BYTES,
        MAX_MAILBOX_BYTES, MAX_MAILBOX_MESSAGES, MAX_MAILBOXES, MAX_MAILBOXES_PER_ACTOR,
        MAX_PENDING_RECV, MAX_QUEUED_BYTES, MAX_REJECTED_ACTORS, MAX_UNACKED_BYTES,
        MAX_UNACKED_MESSAGES,
    },
    message::{Admission, Digits, Kind, MailboxId, OpenRequest, Stage},
    phase::{
        Actor, IndexChange, Mailbox, Outcome, check_actor_mailboxes, check_actor_mailboxes_within,
        check_pending_recv, check_pending_recv_within, check_queued_bytes,
        check_queued_bytes_within, check_stored_mailboxes, check_stored_mailboxes_within,
    },
};

const NOW: u64 = 1_800_000_000;
const ID: MailboxId = MailboxId([9; 16]);
const OWNER: Actor = [1; 32];
const ALICE: Actor = [2; 32];
const BOB: Actor = [3; 32];
const CAROL: Actor = [4; 32];
const MALLORY: Actor = [5; 32];

fn actor(n: u8) -> Actor {
    [n; 32]
}

fn digits() -> Digits {
    Digits::parse("01234567").unwrap()
}

fn request(admission: Admission, candidates: u8, ttl: u64, intro: usize) -> OpenRequest {
    OpenRequest {
        kind: Kind::parse("pairing").unwrap(),
        ttl,
        admission,
        candidates,
        intro: vec![0xaa; intro],
    }
}

fn open(admission: Admission, candidates: u8) -> Mailbox {
    Mailbox::open(
        OWNER,
        &request(admission, candidates, 900, 3),
        ID,
        digits(),
        NOW,
    )
    .unwrap()
}

/// An owner-admission mailbox with ALICE admitted as the peer.
fn admitted() -> Mailbox {
    let mut mailbox = open(Admission::Owner, 4);
    mailbox.join(ALICE, vec![], NOW).unwrap();
    mailbox.admit(&OWNER, &ALICE, NOW).unwrap();
    mailbox
}

fn outcome(wake: &[Actor], dropped: &[Actor], index: IndexChange, remove: bool) -> Outcome {
    Outcome {
        wake: wake.to_vec(),
        dropped: dropped.to_vec(),
        index,
        remove,
    }
}

#[test]
fn open_validates_the_request() {
    let rows = [
        (Admission::Owner, 4, 1, 0, true),
        (Admission::Owner, 4, 900, MAX_INTRO_BYTES, true),
        (Admission::First, 1, 60, 0, true),
        (Admission::Owner, 1, 60, 0, true),
        (Admission::Owner, 4, 0, 0, false),
        (Admission::Owner, 4, 901, 0, false),
        (Admission::Owner, 0, 60, 0, false),
        (Admission::Owner, 5, 60, 0, false),
        (Admission::First, 2, 60, 0, false),
        (Admission::Owner, 4, 60, MAX_INTRO_BYTES + 1, false),
    ];
    for (admission, candidates, ttl, intro, ok) in rows {
        let result = Mailbox::open(
            OWNER,
            &request(admission, candidates, ttl, intro),
            ID,
            digits(),
            NOW,
        );
        match result {
            Ok(mailbox) => {
                assert!(ok, "{admission:?} {candidates} {ttl} {intro}");
                assert_eq!(mailbox.expires(), NOW + ttl);
                assert_eq!(mailbox.stage(), Stage::Open);
                assert_eq!(mailbox.owner(), &OWNER);
                assert_eq!(mailbox.admission(), admission);
                assert_eq!(mailbox.candidates(), candidates);
                assert_eq!(mailbox.intro().len(), intro);
                assert_eq!(mailbox.id(), ID);
                assert_eq!(mailbox.kind().as_str(), "pairing");
                assert_eq!(mailbox.digits(), &digits());
                assert!(mailbox.peer().is_none());
                assert_eq!(mailbox.rejects(), 0);
                let found = mailbox.lookup_view(NOW).unwrap();
                assert_eq!(found.id, ID);
                assert_eq!(found.expires, NOW + ttl);
                assert_eq!(found.intro, mailbox.intro());
            }
            Err(code) => {
                assert!(!ok, "{admission:?} {candidates} {ttl} {intro}");
                assert_eq!(code, ErrorCode::InvalidMessage);
            }
        }
    }
    assert_eq!(
        Mailbox::open(
            OWNER,
            &request(Admission::Owner, 4, 900, 0),
            ID,
            digits(),
            u64::MAX
        )
        .unwrap_err(),
        ErrorCode::InvalidMessage
    );
}

#[test]
fn join_with_owner_admission() {
    let mut mailbox = open(Admission::Owner, 2);
    assert_eq!(
        mailbox.join(ALICE, vec![7], NOW).unwrap(),
        outcome(&[OWNER], &[], IndexChange::Unchanged, false)
    );
    assert_eq!(mailbox.stage(), Stage::Open);
    assert!(mailbox.lookup_view(NOW).is_some());

    let rows: [(Actor, usize, ErrorCode); 4] = [
        (OWNER, 0, ErrorCode::NotPermitted),
        (ALICE, 0, ErrorCode::Conflict),
        (BOB, MAX_INTRO_BYTES + 1, ErrorCode::InvalidMessage),
        (MALLORY, 0, ErrorCode::NotPermitted),
    ];
    mailbox.join(MALLORY, vec![], NOW).unwrap();
    mailbox.reject(&OWNER, &MALLORY, NOW).unwrap();
    for (joiner, intro, code) in rows {
        assert_eq!(mailbox.join(joiner, vec![0; intro], NOW), Err(code));
    }
    mailbox.join(BOB, vec![0; MAX_INTRO_BYTES], NOW).unwrap();
    assert_eq!(
        mailbox.join(CAROL, vec![], NOW),
        Err(ErrorCode::Capacity),
        "the waiting list holds `candidates` actors"
    );
    let waiting: Vec<Actor> = mailbox.waiting().iter().map(|w| w.actor).collect();
    assert_eq!(waiting, [ALICE, BOB]);
    assert_eq!(mailbox.waiting()[0].intro, [7]);
}

#[test]
fn join_with_first_admission() {
    let mut mailbox = open(Admission::First, 1);
    assert_eq!(
        mailbox.join(ALICE, vec![], NOW).unwrap(),
        outcome(&[OWNER], &[], IndexChange::Remove, false)
    );
    assert_eq!(mailbox.stage(), Stage::Admitted);
    assert_eq!(mailbox.peer(), Some(&ALICE));
    assert!(mailbox.waiting().is_empty());
    assert!(mailbox.lookup_view(NOW).is_none());
    assert_eq!(mailbox.join(BOB, vec![], NOW), Err(ErrorCode::WrongStage));
    assert_eq!(mailbox.join(ALICE, vec![], NOW), Err(ErrorCode::Conflict));
    assert_eq!(
        mailbox.join(OWNER, vec![], NOW),
        Err(ErrorCode::NotPermitted)
    );
    assert_eq!(mailbox.admit(&OWNER, &BOB, NOW), Err(ErrorCode::WrongStage));
}

#[test]
fn join_outside_open_is_wrong_stage() {
    let mut mailbox = admitted();
    assert_eq!(mailbox.join(BOB, vec![], NOW), Err(ErrorCode::WrongStage));
    mailbox.close(&OWNER, NOW).unwrap();
    assert_eq!(mailbox.join(BOB, vec![], NOW), Err(ErrorCode::WrongStage));
}

#[test]
fn admit_makes_the_peer_and_drops_the_others() {
    let mut mailbox = open(Admission::Owner, 4);
    for joiner in [ALICE, BOB, CAROL] {
        mailbox.join(joiner, vec![], NOW).unwrap();
    }
    let rows: [(Actor, Actor, ErrorCode); 4] = [
        (ALICE, BOB, ErrorCode::NotPermitted),
        (MALLORY, BOB, ErrorCode::NotPermitted),
        (OWNER, MALLORY, ErrorCode::NotPermitted),
        (OWNER, OWNER, ErrorCode::NotPermitted),
    ];
    for (by, target, code) in rows {
        assert_eq!(mailbox.admit(&by, &target, NOW), Err(code));
    }
    assert_eq!(
        mailbox.admit(&OWNER, &BOB, NOW).unwrap(),
        outcome(&[BOB], &[ALICE, CAROL], IndexChange::Remove, false)
    );
    assert_eq!(mailbox.stage(), Stage::Admitted);
    assert_eq!(mailbox.peer(), Some(&BOB));
    assert!(mailbox.waiting().is_empty());
    assert!(mailbox.lookup_view(NOW).is_none());
    assert_eq!(
        mailbox.recv(&ALICE, 0, NOW),
        Err(ErrorCode::NotPermitted),
        "a dropped candidate has no access"
    );
    assert_eq!(
        mailbox.admit(&OWNER, &ALICE, NOW),
        Err(ErrorCode::WrongStage)
    );
}

#[test]
fn reject_records_a_candidate() {
    let mut mailbox = open(Admission::Owner, 4);
    mailbox.join(ALICE, vec![], NOW).unwrap();
    mailbox.join(BOB, vec![], NOW).unwrap();
    let rows: [(Actor, Actor, ErrorCode); 3] = [
        (BOB, ALICE, ErrorCode::NotPermitted),
        (MALLORY, ALICE, ErrorCode::NotPermitted),
        (OWNER, MALLORY, ErrorCode::NotPermitted),
    ];
    for (by, target, code) in rows {
        assert_eq!(mailbox.reject(&by, &target, NOW), Err(code));
    }
    assert_eq!(
        mailbox.reject(&OWNER, &ALICE, NOW).unwrap(),
        outcome(&[], &[ALICE], IndexChange::Unchanged, false)
    );
    assert_eq!(mailbox.rejected(), [ALICE]);
    assert_eq!(mailbox.waiting().len(), 1);
    assert_eq!(mailbox.recv(&ALICE, 0, NOW), Err(ErrorCode::NotPermitted));
    assert_eq!(
        mailbox.join(ALICE, vec![], NOW),
        Err(ErrorCode::NotPermitted),
        "a rejected actor cannot join again until expiry"
    );
    mailbox.recv(&OWNER, 0, NOW + 150).unwrap();
    assert_eq!(
        mailbox.join(ALICE, vec![], NOW + 300),
        Err(ErrorCode::NotPermitted)
    );
}

#[test]
fn rejected_set_is_bounded() {
    let mut mailbox = open(Admission::Owner, 4);
    for n in 0..MAX_REJECTED_ACTORS {
        let candidate = actor(100 + u8::try_from(n).unwrap());
        mailbox.join(candidate, vec![], NOW).unwrap();
        mailbox.reject(&OWNER, &candidate, NOW).unwrap();
    }
    assert_eq!(mailbox.rejected().len(), MAX_REJECTED_ACTORS);
    mailbox.join(ALICE, vec![], NOW).unwrap();
    assert_eq!(
        mailbox.reject(&OWNER, &ALICE, NOW),
        Err(ErrorCode::Capacity)
    );
    assert_eq!(
        mailbox.waiting().len(),
        1,
        "a refused reject changes nothing"
    );
    assert_eq!(mailbox.rejected().len(), MAX_REJECTED_ACTORS);
}

#[test]
fn reject_evicts_the_peer_and_restores_the_digits() {
    let mut mailbox = admitted();
    mailbox.send(&OWNER, vec![1; 10], NOW).unwrap();
    mailbox.send(&ALICE, vec![2; 20], NOW).unwrap();
    assert_eq!(mailbox.queued_bytes(), 30);
    assert_eq!(
        mailbox.reject(&OWNER, &ALICE, NOW).unwrap(),
        outcome(&[], &[ALICE], IndexChange::Add, false)
    );
    assert_eq!(mailbox.stage(), Stage::Open);
    assert!(mailbox.peer().is_none());
    assert_eq!(mailbox.rejects(), 1);
    assert_eq!(mailbox.queued_bytes(), 0, "both queues are cleared");
    assert_eq!(mailbox.digits(), &digits(), "the same digits are restored");
    assert!(mailbox.lookup_view(NOW).is_some());
    assert!(
        mailbox.rejected().is_empty(),
        "an evicted peer is not recorded"
    );
    assert_eq!(mailbox.recv(&ALICE, 0, NOW), Err(ErrorCode::NotPermitted));
    let view = mailbox.recv(&OWNER, 1, NOW).unwrap();
    assert!(view.messages.is_empty());
    assert!(view.peer.is_none());

    mailbox.join(ALICE, vec![], NOW).unwrap();
    mailbox.admit(&OWNER, &ALICE, NOW).unwrap();
    let (sent, _) = mailbox.send(&OWNER, vec![3], NOW).unwrap();
    assert_eq!(
        sent.seq, 2,
        "sequence numbers keep counting after an eviction"
    );
}

#[test]
fn third_eviction_closes_the_mailbox() {
    let mut mailbox = admitted();
    for evictions in 1..=2 {
        assert_eq!(
            mailbox.reject(&OWNER, &ALICE, NOW).unwrap().index,
            IndexChange::Add
        );
        assert_eq!(mailbox.rejects(), evictions);
        mailbox.join(ALICE, vec![], NOW).unwrap();
        mailbox.admit(&OWNER, &ALICE, NOW).unwrap();
    }
    assert_eq!(
        mailbox.reject(&OWNER, &ALICE, NOW).unwrap(),
        outcome(&[], &[ALICE], IndexChange::Unchanged, true)
    );
    assert_eq!(mailbox.rejects(), 3);
}

#[test]
fn reject_of_a_closing_peer_is_wrong_stage() {
    let mut mailbox = admitted();
    mailbox.close(&ALICE, NOW).unwrap();
    assert_eq!(
        mailbox.reject(&OWNER, &ALICE, NOW),
        Err(ErrorCode::WrongStage)
    );
    assert_eq!(
        mailbox.reject(&ALICE, &OWNER, NOW),
        Err(ErrorCode::NotPermitted)
    );
}

#[test]
fn send_is_admitted_only_and_counts_per_direction() {
    let mut mailbox = open(Admission::Owner, 4);
    mailbox.join(ALICE, vec![], NOW).unwrap();
    assert_eq!(
        mailbox.send(&OWNER, vec![1], NOW),
        Err(ErrorCode::WrongStage)
    );
    assert_eq!(
        mailbox.send(&ALICE, vec![1], NOW),
        Err(ErrorCode::NotPermitted)
    );
    mailbox.admit(&OWNER, &ALICE, NOW).unwrap();
    let rows: [(Actor, usize, Result<u64, ErrorCode>); 6] = [
        (OWNER, 1, Ok(1)),
        (OWNER, MAX_DATA_BYTES, Ok(2)),
        (ALICE, 0, Ok(1)),
        (OWNER, MAX_DATA_BYTES + 1, Err(ErrorCode::InvalidMessage)),
        (MALLORY, 1, Err(ErrorCode::NotPermitted)),
        (ALICE, 1, Ok(2)),
    ];
    for (by, len, expected) in rows {
        let result = mailbox.send(&by, vec![0; len], NOW).map(|(sent, outcome)| {
            let recipient = if by == OWNER { ALICE } else { OWNER };
            assert_eq!(outcome, outcome_wake(recipient));
            sent.seq
        });
        assert_eq!(result, expected);
    }
    mailbox.close(&OWNER, NOW).unwrap();
    assert_eq!(
        mailbox.send(&OWNER, vec![1], NOW),
        Err(ErrorCode::WrongStage)
    );
    assert_eq!(
        mailbox.send(&ALICE, vec![1], NOW),
        Err(ErrorCode::WrongStage)
    );
}

fn outcome_wake(actor: Actor) -> Outcome {
    outcome(&[actor], &[], IndexChange::Unchanged, false)
}

#[test]
fn unacknowledged_message_limit_per_direction() {
    let mut mailbox = admitted();
    for _ in 0..MAX_UNACKED_MESSAGES {
        mailbox.send(&OWNER, vec![1], NOW).unwrap();
    }
    assert_eq!(
        mailbox.send(&OWNER, vec![1], NOW),
        Err(ErrorCode::QueueFull)
    );
    mailbox.send(&ALICE, vec![1], NOW).unwrap();
    mailbox.recv(&ALICE, 1, NOW).unwrap();
    let (sent, _) = mailbox.send(&OWNER, vec![1], NOW).unwrap();
    assert_eq!(sent.seq, 17);
}

#[test]
fn unacknowledged_byte_limit_per_direction() {
    let mut mailbox = admitted();
    for _ in 0..MAX_UNACKED_BYTES / MAX_DATA_BYTES {
        mailbox.send(&ALICE, vec![0; MAX_DATA_BYTES], NOW).unwrap();
    }
    assert_eq!(mailbox.queued_bytes(), MAX_UNACKED_BYTES);
    assert_eq!(
        mailbox.send(&ALICE, vec![0], NOW),
        Err(ErrorCode::QueueFull)
    );
    mailbox.send(&ALICE, vec![], NOW).unwrap();
    mailbox.send(&OWNER, vec![0; MAX_DATA_BYTES], NOW).unwrap();
    mailbox.recv(&OWNER, 1, NOW).unwrap();
    assert_eq!(mailbox.queued_bytes(), MAX_UNACKED_BYTES);
    mailbox.send(&ALICE, vec![0; MAX_DATA_BYTES], NOW).unwrap();
}

#[test]
fn cumulative_message_limit_per_mailbox() {
    let mut mailbox = admitted();
    for n in 1..=MAX_MAILBOX_MESSAGES as u64 {
        let by = if n % 2 == 0 { OWNER } else { ALICE };
        mailbox.send(&by, vec![1], NOW).unwrap();
        mailbox.recv(&OWNER, mailbox_seq_to_owner(n), NOW).unwrap();
        mailbox.recv(&ALICE, n / 2, NOW).unwrap();
    }
    assert_eq!(mailbox.queued_bytes(), 0);
    assert_eq!(
        mailbox.send(&OWNER, vec![1], NOW),
        Err(ErrorCode::QueueFull)
    );
    assert_eq!(mailbox.send(&ALICE, vec![], NOW), Err(ErrorCode::QueueFull));
}

/// Messages ALICE sent after `n` alternating sends starting with ALICE.
fn mailbox_seq_to_owner(n: u64) -> u64 {
    n.div_ceil(2)
}

#[test]
fn cumulative_byte_limit_per_mailbox() {
    let mut mailbox = admitted();
    for n in 1..=(MAX_MAILBOX_BYTES / MAX_DATA_BYTES) as u64 {
        mailbox.send(&OWNER, vec![0; MAX_DATA_BYTES], NOW).unwrap();
        mailbox.recv(&ALICE, n, NOW).unwrap();
    }
    assert_eq!(mailbox.queued_bytes(), 0);
    assert_eq!(
        mailbox.send(&ALICE, vec![0], NOW),
        Err(ErrorCode::QueueFull)
    );
    mailbox.send(&ALICE, vec![], NOW).unwrap();
}

#[test]
fn recv_views_by_role() {
    let mut mailbox = open(Admission::Owner, 4);
    mailbox.join(ALICE, vec![1], NOW).unwrap();
    mailbox.join(BOB, vec![2], NOW).unwrap();

    let owner = mailbox.recv(&OWNER, 0, NOW).unwrap();
    assert_eq!(owner.stage, Stage::Open);
    assert_eq!(owner.waiting.len(), 2);
    let candidate = mailbox.recv(&ALICE, 0, NOW).unwrap();
    assert!(
        candidate.waiting.is_empty(),
        "candidates see an empty waiting"
    );
    assert!(candidate.messages.is_empty());
    assert!(candidate.peer.is_none());
    assert_eq!(mailbox.recv(&MALLORY, 0, NOW), Err(ErrorCode::NotPermitted));
    assert_eq!(
        mailbox.recv(&OWNER, 1, NOW),
        Err(ErrorCode::InvalidMessage),
        "nothing was ever sent to the owner"
    );

    mailbox.admit(&OWNER, &ALICE, NOW).unwrap();
    for data in [[1], [2], [3]] {
        mailbox.send(&OWNER, data.to_vec(), NOW).unwrap();
    }
    mailbox.send(&ALICE, vec![9], NOW).unwrap();
    assert_eq!(mailbox.queued_bytes(), 4);

    let peer = mailbox.recv(&ALICE, 0, NOW).unwrap();
    assert!(peer.waiting.is_empty());
    assert_eq!(peer.peer, Some(ALICE));
    let seqs: Vec<u64> = peer.messages.iter().map(|m| m.seq).collect();
    assert_eq!(seqs, [1, 2, 3], "only messages addressed to the requester");

    let peer = mailbox.recv(&ALICE, 2, NOW).unwrap();
    assert_eq!(peer.messages.len(), 1);
    assert_eq!(peer.messages[0].seq, 3);
    assert_eq!(peer.messages[0].data, [3]);
    assert_eq!(
        mailbox.queued_bytes(),
        2,
        "acknowledged messages are deleted"
    );
    let peer = mailbox.recv(&ALICE, 0, NOW).unwrap();
    assert_eq!(peer.messages.len(), 1, "deleted messages never come back");
    assert_eq!(mailbox.recv(&ALICE, 4, NOW), Err(ErrorCode::InvalidMessage));

    let owner = mailbox.recv(&OWNER, 1, NOW).unwrap();
    assert!(owner.messages.is_empty());
    assert!(owner.waiting.is_empty());
    assert_eq!(mailbox.queued_bytes(), 1);
}

#[test]
fn candidate_close_removes_only_itself() {
    let mut mailbox = open(Admission::Owner, 4);
    mailbox.join(ALICE, vec![], NOW).unwrap();
    mailbox.join(BOB, vec![], NOW).unwrap();
    assert_eq!(mailbox.close(&ALICE, NOW).unwrap(), outcome_wake(OWNER));
    let waiting: Vec<Actor> = mailbox.waiting().iter().map(|w| w.actor).collect();
    assert_eq!(waiting, [BOB]);
    assert_eq!(mailbox.stage(), Stage::Open);
    assert!(mailbox.rejected().is_empty());
    assert_eq!(mailbox.close(&ALICE, NOW), Err(ErrorCode::NotPermitted));
    assert_eq!(mailbox.close(&MALLORY, NOW), Err(ErrorCode::NotPermitted));
    mailbox.join(ALICE, vec![], NOW).unwrap();
}

#[test]
fn owner_close_of_an_open_mailbox_removes_it() {
    let mut mailbox = open(Admission::Owner, 4);
    mailbox.join(ALICE, vec![], NOW).unwrap();
    assert_eq!(
        mailbox.close(&OWNER, NOW).unwrap(),
        outcome(&[], &[ALICE], IndexChange::Remove, true)
    );
}

#[test]
fn closing_drains_then_removes_on_acknowledgement() {
    let mut mailbox = admitted();
    mailbox.send(&OWNER, vec![1], NOW).unwrap();
    mailbox.send(&OWNER, vec![2], NOW).unwrap();
    assert_eq!(mailbox.close(&OWNER, NOW).unwrap(), outcome_wake(ALICE));
    assert_eq!(mailbox.stage(), Stage::Closing);
    assert!(mailbox.lookup_view(NOW).is_none());
    assert_eq!(
        mailbox.close(&OWNER, NOW).unwrap(),
        Outcome::default(),
        "a repeated close changes nothing"
    );

    let view = mailbox.recv(&ALICE, 0, NOW + 1).unwrap();
    assert_eq!(view.stage, Stage::Closing);
    assert_eq!(view.messages.len(), 2);
    assert!(!mailbox.removal_due(NOW + 1));
    let view = mailbox.recv(&ALICE, 1, NOW + 2).unwrap();
    assert_eq!(view.messages.len(), 1);
    assert!(!mailbox.removal_due(NOW + 2));
    let view = mailbox.recv(&OWNER, 0, NOW + 2).unwrap();
    assert_eq!(view.stage, Stage::Closing);
    assert!(
        !mailbox.removal_due(NOW + 2),
        "the closer's recv does not drain"
    );
    let view = mailbox.recv(&ALICE, 2, NOW + 3).unwrap();
    assert!(view.messages.is_empty());
    assert_eq!(view.stage, Stage::Closing);
    assert!(
        mailbox.removal_due(NOW + 3),
        "the last message is acknowledged"
    );
    assert_eq!(
        mailbox.recv(&ALICE, 2, NOW + 3),
        Err(ErrorCode::UnknownMailbox)
    );
}

#[test]
fn closing_with_an_empty_queue_shows_closing_once() {
    let mut mailbox = admitted();
    mailbox.close(&ALICE, NOW).unwrap();
    assert!(!mailbox.removal_due(NOW));
    let view = mailbox.recv(&OWNER, 0, NOW).unwrap();
    assert_eq!(view.stage, Stage::Closing);
    assert!(mailbox.removal_due(NOW));
}

#[test]
fn closing_removes_when_the_other_side_closes() {
    let mut mailbox = admitted();
    mailbox.send(&ALICE, vec![1], NOW).unwrap();
    assert_eq!(mailbox.close(&ALICE, NOW).unwrap(), outcome_wake(OWNER));
    assert_eq!(
        mailbox.close(&OWNER, NOW).unwrap(),
        outcome(&[], &[ALICE], IndexChange::Unchanged, true)
    );
}

#[test]
fn closing_removes_after_the_grace_period() {
    let mut mailbox = admitted();
    mailbox.send(&OWNER, vec![1], NOW).unwrap();
    mailbox.close(&OWNER, NOW).unwrap();
    let last = NOW + CLOSING_GRACE_SECONDS - 1;
    mailbox.recv(&ALICE, 0, last).unwrap();
    assert!(!mailbox.removal_due(last));
    assert!(mailbox.removal_due(NOW + CLOSING_GRACE_SECONDS));
    assert_eq!(
        mailbox.recv(&ALICE, 1, NOW + CLOSING_GRACE_SECONDS),
        Err(ErrorCode::UnknownMailbox)
    );
}

#[test]
fn inactivity_removes_the_mailbox() {
    let limit = NOW + INACTIVITY_SECONDS;

    let mut mailbox = open(Admission::Owner, 4);
    mailbox.join(ALICE, vec![], limit - 1).unwrap();
    mailbox.recv(&ALICE, 0, limit - 1).unwrap();
    assert!(!mailbox.removal_due(limit - 1));
    assert!(
        mailbox.removal_due(limit),
        "candidate activity does not keep the mailbox"
    );
    assert_eq!(
        mailbox.join(BOB, vec![], limit),
        Err(ErrorCode::UnknownMailbox)
    );
    assert!(mailbox.lookup_view(limit).is_none());

    let mut mailbox = admitted();
    mailbox.recv(&OWNER, 0, limit - 1).unwrap();
    assert!(mailbox.removal_due(limit), "the peer is inactive");

    let mut mailbox = admitted();
    mailbox.send(&ALICE, vec![1], limit - 1).unwrap();
    assert!(mailbox.removal_due(limit), "the owner is inactive");

    let mut mailbox = admitted();
    mailbox.recv(&OWNER, 0, limit - 1).unwrap();
    mailbox.recv(&ALICE, 0, limit - 1).unwrap();
    assert!(!mailbox.removal_due(limit));
    assert!(mailbox.removal_due(limit - 1 + INACTIVITY_SECONDS));
}

#[test]
fn absolute_expiry_removes_the_mailbox() {
    let mut mailbox = Mailbox::open(
        OWNER,
        &request(Admission::Owner, 4, 60, 0),
        ID,
        digits(),
        NOW,
    )
    .unwrap();
    let expires = NOW + 60;
    mailbox.recv(&OWNER, 0, expires - 1).unwrap();
    assert!(mailbox.lookup_view(expires - 1).is_some());
    assert!(!mailbox.removal_due(expires - 1));
    assert!(mailbox.removal_due(expires));
    assert!(mailbox.lookup_view(expires).is_none());
    let rows = [
        mailbox.join(ALICE, vec![], expires),
        mailbox.close(&OWNER, expires),
        mailbox.admit(&OWNER, &ALICE, expires),
        mailbox.reject(&OWNER, &ALICE, expires),
        mailbox.send(&OWNER, vec![], expires).map(|(_, o)| o),
        mailbox.recv(&OWNER, 0, expires).map(|_| Outcome::default()),
    ];
    for result in rows {
        assert_eq!(result, Err(ErrorCode::UnknownMailbox));
    }
}

#[test]
fn expires_never_changes() {
    let mut mailbox = open(Admission::Owner, 4);
    let expires = mailbox.expires();
    let mut t = NOW;
    let check = |mailbox: &Mailbox| assert_eq!(mailbox.expires(), expires);
    for step in 0..3u8 {
        t += 100;
        let _ = mailbox.lookup_view(t);
        let _ = mailbox.join(MALLORY, vec![], t);
        let _ = mailbox.join(OWNER, vec![], t);
        let guess = actor(50 + step);
        mailbox.join(guess, vec![], t).unwrap();
        mailbox.reject(&OWNER, &guess, t).unwrap();
        let _ = mailbox.join(guess, vec![], t);
        mailbox.join(ALICE, vec![], t).unwrap();
        mailbox.join(BOB, vec![], t).unwrap();
        mailbox.close(&BOB, t).unwrap();
        mailbox.recv(&OWNER, 0, t).unwrap();
        mailbox.admit(&OWNER, &ALICE, t).unwrap();
        check(&mailbox);
        mailbox.send(&OWNER, vec![1], t).unwrap();
        mailbox.send(&ALICE, vec![2], t).unwrap();
        mailbox.recv(&ALICE, 0, t).unwrap();
        let _ = mailbox.recv(&MALLORY, 0, t);
        check(&mailbox);
        if step < 2 {
            mailbox.reject(&OWNER, &ALICE, t).unwrap();
            check(&mailbox);
        }
    }
    mailbox.close(&ALICE, t).unwrap();
    check(&mailbox);
    mailbox.recv(&OWNER, 0, t).unwrap();
    check(&mailbox);
}

#[test]
fn broker_limits() {
    assert_eq!(check_stored_mailboxes(0), Ok(()));
    assert_eq!(check_stored_mailboxes(MAX_MAILBOXES - 1), Ok(()));
    assert_eq!(
        check_stored_mailboxes(MAX_MAILBOXES),
        Err(ErrorCode::Capacity)
    );

    assert_eq!(check_actor_mailboxes(MAX_MAILBOXES_PER_ACTOR - 1), Ok(()));
    assert_eq!(
        check_actor_mailboxes(MAX_MAILBOXES_PER_ACTOR),
        Err(ErrorCode::Capacity)
    );

    let rows = [
        (0, MAX_QUEUED_BYTES, Ok(())),
        (MAX_QUEUED_BYTES - 1, 1, Ok(())),
        (MAX_QUEUED_BYTES, 0, Ok(())),
        (MAX_QUEUED_BYTES, 1, Err(ErrorCode::QueueFull)),
        (usize::MAX, 1, Err(ErrorCode::QueueFull)),
    ];
    for (queued, additional, expected) in rows {
        assert_eq!(check_queued_bytes(queued, additional), expected);
    }

    let rows = [
        (0, 0, Ok(())),
        (0, MAX_PENDING_RECV - 1, Ok(())),
        (1, 0, Err(ErrorCode::Capacity)),
        (0, MAX_PENDING_RECV, Err(ErrorCode::Capacity)),
    ];
    for (on_connection, global, expected) in rows {
        assert_eq!(check_pending_recv(on_connection, global), expected);
    }
}

#[test]
fn broker_limits_within_a_configured_limit() {
    assert_eq!(check_stored_mailboxes_within(1, 2), Ok(()));
    assert_eq!(
        check_stored_mailboxes_within(2, 2),
        Err(ErrorCode::Capacity)
    );
    assert_eq!(
        check_stored_mailboxes_within(0, 0),
        Err(ErrorCode::Capacity)
    );

    assert_eq!(check_actor_mailboxes_within(0, 1), Ok(()));
    assert_eq!(check_actor_mailboxes_within(1, 1), Err(ErrorCode::Capacity));

    assert_eq!(check_queued_bytes_within(5, 5, 10), Ok(()));
    assert_eq!(
        check_queued_bytes_within(5, 6, 10),
        Err(ErrorCode::QueueFull)
    );
    assert_eq!(
        check_queued_bytes_within(usize::MAX, 1, usize::MAX),
        Err(ErrorCode::QueueFull)
    );

    assert_eq!(check_pending_recv_within(1, 7, 2, 8), Ok(()));
    assert_eq!(
        check_pending_recv_within(2, 0, 2, 8),
        Err(ErrorCode::Capacity)
    );
    assert_eq!(
        check_pending_recv_within(0, 8, 2, 8),
        Err(ErrorCode::Capacity)
    );
}

#[test]
fn digits_key_a_lookup_index_by_value() {
    let mut index = std::collections::HashMap::new();
    index.insert(Digits::parse("00000001").unwrap(), ID);
    assert_eq!(index.get(&Digits::parse("00000001").unwrap()), Some(&ID));
    assert_eq!(index.get(&Digits::parse("00000002").unwrap()), None);
}
