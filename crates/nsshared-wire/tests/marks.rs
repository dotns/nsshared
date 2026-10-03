//! Record ordering and conflicts: quick-v2 §3.3.

#![allow(clippy::unwrap_used, reason = "test fixture helpers")]

use ed25519_dalek::SigningKey;
use nsshared_wire::{
    IdentityMismatch, NodeRecord, NodeRecordFields, RecordDecision, RecordMarks, RelayId,
};
use proptest::prelude::*;

fn signer() -> SigningKey {
    SigningKey::from_bytes(&[7; 32])
}

fn record_with(generation: u64, key: u8, issued_at: u64, relays: &[&str]) -> NodeRecord {
    NodeRecord::sign(
        &signer(),
        NodeRecordFields {
            wg_key: [key; 32],
            generation,
            issued_at,
            expires: issued_at + 604_800,
            relays: relays
                .iter()
                .map(|text| RelayId::parse(text).unwrap())
                .collect(),
        },
    )
    .unwrap()
}

fn record(generation: u64, key: u8, issued_at: u64) -> NodeRecord {
    record_with(generation, key, issued_at, &[])
}

fn marks_at(record: &NodeRecord) -> RecordMarks {
    let mut marks = RecordMarks::new(*record.identity());
    assert_eq!(marks.apply(record), Ok(RecordDecision::Advanced));
    marks
}

/// Applies `candidate` after checking that `evaluate` agrees, returning the prior state.
fn step(marks: &mut RecordMarks, candidate: &NodeRecord, expected: RecordDecision) -> RecordMarks {
    let before = marks.clone();
    assert_eq!(marks.evaluate(candidate), Ok(expected));
    assert_eq!(*marks, before, "evaluate must not change state");
    assert_eq!(marks.apply(candidate), Ok(expected));
    before
}

#[test]
fn initial_state_accepts_the_first_record() {
    let first = record(3, 1, 100);
    let mut marks = RecordMarks::new(*first.identity());
    assert_eq!(marks.current(), None);
    assert_eq!(marks.committed_gen(), 0);
    assert!(!marks.is_conflicted());
    step(&mut marks, &first, RecordDecision::Advanced);
    assert_eq!(marks.current(), Some(&first));
    assert_eq!(marks.committed_gen(), 3);
    assert_eq!(marks.identity(), first.identity());
}

#[test]
fn refutation_row_1_lower_generation_is_rejected() {
    let mut marks = marks_at(&record(3, 1, 100));
    let before = step(&mut marks, &record(2, 2, 200), RecordDecision::Stale);
    assert_eq!(marks, before);
}

#[test]
fn refutation_row_2_higher_generation_replaces_and_clears_conflict() {
    let mut marks = marks_at(&record(3, 1, 100));
    step(&mut marks, &record(3, 2, 100), RecordDecision::Conflict);
    assert!(marks.is_conflicted());
    let next = record(4, 2, 50);
    step(&mut marks, &next, RecordDecision::Advanced);
    assert_eq!(marks.current(), Some(&next));
    assert_eq!(marks.committed_gen(), 4);
    assert!(!marks.is_conflicted());
}

#[test]
fn refutation_row_3_same_generation_other_key_latches_conflict() {
    let first = record(3, 1, 100);
    let mut marks = marks_at(&first);
    step(&mut marks, &record(3, 2, 50), RecordDecision::Conflict);
    assert!(marks.is_conflicted());
    assert_eq!(marks.current(), Some(&first));
    assert_eq!(marks.committed_gen(), 3);
    // Same-generation inputs keep the latch, whatever their key or issued_at.
    step(&mut marks, &record(3, 2, 500), RecordDecision::Conflict);
    step(&mut marks, &record(3, 9, 100), RecordDecision::Conflict);
    step(&mut marks, &record(3, 1, 100), RecordDecision::Unchanged);
    let refreshed = record(3, 1, 200);
    step(&mut marks, &refreshed, RecordDecision::Refreshed);
    assert!(marks.is_conflicted());
    assert_eq!(marks.current(), Some(&refreshed));
    step(&mut marks, &record(2, 1, 900), RecordDecision::Stale);
    assert!(marks.is_conflicted());
}

#[test]
fn refutation_row_4_same_key_larger_issued_at_replaces_bytes_only() {
    let mut marks = marks_at(&record(3, 1, 100));
    let refreshed = record_with(3, 1, 101, &["relay.example:51822"]);
    step(&mut marks, &refreshed, RecordDecision::Refreshed);
    assert_eq!(marks.current(), Some(&refreshed));
    assert_eq!(marks.committed_gen(), 3);
    assert!(!marks.is_conflicted());
}

#[test]
fn refutation_row_5_other_inputs_are_idempotent() {
    let first = record(3, 1, 100);
    let mut marks = marks_at(&first);
    for candidate in [
        first.clone(),
        record(3, 1, 99),
        record_with(3, 1, 100, &["relay.example:51822"]),
    ] {
        let before = step(&mut marks, &candidate, RecordDecision::Unchanged);
        assert_eq!(marks, before);
    }
}

#[test]
fn refutation_identity_mismatch() {
    let mut marks = RecordMarks::new([0; 32]);
    let before = marks.clone();
    let candidate = record(1, 1, 1);
    assert_eq!(marks.evaluate(&candidate), Err(IdentityMismatch));
    assert_eq!(marks.apply(&candidate), Err(IdentityMismatch));
    assert_eq!(marks, before);
}

/// A small input space so that equal generations, keys and issued_at values collide often.
fn arb_record() -> impl Strategy<Value = NodeRecord> {
    (1_u64..5, 0_u8..3, 0_u64..4, any::<bool>()).prop_map(|(generation, key, issued, relay)| {
        let relays: &[&str] = if relay { &["relay.example:1"] } else { &[] };
        record_with(generation, key, issued, relays)
    })
}

fn identity() -> [u8; 32] {
    signer().verifying_key().to_bytes()
}

proptest! {
    #[test]
    fn rejected_inputs_never_change_state(inputs in prop::collection::vec(arb_record(), 1..24)) {
        let mut marks = RecordMarks::new(identity());
        for candidate in &inputs {
            let before = marks.clone();
            let decision = marks.apply(candidate).unwrap();
            if matches!(decision, RecordDecision::Stale | RecordDecision::Unchanged) {
                prop_assert_eq!(&marks, &before);
            }
            let other = SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes();
            let mut foreign = RecordMarks::new(other);
            let foreign_before = foreign.clone();
            prop_assert_eq!(foreign.apply(candidate), Err(IdentityMismatch));
            prop_assert_eq!(foreign, foreign_before);
        }
    }

    #[test]
    fn committed_gen_is_monotone(inputs in prop::collection::vec(arb_record(), 1..24)) {
        let mut marks = RecordMarks::new(identity());
        for candidate in &inputs {
            let before = marks.committed_gen();
            marks.apply(candidate).unwrap();
            prop_assert!(marks.committed_gen() >= before);
            prop_assert_eq!(marks.committed_gen(), marks.current().map_or(0, NodeRecord::generation));
        }
    }

    #[test]
    fn conflict_latches_until_a_higher_generation(
        inputs in prop::collection::vec(arb_record(), 1..24),
    ) {
        let mut marks = RecordMarks::new(identity());
        for candidate in &inputs {
            let before = marks.clone();
            let decision = marks.apply(candidate).unwrap();
            if before.is_conflicted() && marks.committed_gen() == before.committed_gen() {
                prop_assert!(marks.is_conflicted());
            }
            if before.is_conflicted() && !marks.is_conflicted() {
                prop_assert_eq!(decision, RecordDecision::Advanced);
                prop_assert!(marks.committed_gen() > before.committed_gen());
            }
            if decision == RecordDecision::Conflict {
                prop_assert!(marks.is_conflicted());
            }
        }
    }

    #[test]
    fn distinct_generations_are_order_independent(
        generations in prop::collection::btree_set(1_u64..1_000, 1..8)
            .prop_map(|set| set.into_iter().collect::<Vec<_>>())
            .prop_shuffle(),
    ) {
        let records: Vec<NodeRecord> = generations
            .iter()
            .map(|&generation| record(generation, generation as u8, generation))
            .collect();
        let mut shuffled = RecordMarks::new(identity());
        for candidate in &records {
            shuffled.apply(candidate).unwrap();
        }
        let mut sorted_records = records.clone();
        sorted_records.sort_by_key(NodeRecord::generation);
        let mut sorted = RecordMarks::new(identity());
        for candidate in &sorted_records {
            sorted.apply(candidate).unwrap();
        }
        prop_assert_eq!(&shuffled, &sorted);
        prop_assert_eq!(shuffled.committed_gen(), generations.iter().copied().max().unwrap());
        prop_assert!(!shuffled.is_conflicted());
    }
}
