//! Region mark merge: quick-v2 §8.5 and quick-protocol §12.8 rule 2 without
//! `revoked_through`, plus the link to the per-identity record state of quick-v2 §3.3.

#![allow(clippy::unwrap_used, clippy::panic, reason = "test fixture helpers")]

use ed25519_dalek::SigningKey;
use ns_wire::{
    NodeRecord, NodeRecordFields, RecordMarks, RegionMarks, RegionMarksJoin,
    RegionMarksOwnerMismatch, join_region_marks,
};
use proptest::prelude::*;

const OWNER: [u8; 32] = [0x22; 32];

fn marks(generation: u64, key: u8, conflicted: bool, high_water: u64) -> RegionMarks {
    RegionMarks {
        identity: OWNER,
        committed_gen: generation,
        committed_key: [key; 32],
        conflicted,
        incarnation_high_water: high_water,
    }
}

fn join(current: RegionMarks, incoming: RegionMarks) -> RegionMarks {
    let RegionMarksJoin { state, changed } = join_region_marks(current, incoming).unwrap();
    assert_eq!(changed, state != current);
    state
}

#[test]
fn larger_generation_wins_with_all_its_fields() {
    let old = marks(4, 0x10, true, 90);
    let new = marks(5, 0x30, false, 1);
    assert_eq!(join(old, new), new);
    assert_eq!(join(new, old), new);
    let result = join_region_marks(new, old).unwrap();
    assert!(!result.changed);
}

#[test]
fn equal_generation_takes_max_high_water_and_or_conflict() {
    assert_eq!(
        join(marks(5, 0x10, false, 3), marks(5, 0x10, true, 8)),
        marks(5, 0x10, true, 8)
    );
    assert_eq!(
        join(marks(5, 0x10, false, 9), marks(5, 0x10, false, 8)),
        marks(5, 0x10, false, 9)
    );
}

#[test]
fn equal_generation_different_keys_latch_conflict_with_smaller_key() {
    let joined = join(marks(5, 0x30, false, 1), marks(5, 0x10, false, 2));
    assert_eq!(joined, marks(5, 0x10, true, 2));
    // The latch survives a later join with either key.
    assert_eq!(
        join(joined, marks(5, 0x30, false, 0)),
        marks(5, 0x10, true, 2)
    );
    // Only a higher generation clears it.
    assert_eq!(
        join(joined, marks(6, 0x30, false, 0)),
        marks(6, 0x30, false, 0)
    );
}

#[test]
fn refutation_merge_with_different_identity() {
    let mut other = marks(5, 0x10, false, 1);
    other.identity = [0x23; 32];
    assert_eq!(
        join_region_marks(marks(5, 0x10, false, 1), other),
        Err(RegionMarksOwnerMismatch)
    );
}

#[test]
fn marks_from_record_state() {
    let signer = SigningKey::from_bytes(&[7; 32]);
    let identity = signer.verifying_key().to_bytes();
    let mut state = RecordMarks::new(identity);
    assert_eq!(RegionMarks::from_record_marks(&state, 0), None);

    let record = |generation: u64, wg: u8| {
        NodeRecord::sign(
            &signer,
            NodeRecordFields {
                wg_key: [wg; 32],
                generation,
                issued_at: 1_767_225_600,
                expires: 1_767_830_400,
                relays: Vec::new(),
            },
        )
        .unwrap()
    };
    state.apply(&record(3, 0x40)).unwrap();
    assert_eq!(
        RegionMarks::from_record_marks(&state, 6),
        Some(RegionMarks {
            identity,
            committed_gen: 3,
            committed_key: [0x40; 32],
            conflicted: false,
            incarnation_high_water: 6,
        })
    );
    state.apply(&record(3, 0x41)).unwrap();
    let conflicted = RegionMarks::from_record_marks(&state, 6).unwrap();
    assert!(conflicted.conflicted);
    assert_eq!(conflicted.committed_key, [0x40; 32]);
}

fn marks_strategy() -> impl Strategy<Value = RegionMarks> {
    // Few generations and keys so equal-generation joins are frequent.
    (1..4_u64, 0..3_u8, any::<bool>(), 0..5_u64).prop_map(
        |(generation, key, conflicted, high_water)| marks(generation, key, conflicted, high_water),
    )
}

proptest! {
    #[test]
    fn join_is_commutative(a in marks_strategy(), b in marks_strategy()) {
        prop_assert_eq!(join(a, b), join(b, a));
    }

    #[test]
    fn join_is_associative(a in marks_strategy(), b in marks_strategy(), c in marks_strategy()) {
        prop_assert_eq!(join(join(a, b), c), join(a, join(b, c)));
    }

    #[test]
    fn join_is_idempotent(a in marks_strategy(), b in marks_strategy()) {
        prop_assert_eq!(join(a, a), a);
        let joined = join(a, b);
        prop_assert_eq!(join(joined, b), joined);
        prop_assert!(!join_region_marks(joined, b).unwrap().changed);
    }

    #[test]
    fn join_is_monotone_in_generation(a in marks_strategy(), b in marks_strategy()) {
        let joined = join(a, b);
        prop_assert_eq!(joined.committed_gen, a.committed_gen.max(b.committed_gen));
        // The winning generation carries only its own incarnation high water.
        if a.committed_gen != b.committed_gen {
            let winner = if a.committed_gen > b.committed_gen { a } else { b };
            prop_assert_eq!(joined, winner);
        }
    }

    #[test]
    fn conflict_latches_across_equal_generation_keys(
        generation in 1..4_u64,
        key_a in 0..3_u8,
        key_b in 0..3_u8,
        later in marks_strategy(),
    ) {
        let joined = join(marks(generation, key_a, false, 0), marks(generation, key_b, false, 0));
        prop_assert_eq!(joined.conflicted, key_a != key_b);
        prop_assert_eq!(joined.committed_key, [key_a.min(key_b); 32]);
        if key_a != key_b {
            let after = join(joined, later);
            if later.committed_gen <= generation {
                prop_assert!(after.conflicted);
            }
        }
    }
}
