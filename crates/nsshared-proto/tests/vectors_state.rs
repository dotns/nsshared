//! Generated record and registry state vectors (quick-v2 §3.3, §7.2, §7.6).

#![allow(clippy::unwrap_used, clippy::panic, reason = "test fixture helpers")]

mod support;

use nsshared_proto::{
    NodeRecord,
    record::{MarksDecodeError, RecordMarks},
    rendezvous::registry::{RegistryEntry, RegistryStateError},
};
use support::vectors::{Vector, load};

fn records(v: &Vector) -> Vec<NodeRecord> {
    let count = usize::try_from(v.u64("record_count")).unwrap();
    (0..count)
        .map(|i| NodeRecord::decode(&v.hex(&format!("record_{i}"))).unwrap())
        .collect()
}

#[test]
fn summaries_match_vectors_in_any_order() {
    let vectors = load("registry_state");
    let mut seen = 0;
    for v in vectors.iter().filter(|v| v.get("kind") == "summary") {
        seen += 1;
        let records = records(v);
        for order in [records.clone(), records.iter().rev().cloned().collect()] {
            let mut marks = RecordMarks::new(*order[0].identity());
            for record in &order {
                marks.apply(record).unwrap();
            }
            assert_eq!(marks.encode(), v.hex("state"), "{}", v.name());
            assert_eq!(
                marks.is_conflicted(),
                v.u64("conflicted") == 1,
                "{}",
                v.name()
            );
        }
        assert_eq!(
            RecordMarks::decode(&v.hex("state")).unwrap().encode(),
            v.hex("state")
        );
    }
    assert!(seen >= 9);
}

#[test]
fn merges_match_vectors_both_ways() {
    let vectors = load("registry_state");
    let mut seen = 0;
    for v in vectors.iter().filter(|v| v.get("kind") == "merge") {
        seen += 1;
        let a = RecordMarks::decode(&v.hex("state_a")).unwrap();
        let b = RecordMarks::decode(&v.hex("state_b")).unwrap();
        for (left, right) in [(&a, &b), (&b, &a)] {
            let mut merged = left.clone();
            merged.merge(right).unwrap();
            assert_eq!(merged.encode(), v.hex("state"), "{}", v.name());
        }
    }
    for v in vectors.iter().filter(|v| v.get("kind") == "registry_merge") {
        seen += 1;
        let a = RegistryEntry::decode(&v.hex("state_a")).unwrap();
        let b = RegistryEntry::decode(&v.hex("state_b")).unwrap();
        for (left, right) in [(&a, &b), (&b, &a)] {
            let mut merged = left.clone();
            merged.merge(right, v.u64("now")).unwrap();
            assert_eq!(merged.encode(), v.hex("state"), "{}", v.name());
        }
    }
    assert!(seen >= 7);
}

#[test]
fn restore_refutations_match_vectors() {
    let vectors = load("registry_state");
    let mut seen = 0;
    for v in vectors.iter().filter(|v| v.is_reject()) {
        seen += 1;
        match v.get("kind") {
            "restore" => {
                let error = RecordMarks::decode(&v.hex("state")).expect_err(v.name());
                let matches = match v.reason() {
                    "version" => error == MarksDecodeError::Version,
                    "identity" => error == MarksDecodeError::Identity,
                    "evidence" => error == MarksDecodeError::Evidence,
                    other => panic!("{}: unknown reason {other}", v.name()),
                };
                assert!(matches, "{}: {error:?}", v.name());
            }
            "registry_restore" => assert_eq!(
                RegistryEntry::decode(&v.hex("state")),
                Err(RegistryStateError::Tiers),
                "{}",
                v.name()
            ),
            other => panic!("{}: unknown kind {other}", v.name()),
        }
    }
    assert!(seen >= 10);
}
