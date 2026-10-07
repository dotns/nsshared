//! Record state summary, export / restore and merge: quick-v2 §3.3, §7.6.

#![allow(clippy::unwrap_used, reason = "test fixture helpers")]

use ed25519_dalek::SigningKey;
use nsshared_proto::{
    NodeRecord, RelayId,
    encoding::CborWriter,
    record::{
        IdentityMismatch, MarksDecodeError, NodeRecordFields, RECORD_STATE_VERSION, RecordMarks,
    },
};
use proptest::prelude::*;

fn signer() -> SigningKey {
    SigningKey::from_bytes(&[7; 32])
}

fn identity() -> [u8; 32] {
    signer().verifying_key().to_bytes()
}

fn record_with(
    signer: &SigningKey,
    generation: u64,
    key: u8,
    issued_at: u64,
    relay: bool,
) -> NodeRecord {
    NodeRecord::sign(
        signer,
        NodeRecordFields {
            wg_key: [key; 32],
            generation,
            issued_at,
            expires: issued_at + 604_800,
            relays: if relay {
                vec![RelayId::parse("relay.example:1").unwrap()]
            } else {
                Vec::new()
            },
        },
    )
    .unwrap()
}

fn record(generation: u64, key: u8, issued_at: u64) -> NodeRecord {
    record_with(&signer(), generation, key, issued_at, false)
}

/// A small input space so that equal generations, keys and issued_at values collide often.
fn arb_record() -> impl Strategy<Value = NodeRecord> {
    (1_u64..4, 0_u8..3, 0_u64..3, any::<bool>()).prop_map(|(generation, key, issued, relay)| {
        record_with(&signer(), generation, key, issued, relay)
    })
}

fn state_of(records: &[NodeRecord]) -> RecordMarks {
    let mut marks = RecordMarks::new(identity());
    for record in records {
        marks.apply(record).unwrap();
    }
    marks
}

fn raw_state(version: u64, identity: &[u8; 32], records: [Option<&NodeRecord>; 2]) -> Vec<u8> {
    let mut writer = CborWriter::with_capacity(1400);
    writer.array(4).uint(version).bytes(identity);
    for record in records {
        match record {
            Some(record) => writer.bytes(record.as_bytes()),
            None => writer.null(),
        };
    }
    writer.into_bytes()
}

proptest! {
    #[test]
    fn arrival_order_does_not_matter(
        records in prop::collection::vec(arb_record(), 1..16).prop_shuffle(),
    ) {
        let mut sorted = records.clone();
        sorted.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        prop_assert_eq!(state_of(&records), state_of(&sorted));
    }

    #[test]
    fn merge_is_the_union(
        a in prop::collection::vec(arb_record(), 0..10),
        b in prop::collection::vec(arb_record(), 0..10),
    ) {
        let mut merged = state_of(&a);
        merged.merge(&state_of(&b)).unwrap();
        let union: Vec<NodeRecord> = a.iter().chain(&b).cloned().collect();
        prop_assert_eq!(merged, state_of(&union));
    }

    #[test]
    fn merge_is_commutative_associative_and_idempotent(
        a in prop::collection::vec(arb_record(), 0..8),
        b in prop::collection::vec(arb_record(), 0..8),
        c in prop::collection::vec(arb_record(), 0..8),
    ) {
        let (a, b, c) = (state_of(&a), state_of(&b), state_of(&c));
        let mut a_then_b = a.clone();
        a_then_b.merge(&b).unwrap();
        let mut b_then_a = b.clone();
        b_then_a.merge(&a).unwrap();
        prop_assert_eq!(&a_then_b, &b_then_a);
        let mut ab_c = a_then_b.clone();
        ab_c.merge(&c).unwrap();
        let mut bc = b.clone();
        bc.merge(&c).unwrap();
        let mut a_bc = a.clone();
        a_bc.merge(&bc).unwrap();
        prop_assert_eq!(&ab_c, &a_bc);
        let mut aa = a.clone();
        aa.merge(&a).unwrap();
        prop_assert_eq!(aa, a);
    }

    #[test]
    fn export_restores_the_same_state(records in prop::collection::vec(arb_record(), 0..12)) {
        let marks = state_of(&records);
        prop_assert_eq!(RecordMarks::decode(&marks.encode()), Ok(marks));
    }
}

#[test]
fn merge_rejects_another_identity() {
    let mut marks = state_of(&[record(1, 1, 1)]);
    let before = marks.clone();
    let other = RecordMarks::new([9; 32]);
    assert_eq!(marks.merge(&other), Err(IdentityMismatch));
    assert_eq!(marks, before);
}

#[test]
fn empty_state_round_trips() {
    let marks = RecordMarks::new(identity());
    assert_eq!(marks.encode(), raw_state(1, &identity(), [None, None]));
    assert_eq!(RecordMarks::decode(&marks.encode()), Ok(marks));
}

#[test]
fn decode_refutations() {
    let r = record(2, 1, 10);
    let smaller_other_key = record(2, 2, 5);
    let larger_other_key = record(2, 2, 50);
    let same_key = record(2, 1, 5);
    let older_gen = record(1, 2, 5);
    let foreign = record_with(&SigningKey::from_bytes(&[8; 32]), 2, 2, 5, false);
    let id = identity();
    assert_eq!(RECORD_STATE_VERSION, 1);
    assert!(RecordMarks::decode(&raw_state(1, &id, [Some(&r), Some(&smaller_other_key)])).is_ok());
    for (encoded, expected) in [
        (
            raw_state(2, &id, [Some(&r), None]),
            MarksDecodeError::Version,
        ),
        (
            raw_state(1, &id, [Some(&foreign), None]),
            MarksDecodeError::Identity,
        ),
        (
            raw_state(1, &id, [None, Some(&smaller_other_key)]),
            MarksDecodeError::Evidence,
        ),
        (
            raw_state(1, &id, [Some(&r), Some(&same_key)]),
            MarksDecodeError::Evidence,
        ),
        (
            raw_state(1, &id, [Some(&r), Some(&larger_other_key)]),
            MarksDecodeError::Evidence,
        ),
        (
            raw_state(1, &id, [Some(&r), Some(&older_gen)]),
            MarksDecodeError::Evidence,
        ),
    ] {
        assert_eq!(RecordMarks::decode(&encoded), Err(expected));
    }
    let mut tampered = raw_state(1, &id, [Some(&r), None]);
    let last = tampered.len() - 2;
    tampered[last] ^= 1;
    assert!(matches!(
        RecordMarks::decode(&tampered),
        Err(MarksDecodeError::Record(_))
    ));
    let mut trailing = raw_state(1, &id, [Some(&r), None]);
    trailing.push(0);
    assert!(matches!(
        RecordMarks::decode(&trailing),
        Err(MarksDecodeError::Cbor(_))
    ));
}
