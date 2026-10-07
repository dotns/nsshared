//! Registry state export / restore and member merge: quick-v2 §7.2, §7.6.

#![allow(clippy::unwrap_used, reason = "test fixture helpers")]

use ed25519_dalek::SigningKey;
use nsshared_proto::{
    NodeRecord, RelayId,
    encoding::CborWriter,
    record::{IdentityMismatch, NodeRecordFields},
    rendezvous::{
        message::DnsPublication,
        registry::{self, RegistryEntry, RegistryStateError, VerifiedPublish},
    },
};
use proptest::prelude::*;

const NOW: u64 = 1_800_000_000;
const NONCE: [u8; 32] = [3; 32];

fn signer() -> SigningKey {
    SigningKey::from_bytes(&[7; 32])
}

fn identity() -> [u8; 32] {
    signer().verifying_key().to_bytes()
}

fn authority() -> RelayId {
    RelayId::parse("relay-1.relay.ns.io:443").unwrap()
}

fn record(generation: u64, key: u8, issued_at: u64) -> NodeRecord {
    NodeRecord::sign(
        &signer(),
        NodeRecordFields {
            wg_key: [key; 32],
            generation,
            issued_at,
            expires: issued_at + 3600,
            relays: Vec::new(),
        },
    )
    .unwrap()
}

fn verified(record: &NodeRecord, dns: DnsPublication) -> VerifiedPublish {
    let request = registry::publish_request(&signer(), &NONCE, &authority(), record, dns);
    registry::verify_publish(&request, &NONCE, &authority(), NOW).unwrap()
}

fn arb_publish() -> impl Strategy<Value = VerifiedPublish> {
    (1_u64..4, 0_u8..2, 0_u64..3, 0_u8..3).prop_map(|(generation, key, issued, tier)| {
        let tier = [
            DnsPublication::None,
            DnsPublication::Address,
            DnsPublication::Record,
        ][usize::from(tier)];
        verified(&record(generation, key, NOW - 100 + issued), tier)
    })
}

fn member(publishes: &[VerifiedPublish]) -> RegistryEntry {
    let mut entry = RegistryEntry::new(identity());
    for publish in publishes {
        let _ = entry.apply_publish(publish, NOW);
    }
    entry
}

fn merged(a: &RegistryEntry, b: &RegistryEntry) -> RegistryEntry {
    let mut out = a.clone();
    out.merge(b, NOW).unwrap();
    out
}

proptest! {
    // Every case signs records; keep the run short.
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn member_merge_is_commutative_associative_and_idempotent(
        a in prop::collection::vec(arb_publish(), 0..8),
        b in prop::collection::vec(arb_publish(), 0..8),
        c in prop::collection::vec(arb_publish(), 0..8),
    ) {
        let (a, b, c) = (member(&a), member(&b), member(&c));
        prop_assert_eq!(merged(&a, &b), merged(&b, &a));
        prop_assert_eq!(merged(&merged(&a, &b), &c), merged(&a, &merged(&b, &c)));
        prop_assert_eq!(merged(&a, &a), a);
    }

    #[test]
    fn export_restores_the_same_state(publishes in prop::collection::vec(arb_publish(), 0..10)) {
        let entry = member(&publishes);
        prop_assert_eq!(RegistryEntry::decode(&entry.encode()), Ok(entry));
    }

    #[test]
    fn dns_is_served_only_for_a_single_tier_without_conflict(
        publishes in prop::collection::vec(arb_publish(), 0..10),
    ) {
        let entry = member(&publishes);
        if entry.marks().is_conflicted() || entry.is_publish_conflicted() {
            prop_assert_eq!(entry.dns(), DnsPublication::None);
        }
    }
}

#[test]
fn merge_takes_the_larger_revision_and_unions_equal_ones() {
    let first = record(1, 1, NOW - 50);
    let resigned = record(1, 1, NOW - 40);
    let a = member(&[verified(&first, DnsPublication::Record)]);
    let b = member(&[verified(&first, DnsPublication::Address)]);
    let ab = merged(&a, &b);
    assert!(ab.is_publish_conflicted());
    assert_eq!(ab.dns(), DnsPublication::None);
    let c = member(&[verified(&resigned, DnsPublication::Address)]);
    let abc = merged(&ab, &c);
    assert!(!abc.is_publish_conflicted());
    assert_eq!(abc.dns(), DnsPublication::Address);
    assert_eq!(abc.record(), Some(&resigned));
}

#[test]
fn merge_ignores_deleted_states_and_other_identities() {
    let live = member(&[verified(&record(1, 1, NOW - 50), DnsPublication::Record)]);
    let mut entry = live.clone();
    let late = NOW + 3600 + 11;
    entry.merge(&live, late).unwrap();
    assert_eq!(entry, RegistryEntry::new(identity()));
    let mut entry = live.clone();
    assert_eq!(
        entry.merge(&RegistryEntry::new([9; 32]), NOW),
        Err(IdentityMismatch)
    );
    assert_eq!(entry, live);
}

fn raw(marks: &[u8], pub_gen: u64, pub_issued_at: u64, tiers: u64) -> Vec<u8> {
    let mut writer = CborWriter::with_capacity(2000);
    writer.array(5).uint(1);
    let mut out = writer.into_bytes();
    out.extend_from_slice(marks);
    let mut tail = CborWriter::with_capacity(32);
    tail.uint(pub_gen).uint(pub_issued_at).uint(tiers);
    out.extend_from_slice(&tail.into_bytes());
    out
}

#[test]
fn decode_refutations() {
    let entry = member(&[verified(&record(1, 1, NOW - 50), DnsPublication::Record)]);
    let marks = entry.marks().encode();
    let empty = RegistryEntry::new(identity()).marks().encode();
    assert_eq!(
        RegistryEntry::decode(&raw(&marks, 1, NOW - 50, 0b100)),
        Ok(entry)
    );
    for encoded in [
        raw(&marks, 1, NOW - 50, 0b1000),
        raw(&marks, 1, NOW - 50, 0),
        raw(&marks, 0, 0, 0b001),
        raw(&empty, 1, NOW - 50, 0b001),
        raw(&marks, 1, NOW - 50, 256),
    ] {
        assert_eq!(
            RegistryEntry::decode(&encoded),
            Err(RegistryStateError::Tiers)
        );
    }
    let mut version = raw(&marks, 1, NOW - 50, 0b100);
    version[1] = 2;
    assert_eq!(
        RegistryEntry::decode(&version),
        Err(RegistryStateError::Version)
    );
}
