//! Node registry: quick-v2 §3.3 and §7.

#![allow(clippy::unwrap_used, reason = "test fixture helpers")]

use ed25519_dalek::SigningKey;
use ns_rendezvous::{
    capability::{self, Capabilities},
    directory::{CODE_LETTERS, Directory, RelayEntry},
    error::ErrorCode,
    message::{PublishRequest, Published},
    registry::{
        self, DELETION_GRACE_SECONDS, LookupError, PUBLISH_CONTEXT, RegistryEntry, SHARD_LABEL,
        VerifiedPublish,
    },
};
use ns_wire::{NodeId, NodeRecord, NodeRecordError, NodeRecordFields, RecordExpired, RelayId};
use std::net::IpAddr;

const NOW: u64 = 1_800_000_000;
const NONCE: [u8; 32] = [7; 32];

fn authority() -> RelayId {
    RelayId::parse("relay-1.relay.ns.io:443").unwrap()
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn record_with(signer: &SigningKey, generation: u64, wg: u8, issued_at: u64) -> NodeRecord {
    NodeRecord::sign(
        signer,
        NodeRecordFields {
            wg_key: [wg; 32],
            generation,
            issued_at,
            expires: issued_at + 3600,
            relays: vec![authority()],
        },
    )
    .unwrap()
}

fn record(generation: u64, wg: u8) -> NodeRecord {
    record_with(&key(1), generation, wg, NOW - 10)
}

fn verified(record: &NodeRecord, dns: bool) -> VerifiedPublish {
    let request = registry::publish_request(&key(1), &NONCE, &authority(), record, dns);
    registry::verify_publish(&request, &NONCE, &authority(), NOW).unwrap()
}

fn entry(id: u16, capabilities: Vec<capability::Capability>) -> RelayEntry {
    let code = [
        CODE_LETTERS[usize::from(id / 24) % 24],
        CODE_LETTERS[usize::from(id % 24)],
    ];
    RelayEntry::new(
        id,
        String::from_utf8(code.to_vec()).unwrap(),
        format!("relay-{id}.relay.ns.io"),
        vec!["203.0.113.1".parse::<IpAddr>().unwrap()],
        443,
        Capabilities::new(capabilities).unwrap(),
    )
    .unwrap()
}

fn registry_entry(id: u16) -> RelayEntry {
    entry(id, vec![capability::UDP, capability::REGISTRY])
}

fn node(index: u32) -> NodeId {
    NodeId::derive(&{
        let mut identity = [0; 32];
        identity[..4].copy_from_slice(&index.to_be_bytes());
        identity
    })
}

// ---- publish proof ----

#[test]
fn constants_match_the_spec() {
    assert_eq!(PUBLISH_CONTEXT, b"ns/registry-publish/v2");
    assert_eq!(SHARD_LABEL, b"ns-registry-shard-v2");
    assert_eq!(registry::MAX_RECORDS, 10_000_000);
    assert_eq!(registry::PUBLISHES_PER_IP_PER_MINUTE, 12);
    assert_eq!(registry::PUBLISH_INTERVAL_PER_IDENTITY_SECONDS, 60);
    assert_eq!(registry::PUBLISHES_PER_SECOND, 1000);
    assert_eq!(registry::LOOKUP_NODES_PER_IP_PER_MINUTE, 60);
    assert_eq!(registry::LOOKUP_NODES_PER_SECOND, 5000);
    assert_eq!(DELETION_GRACE_SECONDS, 10);
}

#[test]
fn proof_message_layout() {
    let message = registry::publish_proof_message(&NONCE, &authority(), b"rec", true);
    let authority = b"relay-1.relay.ns.io:443";
    let mut expected = PUBLISH_CONTEXT.to_vec();
    expected.extend_from_slice(&NONCE);
    expected.extend_from_slice(authority);
    // SHA-256("rec")
    let digest: [u8; 32] = {
        use sha2::Digest;
        sha2::Sha256::digest(b"rec").into()
    };
    expected.extend_from_slice(&digest);
    expected.push(1);
    assert_eq!(message, expected);
    let off = registry::publish_proof_message(
        &NONCE,
        &RelayId::parse("relay-1.relay.ns.io:443").unwrap(),
        b"rec",
        false,
    );
    assert_eq!(off.last(), Some(&0));
}

#[test]
fn proof_round_trip() {
    let record = record(1, 1);
    for dns in [false, true] {
        let request = registry::publish_request(&key(1), &NONCE, &authority(), &record, dns);
        assert_eq!(request.record, record.as_bytes());
        let verified = registry::verify_publish(&request, &NONCE, &authority(), NOW).unwrap();
        assert_eq!(verified.record(), &record);
        assert_eq!(verified.dns(), dns);
        assert_eq!(verified.node_id(), record.node_id());
    }
}

#[test]
fn proof_fails_for_any_changed_input() {
    let record = record(1, 1);
    let request = registry::publish_request(&key(1), &NONCE, &authority(), &record, true);
    let invalid = Err(ErrorCode::InvalidMessage);

    let mut other_nonce = NONCE;
    other_nonce[31] ^= 1;
    assert_eq!(
        registry::verify_publish(&request, &other_nonce, &authority(), NOW),
        invalid
    );
    let other_authority = RelayId::parse("relay-2.relay.ns.io:443").unwrap();
    assert_eq!(
        registry::verify_publish(&request, &NONCE, &other_authority, NOW),
        invalid
    );

    let flipped_dns = PublishRequest {
        dns: false,
        ..request.clone()
    };
    assert_eq!(
        registry::verify_publish(&flipped_dns, &NONCE, &authority(), NOW),
        invalid
    );

    // Another valid record of the same identity under the old proof.
    let other_record = PublishRequest {
        record: record_with(&key(1), 1, 1, NOW - 9).as_bytes().to_vec(),
        ..request.clone()
    };
    assert_eq!(
        registry::verify_publish(&other_record, &NONCE, &authority(), NOW),
        invalid
    );

    // A proof by another key over the same inputs.
    let foreign = PublishRequest {
        proof: registry::create_publish_proof(
            &key(2),
            &NONCE,
            &authority(),
            record.as_bytes(),
            true,
        ),
        ..request.clone()
    };
    assert_eq!(
        registry::verify_publish(&foreign, &NONCE, &authority(), NOW),
        invalid
    );

    let mut tampered_proof = request.clone();
    tampered_proof.proof[0] ^= 1;
    assert_eq!(
        registry::verify_publish(&tampered_proof, &NONCE, &authority(), NOW),
        invalid
    );
}

#[test]
fn any_flipped_record_byte_is_rejected() {
    let record = record(1, 1);
    let request = registry::publish_request(&key(1), &NONCE, &authority(), &record, false);
    for index in 0..request.record.len() {
        let mut tampered = request.clone();
        tampered.record[index] ^= 1;
        assert_eq!(
            registry::verify_publish(&tampered, &NONCE, &authority(), NOW),
            Err(ErrorCode::InvalidMessage),
            "byte {index}"
        );
    }
}

#[test]
fn invalid_or_expired_records_are_rejected() {
    let garbage = PublishRequest {
        record: vec![0x80],
        dns: false,
        proof: [0; 64],
    };
    assert_eq!(
        registry::verify_publish(&garbage, &NONCE, &authority(), NOW),
        Err(ErrorCode::InvalidMessage)
    );

    let record = record(1, 1);
    let request = registry::publish_request(&key(1), &NONCE, &authority(), &record, false);
    assert!(registry::verify_publish(&request, &NONCE, &authority(), record.expires() - 1).is_ok());
    for now in [record.expires(), record.expires() + 1] {
        assert_eq!(
            registry::verify_publish(&request, &NONCE, &authority(), now),
            Err(ErrorCode::InvalidMessage)
        );
    }
}

// ---- HRW sharding ----

#[test]
fn shard_weight_is_keyed_blake2s_of_node_id_and_be16_id() {
    use blake2::digest::{KeyInit, Mac};
    let node = node(1);
    let mut mac =
        blake2::Blake2sMac::<blake2::digest::consts::U8>::new_from_slice(SHARD_LABEL).unwrap();
    mac.update(node.as_bytes());
    mac.update(&[0x01, 0x02]);
    let expected: [u8; 8] = mac.finalize().into_bytes().into();
    assert_eq!(registry::shard_weight(&node, 0x0102), expected);
    assert_eq!(registry::shard_weight(&node, 0x0102), expected);
    assert_ne!(registry::shard_weight(&node, 0x0201), expected);
    assert_ne!(registry::shard_weight(&self::node(2), 0x0102), expected);
}

#[test]
fn shard_order_sorts_by_weight_descending() {
    let entries: Vec<_> = (1..=10).map(registry_entry).collect();
    let domain: Vec<_> = entries.iter().collect();
    for index in 0..50 {
        let node = node(index);
        let order = registry::shard_order(&node, &domain);
        assert_eq!(order.len(), 10);
        let weights: Vec<u64> = order
            .iter()
            .map(|id| u64::from_be_bytes(registry::shard_weight(&node, *id)))
            .collect();
        assert!(weights.windows(2).all(|pair| pair[0] >= pair[1]));
        // Independent of domain order.
        let reversed: Vec<_> = entries.iter().rev().collect();
        assert_eq!(registry::shard_order(&node, &reversed), order);
        assert_eq!(registry::shard_relays(&node, &domain), order[..2]);
        assert_eq!(registry::lookup_relays(&node, &domain), order[..4]);
        for (rank, id) in order.iter().enumerate() {
            assert_eq!(registry::is_responsible(&node, *id, &domain), rank < 4);
            assert_eq!(
                registry::check_responsible(&node, *id, &domain),
                if rank < 4 {
                    Ok(())
                } else {
                    Err(ErrorCode::InvalidMessage)
                }
            );
        }
        assert!(!registry::is_responsible(&node, 11, &domain));
    }
}

#[test]
fn small_domains() {
    let entries: Vec<_> = (1..=3).map(registry_entry).collect();
    let domain: Vec<_> = entries.iter().collect();
    let node = node(3);
    assert_eq!(registry::lookup_relays(&node, &domain).len(), 3);
    assert_eq!(registry::shard_relays(&node, &domain).len(), 2);
    assert!(registry::shard_order(&node, &[]).is_empty());

    let only = entry(42, vec![capability::UDP]);
    let single = registry::single_relay_domain(&only);
    assert_eq!(registry::shard_relays(&node, &single), [42]);
    assert_eq!(registry::lookup_relays(&node, &single), [42]);
    assert!(registry::is_responsible(&node, 42, &single));
}

#[test]
fn registry_domain_keeps_only_registry_entries() {
    let directory = Directory::new(
        1,
        vec![
            registry_entry(1),
            entry(2, vec![capability::UDP, capability::MAILBOX]),
            registry_entry(3),
            entry(4, vec![capability::WSS]),
        ],
    )
    .unwrap();
    let domain = registry::registry_domain(&directory);
    let ids: Vec<_> = domain.iter().map(|entry| entry.id()).collect();
    assert_eq!(ids, [1, 3]);
    for index in 0..20 {
        let order = registry::shard_order(&node(index), &domain);
        assert!(order.iter().all(|id| *id == 1 || *id == 3));
    }
}

#[test]
fn adding_one_entry_moves_only_shards_that_now_include_it() {
    let entries: Vec<_> = (1..=12).map(|id| registry_entry(id * 7)).collect();
    let old: Vec<_> = entries.iter().collect();
    let added = registry_entry(1000);
    let mut new = old.clone();
    new.insert(5, &added);
    let mut moved = 0;
    for index in 0..2000 {
        let node = node(index);
        let old_order = registry::shard_order(&node, &old);
        let new_order = registry::shard_order(&node, &new);
        // The relative order of the old entries never changes.
        let without: Vec<_> = new_order.iter().copied().filter(|id| *id != 1000).collect();
        assert_eq!(without, old_order);
        for take in [2, 4] {
            let old_top = &old_order[..take];
            let new_top = &new_order[..take];
            if old_top != new_top {
                assert!(new_top.contains(&1000));
                // Only the last old member drops out; the rest keep their ranks.
                let kept: Vec<_> = new_top.iter().copied().filter(|id| *id != 1000).collect();
                assert_eq!(kept, old_top[..take - 1]);
                if take == 2 {
                    moved += 1;
                }
            }
        }
    }
    // Roughly 2/13 of the shards move; none would be a broken weight.
    assert!(moved > 100 && moved < 500, "moved {moved}");
}

// ---- relay-side acceptance (§3.3) ----

#[test]
fn first_publish_is_accepted() {
    let mut state = RegistryEntry::new(*key(1).verifying_key().as_bytes());
    assert!(state.record().is_none());
    let first = record(1, 1);
    assert_eq!(
        state.apply_publish(&verified(&first, true), NOW),
        Ok(Published {
            expires: first.expires()
        })
    );
    assert_eq!(state.record(), Some(&first));
    assert!(state.dns());
    assert_eq!(state.marks().committed_gen(), 1);
}

#[test]
fn higher_generation_is_accepted_and_lower_rejected() {
    let mut state = RegistryEntry::new(*key(1).verifying_key().as_bytes());
    let second = record(2, 2);
    state.apply_publish(&verified(&second, false), NOW).unwrap();
    let before = state.clone();
    assert_eq!(
        state.apply_publish(&verified(&record(1, 1), true), NOW),
        Err(ErrorCode::Conflict)
    );
    assert_eq!(state, before);

    let third = record_with(&key(1), 3, 3, NOW - 5);
    assert_eq!(
        state.apply_publish(&verified(&third, true), NOW),
        Ok(Published {
            expires: third.expires()
        })
    );
    assert_eq!(state.record(), Some(&third));
    assert!(state.dns());
}

#[test]
fn same_generation_refresh_replaces_the_record() {
    let mut state = RegistryEntry::new(*key(1).verifying_key().as_bytes());
    state
        .apply_publish(&verified(&record(1, 1), false), NOW)
        .unwrap();
    let refreshed = record_with(&key(1), 1, 1, NOW - 5);
    assert_eq!(
        state.apply_publish(&verified(&refreshed, false), NOW),
        Ok(Published {
            expires: refreshed.expires()
        })
    );
    assert_eq!(state.record(), Some(&refreshed));
}

#[test]
fn dns_follows_the_latest_accepted_publish() {
    let mut state = RegistryEntry::new(*key(1).verifying_key().as_bytes());
    let first = record(1, 1);
    state.apply_publish(&verified(&first, true), NOW).unwrap();
    assert!(state.dns());
    // The same record again is idempotent for §3.3 but still an accepted publish.
    assert_eq!(
        state.apply_publish(&verified(&first, false), NOW),
        Ok(Published {
            expires: first.expires()
        })
    );
    assert!(!state.dns());
    assert_eq!(state.record(), Some(&first));
    // A rejected publish never changes the choice.
    state
        .apply_publish(&verified(&record(2, 2), false), NOW)
        .unwrap();
    assert_eq!(
        state.apply_publish(&verified(&first, true), NOW),
        Err(ErrorCode::Conflict)
    );
    assert!(!state.dns());
}

#[test]
fn conflict_latches_until_a_higher_generation() {
    let mut state = RegistryEntry::new(*key(1).verifying_key().as_bytes());
    let original = record(1, 1);
    state
        .apply_publish(&verified(&original, false), NOW)
        .unwrap();
    // Same gen, different K.
    assert_eq!(
        state.apply_publish(&verified(&record(1, 9), true), NOW),
        Err(ErrorCode::Conflict)
    );
    assert!(state.marks().is_conflicted());
    assert!(!state.dns());
    assert_eq!(state.record(), Some(&original));
    assert_eq!(
        registry::lookup(Some(&state), NOW),
        Err(ErrorCode::Conflict)
    );

    // While latched, the same generation is rejected even with the original K.
    let before = state.clone();
    for candidate in [original.clone(), record_with(&key(1), 1, 1, NOW - 5)] {
        assert_eq!(
            state.apply_publish(&verified(&candidate, false), NOW),
            Err(ErrorCode::Conflict)
        );
        assert_eq!(state, before);
    }

    // A higher generation clears it.
    let rotated = record_with(&key(1), 2, 2, NOW - 5);
    state.apply_publish(&verified(&rotated, true), NOW).unwrap();
    assert!(!state.marks().is_conflicted());
    assert_eq!(
        registry::lookup(Some(&state), NOW).unwrap().record,
        Some(rotated.as_bytes().to_vec())
    );
}

#[test]
fn apply_rejects_foreign_or_expired_publishes() {
    let mut state = RegistryEntry::new(*key(2).verifying_key().as_bytes());
    let publish = verified(&record(1, 1), false);
    assert_eq!(
        state.apply_publish(&publish, NOW),
        Err(ErrorCode::InvalidMessage)
    );
    let mut state = RegistryEntry::new(*key(1).verifying_key().as_bytes());
    assert_eq!(
        state.apply_publish(&publish, publish.record().expires()),
        Err(ErrorCode::InvalidMessage)
    );
    assert!(state.record().is_none());
}

#[test]
fn deleted_state_accepts_a_fresh_record() {
    let mut state = RegistryEntry::new(*key(1).verifying_key().as_bytes());
    let old = record_with(&key(1), 5, 5, NOW - 4000);
    let request = registry::publish_request(&key(1), &NONCE, &authority(), &old, false);
    let old = registry::verify_publish(&request, &NONCE, &authority(), NOW - 3900).unwrap();
    state.apply_publish(&old, NOW - 3900).unwrap();
    let expires = old.record().expires();
    // Within the grace a lower generation is still a conflict; after it, a fresh start.
    let lower = verified(&record(1, 1), false);
    assert_eq!(
        state.apply_publish(&lower, expires + DELETION_GRACE_SECONDS),
        Err(ErrorCode::Conflict)
    );
    assert!(
        state
            .apply_publish(&lower, expires + DELETION_GRACE_SECONDS + 1)
            .is_ok()
    );
    assert_eq!(state.marks().committed_gen(), 1);
}

// ---- lookup_node ----

#[test]
fn lookup_semantics() {
    assert_eq!(registry::lookup(None, NOW).unwrap().record, None);
    let empty = RegistryEntry::new([1; 32]);
    assert_eq!(registry::lookup(Some(&empty), NOW).unwrap().record, None);

    let mut state = RegistryEntry::new(*key(1).verifying_key().as_bytes());
    let first = record(1, 1);
    state.apply_publish(&verified(&first, true), NOW).unwrap();
    let expires = first.expires();
    assert_eq!(
        registry::lookup(Some(&state), expires - 1).unwrap().record,
        Some(first.as_bytes().to_vec())
    );
    for now in [expires, expires + DELETION_GRACE_SECONDS + 1] {
        assert_eq!(registry::lookup(Some(&state), now).unwrap().record, None);
    }
}

#[test]
fn deletion_grace() {
    assert!(RegistryEntry::new([1; 32]).deletion_due(0));
    let mut state = RegistryEntry::new(*key(1).verifying_key().as_bytes());
    let first = record(1, 1);
    state.apply_publish(&verified(&first, false), NOW).unwrap();
    let expires = first.expires();
    assert!(!state.deletion_due(expires));
    assert!(!state.deletion_due(expires + DELETION_GRACE_SECONDS));
    assert!(state.deletion_due(expires + DELETION_GRACE_SECONDS + 1));
}

// ---- client check ----

#[test]
fn client_verifies_lookup_results() {
    let first = record(1, 1);
    let node_id = first.node_id();
    assert_eq!(
        registry::verify_lookup_result(&node_id, first.as_bytes(), NOW),
        Ok(first.clone())
    );
    // A valid record of another identity.
    let other = record_with(&key(2), 1, 1, NOW - 10);
    assert_eq!(
        registry::verify_lookup_result(&node_id, other.as_bytes(), NOW),
        Err(LookupError::NodeIdMismatch)
    );
    assert_eq!(
        registry::verify_lookup_result(&node_id, first.as_bytes(), first.expires()),
        Err(LookupError::Expired(RecordExpired {
            expires: first.expires(),
            now: first.expires()
        }))
    );
    let mut tampered = first.as_bytes().to_vec();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert_eq!(
        registry::verify_lookup_result(&node_id, &tampered, NOW),
        Err(LookupError::Record(NodeRecordError::BadSignature))
    );
}
