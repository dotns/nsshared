//! Registry store and served directory: quick-v2 §3.3, §7; rendezvous §5.4.

#![allow(clippy::unwrap_used, reason = "test fixture helpers")]

use ed25519_dalek::SigningKey;
use nsshared_mock_rendezvous::{
    config::Limits,
    registry::{RegistryStore, self_entry},
};
use nsshared_proto::rendezvous::{
    capability::{self, Capabilities},
    directory::{Directory, RelayEntry},
    error::ErrorCode,
    message::{LookupNodeRequest, PublishRequest, RecordResult},
    registry,
};
use nsshared_proto::{NodeId, NodeRecord, NodeRecordFields, RelayId};
use std::net::IpAddr;

const NOW: u64 = 1_800_000_000;
const NONCE: [u8; 32] = [7; 32];

fn ip() -> IpAddr {
    "203.0.113.1".parse().unwrap()
}

fn mock_entry() -> RelayEntry {
    self_entry(
        1,
        "AB".to_owned(),
        "mock.relay.ns.io".to_owned(),
        vec![ip()],
        443,
        &[],
    )
    .unwrap()
}

fn other_entry(id: u16, code: &str, host: &str) -> RelayEntry {
    RelayEntry::new(
        id,
        code.to_owned(),
        host.to_owned(),
        vec![ip()],
        443,
        Capabilities::new(vec![capability::MAILBOX, capability::REGISTRY]).unwrap(),
    )
    .unwrap()
}

fn store() -> RegistryStore {
    RegistryStore::new(Limits::default(), mock_entry()).unwrap()
}

fn authority() -> RelayId {
    mock_entry().relay_id()
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

fn request(signer: &SigningKey, record: &NodeRecord) -> PublishRequest {
    registry::publish_request(signer, &NONCE, &authority(), record, false)
}

fn publish(store: &mut RegistryStore, record: &NodeRecord) -> Result<u64, ErrorCode> {
    store
        .publish(&request(&key(1), record), &NONCE, NOW)
        .map(|published| published.expires)
}

fn lookup(store: &RegistryStore, seed: u8, now: u64) -> Result<RecordResult, ErrorCode> {
    let node_id = NodeId::derive(&key(seed).verifying_key().to_bytes());
    store.lookup_node(
        &LookupNodeRequest {
            node_id: *node_id.as_bytes(),
        },
        now,
    )
}

fn hit(record: &NodeRecord) -> Result<RecordResult, ErrorCode> {
    Ok(RecordResult {
        record: Some(record.as_bytes().to_vec()),
    })
}

const MISS: Result<RecordResult, ErrorCode> = Ok(RecordResult { record: None });

// ---- publish and lookup_node ----

#[test]
fn publish_then_lookup_hit() {
    let mut store = store();
    let first = record(1, 1);
    assert_eq!(publish(&mut store, &first), Ok(first.expires()));
    assert_eq!(store.len(), 1);
    assert_eq!(lookup(&store, 1, NOW), hit(&first));
}

#[test]
fn lookup_of_an_unknown_node_is_null() {
    let mut store = store();
    publish(&mut store, &record(1, 1)).unwrap();
    assert_eq!(lookup(&store, 2, NOW), MISS);
}

#[test]
fn bad_proof_is_invalid_message() {
    let mut store = store();
    let mut bad = request(&key(1), &record(1, 1));
    bad.proof[0] ^= 1;
    assert_eq!(
        store.publish(&bad, &NONCE, NOW),
        Err(ErrorCode::InvalidMessage)
    );
    // Signed by another key than the record's identity.
    let foreign = request(&key(2), &record(1, 1));
    assert_eq!(
        store.publish(&foreign, &NONCE, NOW),
        Err(ErrorCode::InvalidMessage)
    );
    assert!(store.is_empty());
}

#[test]
fn proof_for_another_challenge_nonce_is_rejected() {
    let mut store = store();
    let request = request(&key(1), &record(1, 1));
    assert_eq!(
        store.publish(&request, &[8; 32], NOW),
        Err(ErrorCode::InvalidMessage)
    );
    assert!(store.is_empty());
}

#[test]
fn proof_for_another_authority_is_rejected() {
    let mut store = store();
    let other = RelayId::parse("other.relay.ns.io:443").unwrap();
    let request = registry::publish_request(&key(1), &NONCE, &other, &record(1, 1), false);
    assert_eq!(
        store.publish(&request, &NONCE, NOW),
        Err(ErrorCode::InvalidMessage)
    );
}

#[test]
fn higher_gen_supersedes() {
    let mut store = store();
    publish(&mut store, &record(1, 1)).unwrap();
    let next = record(2, 2);
    publish(&mut store, &next).unwrap();
    assert_eq!(lookup(&store, 1, NOW), hit(&next));
}

#[test]
fn lower_gen_is_conflict() {
    let mut store = store();
    let current = record(2, 1);
    publish(&mut store, &current).unwrap();
    assert_eq!(publish(&mut store, &record(1, 1)), Err(ErrorCode::Conflict));
    assert_eq!(lookup(&store, 1, NOW), hit(&current));
}

#[test]
fn same_gen_other_key_latches_conflict_until_a_higher_gen() {
    let mut store = store();
    publish(&mut store, &record(1, 1)).unwrap();
    assert_eq!(publish(&mut store, &record(1, 2)), Err(ErrorCode::Conflict));
    assert_eq!(lookup(&store, 1, NOW), Err(ErrorCode::Conflict));
    // Republishing the first record does not clear the latch.
    assert_eq!(publish(&mut store, &record(1, 1)), Err(ErrorCode::Conflict));
    assert_eq!(lookup(&store, 1, NOW), Err(ErrorCode::Conflict));
    let next = record(2, 3);
    publish(&mut store, &next).unwrap();
    assert_eq!(lookup(&store, 1, NOW), hit(&next));
}

#[test]
fn same_gen_same_key_newer_issued_at_replaces() {
    let mut store = store();
    publish(&mut store, &record_with(&key(1), 1, 1, NOW - 10)).unwrap();
    let newer = record_with(&key(1), 1, 1, NOW - 5);
    assert_eq!(publish(&mut store, &newer), Ok(newer.expires()));
    assert_eq!(lookup(&store, 1, NOW), hit(&newer));
    // An older issued_at is idempotent and keeps the newer bytes.
    publish(&mut store, &record_with(&key(1), 1, 1, NOW - 10)).unwrap();
    assert_eq!(lookup(&store, 1, NOW), hit(&newer));
}

#[test]
fn record_cap_refuses_only_new_identities() {
    let limits = Limits {
        registry_records: 1,
        ..Limits::default()
    };
    let mut store = RegistryStore::new(limits, mock_entry()).unwrap();
    publish(&mut store, &record(1, 1)).unwrap();
    let stranger = record_with(&key(2), 1, 1, NOW - 10);
    assert_eq!(
        store.publish(&request(&key(2), &stranger), &NONCE, NOW),
        Err(ErrorCode::Capacity)
    );
    let next = record(2, 2);
    publish(&mut store, &next).unwrap();
    assert_eq!(lookup(&store, 1, NOW), hit(&next));
    assert_eq!(store.len(), 1);
}

#[test]
fn expired_records_read_null_and_the_sweep_removes_them() {
    let mut store = store();
    let first = record(1, 1);
    publish(&mut store, &first).unwrap();
    let expires = first.expires();
    assert_eq!(lookup(&store, 1, expires - 1), hit(&first));
    assert_eq!(lookup(&store, 1, expires), MISS);
    store.sweep(expires + registry::DELETION_GRACE_SECONDS);
    assert_eq!(store.len(), 1);
    store.sweep(expires + registry::DELETION_GRACE_SECONDS + 1);
    assert!(store.is_empty());
}

#[test]
fn conflict_latch_survives_until_deletion() {
    let mut store = store();
    let first = record(1, 1);
    publish(&mut store, &first).unwrap();
    assert_eq!(publish(&mut store, &record(1, 2)), Err(ErrorCode::Conflict));
    store.sweep(first.expires() + registry::DELETION_GRACE_SECONDS);
    assert_eq!(store.len(), 1);
    store.sweep(first.expires() + registry::DELETION_GRACE_SECONDS + 1);
    assert!(store.is_empty());
}

#[test]
fn verify_exposes_the_identity_for_the_rate_limit() {
    let mut store = store();
    let first = record(1, 1);
    let verified = store
        .verify(&request(&key(1), &first), &NONCE, NOW)
        .unwrap();
    assert_eq!(
        verified.record().identity(),
        &key(1).verifying_key().to_bytes()
    );
    assert_eq!(
        store.accept(&verified, NOW).unwrap().expires,
        first.expires()
    );
}

// ---- directory ----

#[test]
fn default_directory_lists_only_the_self_entry() {
    let store = store();
    assert_eq!(store.directory().version(), 1);
    assert_eq!(store.directory().relays(), [mock_entry()]);
    assert_eq!(
        store.self_entry().relay_id().as_str(),
        "mock.relay.ns.io:443"
    );
    assert_eq!(
        store.self_entry().capabilities().as_slice(),
        [capability::MAILBOX, capability::REGISTRY]
    );
}

#[test]
fn self_entry_takes_extra_capabilities_once() {
    let entry = self_entry(
        1,
        "AB".to_owned(),
        "mock.relay.ns.io".to_owned(),
        vec![ip()],
        443,
        &[capability::UDP, capability::REGISTRY, capability::WSS],
    )
    .unwrap();
    assert_eq!(
        entry.capabilities().as_slice(),
        [
            capability::MAILBOX,
            capability::REGISTRY,
            capability::UDP,
            capability::WSS
        ]
    );
    assert_eq!(
        self_entry(
            0,
            "AB".to_owned(),
            "mock.relay.ns.io".to_owned(),
            vec![ip()],
            443,
            &[]
        )
        .unwrap_err(),
        ErrorCode::InvalidDirectory
    );
}

#[test]
fn explicit_directory_must_list_the_self_entry() {
    let other = other_entry(2, "AC", "other.relay.ns.io");
    let listed = Directory::new(5, vec![other.clone(), mock_entry()]).unwrap();
    let store =
        RegistryStore::with_directory(Limits::default(), mock_entry(), listed.clone()).unwrap();
    assert_eq!(store.directory(), &listed);

    let reject = |directory: Directory| {
        RegistryStore::with_directory(Limits::default(), mock_entry(), directory).unwrap_err()
    };
    // Missing.
    assert_eq!(
        reject(Directory::new(5, vec![other]).unwrap()),
        ErrorCode::InvalidDirectory
    );
    // Same id, other host.
    assert_eq!(
        reject(Directory::new(5, vec![other_entry(1, "AB", "elsewhere.relay.ns.io")]).unwrap()),
        ErrorCode::InvalidDirectory
    );
    // Listed without registry.
    let mailbox_only = RelayEntry::new(
        1,
        "AB".to_owned(),
        "mock.relay.ns.io".to_owned(),
        vec![ip()],
        443,
        Capabilities::new(vec![capability::MAILBOX]).unwrap(),
    )
    .unwrap();
    assert_eq!(
        reject(Directory::new(5, vec![mailbox_only.clone()]).unwrap()),
        ErrorCode::InvalidDirectory
    );
    // A self entry without registry is refused by the default constructor too.
    assert_eq!(
        RegistryStore::new(Limits::default(), mailbox_only).unwrap_err(),
        ErrorCode::InvalidDirectory
    );
}

#[test]
fn set_directory_applies_the_update_rules() {
    let mut store = store();
    let other = other_entry(2, "AC", "other.relay.ns.io");
    let grown = Directory::new(2, vec![mock_entry(), other.clone()]).unwrap();
    store.set_directory(grown.clone()).unwrap();
    assert_eq!(store.directory(), &grown);
    // The same directory again is accepted.
    store.set_directory(grown.clone()).unwrap();

    // Lower version.
    let older = Directory::new(1, vec![mock_entry(), other.clone()]).unwrap();
    assert_eq!(store.set_directory(older), Err(ErrorCode::InvalidDirectory));
    // Same version, other content.
    let changed = Directory::new(2, vec![mock_entry()]).unwrap();
    assert_eq!(
        store.set_directory(changed),
        Err(ErrorCode::InvalidDirectory)
    );
    // Removes an id.
    let shrunk = Directory::new(3, vec![mock_entry()]).unwrap();
    assert_eq!(
        store.set_directory(shrunk),
        Err(ErrorCode::InvalidDirectory)
    );
    // Drops registry from the self entry.
    let demoted = RelayEntry::new(
        1,
        "AB".to_owned(),
        "mock.relay.ns.io".to_owned(),
        vec![ip()],
        443,
        Capabilities::new(vec![capability::MAILBOX]).unwrap(),
    )
    .unwrap();
    let demoted = Directory::new(3, vec![demoted, other]).unwrap();
    assert_eq!(
        store.set_directory(demoted),
        Err(ErrorCode::InvalidDirectory)
    );
    assert_eq!(store.directory(), &grown);
}
