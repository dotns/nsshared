use std::collections::{BTreeMap, BTreeSet};

use control::envelope::ControlEnvelope;
use control::mesh::*;
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}
fn public(seed: u8) -> [u8; 32] {
    key(seed).verifying_key().to_bytes()
}

fn state() -> CompactState {
    CompactState {
        network_pub: public(12),
        seq: 1,
        members: BTreeMap::from([
            (
                public(11),
                CompactMember {
                    wg_pub: [4; 32],
                    incarnation: 1,
                },
            ),
            (
                public(15),
                CompactMember {
                    wg_pub: [5; 32],
                    incarnation: 1,
                },
            ),
        ]),
        admins_revision: 0,
        admins: BTreeSet::new(),
        evicted_through: BTreeMap::new(),
    }
}

struct Signed {
    kind: ManagementKind,
    raw: Vec<u8>,
    receipt: CommitReceipt,
}
impl Signed {
    fn new(kind: ManagementKind, raw: Vec<u8>, author: u8, op_id: [u8; 16], seq: u64) -> Self {
        let mut receipt = CommitReceipt {
            network_pub: public(12),
            author_pub: public(author),
            op_id,
            seq,
            record_digest: Sha256::digest(&raw).into(),
            signature: [0; 64],
        };
        receipt.signature = key(13).sign(&receipt.signing_input()).to_bytes();
        Self { kind, raw, receipt }
    }
    fn verified(&self) -> AuthenticatedRecord<'_> {
        AuthenticatedRecord::verify(
            self.kind,
            &self.raw,
            &self.receipt,
            &public(13),
            &public(12),
            self.receipt.seq - 1,
        )
        .unwrap()
    }
}

fn add_value(author: u8, joiner: u8, incarnation: u64, wg: u8) -> Accept {
    let approver_wg = [match author {
        11 => 4,
        15 => 5,
        _ => 7,
    }; 32];
    Accept {
        network_pub: public(12),
        network_name: "fixture".into(),
        relay_origin: "https://relay.example:443".into(),
        approver_wg,
        joiner_id: member_id(&public(joiner)),
        joiner_pub: public(joiner),
        joiner_wg: [wg; 32],
        request_id: [2; 16],
        member_incarnation: incarnation,
        capabilities: 0,
        joiner_addrs: derive_overlay_addresses(&[wg; 32], 0).unwrap(),
        approver_addrs: derive_overlay_addresses(&approver_wg, 0).unwrap(),
        added_at: 1000,
        expires_at: 1060,
        network_sig: [0; 64],
    }
}

fn sign_add(mut add: Accept, author: u8, seq: u64) -> Signed {
    add.request_id[8..].copy_from_slice(&seq.to_be_bytes());
    add.network_sig = key(12)
        .sign(&add.network_signing_input().unwrap())
        .to_bytes();
    let mut envelope = ControlEnvelope {
        v: 1,
        api: Accept::API.into(),
        ts: add.added_at,
        nonce: [3; 16],
        machine_id: None,
        machine_key_pub: public(author),
        payload: add.encode().unwrap().into(),
        signature: [0; 64],
    };
    let mut input = b"nsio-ctrl-v1\0".to_vec();
    input.push(1);
    input.extend_from_slice(&u32::try_from(envelope.api.len()).unwrap().to_be_bytes());
    input.extend_from_slice(envelope.api.as_bytes());
    input.extend_from_slice(&envelope.ts.to_be_bytes());
    input.extend_from_slice(&envelope.nonce);
    input.push(0);
    input.extend_from_slice(&envelope.machine_key_pub);
    input.extend_from_slice(&Sha256::digest(&envelope.payload));
    envelope.signature = key(author).sign(&input).to_bytes();
    Signed::new(
        ManagementKind::Add,
        envelope.to_cbor().unwrap(),
        author,
        add.request_id,
        seq,
    )
}

fn sign_admins(author: u8, members: &[u8], revision: u64, seq: u64) -> Signed {
    let mut op_id = [9; 16];
    op_id[8..].copy_from_slice(&seq.to_be_bytes());
    let ids: BTreeSet<_> = members
        .iter()
        .map(|seed| member_id(&public(*seed)))
        .collect();
    let admins = Admins {
        admins: ids.into_iter().flatten().collect(),
        admins_revision: revision,
    };
    let mut record = SignedManagementRecord {
        kind: SignedManagementRecord::ADMINS,
        network_pub: public(12),
        op_id,
        author_pub: public(author),
        issued_at: 1000,
        expires_at: 1060,
        body: admins.encode().unwrap(),
        signature: [0; 64],
    };
    record.signature = key(author)
        .sign(&record.signing_input().unwrap())
        .to_bytes();
    Signed::new(
        ManagementKind::Admins,
        record.encode().unwrap(),
        author,
        record.op_id,
        seq,
    )
}

fn unchanged_membership(
    old: &CompactState,
    reduction: &MembershipReduction,
    effect: MembershipEffect,
) {
    let mut expected = old.clone();
    expected.seq += 1;
    assert_eq!(reduction.effect, effect);
    assert_eq!(reduction.state, expected);
}

#[test]
fn mesh_membership_adds_preserve_watermarks_and_only_advance_incarnations() {
    let initial = state();
    let original = sign_add(add_value(11, 14, 1, 6), 11, 2);
    let reduction = initial.reduce_add(&original.verified()).unwrap();
    assert_eq!(reduction.effect, MembershipEffect::Applied);
    assert_eq!(reduction.state.seq, 2);
    assert_eq!(reduction.state.members.len(), 3);
    assert_eq!(
        reduction.state.members[&public(14)],
        CompactMember {
            wg_pub: [6; 32],
            incarnation: 1
        }
    );
    assert_eq!(initial, state());
    assert!(reduction.state.reduce_add(&original.verified()).is_err());
    let repeated = sign_add(add_value(11, 14, 1, 9), 11, 3);
    let stale = reduction.state.reduce_add(&repeated.verified()).unwrap();
    unchanged_membership(&reduction.state, &stale, MembershipEffect::StaleIncarnation);
    let mut evicted = initial;
    evicted.evicted_through.insert(public(14), 1);
    unchanged_membership(
        &evicted,
        &evicted.reduce_add(&original.verified()).unwrap(),
        MembershipEffect::StaleIncarnation,
    );
    let rejoin = sign_add(add_value(11, 14, 2, 8), 11, 2);
    let admitted = evicted.reduce_add(&rejoin.verified()).unwrap();
    assert_eq!(admitted.effect, MembershipEffect::Applied);
    assert_eq!(admitted.state.members[&public(14)].incarnation, 2);
    assert_eq!(admitted.state.evicted_through[&public(14)], 1);
    let old = sign_add(add_value(11, 14, 1, 6), 11, 3);
    unchanged_membership(
        &admitted.state,
        &admitted.state.reduce_add(&old.verified()).unwrap(),
        MembershipEffect::StaleIncarnation,
    );
    evicted.evicted_through.insert(public(14), u64::MAX);
    let exhausted = sign_add(add_value(11, 14, u64::MAX, 8), 11, 2);
    unchanged_membership(
        &evicted,
        &evicted.reduce_add(&exhausted.verified()).unwrap(),
        MembershipEffect::StaleIncarnation,
    );
}

#[test]
fn mesh_membership_admin_revision_races_and_last_admin_removal_are_deterministic() {
    let initial = state();
    let designate = sign_admins(15, &[11], 1, 2);
    let first = initial.reduce_admins(&designate.verified()).unwrap();
    assert_eq!(first.effect, MembershipEffect::Applied);
    assert_eq!(first.state.admins, BTreeSet::from([public(11)]));
    assert_eq!(first.state.admins_revision, 1);
    let denied = sign_admins(15, &[15], 2, 3);
    let second = first.state.reduce_admins(&denied.verified()).unwrap();
    unchanged_membership(&first.state, &second, MembershipEffect::NotEntitled);
    let update = sign_admins(11, &[15, 11], 2, 4);
    let third = second.state.reduce_admins(&update.verified()).unwrap();
    assert_eq!(third.effect, MembershipEffect::Applied);
    assert_eq!(third.state.admins, BTreeSet::from([public(11), public(15)]));
    let race = sign_admins(11, &[11], 2, 5);
    let fourth = third.state.reduce_admins(&race.verified()).unwrap();
    unchanged_membership(&third.state, &fourth, MembershipEffect::StaleAdminRevision);
    let clear = sign_admins(15, &[], 3, 6);
    let fifth = fourth.state.reduce_admins(&clear.verified()).unwrap();
    assert_eq!(fifth.effect, MembershipEffect::Applied);
    assert!(fifth.state.admins.is_empty());
    assert_eq!(fifth.state.admins_revision, 3);
    let join = sign_add(add_value(15, 14, 1, 6), 15, 7);
    assert_eq!(
        fifth.state.reduce_add(&join.verified()).unwrap().effect,
        MembershipEffect::Applied
    );
    for revision in [1, 4, u64::MAX] {
        let stale = sign_admins(11, &[15], revision, 3);
        unchanged_membership(
            &first.state,
            &first.state.reduce_admins(&stale.verified()).unwrap(),
            MembershipEffect::StaleAdminRevision,
        );
    }
}

#[test]
fn mesh_membership_admins_resolve_retained_full_keys_without_restoring_membership() {
    let mut initial = state();
    initial.admins_revision = 1;
    initial.admins = BTreeSet::from([public(11), public(16)]);
    let retain = sign_admins(11, &[16, 11], 2, 2);
    let retained = initial.reduce_admins(&retain.verified()).unwrap();
    assert_eq!(retained.effect, MembershipEffect::Applied);
    assert_eq!(retained.state.admins, initial.admins);
    assert_eq!(retained.state.members, initial.members);
    let unauthorized = sign_admins(16, &[], 3, 3);
    unchanged_membership(
        &retained.state,
        &retained
            .state
            .reduce_admins(&unauthorized.verified())
            .unwrap(),
        MembershipEffect::NotEntitled,
    );
    let remove = sign_admins(11, &[11], 3, 3);
    let removed = retained.state.reduce_admins(&remove.verified()).unwrap();
    assert_eq!(removed.effect, MembershipEffect::Applied);
    assert_eq!(removed.state.admins, BTreeSet::from([public(11)]));
    assert_eq!(removed.state.members, initial.members);
}

#[test]
fn mesh_membership_never_grants_nonmembers_or_nonadmins_historical_management_rights() {
    let mut initial = state();
    initial.admins_revision = 1;
    initial.admins.insert(public(11));
    for author in [15, 16] {
        let add = sign_add(add_value(author, 14, 1, 6), author, 2);
        unchanged_membership(
            &initial,
            &initial.reduce_add(&add.verified()).unwrap(),
            MembershipEffect::NotEntitled,
        );
        let admins = sign_admins(author, &[], 2, 2);
        unchanged_membership(
            &initial,
            &initial.reduce_admins(&admins.verified()).unwrap(),
            MembershipEffect::NotEntitled,
        );
    }
    // This valid compact input does not select how evict transitions the admin set.
    initial.members.remove(&public(11));
    let add = sign_add(add_value(11, 14, 1, 6), 11, 2);
    unchanged_membership(
        &initial,
        &initial.reduce_add(&add.verified()).unwrap(),
        MembershipEffect::NotEntitled,
    );
    let admins = sign_admins(11, &[15], 2, 2);
    unchanged_membership(
        &initial,
        &initial.reduce_admins(&admins.verified()).unwrap(),
        MembershipEffect::NotEntitled,
    );
    let mut initial = state();
    initial.members.get_mut(&public(11)).unwrap().wg_pub = [8; 32];
    unchanged_membership(
        &initial,
        &initial.reduce_add(&add.verified()).unwrap(),
        MembershipEffect::NotEntitled,
    );
    let envelope = ControlEnvelope::from_cbor(&add.raw).unwrap();
    assert!(envelope.verify_request(2000).is_err());
    assert_eq!(
        state().reduce_add(&add.verified()).unwrap().effect,
        MembershipEffect::Applied
    );
}

#[test]
fn mesh_membership_rejects_wrong_context_gaps_overflow_and_field_bindings() {
    let initial = state();
    let add = sign_add(add_value(11, 14, 1, 6), 11, 2);
    let admins = sign_admins(11, &[15], 1, 2);
    assert!(initial.reduce_add(&admins.verified()).is_err());
    assert!(initial.reduce_admins(&add.verified()).is_err());
    for change in [
        |s: &mut CompactState| s.network_pub = public(17),
        |s: &mut CompactState| s.seq = 0,
        |s: &mut CompactState| s.seq = 2,
        |s: &mut CompactState| s.seq = u64::MAX,
        |s: &mut CompactState| s.members.get_mut(&public(15)).unwrap().wg_pub = [4; 32],
    ] {
        let mut bad = initial.clone();
        change(&mut bad);
        assert!(bad.reduce_add(&add.verified()).is_err());
        assert!(bad.reduce_admins(&admins.verified()).is_err());
    }
    for change in [
        |a: &mut Accept| a.joiner_addrs.v4[3] ^= 1,
        |a: &mut Accept| a.approver_addrs.v6[15] ^= 1,
    ] {
        let mut bad = add_value(11, 14, 1, 6);
        change(&mut bad);
        let signed = sign_add(bad, 11, 2);
        assert!(initial.reduce_add(&signed.verified()).is_err());
    }
    let duplicate_wg = sign_add(add_value(11, 14, 1, 4), 11, 2);
    assert!(initial.reduce_add(&duplicate_wg.verified()).is_err());
    let unknown_admin = sign_admins(11, &[18], 1, 2);
    assert!(initial.reduce_admins(&unknown_admin.verified()).is_err());
    assert_eq!(initial, state());
}

#[test]
fn mesh_membership_enforces_member_and_retained_identity_capacity_without_partial_results() {
    let mut full = state();
    for seed in 40..70 {
        full.members.insert(
            public(seed),
            CompactMember {
                wg_pub: [seed; 32],
                incarnation: 1,
            },
        );
    }
    assert_eq!(full.members.len(), MAX_COMPACT_MEMBERS);
    full.validate().unwrap();
    let original = full.clone();
    let add = sign_add(add_value(11, 14, 1, 6), 11, 2);
    assert!(full.reduce_add(&add.verified()).is_err());
    assert_eq!(full, original);
    let replace = sign_add(add_value(11, 15, 2, 5), 11, 2);
    let replacement = full.reduce_add(&replace.verified()).unwrap();
    assert_eq!(replacement.effect, MembershipEffect::Applied);
    assert_eq!(replacement.state.members.len(), MAX_COMPACT_MEMBERS);
    let mut retained = state();
    for index in 0_u64..4094 {
        let mut identity = [99; 32];
        identity[..8].copy_from_slice(&index.to_be_bytes());
        retained.evicted_through.insert(identity, 1);
    }
    retained.validate().unwrap();
    assert!(retained.reduce_add(&add.verified()).is_err());
    retained.evicted_through.pop_first();
    retained.evicted_through.insert(public(14), 1);
    let rejoin = sign_add(add_value(11, 14, 2, 6), 11, 2);
    let restored = retained.reduce_add(&rejoin.verified()).unwrap();
    assert_eq!(restored.effect, MembershipEffect::Applied);
    assert_eq!(restored.state.evicted_through, retained.evicted_through);
    assert_eq!(restored.state.members.len(), 3);
}
