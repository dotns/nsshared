#![allow(clippy::unwrap_used)]

use nsshared_control::account::{
    relay::{ParticipantRosterScope, RosterVersion},
    usage::RetentionSeal,
};
use nsshared_identity::keys::IdentitySecret;

#[test]
fn empty_retention_seal_roundtrip() {
    let scope = ParticipantRosterScope {
        issuer: IdentitySecret::from_seed([1; 32]).public(),
        recipient: IdentitySecret::from_seed([2; 32]).public(),
    };
    let seal = RetentionSeal {
        scope,
        owner_generation: 1,
        epoch: RosterVersion(7),
        parts: vec![],
    };
    let bytes = seal.canonical().unwrap();
    assert_eq!(RetentionSeal::decode(&bytes).unwrap(), seal);
    seal.validate_for(scope, 1).unwrap();
}

use nsshared_control::account::{
    AccountError, MAX_BYTES, MAX_IDENTITIES,
    relay::{Frame, FrameKind},
    usage::{RetentionError, RetentionOutcome, RetentionSealAck, UsageAnswer, UsageReport},
};
use nsshared_testkit::hex::unhex;
use std::collections::BTreeMap;

type Vector = BTreeMap<&'static str, &'static str>;

fn vectors() -> Vec<Vector> {
    nsshared_testkit::vector_fields!("account/usage/retention")
        .into_iter()
        .filter(|fields| fields.contains_key("bytes"))
        .collect()
}

fn seal(name: &str) -> RetentionSeal {
    let fields = vectors();
    let fields = fields.iter().find(|v| v["name"] == name).unwrap();
    RetentionSeal::decode(&unhex(fields["bytes"])).unwrap()
}

#[test]
fn retention_independent_vectors_and_participant_carrier() {
    let mut accepted_seals = 0;
    let mut accepted_acks = 0;
    let mut rejected = 0;
    for vector in vectors() {
        let bytes = unhex(vector["bytes"]);
        if vector["kind"] == "seal" {
            let decoded = RetentionSeal::decode(&bytes);
            if vector["decision"] == "reject" {
                assert!(decoded.is_err(), "{}", vector["name"]);
                rejected += 1;
                continue;
            }
            let decoded = decoded.unwrap();
            assert_eq!(decoded.canonical().unwrap(), bytes);
            assert_eq!(
                decoded.computed_digest().unwrap().as_slice(),
                unhex(vector["digest"])
            );
            assert!(UsageReport::decode(&bytes).is_err());
            assert!(UsageAnswer::decode(&bytes).is_err());
            assert!(RetentionSealAck::decode(&bytes).is_err());
            Frame::new(FrameKind::Report, bytes).unwrap();
            accepted_seals += 1;
        } else {
            let decoded = RetentionSealAck::decode(&bytes);
            if vector["decision"] == "reject" {
                assert!(decoded.is_err(), "{}", vector["name"]);
                rejected += 1;
                continue;
            }
            let decoded = decoded.unwrap();
            assert_eq!(decoded.canonical().unwrap(), bytes);
            assert_eq!(
                decoded.validate_for(&seal(vector["seal"])).unwrap(),
                decoded.outcome
            );
            assert!(UsageAnswer::decode(&bytes).is_err());
            assert!(RetentionSeal::decode(&bytes).is_err());
            Frame::new(FrameKind::Answer, bytes).unwrap();
            accepted_acks += 1;
        }
    }
    assert_eq!(accepted_seals, 2);
    assert_eq!(accepted_acks, 10);
    assert_eq!(rejected, 33);
}

#[test]
fn retention_authenticated_scope_and_immutable_replay() {
    let original = seal("populated");
    original
        .validate_for(original.scope, original.owner_generation)
        .unwrap();
    original.validate_duplicate(&original).unwrap();
    let stranger = IdentitySecret::from_seed([3; 32]).public();
    let mut scope = original.scope;
    scope.issuer = stranger;
    assert!(matches!(
        original.validate_for(scope, 3),
        Err(RetentionError::Issuer)
    ));
    scope = original.scope;
    scope.recipient = stranger;
    assert!(matches!(
        original.validate_for(scope, 3),
        Err(RetentionError::Recipient)
    ));
    assert!(matches!(
        original.validate_for(original.scope, 4),
        Err(RetentionError::OwnerGeneration)
    ));
    for field in 0..4 {
        let mut changed = original.clone();
        match field {
            0 => changed.scope.issuer = stranger,
            1 => changed.scope.recipient = stranger,
            2 => changed.owner_generation += 1,
            _ => changed.epoch.0 += 1,
        }
        assert!(changed.validate_duplicate(&original).is_err());
        assert_ne!(
            changed.computed_digest().unwrap(),
            original.computed_digest().unwrap()
        );
    }
    for field in 0..6 {
        let mut changed = original.clone();
        let last = changed.parts.last_mut().unwrap();
        match field {
            0 => last.incarnation.0[0] += 1,
            1 => last.profile = nsshared_control::account::usage::UsageProfile::Service,
            2 => last.sequence += 1,
            3 => last.part_index += 1,
            4 => last.part_digest[0] ^= 1,
            _ => changed.parts.clear(),
        }
        assert!(matches!(
            changed.validate_duplicate(&original),
            Err(RetentionError::Conflict)
        ));
        assert_ne!(
            changed.computed_digest().unwrap(),
            original.computed_digest().unwrap()
        );
    }
    let empty = seal("empty");
    empty.validate_duplicate(&empty).unwrap();
    assert!(matches!(
        empty.validate_duplicate(&original),
        Err(RetentionError::Conflict)
    ));
}

#[test]
fn retention_ack_correlates_every_identity_field_and_digest() {
    let original = seal("populated");
    let ack = RetentionSealAck {
        scope: original.scope,
        owner_generation: original.owner_generation,
        epoch: original.epoch,
        seal_digest: original.computed_digest().unwrap(),
        outcome: RetentionOutcome::Committed,
    };
    assert_eq!(
        ack.validate_for(&original).unwrap(),
        RetentionOutcome::Committed
    );
    for field in 0..5 {
        let mut changed = ack.clone();
        match field {
            0 => changed.scope.issuer = original.scope.recipient,
            1 => changed.scope.recipient = original.scope.issuer,
            2 => changed.owner_generation += 1,
            3 => changed.epoch.0 += 1,
            _ => changed.seal_digest[0] ^= 1,
        }
        let err = changed.validate_for(&original).unwrap_err();
        assert!(matches!(
            (field, err),
            (0, RetentionError::Issuer)
                | (1, RetentionError::Recipient)
                | (2, RetentionError::OwnerGeneration)
                | (3, RetentionError::Epoch)
                | (4, RetentionError::Digest)
        ));
    }
    assert!(matches!(
        ack.validate_for(&seal("empty")),
        Err(RetentionError::Digest)
    ));
}

#[test]
fn retention_constructed_bounds_and_ordering() {
    let original = seal("populated");
    let mut changed = original.clone();
    changed.parts.swap(0, 1);
    assert!(changed.canonical().is_err());
    let mut changed = original.clone();
    changed.parts.insert(1, changed.parts[0].clone());
    changed.parts[1].part_digest[0] ^= 1;
    assert!(changed.canonical().is_err());
    let mut changed = original.clone();
    changed.parts = vec![original.parts[0].clone(); MAX_IDENTITIES + 1];
    assert!(matches!(
        changed.canonical(),
        Err(RetentionError::Contract(AccountError::Bounds))
    ));
    changed.parts = (1..=MAX_IDENTITIES)
        .map(|sequence| {
            let mut part = original.parts[0].clone();
            part.sequence = sequence as u64;
            part
        })
        .collect();
    let encoded = changed.canonical().unwrap();
    assert_eq!(RetentionSeal::decode(&encoded).unwrap(), changed);
    Frame::new(FrameKind::Report, encoded).unwrap();
    for field in 0..4 {
        let mut changed = original.clone();
        match field {
            0 => changed.owner_generation = 0,
            1 => changed.epoch.0 = 0,
            2 => changed.parts[0].sequence = 0,
            _ => changed.parts[0].part_index = MAX_IDENTITIES as u64,
        }
        assert!(changed.canonical().is_err());
    }
    assert!(RetentionSeal::decode(&vec![0; MAX_BYTES + 1]).is_err());
    assert!(RetentionSealAck::decode(&vec![0; MAX_BYTES + 1]).is_err());
}
