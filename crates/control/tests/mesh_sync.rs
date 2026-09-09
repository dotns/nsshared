use std::collections::{BTreeMap, BTreeSet};

use ciborium::value::Value;
use control::envelope::ControlEnvelope;
use control::mesh::*;
use ed25519_dalek::{Signer as _, SigningKey};
use sha2::{Digest as _, Sha256};

#[path = "fixtures/mesh-sync-v1/oracle.rs"]
mod oracle;

fn suite() -> serde_json::Value {
    serde_json::from_str(include_str!("fixtures/mesh-sync-v1/vectors.json")).unwrap()
}

fn bytes(suite: &serde_json::Value, name: &str) -> Vec<u8> {
    hex::decode(suite[name].as_str().unwrap()).unwrap()
}

fn fixed(name: &str) -> SyncFrame {
    let suite = suite();
    let vector = suite["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|vector| vector["name"] == name)
        .unwrap();
    SyncFrame::decode(&hex::decode(vector["frame_hex"].as_str().unwrap()).unwrap()).unwrap()
}

fn cbor(value: &Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(value, &mut bytes).unwrap();
    bytes
}

fn value(frame: &SyncFrame) -> Value {
    ciborium::de::from_reader(frame.encode_body().unwrap().as_slice()).unwrap()
}

fn fields(value: &mut Value) -> &mut Vec<(Value, Value)> {
    let Value::Map(fields) = value else {
        panic!("map")
    };
    fields
}

fn set(value: &mut Value, key: u64, new: Value) {
    let (_, slot) = fields(value)
        .iter_mut()
        .find(|(old, _)| *old == Value::Integer(key.into()))
        .unwrap();
    *slot = new;
}

#[test]
fn mesh_sync_independent_oracle_matches_fixed_frames_and_hashes() {
    let suite = suite();
    assert_eq!(suite, oracle::vectors());
    assert_eq!(suite["version"], 1);
    assert_eq!(suite["vectors"].as_array().unwrap().len(), 10);
    let mut kinds = BTreeSet::new();
    for vector in suite["vectors"].as_array().unwrap() {
        let raw = hex::decode(vector["frame_hex"].as_str().unwrap()).unwrap();
        let decoded = SyncFrame::decode(&raw).unwrap();
        assert_eq!(decoded.encode().unwrap(), raw, "{}", vector["name"]);
        assert_eq!(decoded.encode_body().unwrap(), &raw[4..]);
        assert_eq!(
            decode_sync_length(raw[..4].try_into().unwrap()).unwrap(),
            raw.len() - 4
        );
        assert_eq!(SyncFrame::decode_body(&raw[4..]).unwrap(), decoded);
        kinds.insert(match decoded.message {
            SyncMessage::Digest { .. } => 0,
            SyncMessage::Pull { .. } => 1,
            SyncMessage::Records { .. } => 2,
            SyncMessage::Done { .. } => 3,
            SyncMessage::DoneAck { .. } => 4,
        });
    }
    assert_eq!(kinds, BTreeSet::from([0, 1, 2, 3, 4]));
    assert_eq!(fixed("digest-empty").version.history_seq, 0);
    assert!(matches!(
        fixed("digest-empty").message,
        SyncMessage::Digest { owner_count: 0 }
    ));
    assert!(matches!(
        fixed("pull-genesis").message,
        SyncMessage::Pull {
            start: 0,
            base_history_digest: None,
            ..
        }
    ));
    assert!(matches!(
        fixed("pull-gap").message,
        SyncMessage::Pull {
            start: 1,
            base_history_digest: Some(_),
            ..
        }
    ));
    assert_ne!(fixed("done"), fixed("done-ack"));
}

#[test]
fn mesh_sync_frame_total_bound_is_checked_before_body_decode_without_widening_control() {
    let original = fixed("digest");
    let mut padded = value(&original);
    fields(&mut padded).push((Value::Integer(99.into()), Value::Bytes(Vec::new())));
    let length = MAX_SYNC_BODY - cbor(&padded).len() - 2;
    set(&mut padded, 99, Value::Bytes(vec![0; length]));
    let body = cbor(&padded);
    assert_eq!(body.len(), MAX_SYNC_BODY);
    assert_eq!(SyncFrame::decode_body(&body).unwrap(), original);
    let mut frame = (body.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(&body);
    assert_eq!(frame.len(), MAX_SYNC_FRAME);
    assert_eq!(SyncFrame::decode(&frame).unwrap(), original);
    assert!(Register::decode(&body).is_err());
    assert!(CommitReceipt::decode(&body).is_err());
    assert!(decode_sync_length((MAX_SYNC_BODY as u32).to_be_bytes()).is_ok());
    for length in [0, MAX_SYNC_BODY as u32 + 1, u32::MAX] {
        assert!(decode_sync_length(length.to_be_bytes()).is_err());
    }
    frame.push(0);
    assert!(SyncFrame::decode(&frame).is_err());
    assert!(SyncFrame::decode_body(&frame[4..]).is_err());
    for raw in [
        vec![],
        vec![0; 3],
        vec![0; 4],
        vec![0, 0, 0, 1],
        vec![0, 0, 0, 1, 0, 0],
    ] {
        assert!(SyncFrame::decode(&raw).is_err());
    }
    let canonical = original.encode().unwrap();
    for end in 0..canonical.len() {
        assert!(SyncFrame::decode(&canonical[..end]).is_err());
    }
}

#[test]
fn mesh_sync_rejects_invalid_cbor_versions_widths_and_preserves_optional_field_policy() {
    let original = fixed("digest");
    for (field, new) in [
        (0, Value::Integer(2.into())),
        (1, Value::Integer(5.into())),
        (1, Value::Integer((-1).into())),
        (2, Value::Bytes(vec![0; 31])),
        (3, Value::Null),
        (4, Value::Integer(65.into())),
        (4, Value::Bool(false)),
    ] {
        let mut bad = value(&original);
        set(&mut bad, field, new);
        assert!(SyncFrame::decode_body(&cbor(&bad)).is_err());
    }
    for key in 0..=4 {
        let mut bad = value(&original);
        fields(&mut bad).retain(|(k, _)| *k != Value::Integer(key.into()));
        assert!(SyncFrame::decode_body(&cbor(&bad)).is_err());
    }
    let mut bad = value(&original);
    let duplicate = fields(&mut bad)[0].clone();
    fields(&mut bad).push(duplicate);
    assert!(SyncFrame::decode_body(&cbor(&bad)).is_err());
    let mut bad = value(&original);
    let version = &mut fields(&mut bad)[3].1;
    let duplicate = fields(version)[1].clone();
    fields(version).push(duplicate);
    assert!(SyncFrame::decode_body(&cbor(&bad)).is_err());
    let mut good = value(&original);
    fields(&mut good).reverse();
    fields(&mut good).push((Value::Integer(99.into()), Value::Array(vec![Value::Null])));
    assert_eq!(SyncFrame::decode_body(&cbor(&good)).unwrap(), original);
    for unsupported in [Value::Float(1.0), Value::Tag(1, Box::new(Value::Null))] {
        set(&mut good, 99, unsupported);
        assert!(SyncFrame::decode_body(&cbor(&good)).is_err());
    }
    let canonical = original.encode_body().unwrap();
    let mut trailing = canonical.clone();
    trailing.push(0);
    assert!(SyncFrame::decode_body(&trailing).is_err());
    let mut indefinite = canonical.clone();
    indefinite[0] = 0xbf;
    indefinite.push(0xff);
    assert!(SyncFrame::decode_body(&indefinite).is_err());
    let mut nonminimal = canonical;
    nonminimal.splice(1..2, [0x18, 0x00]);
    assert!(SyncFrame::decode_body(&nonminimal).is_err());
    for name in ["done", "done-ack"] {
        let mut bad = value(&fixed(name));
        set(&mut bad, 4, Value::Bytes(vec![9; 15]));
        assert!(SyncFrame::decode_body(&cbor(&bad)).is_err());
    }
}

#[test]
fn mesh_sync_pages_enforce_ranges_receipt_context_counts_and_original_bounds() {
    let base = fixed("pull-gap");
    for message in [
        SyncMessage::Pull {
            request_id: 0,
            section: SyncSection::History,
            start: 1,
            limit: 24,
            base_history_digest: Some([0; 32]),
        },
        SyncMessage::Pull {
            request_id: 1,
            section: SyncSection::History,
            start: 2,
            limit: 24,
            base_history_digest: Some([0; 32]),
        },
        SyncMessage::Pull {
            request_id: 1,
            section: SyncSection::History,
            start: 0,
            limit: 24,
            base_history_digest: Some([0; 32]),
        },
        SyncMessage::Pull {
            request_id: 1,
            section: SyncSection::History,
            start: 1,
            limit: 24,
            base_history_digest: None,
        },
        SyncMessage::Pull {
            request_id: 1,
            section: SyncSection::Owners,
            start: 64,
            limit: 24,
            base_history_digest: None,
        },
        SyncMessage::Pull {
            request_id: 1,
            section: SyncSection::Owners,
            start: 0,
            limit: 0,
            base_history_digest: None,
        },
        SyncMessage::Pull {
            request_id: 1,
            section: SyncSection::Owners,
            start: 0,
            limit: 25,
            base_history_digest: None,
        },
        SyncMessage::Pull {
            request_id: 1,
            section: SyncSection::Owners,
            start: 0,
            limit: 24,
            base_history_digest: Some([0; 32]),
        },
    ] {
        assert!(
            SyncFrame {
                message,
                ..base.clone()
            }
            .encode()
            .is_err()
        );
    }
    let history = fixed("records-history");
    for case in 0..8 {
        let mut bad = history.clone();
        let SyncMessage::Records {
            request_id,
            start,
            entries: SyncEntries::History(entries),
            more,
        } = &mut bad.message
        else {
            panic!()
        };
        match case {
            0 => *request_id = 0,
            1 => *start = u64::MAX,
            2 => *more = true,
            3 => entries.swap(0, 1),
            4 => entries[0].original.clear(),
            5 => entries[0].original.resize(1201, 0),
            6 => entries[0].receipt.resize(1201, 0),
            _ => {
                let mut receipt = CommitReceipt::decode(&entries[0].receipt).unwrap();
                receipt.network_pub = [99; 32];
                entries[0].receipt = receipt.encode().unwrap();
            }
        }
        assert!(bad.encode().is_err());
    }
    for (start, count, bytes, more, valid) in [
        (0, 24, 1200, true, true),
        (48, 16, 1, false, true),
        (0, 25, 1, true, false),
        (0, 0, 1, false, false),
        (63, 2, 1, false, false),
        (63, 1, 1, true, false),
        (0, 1, 1201, false, false),
        (0, 1, 0, false, false),
        (u64::MAX, 2, 1, false, false),
    ] {
        let frame = SyncFrame {
            message: SyncMessage::Records {
                request_id: 1,
                start,
                entries: SyncEntries::Owners(vec![vec![1; bytes]; count]),
                more,
            },
            ..base.clone()
        };
        let encoded = frame.encode();
        assert_eq!(encoded.is_ok(), valid);
        if let Ok(encoded) = encoded {
            assert_eq!(SyncFrame::decode(&encoded).unwrap(), frame);
        }
    }
    let mut bad = value(&history);
    set(
        &mut bad,
        7,
        Value::Array(vec![Value::Array(vec![Value::Bytes(vec![1])])]),
    );
    assert!(SyncFrame::decode_body(&cbor(&bad)).is_err());
}

#[test]
fn mesh_sync_history_hashes_authenticated_originals_not_only_membership_or_receipt_encoding() {
    let suite = suite();
    let network: [u8; 32] = bytes(&suite, "network_pub_hex").try_into().unwrap();
    let relay: [u8; 32] = bytes(&suite, "relay_key_hex").try_into().unwrap();
    let original = bytes(&suite, "creation_hex");
    let genesis = Genesis::from_register(&original, &network).unwrap();
    let creation = CommitReceipt::decode(&bytes(&suite, "creation_receipt_hex")).unwrap();
    let zero = SyncHistoryDigest::from_genesis(&genesis, &creation, &relay).unwrap();
    assert_eq!(zero.network_pub(), &network);
    assert_eq!(zero.seq(), 0);
    assert_eq!(zero.digest().as_slice(), bytes(&suite, "history_0_hex"));
    let original = bytes(&suite, "record_hex");
    let receipt = CommitReceipt::decode(&bytes(&suite, "record_receipt_hex")).unwrap();
    let record = AuthenticatedRecord::verify(
        ManagementKind::Admins,
        &original,
        &receipt,
        &relay,
        &network,
        0,
    )
    .unwrap();
    let one = zero.advance(&record).unwrap();
    assert_eq!(one.seq(), 1);
    assert_eq!(one.digest().as_slice(), bytes(&suite, "history_1_hex"));
    assert_eq!(
        genesis.state().reduce_admins(&record).unwrap().effect,
        MembershipEffect::StaleAdminRevision
    );
    assert!(one.advance(&record).is_err());
    assert_eq!(zero.seq(), 0);
    for case in 0..3 {
        let mut bad = creation.clone();
        match case {
            0 => bad.seq = 1,
            1 => bad.record_digest[0] ^= 1,
            _ => bad.signature[0] ^= 1,
        }
        assert!(SyncHistoryDigest::from_genesis(&genesis, &bad, &relay).is_err());
    }
    let mut changed_receipt: Value =
        ciborium::de::from_reader(receipt.encode().unwrap().as_slice()).unwrap();
    fields(&mut changed_receipt).reverse();
    fields(&mut changed_receipt).push((Value::Integer(99.into()), Value::Bytes(vec![7])));
    let changed_receipt = CommitReceipt::decode(&cbor(&changed_receipt)).unwrap();
    let same = AuthenticatedRecord::verify(
        ManagementKind::Admins,
        &original,
        &changed_receipt,
        &relay,
        &network,
        0,
    )
    .unwrap();
    assert_eq!(zero.advance(&same).unwrap(), one);
    let mut reordered: Value = ciborium::de::from_reader(original.as_slice()).unwrap();
    fields(&mut reordered).reverse();
    let reordered = cbor(&reordered);
    assert_ne!(original, reordered);
    let mut other_receipt = receipt.clone();
    other_receipt.record_digest = Sha256::digest(&reordered).into();
    other_receipt.signature = SigningKey::from_bytes(&[13; 32])
        .sign(&other_receipt.signing_input())
        .to_bytes();
    let other = AuthenticatedRecord::verify(
        ManagementKind::Admins,
        &reordered,
        &other_receipt,
        &relay,
        &network,
        0,
    )
    .unwrap();
    assert_eq!(
        genesis.state().reduce_admins(&other).unwrap().state,
        genesis.state().reduce_admins(&record).unwrap().state
    );
    assert_ne!(zero.advance(&other).unwrap(), one);
    let foreign = SigningKey::from_bytes(&[17; 32]);
    other_receipt.signature = foreign.sign(&other_receipt.signing_input()).to_bytes();
    let other = AuthenticatedRecord::verify(
        ManagementKind::Admins,
        &reordered,
        &other_receipt,
        &foreign.verifying_key().to_bytes(),
        &network,
        0,
    )
    .unwrap();
    assert!(zero.advance(&other).is_err());
}

fn owner_record(network: [u8; 32], seed: u8, capability: bool, timestamp: u64) -> Vec<u8> {
    let (api, payload) = if capability {
        (
            CapabilityUpdate::API,
            CapabilityUpdate {
                network_pub: network,
                member_incarnation: 1,
                capabilities: 1,
            }
            .encode()
            .unwrap(),
        )
    } else {
        (
            AddressUpdate::API,
            AddressUpdate {
                network_pub: network,
                member_incarnation: 1,
                v4_salt: 7,
            }
            .encode()
            .unwrap(),
        )
    };
    let key = SigningKey::from_bytes(&[seed; 32]);
    let public = key.verifying_key().to_bytes();
    let mut input = b"nsio-ctrl-v1\0".to_vec();
    input.push(1);
    input.extend_from_slice(&(api.len() as u32).to_be_bytes());
    input.extend_from_slice(api.as_bytes());
    input.extend_from_slice(&timestamp.to_be_bytes());
    input.extend_from_slice(&[2; 16]);
    input.push(0);
    input.extend_from_slice(&public);
    input.extend_from_slice(&Sha256::digest(&payload));
    ControlEnvelope {
        v: 1,
        api: api.into(),
        ts: timestamp,
        nonce: [2; 16],
        machine_id: None,
        machine_key_pub: public,
        payload: payload.into(),
        signature: key.sign(&input).to_bytes(),
    }
    .to_cbor()
    .unwrap()
}

#[test]
fn mesh_sync_owner_digest_binds_winner_time_bytes_and_current_identity_without_remerging() {
    let suite = suite();
    let network: [u8; 32] = bytes(&suite, "network_pub_hex").try_into().unwrap();
    let original = bytes(&suite, "creation_hex");
    let genesis = Genesis::from_register(&original, &network).unwrap();
    let state = genesis.state();
    let owners: Vec<_> = suite["owners_hex"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| hex::decode(s.as_str().unwrap()).unwrap())
        .collect();
    let verified: Vec<_> = owners
        .iter()
        .map(|raw| AuthenticatedOwnerRecord::verify(raw, state).unwrap())
        .collect();
    let digest = sync_owners_digest(state, &verified).unwrap();
    assert_eq!(digest.as_slice(), bytes(&suite, "owners_2_hex"));
    assert_eq!(
        sync_owners_digest(state, &[]).unwrap().as_slice(),
        bytes(&suite, "owners_empty_hex")
    );
    let reversed: Vec<_> = owners
        .iter()
        .rev()
        .map(|raw| AuthenticatedOwnerRecord::verify(raw, state).unwrap())
        .collect();
    assert_eq!(sync_owners_digest(state, &reversed).unwrap(), digest);
    let duplicate: Vec<_> = [0, 0]
        .iter()
        .map(|&i| AuthenticatedOwnerRecord::verify(&owners[i], state).unwrap())
        .collect();
    assert!(sync_owners_digest(state, &duplicate).is_err());
    for case in 0..4 {
        let mut changed = state.clone();
        match case {
            0 => changed.network_pub = [88; 32],
            1 => changed.members.clear(),
            2 => changed.members.values_mut().next().unwrap().incarnation = 2,
            _ => changed.members.values_mut().next().unwrap().wg_pub = [88; 32],
        }
        assert!(sync_owners_digest(&changed, &verified).is_err());
    }
    let newer = owner_record(network, 11, true, 1001);
    let winners = [
        AuthenticatedOwnerRecord::verify(&owners[0], state).unwrap(),
        AuthenticatedOwnerRecord::verify(&newer, state).unwrap(),
    ];
    let updated = sync_owners_digest(state, &winners).unwrap();
    assert_ne!(updated, digest);
    let old_version = fixed("digest").version;
    assert_ne!(
        old_version,
        SyncVersion {
            owners_digest: updated,
            ..old_version
        }
    );
}

#[test]
fn mesh_sync_all_64_owner_winners_fit_bounded_pages_without_truncation() {
    let mut state = CompactState {
        network_pub: [99; 32],
        seq: 0,
        members: BTreeMap::new(),
        admins_revision: 0,
        admins: BTreeSet::new(),
        evicted_through: BTreeMap::new(),
    };
    let mut owners = Vec::new();
    for seed in 1..=32 {
        let public = SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes();
        state.members.insert(
            public,
            CompactMember {
                wg_pub: [seed; 32],
                incarnation: 1,
            },
        );
        for capability in [false, true] {
            owners.push(owner_record(state.network_pub, seed, capability, 1000));
        }
    }
    owners.sort_by_cached_key(|raw| {
        let owner = AuthenticatedOwnerRecord::verify(raw, &state).unwrap();
        (
            *owner.owner_pub(),
            owner.incarnation(),
            owner.kind() == OwnerRecordKind::Capability,
        )
    });
    let verified: Vec<_> = owners
        .iter()
        .map(|raw| AuthenticatedOwnerRecord::verify(raw, &state).unwrap())
        .collect();
    let owners_digest = sync_owners_digest(&state, &verified).unwrap();
    let mut received = Vec::new();
    for (index, page) in owners.chunks(MAX_SYNC_PAGE).enumerate() {
        let start = index * MAX_SYNC_PAGE;
        let frame = SyncFrame {
            network_pub: state.network_pub,
            version: SyncVersion {
                history_seq: 0,
                history_digest: [7; 32],
                owners_digest,
            },
            message: SyncMessage::Records {
                request_id: index as u64 + 1,
                start: start as u64,
                entries: SyncEntries::Owners(page.to_vec()),
                more: start + page.len() < owners.len(),
            },
        };
        let encoded = frame.encode().unwrap();
        assert!(encoded.len() > 1200 && encoded.len() <= MAX_SYNC_FRAME);
        let SyncMessage::Records {
            entries: SyncEntries::Owners(page),
            ..
        } = SyncFrame::decode(&encoded).unwrap().message
        else {
            panic!()
        };
        received.extend(page);
    }
    assert_eq!(received, owners);
    let too_many: Vec<_> = owners
        .iter()
        .chain(owners.iter().take(1))
        .map(|raw| AuthenticatedOwnerRecord::verify(raw, &state).unwrap())
        .collect();
    assert!(sync_owners_digest(&state, &too_many).is_err());
}
