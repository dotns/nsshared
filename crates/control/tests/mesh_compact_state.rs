use control::mesh::*;
use std::collections::{BTreeMap, BTreeSet};

fn state() -> CompactState {
    CompactState {
        network_pub: [1; 32],
        seq: 7,
        members: BTreeMap::from([
            (
                [2; 32],
                CompactMember {
                    wg_pub: [4; 32],
                    incarnation: 2,
                },
            ),
            (
                [3; 32],
                CompactMember {
                    wg_pub: [5; 32],
                    incarnation: 1,
                },
            ),
        ]),
        admins_revision: 1,
        admins: BTreeSet::from([[2; 32]]),
        evicted_through: BTreeMap::from([([2; 32], 1), ([6; 32], 3)]),
    }
}

#[test]
fn mesh_compact_state_matches_independent_binary_and_digest() {
    let value = state();
    let mut expected = vec![0, 1];
    expected.extend_from_slice(&[1; 32]);
    expected.extend_from_slice(&7_u64.to_be_bytes());
    expected.extend_from_slice(&2_u32.to_be_bytes());
    for (key, wg, inc) in [(2, 4, 2_u64), (3, 5, 1)] {
        expected.extend_from_slice(&[key; 32]);
        expected.extend_from_slice(&[wg; 32]);
        expected.extend_from_slice(&inc.to_be_bytes());
    }
    expected.extend_from_slice(&1_u64.to_be_bytes());
    expected.extend_from_slice(&1_u32.to_be_bytes());
    expected.extend_from_slice(&[2; 32]);
    expected.extend_from_slice(&2_u32.to_be_bytes());
    for (key, watermark) in [(2, 1_u64), (6, 3)] {
        expected.extend_from_slice(&[key; 32]);
        expected.extend_from_slice(&watermark.to_be_bytes());
    }
    assert_eq!(expected.len(), 318);
    assert_eq!(value.encode().unwrap(), expected);
    // Fixed digest independently computed from the explicit binary fields with hashlib.
    assert_eq!(
        hex::encode(value.digest().unwrap()),
        "27ce18aadfec363d31981046fa06fab834e66786bf54ef9e7ab62d0257e29695"
    );
    assert_eq!(CompactState::decode(&expected).unwrap(), value);
    assert_eq!(
        CompactState::decode_for_anchor(&expected, &[1; 32], 7, &value.digest().unwrap()).unwrap(),
        value
    );
    assert!(
        CompactState::decode_for_anchor(&expected, &[2; 32], 7, &value.digest().unwrap()).is_err()
    );
    assert!(
        CompactState::decode_for_anchor(&expected, &[1; 32], 8, &value.digest().unwrap()).is_err()
    );
    assert!(CompactState::decode_for_anchor(&expected, &[1; 32], 7, &[0; 32]).is_err());
    let mut reordered = value.clone();
    reordered.members = value.members.into_iter().rev().collect();
    reordered.evicted_through = value.evicted_through.into_iter().rev().collect();
    assert_eq!(reordered.encode().unwrap(), expected);
}

#[test]
fn mesh_compact_state_rejects_order_duplicates_versions_and_truncation() {
    let bytes = state().encode().unwrap();
    for length in 0..bytes.len() {
        assert!(CompactState::decode(&bytes[..length]).is_err());
    }
    let mut extra = bytes.clone();
    extra.push(0);
    assert!(CompactState::decode(&extra).is_err());
    let mut version = bytes.clone();
    version[1] = 2;
    assert!(CompactState::decode(&version).is_err());
    let mut count = bytes.clone();
    count[42..46].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(CompactState::decode(&count).is_err());
    let mut duplicate = bytes.clone();
    duplicate[118..150].copy_from_slice(&[2; 32]);
    assert!(CompactState::decode(&duplicate).is_err());
    let mut reversed = bytes.clone();
    reversed[46..118].copy_from_slice(&bytes[118..190]);
    reversed[118..190].copy_from_slice(&bytes[46..118]);
    assert!(CompactState::decode(&reversed).is_err());
    let mut watermarks = bytes.clone();
    watermarks[278..310].copy_from_slice(&[2; 32]);
    assert!(CompactState::decode(&watermarks).is_err());
    let mut two_admins = state();
    two_admins.admins.insert([3; 32]);
    let mut admins = two_admins.encode().unwrap();
    admins[234..266].copy_from_slice(&[2; 32]);
    assert!(CompactState::decode(&admins).is_err());
    assert!(CompactState::decode(&vec![0; MAX_COMPACT_BYTES + 1]).is_err());
}

#[test]
fn mesh_compact_state_checks_capacities_and_incarnation_watermarks() {
    for change in [
        |s: &mut CompactState| s.members.get_mut(&[2; 32]).unwrap().incarnation = 0,
        |s: &mut CompactState| s.members.get_mut(&[2; 32]).unwrap().incarnation = 1,
        |s: &mut CompactState| s.members.get_mut(&[2; 32]).unwrap().wg_pub = [5; 32],
        |s: &mut CompactState| s.admins_revision = 8,
        |s: &mut CompactState| s.admins_revision = 0,
        |s: &mut CompactState| {
            s.evicted_through.insert([6; 32], 0);
        },
    ] {
        let mut invalid = state();
        change(&mut invalid);
        assert!(invalid.encode().is_err());
    }
    let mut capacity = state();
    capacity.members.clear();
    capacity.admins.clear();
    capacity.evicted_through.clear();
    for byte in 0..33 {
        capacity.members.insert(
            [byte; 32],
            CompactMember {
                wg_pub: [byte; 32],
                incarnation: u64::MAX,
            },
        );
    }
    assert!(capacity.encode().is_err());
    capacity.members.clear();
    for index in 0..MAX_RETAINED_IDENTITIES {
        let mut key = [0; 32];
        key[..8].copy_from_slice(&(index as u64).to_be_bytes());
        capacity.evicted_through.insert(key, u64::MAX);
    }
    let bytes = capacity.encode().unwrap();
    assert!(bytes.len() < MAX_COMPACT_BYTES);
    assert_eq!(CompactState::decode(&bytes).unwrap(), capacity);
    capacity.evicted_through.insert([255; 32], 1);
    assert!(capacity.encode().is_err());
    capacity.evicted_through.remove(&[255; 32]);
    capacity.members.insert(
        [255; 32],
        CompactMember {
            wg_pub: [1; 32],
            incarnation: 1,
        },
    );
    assert!(capacity.encode().is_err());
}
