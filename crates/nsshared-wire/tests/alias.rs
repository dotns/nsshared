//! IPv4 alias candidates: quick-v2 §2.2, §6.2.

use ed25519_dalek::SigningKey;
use nsshared_wire::{
    AliasError, AliasPool, Identity, alias_candidate, alias_candidates, alias_h22, select_alias,
};
use sha2::{Digest, Sha256};
use std::net::Ipv4Addr;

fn demo_identity() -> Identity {
    let seed: [u8; 32] = Sha256::digest(b"ns-demo-node-v2").into();
    SigningKey::from_bytes(&seed).verifying_key().to_bytes()
}

#[test]
fn default_pool_is_cgnat_range() {
    let pool = AliasPool::default();
    assert_eq!(pool.base(), Ipv4Addr::new(100, 64, 0, 0));
    assert_eq!(pool.prefix_len(), 10);
    assert_eq!(pool.size(), 1 << 22);
    assert_eq!(AliasPool::new(Ipv4Addr::new(100, 64, 0, 0), 10), Ok(pool));
}

// Expected values computed independently with Python hashlib.blake2s(key=b"ns-alias4-v2",
// digest_size=3) over the demo identity.
#[test]
fn demo_candidates_match_independent_computation() {
    let pool = AliasPool::default();
    let ipv4 = alias_candidates(&demo_identity(), 4, &pool).unwrap();
    assert_eq!(
        ipv4[..3],
        [
            Ipv4Addr::new(100, 101, 160, 74),
            Ipv4Addr::new(100, 64, 224, 24),
            Ipv4Addr::new(100, 75, 90, 161),
        ]
    );
    assert_eq!(alias_h22(&demo_identity(), 4, 15), Ok(3_545_257));
    let ipv6 = alias_candidates(&demo_identity(), 6, &pool).unwrap();
    assert_eq!(
        ipv6[..3],
        [
            Ipv4Addr::new(100, 126, 156, 139),
            Ipv4Addr::new(100, 96, 37, 57),
            Ipv4Addr::new(100, 68, 90, 170),
        ]
    );
    assert_eq!(alias_h22(&demo_identity(), 6, 15), Ok(1_162_940));
    for (index, candidate) in (0..16).zip(ipv4) {
        assert_eq!(
            alias_candidate(&demo_identity(), 4, index, &pool),
            Ok(candidate)
        );
    }
}

#[test]
fn candidates_stay_inside_a_small_pool() {
    let pool = AliasPool::new(Ipv4Addr::new(10, 1, 2, 0), 24).unwrap();
    for candidate in alias_candidates(&demo_identity(), 4, &pool).unwrap() {
        assert_eq!(candidate.octets()[..3], [10, 1, 2]);
    }
    let single = AliasPool::new(Ipv4Addr::new(10, 1, 2, 3), 32).unwrap();
    assert_eq!(
        alias_candidates(&demo_identity(), 6, &single).unwrap(),
        [Ipv4Addr::new(10, 1, 2, 3); 16]
    );
}

#[test]
fn selection_skips_self4_and_unavailable_candidates() {
    let pool = AliasPool::default();
    let candidates = alias_candidates(&demo_identity(), 4, &pool).unwrap();
    assert_eq!(
        select_alias(&demo_identity(), 4, &pool, Ipv4Addr::LOCALHOST, |_| false),
        Ok(candidates[0])
    );
    assert_eq!(
        select_alias(&demo_identity(), 4, &pool, candidates[0], |address| {
            address == candidates[1]
        }),
        Ok(candidates[2])
    );
}

#[test]
fn refutation_alias_invalid_kind() {
    let pool = AliasPool::default();
    assert_eq!(
        alias_h22(&demo_identity(), 5, 0),
        Err(AliasError::InvalidKind(5))
    );
    assert_eq!(
        alias_candidates(&demo_identity(), 0, &pool),
        Err(AliasError::InvalidKind(0))
    );
    assert_eq!(
        select_alias(&demo_identity(), 46, &pool, Ipv4Addr::LOCALHOST, |_| false),
        Err(AliasError::InvalidKind(46))
    );
}

#[test]
fn refutation_alias_invalid_index() {
    assert_eq!(
        alias_h22(&demo_identity(), 4, 16),
        Err(AliasError::InvalidIndex(16))
    );
    assert_eq!(
        alias_candidate(&demo_identity(), 6, 255, &AliasPool::default()),
        Err(AliasError::InvalidIndex(255))
    );
}

#[test]
fn refutation_alias_pool_prefix_out_of_range() {
    assert_eq!(
        AliasPool::new(Ipv4Addr::new(10, 0, 0, 0), 33),
        Err(AliasError::PrefixOutOfRange(33))
    );
}

#[test]
fn refutation_alias_pool_misaligned_base() {
    assert_eq!(
        AliasPool::new(Ipv4Addr::new(100, 64, 0, 1), 10),
        Err(AliasError::MisalignedBase {
            base: Ipv4Addr::new(100, 64, 0, 1),
            prefix_len: 10,
        })
    );
    assert_eq!(
        AliasPool::new(Ipv4Addr::new(0, 0, 0, 1), 0),
        Err(AliasError::MisalignedBase {
            base: Ipv4Addr::new(0, 0, 0, 1),
            prefix_len: 0,
        })
    );
}

#[test]
fn refutation_alias_exhaustion() {
    let pool = AliasPool::default();
    let mut checked = 0;
    let result = select_alias(&demo_identity(), 4, &pool, Ipv4Addr::LOCALHOST, |_| {
        checked += 1;
        true
    });
    assert_eq!(result, Err(AliasError::Exhausted));
    assert_eq!(checked, 16);

    let single = AliasPool::new(Ipv4Addr::new(10, 1, 2, 3), 32).unwrap();
    assert_eq!(
        select_alias(
            &demo_identity(),
            4,
            &single,
            Ipv4Addr::new(10, 1, 2, 3),
            |_| false
        ),
        Err(AliasError::Exhausted)
    );
}
