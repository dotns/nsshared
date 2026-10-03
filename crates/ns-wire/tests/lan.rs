//! LAN prefix derivation: next §4.1.

use ed25519_dalek::SigningKey;
use ns_wire::{Identity, LAN_PREFIX_LEN, Lan6Prefix};
use proptest::prelude::*;
use sha2::{Digest, Sha256};
use std::net::{Ipv4Addr, Ipv6Addr};

fn demo_identity() -> Identity {
    let seed: [u8; 32] = Sha256::digest(b"ns-demo-node-v2").into();
    SigningKey::from_bytes(&seed).verifying_key().to_bytes()
}

const DEMO_IPV4: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 10);

// Pinned from Python: hashlib.blake2s(I + subnet_id.to_bytes(2, "big"), digest_size=9,
// key=b"ns-lan-addr-v2") with I the quick-v2 §2.3 demo identity.
const DEMO_PREFIX_0: Ipv6Addr = Ipv6Addr::new(0xfd05, 0x18f0, 0x3a1e, 0x227d, 0x658a, 0, 0, 0);
const DEMO_PREFIX_1: Ipv6Addr = Ipv6Addr::new(0xfdc4, 0x700a, 0x50ab, 0xbe11, 0x6586, 0, 0, 0);

#[test]
fn demo_prefix_subnet_0_matches_known_answer() {
    let prefix = Lan6Prefix::derive(&demo_identity(), 0);
    assert_eq!(prefix.addr(), DEMO_PREFIX_0);
    assert_eq!(prefix.bytes(), DEMO_PREFIX_0.octets());
    assert_eq!(
        prefix.embed(DEMO_IPV4),
        Ipv6Addr::new(0xfd05, 0x18f0, 0x3a1e, 0x227d, 0x658a, 0, 0xc0a8, 0x010a)
    );
    assert_eq!(prefix.to_string(), "fd05:18f0:3a1e:227d:658a::/96");
}

#[test]
fn demo_prefix_subnet_1_matches_known_answer() {
    let prefix = Lan6Prefix::derive(&demo_identity(), 1);
    assert_eq!(prefix.addr(), DEMO_PREFIX_1);
    assert_eq!(
        prefix.embed(DEMO_IPV4),
        Ipv6Addr::new(0xfdc4, 0x700a, 0x50ab, 0xbe11, 0x6586, 0, 0xc0a8, 0x010a)
    );
}

#[test]
fn prefix_len_is_96() {
    assert_eq!(LAN_PREFIX_LEN, 96);
    assert_eq!(Lan6Prefix::derive(&demo_identity(), 0).prefix_len(), 96);
}

#[test]
fn extract_returns_embedded_ipv4() {
    let prefix = Lan6Prefix::derive(&demo_identity(), 0);
    assert_eq!(prefix.extract(prefix.embed(DEMO_IPV4)), Some(DEMO_IPV4));
}

#[test]
fn refutation_extract_outside_prefix() {
    let prefix = Lan6Prefix::derive(&demo_identity(), 0);
    let other = Lan6Prefix::derive(&demo_identity(), 1);
    let foreign = other.embed(DEMO_IPV4);
    assert!(!prefix.contains(foreign));
    assert_eq!(prefix.extract(foreign), None);
    // A nonzero pad (bits 80..96) is outside the prefix.
    let padded = Ipv6Addr::new(0xfd05, 0x18f0, 0x3a1e, 0x227d, 0x658a, 1, 0xc0a8, 0x010a);
    assert_eq!(prefix.extract(padded), None);
}

proptest! {
    #[test]
    fn embed_extract_round_trip(
        identity in any::<[u8; 32]>(),
        subnet_id in any::<u16>(),
        ipv4 in any::<u32>(),
    ) {
        let prefix = Lan6Prefix::derive(&identity, subnet_id);
        let ipv4 = Ipv4Addr::from(ipv4);
        let address = prefix.embed(ipv4);
        prop_assert!(prefix.contains(address));
        prop_assert!(prefix.contains(prefix.addr()));
        prop_assert_eq!(prefix.extract(address), Some(ipv4));
        prop_assert_eq!(address.octets()[0], 0xfd);
        prop_assert_eq!(&address.octets()[10..12], &[0, 0]);
    }

    #[test]
    fn demo_subnet_ids_give_distinct_prefixes(a in any::<u16>(), b in any::<u16>()) {
        prop_assume!(a != b);
        let identity = demo_identity();
        prop_assert_ne!(Lan6Prefix::derive(&identity, a), Lan6Prefix::derive(&identity, b));
    }
}
