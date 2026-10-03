//! Generated identity, lan6 and alias4 vectors (quick-v2 §2.2-§2.3, §6.2; next §4.1).

#![allow(clippy::unwrap_used, clippy::panic, reason = "test fixture helpers")]

mod support;

use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use ed25519_dalek::SigningKey;
use ns_wire::{
    AddressGroup, AliasError, AliasPool, Lan6Prefix, NodeId, alias_candidate, alias_candidates,
    alias_h22,
};
use std::net::{Ipv4Addr, Ipv6Addr};
use support::vectors::{Vector, load};
use x25519_dalek::{PublicKey, StaticSecret};

fn identity_of(vector: &Vector) -> [u8; 32] {
    vector.hex_array("identity")
}

#[test]
fn identities_match_vectors() {
    let vectors = load("identities");
    assert!(vectors.len() >= 5);
    for v in &vectors {
        let identity = SigningKey::from_bytes(&v.hex_array("seed"))
            .verifying_key()
            .to_bytes();
        assert_eq!(identity, identity_of(v), "{}", v.name());
        assert_eq!(URL_SAFE_NO_PAD.encode(identity), v.get("identity_b64url"));

        let node_id = NodeId::derive(&identity);
        assert_eq!(
            node_id.as_bytes(),
            &v.hex_array::<12>("node_id"),
            "{}",
            v.name()
        );
        assert_eq!(node_id.to_string(), v.get("node_id_text"));
        assert_eq!(v.get("node_id_text").parse::<NodeId>().unwrap(), node_id);

        let group = AddressGroup::derive(&identity);
        assert_eq!(group.n6_bytes(), v.hex_array::<16>("n6"), "{}", v.name());
        assert_eq!(group.n4_bytes(), v.hex_array::<16>("n4"), "{}", v.name());
        assert_eq!(group.n6().to_string(), v.get("n6_text"));
        assert_eq!(group.n4().to_string(), v.get("n4_text"));
        let mut g = [0_u8; 16];
        g[1..].copy_from_slice(&v.hex_array::<15>("g"));
        let low_120 = u128::from_be_bytes(group.n6_bytes()) & ((1_u128 << 120) - 1);
        assert_eq!(low_120 >> 1, u128::from_be_bytes(g), "{}", v.name());
        assert_eq!(AddressGroup::from_address(group.n4()), group);
        assert!(group.contains(group.n6()) && group.contains(group.n4()));

        if let Some(wg_seed) = v.opt("wg_seed") {
            let secret: [u8; 32] = support::vectors::decode_hex(wg_seed)
                .unwrap()
                .try_into()
                .unwrap();
            let wg_key = PublicKey::from(&StaticSecret::from(secret)).to_bytes();
            assert_eq!(wg_key, v.hex_array("wg_key"));
            assert_eq!(STANDARD.encode(wg_key), v.get("wg_key_b64"));
        }
    }
}

#[test]
fn lan6_matches_vectors() {
    let vectors = load("lan6");
    assert!(vectors.len() >= 12);
    for v in &vectors {
        let subnet_id = u16::try_from(v.u64("subnet_id")).unwrap();
        let prefix = Lan6Prefix::derive(&identity_of(v), subnet_id);
        assert_eq!(prefix.bytes(), v.hex_array::<16>("prefix"), "{}", v.name());
        assert_eq!(prefix.to_string(), v.get("prefix_text"));

        let ipv4s = v.all("ipv4");
        let embedded = v.all("embedded");
        let texts = v.all("embedded_text");
        assert!(!ipv4s.is_empty() && ipv4s.len() == embedded.len() && ipv4s.len() == texts.len());
        for ((ipv4, hex), text) in ipv4s.iter().zip(&embedded).zip(&texts) {
            let ipv4: Ipv4Addr = ipv4.parse().unwrap();
            let octets: [u8; 16] = support::vectors::decode_hex(hex)
                .unwrap()
                .try_into()
                .unwrap();
            let address = Ipv6Addr::from(octets);
            assert_eq!(prefix.embed(ipv4), address, "{}", v.name());
            assert_eq!(address.to_string(), *text);
            assert_eq!(prefix.extract(address), Some(ipv4));
        }
        let outside = Ipv6Addr::from(v.hex_array::<16>("outside"));
        assert!(!prefix.contains(outside));
        assert_eq!(prefix.extract(outside), None);
    }
}

#[test]
fn alias4_matches_vectors() {
    let vectors = load("alias4");
    let pool = AliasPool::default();
    let mut positives = 0;
    for v in &vectors {
        let identity = identity_of(v);
        let kind = u8::try_from(v.u64("kind")).unwrap();
        if v.is_reject() {
            let index = u8::try_from(v.u64("index")).unwrap();
            let expected = match v.reason() {
                "invalid_kind" => AliasError::InvalidKind(kind),
                "invalid_index" => AliasError::InvalidIndex(index),
                other => panic!("{}: unknown reason {other}", v.name()),
            };
            assert_eq!(
                alias_h22(&identity, kind, index),
                Err(expected),
                "{}",
                v.name()
            );
            assert_eq!(
                alias_candidate(&identity, kind, index, &pool),
                Err(expected)
            );
            continue;
        }
        positives += 1;
        assert_eq!(
            format!("{}/{}", pool.base(), pool.prefix_len()),
            v.get("pool")
        );
        let candidates = alias_candidates(&identity, kind, &pool).unwrap();
        let indices = v.all("index");
        let h22s = v.all("h22");
        let addresses = v.all("candidate");
        assert_eq!(indices.len(), candidates.len());
        assert!(indices.len() == h22s.len() && indices.len() == addresses.len());
        for ((index, h22), address) in indices.iter().zip(&h22s).zip(&addresses) {
            let index: u8 = index.parse().unwrap();
            let address: Ipv4Addr = address.parse().unwrap();
            assert_eq!(
                alias_h22(&identity, kind, index).unwrap(),
                h22.parse::<u32>().unwrap(),
                "{} index {index}",
                v.name()
            );
            assert_eq!(
                alias_candidate(&identity, kind, index, &pool).unwrap(),
                address
            );
            assert_eq!(candidates[usize::from(index)], address);
        }
    }
    assert!(positives >= 6);
}
