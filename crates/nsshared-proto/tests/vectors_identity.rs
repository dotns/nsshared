//! Generated identity vectors (quick-v2 §2.2-§2.3).

#![allow(clippy::unwrap_used, clippy::panic, reason = "test fixture helpers")]

mod support;

use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use ed25519_dalek::SigningKey;
use nsshared_proto::{AddressGroup, NodeId};

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
