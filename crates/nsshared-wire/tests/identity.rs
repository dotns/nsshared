//! Identity derivations: quick-v2 §2.2-§2.3.

use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use ed25519_dalek::SigningKey;
use nsshared_wire::{
    AddressConflict, AddressGroup, GroupOwner, Identity, NodeId, NodeIdParseError,
    check_address_conflict,
};
use proptest::prelude::*;
use sha2::{Digest, Sha256};
use std::net::Ipv6Addr;
use x25519_dalek::{PublicKey, StaticSecret};

fn demo_identity() -> Identity {
    let seed: [u8; 32] = Sha256::digest(b"ns-demo-node-v2").into();
    SigningKey::from_bytes(&seed).verifying_key().to_bytes()
}

fn other_identity() -> Identity {
    let seed: [u8; 32] = Sha256::digest(b"ns-other-node").into();
    SigningKey::from_bytes(&seed).verifying_key().to_bytes()
}

#[test]
fn demo_identity_matches_spec_example() {
    assert_eq!(
        URL_SAFE_NO_PAD.encode(demo_identity()),
        "x9wqBt4ZKdMxi43oc78ScDDD7gAH8g4G6g_FQFZ0Wvs"
    );
}

#[test]
fn demo_wireguard_key_matches_spec_example() {
    let secret: [u8; 32] = Sha256::digest(b"ns-demo-wg-v2").into();
    let public = PublicKey::from(&StaticSecret::from(secret));
    assert_eq!(
        STANDARD.encode(public.as_bytes()),
        "NZkMHL1XEJhrcG68XIzeUZktuR/U1aR2e6u2dcRMzDk="
    );
}

#[test]
fn demo_node_id_matches_spec_example() {
    let node_id = NodeId::derive(&demo_identity());
    assert_eq!(node_id.to_string(), "5kemem6slxrgyd63rcqa");
    assert_eq!("5kemem6slxrgyd63rcqa".parse::<NodeId>(), Ok(node_id));
    assert!(!node_id.is_zero());
}

#[test]
fn demo_addresses_match_spec_example() {
    let group = AddressGroup::derive(&demo_identity());
    let n6: Ipv6Addr = "fda6:72ac:58cb:cc8d:1e39:e507:bda:5052".parse().unwrap();
    let n4: Ipv6Addr = "fda6:72ac:58cb:cc8d:1e39:e507:bda:5053".parse().unwrap();
    assert_eq!(group.n6(), n6);
    assert_eq!(group.n4(), n4);
    assert_eq!(group.n6_bytes(), n6.octets());
    assert_eq!(group.n4_bytes(), n4.octets());
    assert_eq!(group.prefix_len(), 127);
    assert_eq!(
        group.to_string(),
        "fda6:72ac:58cb:cc8d:1e39:e507:bda:5052/127"
    );
    assert!(group.contains(n6));
    assert!(group.contains(n4));
    assert!(!group.contains("fda6:72ac:58cb:cc8d:1e39:e507:bda:5054".parse().unwrap()));
    assert_eq!(AddressGroup::from_address(n4), group);
}

#[test]
fn zero_node_id_is_zero() {
    let node_id = NodeId::from_bytes([0; 12]);
    assert!(node_id.is_zero());
    assert_eq!(node_id.to_string(), "aaaaaaaaaaaaaaaaaaaa");
    assert_eq!(node_id.as_bytes(), &[0; 12]);
}

#[test]
fn refutation_node_id_padding() {
    assert_eq!(
        "5kemem6slxrgyd63rcqa====".parse::<NodeId>(),
        Err(NodeIdParseError::Padding)
    );
}

#[test]
fn refutation_node_id_uppercase() {
    assert_eq!(
        "5KEMEM6SLXRGYD63RCQA".parse::<NodeId>(),
        Err(NodeIdParseError::Uppercase)
    );
}

#[test]
fn refutation_node_id_length() {
    assert_eq!(
        "5kemem6slxrgyd63rcq".parse::<NodeId>(),
        Err(NodeIdParseError::Length(19))
    );
    assert_eq!(
        "5kemem6slxrgyd63rcqaa".parse::<NodeId>(),
        Err(NodeIdParseError::Length(21))
    );
    assert_eq!("".parse::<NodeId>(), Err(NodeIdParseError::Length(0)));
}

#[test]
fn refutation_node_id_invalid_character() {
    assert_eq!(
        "5kemem6slxrgyd63rcq1".parse::<NodeId>(),
        Err(NodeIdParseError::InvalidCharacter(b'1'))
    );
    assert_eq!(
        "5kemem6slxrgyd63rcq-".parse::<NodeId>(),
        Err(NodeIdParseError::InvalidCharacter(b'-'))
    );
}

#[test]
fn refutation_node_id_non_zero_trailing_bits() {
    // `b` = 1 sets the lowest of the four padding bits.
    assert_eq!(
        "5kemem6slxrgyd63rcqb".parse::<NodeId>(),
        Err(NodeIdParseError::NonZeroTrailingBits)
    );
}

#[test]
fn distinct_identities_do_not_conflict() {
    let own = GroupOwner::derive(&demo_identity());
    let peers = [GroupOwner::derive(&[7; 32])];
    let candidate = check_address_conflict(&own, &other_identity(), &peers).unwrap();
    assert_eq!(candidate, GroupOwner::derive(&other_identity()));
}

#[test]
fn same_identity_is_not_a_conflict() {
    let own = GroupOwner::derive(&demo_identity());
    let peers = [GroupOwner::derive(&other_identity())];
    assert!(check_address_conflict(&own, &other_identity(), &peers).is_ok());
    assert!(check_address_conflict(&own, &demo_identity(), &[]).is_ok());
}

#[test]
fn refutation_address_conflict_with_self() {
    let candidate = other_identity();
    let group = AddressGroup::derive(&candidate);
    let own = GroupOwner {
        identity: demo_identity(),
        group,
    };
    assert_eq!(
        check_address_conflict(&own, &candidate, &[]),
        Err(AddressConflict {
            identity: demo_identity(),
            group,
        })
    );
}

#[test]
fn refutation_address_conflict_with_peer() {
    let candidate = other_identity();
    let group = AddressGroup::derive(&candidate);
    let own = GroupOwner::derive(&demo_identity());
    let peers = [
        GroupOwner::derive(&[7; 32]),
        GroupOwner {
            identity: [9; 32],
            group,
        },
    ];
    assert_eq!(
        check_address_conflict(&own, &candidate, &peers),
        Err(AddressConflict {
            identity: [9; 32],
            group,
        })
    );
}

proptest! {
    #[test]
    fn node_id_text_round_trips(bytes in any::<[u8; 12]>()) {
        let node_id = NodeId::from_bytes(bytes);
        let text = node_id.to_string();
        prop_assert_eq!(text.len(), 20);
        prop_assert!(text.bytes().all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b)));
        prop_assert_eq!(text.parse::<NodeId>(), Ok(node_id));
    }

    #[test]
    fn group_normalisation_is_idempotent(octets in any::<[u8; 16]>()) {
        let group = AddressGroup::from_bytes(octets);
        prop_assert_eq!(AddressGroup::from_address(group.n6()), group);
        prop_assert_eq!(AddressGroup::from_address(group.n4()), group);
        prop_assert_eq!(AddressGroup::from_bytes(group.n6_bytes()), group);
        prop_assert!(group.contains(Ipv6Addr::from(octets)));
    }

    #[test]
    fn derived_n6_and_n4_share_a_group(identity in any::<[u8; 32]>()) {
        let group = AddressGroup::derive(&identity);
        prop_assert_eq!(group.n6().octets()[0], 0xfd);
        prop_assert_eq!(group.n6_bytes()[15] & 1, 0);
        prop_assert_eq!(group.n4_bytes()[15] & 1, 1);
        prop_assert_eq!(AddressGroup::from_address(group.n6()), AddressGroup::from_address(group.n4()));
    }
}
