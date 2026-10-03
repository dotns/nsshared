//! Typed identity and session keys: quick-v2 §2.1, §2.3.

use nsshared_wire::{
    AddressGroup, AliasPool, GroupOwner, IdentityKey, IdentitySecret, KeyParseError, Lan6Prefix,
    NodeId, NodeRecord, NodeRecordFields, WgSessionKey, WgSessionSecret, alias_candidates,
};
use proptest::prelude::*;
use sha2::{Digest, Sha256};
use std::net::Ipv6Addr;

const DEMO_I: &str = "x9wqBt4ZKdMxi43oc78ScDDD7gAH8g4G6g_FQFZ0Wvs";
const DEMO_K: &str = "NZkMHL1XEJhrcG68XIzeUZktuR/U1aR2e6u2dcRMzDk=";

fn demo_secret() -> IdentitySecret {
    IdentitySecret::from_seed(Sha256::digest(b"ns-demo-node-v2").into())
}

fn demo_session_secret() -> WgSessionSecret {
    WgSessionSecret::from_bytes(Sha256::digest(b"ns-demo-wg-v2").into())
}

#[test]
fn demo_identity_key_matches_spec_example() {
    let key = demo_secret().public();
    assert_eq!(key.to_string(), DEMO_I);
    assert_eq!(DEMO_I.parse::<IdentityKey>(), Ok(key));
    assert_eq!(key.node_id().to_string(), "5kemem6slxrgyd63rcqa");
    assert_eq!(
        key.node6(),
        "fda6:72ac:58cb:cc8d:1e39:e507:bda:5052"
            .parse::<Ipv6Addr>()
            .unwrap()
    );
    assert_eq!(
        key.node4(),
        "fda6:72ac:58cb:cc8d:1e39:e507:bda:5053"
            .parse::<Ipv6Addr>()
            .unwrap()
    );
}

#[test]
fn demo_session_key_matches_spec_example() {
    let key = demo_session_secret().public();
    assert_eq!(key.to_string(), DEMO_K);
    assert_eq!(DEMO_K.parse::<WgSessionKey>(), Ok(key));
}

#[test]
fn derivations_delegate_to_existing_functions() {
    let key = demo_secret().public();
    let identity = key.to_bytes();
    assert_eq!(key.node_id(), NodeId::derive(&identity));
    assert_eq!(key.address_group(), AddressGroup::derive(&identity));
    assert_eq!(key.group_owner(), GroupOwner::derive(&identity));
    for subnet_id in [0, 7, u16::MAX] {
        assert_eq!(
            key.lan6(subnet_id),
            Lan6Prefix::derive(&identity, subnet_id)
        );
    }
    let pool = AliasPool::default();
    let candidates = key.alias_candidates(4, &pool).unwrap();
    assert_eq!(candidates, alias_candidates(&identity, 4, &pool).unwrap());
    assert_eq!(
        key.select_alias(4, &pool, candidates[0], |_| false),
        Ok(candidates[1])
    );
}

#[test]
fn signing_key_adapter_signs_records() {
    let secret = demo_secret();
    let fields = NodeRecordFields {
        wg_key: demo_session_secret().public().into(),
        generation: 1,
        issued_at: 1_000,
        expires: 2_000,
        relays: Vec::new(),
    };
    let record = NodeRecord::sign(secret.signing_key(), fields).unwrap();
    assert_eq!(record.identity(), secret.public().as_bytes());
    record.verify().unwrap();
}

#[test]
fn generated_secrets_are_usable() {
    let identity = IdentitySecret::generate().unwrap();
    assert_eq!(
        IdentitySecret::from_seed(*identity.expose_seed()).public(),
        identity.public()
    );
    let session = WgSessionSecret::generate().unwrap();
    assert_eq!(
        WgSessionSecret::from_bytes(*session.expose_bytes()).public(),
        session.public()
    );
}

#[test]
fn secret_debug_is_redacted() {
    let identity = demo_secret();
    let debug = format!("{identity:?}");
    assert!(!debug.contains(identity.to_secret_text().as_str()));
    assert!(!debug.contains(&format!("{:?}", identity.expose_seed())));
    assert!(!debug.contains(&format!("{}", identity.expose_seed()[0])));

    let session = demo_session_secret();
    let debug = format!("{session:?}");
    assert!(!debug.contains(session.to_secret_text().as_str()));
    assert!(!debug.contains(&format!("{:?}", session.expose_bytes())));
    assert!(!debug.contains(&format!("{}", session.expose_bytes()[0])));
}

#[test]
fn refutation_identity_key_padding() {
    assert_eq!(
        format!("{DEMO_I}=").parse::<IdentityKey>(),
        Err(KeyParseError::Padding)
    );
    assert_eq!(
        IdentitySecret::from_secret_text(&format!("{DEMO_I}=")).map(|_| ()),
        Err(KeyParseError::Padding)
    );
}

#[test]
fn refutation_identity_key_standard_alphabet() {
    let standard = DEMO_I.replace('_', "/");
    assert_eq!(
        standard.parse::<IdentityKey>(),
        Err(KeyParseError::InvalidCharacter {
            offset: DEMO_I.find('_').unwrap(),
            byte: b'/',
        })
    );
}

#[test]
fn refutation_identity_key_length() {
    assert_eq!(
        DEMO_I[..42].parse::<IdentityKey>(),
        Err(KeyParseError::TextLength {
            expected: 43,
            actual: 42,
        })
    );
    assert_eq!(
        format!("{DEMO_I}A").parse::<IdentityKey>(),
        Err(KeyParseError::TextLength {
            expected: 43,
            actual: 44,
        })
    );
    assert_eq!(
        IdentityKey::try_from(&[0_u8; 31][..]),
        Err(KeyParseError::ByteLength(31))
    );
}

#[test]
fn refutation_identity_key_trailing_bits() {
    // The 43rd symbol carries 4 data bits and 2 bits that must be zero; `s` = 44 = 0b101100.
    let mut text = DEMO_I.to_owned();
    text.replace_range(42.., "t");
    assert_eq!(
        text.parse::<IdentityKey>(),
        Err(KeyParseError::NonCanonicalTrailingBits)
    );
}

#[test]
fn refutation_identity_key_invalid_point() {
    // y = 2 does not decompress to an Edwards point.
    let mut bytes = [0_u8; 32];
    bytes[0] = 2;
    assert_eq!(
        IdentityKey::from_bytes(&bytes),
        Err(KeyParseError::InvalidIdentityKey)
    );
    assert_eq!(
        IdentityKey::try_from(bytes),
        Err(KeyParseError::InvalidIdentityKey)
    );
    assert_eq!(
        "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".parse::<IdentityKey>(),
        Err(KeyParseError::InvalidIdentityKey)
    );
}

#[test]
fn refutation_session_key_url_alphabet() {
    let url = DEMO_K.replace('/', "_");
    assert_eq!(
        url.parse::<WgSessionKey>(),
        Err(KeyParseError::InvalidCharacter {
            offset: DEMO_K.find('/').unwrap(),
            byte: b'_',
        })
    );
}

#[test]
fn refutation_session_key_missing_padding() {
    assert_eq!(
        DEMO_K[..43].parse::<WgSessionKey>(),
        Err(KeyParseError::TextLength {
            expected: 44,
            actual: 43,
        })
    );
    // Right length, but the final `=` replaced by a data symbol.
    assert_eq!(
        format!("{}A", &DEMO_K[..43]).parse::<WgSessionKey>(),
        Err(KeyParseError::Padding)
    );
    assert_eq!(
        WgSessionSecret::from_secret_text(&DEMO_K[..43]).map(|_| ()),
        Err(KeyParseError::TextLength {
            expected: 44,
            actual: 43,
        })
    );
}

#[test]
fn refutation_session_key_length() {
    assert_eq!(
        format!("{DEMO_K}=").parse::<WgSessionKey>(),
        Err(KeyParseError::TextLength {
            expected: 44,
            actual: 45,
        })
    );
    assert_eq!(
        WgSessionKey::try_from(&[0_u8; 33][..]),
        Err(KeyParseError::ByteLength(33))
    );
}

#[test]
fn refutation_session_key_trailing_bits() {
    // The 43rd symbol carries 4 data bits and 2 bits that must be zero.
    let mut text = DEMO_K.to_owned();
    text.replace_range(42..43, "l");
    assert_eq!(
        text.parse::<WgSessionKey>(),
        Err(KeyParseError::NonCanonicalTrailingBits)
    );
}

proptest! {
    #[test]
    fn identity_key_round_trips(seed in any::<[u8; 32]>()) {
        let key = IdentitySecret::from_seed(seed).public();
        prop_assert_eq!(key.to_string().parse::<IdentityKey>(), Ok(key));
        prop_assert_eq!(IdentityKey::from_bytes(key.as_bytes()), Ok(key));
        prop_assert_eq!(IdentityKey::try_from(&key.to_bytes()[..]), Ok(key));
    }

    #[test]
    fn identity_secret_round_trips(seed in any::<[u8; 32]>()) {
        let secret = IdentitySecret::from_seed(seed);
        let text = IdentitySecret::from_secret_text(&secret.to_secret_text()).unwrap();
        prop_assert_eq!(text.expose_seed(), &seed);
        prop_assert_eq!(text.public(), secret.public());
        let binary = IdentitySecret::from_seed(*secret.expose_seed());
        prop_assert_eq!(binary.public(), secret.public());
    }

    #[test]
    fn session_key_round_trips(bytes in any::<[u8; 32]>()) {
        let key = WgSessionKey::from_bytes(bytes);
        prop_assert_eq!(key.to_string().parse::<WgSessionKey>(), Ok(key));
        prop_assert_eq!(WgSessionKey::try_from(&bytes[..]), Ok(key));
        prop_assert_eq!(<[u8; 32]>::from(key), bytes);
    }

    #[test]
    fn session_secret_round_trips(bytes in any::<[u8; 32]>()) {
        let secret = WgSessionSecret::from_bytes(bytes);
        let text = WgSessionSecret::from_secret_text(&secret.to_secret_text()).unwrap();
        prop_assert_eq!(text.expose_bytes(), &bytes);
        prop_assert_eq!(text.public(), secret.public());
        let binary = WgSessionSecret::from_bytes(*secret.expose_bytes());
        prop_assert_eq!(binary.public(), secret.public());
    }
}
