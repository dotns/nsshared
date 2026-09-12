use std::net::SocketAddr;
use std::time::{Duration, Instant};

use control::mesh::*;
use ed25519_dalek::{Signer, SigningKey};

#[test]
fn mesh_cookie_binds_source_identity_request_and_initial_expiry() {
    let key = CookieKey::generate().unwrap();
    let binding = CookieBinding {
        source: SocketAddr::from(([192, 0, 2, 1], 51900)),
        joiner_pub: [1; 32],
        request_id: [2; 16],
        expires_at: 180,
    };
    let cookie = key.issue(&binding, 60).unwrap();
    for now in [60, 89, 90, 119] {
        key.verify(&binding, now, &cookie).unwrap();
    }
    for now in [30, 120, 180] {
        assert!(key.verify(&binding, now, &cookie).is_err());
    }
    for field in 0..6 {
        let mut changed = binding.clone();
        match field {
            0 => changed.source.set_ip([192, 0, 2, 2].into()),
            1 => changed.source.set_port(51901),
            2 => changed.joiner_pub[0] ^= 1,
            3 => changed.request_id[0] ^= 1,
            4 => changed.expires_at += 1,
            _ => changed.source.set_ip("::ffff:192.0.2.1".parse().unwrap()),
        }
        assert!(key.verify(&changed, 60, &cookie).is_err());
    }
    assert!(
        CookieKey::generate()
            .unwrap()
            .verify(&binding, 60, &cookie)
            .is_err()
    );
    let expires = CookieBinding {
        expires_at: 90,
        ..binding
    };
    let cookie = key.issue(&expires, 89).unwrap();
    assert!(key.verify(&expires, 90, &cookie).is_err());
    assert!(key.issue(&expires, 90).is_err());
}

fn hello(challenge: &WssChallenge) -> WssHello {
    let key = SigningKey::from_bytes(&[3; 32]);
    let mut value = WssHello {
        challenge: challenge.nonce(),
        origin: "wss://relay.example:9443".into(),
        signer_pub: key.verifying_key().to_bytes(),
        wg_pub: [4; 32],
        signature: [0; 64],
    };
    value.signature = key.sign(&value.signing_input().unwrap()).to_bytes();
    value
}

#[test]
fn mesh_wss_challenge_binds_connection_origin_and_keys() {
    let now = Instant::now();
    for field in 0..6 {
        let challenge = WssChallenge::generate("wss://relay.example:9443".into(), now).unwrap();
        let mut value = hello(&challenge);
        match field {
            0 => value.challenge[0] ^= 1,
            1 => value.origin = "wss://elsewhere.example:9443".into(),
            2 => value.signer_pub[0] ^= 1,
            3 => value.wg_pub[0] ^= 1,
            4 => value.signature[0] ^= 1,
            _ => {
                let other = WssChallenge::generate(value.origin.clone(), now).unwrap();
                value = hello(&other);
            }
        }
        assert!(challenge.verify(&value, now).is_err());
    }
}

#[test]
fn mesh_wss_expiry_and_independent_signing_input() {
    let now = Instant::now();
    for (elapsed, valid) in [(0, true), (29, true), (30, false), (31, false)] {
        let challenge = WssChallenge::generate("wss://relay.example:9443".into(), now).unwrap();
        let value = hello(&challenge);
        let mut expected = b"nsmesh-wss-v1\0".to_vec();
        expected.extend_from_slice(&value.challenge);
        expected.extend_from_slice(&24_u32.to_be_bytes());
        expected.extend_from_slice(b"wss://relay.example:9443");
        expected.extend_from_slice(&value.signer_pub);
        expected.extend_from_slice(&[4; 32]);
        assert_eq!(value.signing_input().unwrap(), expected);
        assert_eq!(WssHello::decode(&value.encode().unwrap()).unwrap(), value);
        assert_eq!(
            challenge
                .verify(&value, now + Duration::from_secs(elapsed))
                .is_ok(),
            valid
        );
    }
    assert!(WssChallenge::generate("udp://relay.example:51900".into(), now).is_err());
    let challenge = WssChallenge::generate("wss://relay.example:9443".into(), now).unwrap();
    let value = hello(&challenge);
    assert!(
        challenge
            .verify(&value, now - Duration::from_secs(1))
            .is_err()
    );
}
