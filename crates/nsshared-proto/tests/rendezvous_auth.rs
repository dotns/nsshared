//! Challenge and actor hello: rendezvous §3, §4.

#![allow(clippy::unwrap_used, reason = "test fixture helpers")]

use ed25519_dalek::{Signer, SigningKey};
use nsshared_proto::rendezvous::{
    auth::{ACTOR_CONTEXT, AuthError, Challenge, Hello},
    capability::Capabilities,
    error::ErrorCode,
    transport::{Response, decode_response},
};
use nsshared_proto::{RelayId, encoding::encode_base64url};

/// The Ed25519 group order L, little-endian (RFC 8032 §5.1).
const ORDER: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
];

fn authority() -> RelayId {
    RelayId::parse("hkg-a1.relay.ns.io:443").unwrap()
}

fn key() -> SigningKey {
    SigningKey::from_bytes(&[42; 32])
}

#[test]
fn hello_signs_context_nonce_and_authority() {
    let nonce = [5; 32];
    let hello = Hello::sign(&key(), &nonce, &authority());
    assert_eq!(hello.actor, key().verifying_key().to_bytes());
    let mut message = b"ns-rendezvous-actor-v1\0".to_vec();
    message.extend_from_slice(&nonce);
    message.extend_from_slice(b"hkg-a1.relay.ns.io:443");
    assert_eq!(ACTOR_CONTEXT, b"ns-rendezvous-actor-v1\0");
    assert_eq!(hello.signature, key().sign(&message).to_bytes());
    assert_eq!(hello.verify(&nonce, &authority()), Ok(()));
}

#[test]
fn hello_rejects_wrong_nonce_authority_actor_and_signature() {
    let nonce = [5; 32];
    let hello = Hello::sign(&key(), &nonce, &authority());
    let other = RelayId::parse("hkg-a2.relay.ns.io:443").unwrap();
    let port = RelayId::parse("hkg-a1.relay.ns.io:444").unwrap();
    assert_eq!(
        hello.verify(&[6; 32], &authority()),
        Err(AuthError::InvalidSignature)
    );
    assert_eq!(
        hello.verify(&nonce, &other),
        Err(AuthError::InvalidSignature)
    );
    assert_eq!(
        hello.verify(&nonce, &port),
        Err(AuthError::InvalidSignature)
    );

    let mut wrong_actor = hello.clone();
    wrong_actor.actor = SigningKey::from_bytes(&[43; 32]).verifying_key().to_bytes();
    assert_eq!(
        wrong_actor.verify(&nonce, &authority()),
        Err(AuthError::InvalidSignature)
    );

    let mut flipped = hello.clone();
    flipped.signature[0] ^= 1;
    assert_eq!(
        flipped.verify(&nonce, &authority()),
        Err(AuthError::InvalidSignature)
    );

    // S + L is the same signature in non-canonical form; strict verification rejects it.
    let mut non_canonical = hello.clone();
    let mut carry = 0_u16;
    for (byte, order) in non_canonical.signature[32..].iter_mut().zip(ORDER) {
        let sum = u16::from(*byte) + u16::from(order) + carry;
        *byte = sum as u8;
        carry = sum >> 8;
    }
    assert_eq!(carry, 0);
    assert_ne!(non_canonical.signature, hello.signature);
    assert_eq!(
        non_canonical.verify(&nonce, &authority()),
        Err(AuthError::InvalidSignature)
    );

    // A small-order actor key never verifies.
    let mut small_order = hello.clone();
    small_order.actor = [0; 32];
    small_order.actor[0] = 1;
    assert_eq!(
        small_order.verify(&nonce, &authority()),
        Err(AuthError::InvalidSignature)
    );

    assert_eq!(
        ErrorCode::from(AuthError::InvalidSignature),
        ErrorCode::InvalidActor
    );
}

#[test]
fn challenge_authority_must_match() {
    let challenge = Challenge {
        nonce: [1; 32],
        authority: authority(),
        capabilities: Capabilities::default(),
    };
    assert_eq!(challenge.check_authority(&authority()), Ok(()));
    assert_eq!(
        challenge.check_authority(&RelayId::parse("hkg-a1.relay.ns.io:8443").unwrap()),
        Err(AuthError::AuthorityMismatch)
    );
}

fn challenge_json(nonce: &[u8], authority: &str) -> String {
    format!(
        r#"{{"result":"challenge","value":{{"nonce":"{}","authority":"{authority}","capabilities":[]}}}}"#,
        encode_base64url(nonce)
    )
}

#[test]
fn challenge_decoding_validates_nonce_and_authority() {
    let Ok(Response::Challenge(challenge)) =
        decode_response(&challenge_json(&[1; 32], "hkg-a1.relay.ns.io:443"))
    else {
        panic!("challenge did not decode");
    };
    assert_eq!(challenge.authority, authority());

    let mut last_nonzero = [0; 32];
    last_nonzero[31] = 1;
    assert!(decode_response(&challenge_json(&last_nonzero, "a.b:1")).is_ok());

    for text in [
        challenge_json(&[0; 32], "hkg-a1.relay.ns.io:443"),
        challenge_json(&[1; 31], "hkg-a1.relay.ns.io:443"),
        challenge_json(&[1; 32], "HKG-A1.relay.ns.io:443"),
        challenge_json(&[1; 32], "hkg-a1.relay.ns.io"),
        challenge_json(&[1; 32], "hkg-a1.relay.ns.io:0"),
        challenge_json(&[1; 32], "wss://hkg-a1.relay.ns.io:443"),
    ] {
        assert_eq!(
            decode_response(&text),
            Err(ErrorCode::InvalidMessage),
            "{text}"
        );
    }
}
