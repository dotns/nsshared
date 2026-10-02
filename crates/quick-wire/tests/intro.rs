// Integration test crate: helpers panic to report failures.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ed25519_dalek::SigningKey;
use quick_wire::{
    Intro, IntroAck, IntroductionDecodeError, IntroductionInputError, IntroductionValidationError,
    KeyBinding,
};

fn binding(signer: &SigningKey, network_id: [u8; 32], not_after: u64) -> KeyBinding {
    let mut value = KeyBinding {
        ver: 1,
        network_id,
        identity: signer.verifying_key().to_bytes(),
        wireguard_key: [0x42; 32],
        generation: 1,
        not_before: 100,
        not_after,
        signature: [0; 64],
    };
    value.sign(signer).expect("test binding signs");
    value
}

fn bodies() -> (Intro, IntroAck, [u8; 32], [u8; 32], [u8; 32]) {
    let network = [1; 32];
    let recipient_key = SigningKey::from_bytes(&[2; 32]);
    let issuer_key = SigningKey::from_bytes(&[3; 32]);
    let recipient = recipient_key.verifying_key().to_bytes();
    let issuer = issuer_key.verifying_key().to_bytes();
    let secret = [4; 32];
    let nonce = [5; 32];
    let token_id = [6; 32];
    let mut intro = Intro {
        network_id: network,
        recipient,
        binding: binding(&recipient_key, network, 1_000),
        token_id,
        nonce,
        mac: [0; 32],
    };
    intro.authenticate(&secret).expect("intro authenticates");
    let mut ack = IntroAck {
        network_id: network,
        issuer,
        binding: binding(&issuer_key, network, 1_000),
        nonce,
        mac: [0; 32],
    };
    ack.authenticate(&secret).expect("ack authenticates");
    (intro, ack, secret, token_id, nonce)
}

#[test]
fn intro_and_ack_round_trip_exact_fixed_arrays() {
    let (intro, ack, _, _, _) = bodies();
    let intro_bytes = intro.encode().expect("intro encodes");
    let ack_bytes = ack.encode().expect("ack encodes");
    assert_eq!(intro_bytes[0], 0x86);
    assert_eq!(ack_bytes[0], 0x85);
    assert_eq!(Intro::decode(&intro_bytes), Ok(intro));
    assert_eq!(IntroAck::decode(&ack_bytes), Ok(ack));
}

#[test]
fn endpoint_validation_requires_network_sender_token_and_live_nonce() {
    let (intro, ack, secret, token_id, nonce) = bodies();
    assert!(
        intro
            .validate(&secret, &intro.network_id, &intro.recipient, &token_id, 500)
            .is_ok()
    );
    assert!(
        ack.validate(&secret, &ack.network_id, &ack.issuer, &nonce, 500)
            .is_ok()
    );
    assert_eq!(
        intro.validate(&secret, &[9; 32], &intro.recipient, &token_id, 500),
        Err(IntroductionValidationError::NetworkMismatch)
    );
    assert_eq!(
        intro.validate(&secret, &intro.network_id, &[9; 32], &token_id, 500),
        Err(IntroductionValidationError::SenderMismatch)
    );
    assert_eq!(
        intro.validate(&secret, &intro.network_id, &intro.recipient, &[9; 32], 500),
        Err(IntroductionValidationError::TokenMismatch)
    );
    assert_eq!(
        ack.validate(&secret, &ack.network_id, &ack.issuer, &[9; 32], 500),
        Err(IntroductionValidationError::NonceMismatch)
    );
}

#[test]
fn macs_cover_every_field_and_use_separate_contexts() {
    let (intro, ack, secret, token_id, nonce) = bodies();
    assert_ne!(intro.mac, ack.mac);
    assert_eq!(
        intro.validate(
            &[8; 32],
            &intro.network_id,
            &intro.recipient,
            &token_id,
            500
        ),
        Err(IntroductionValidationError::InvalidMac)
    );
    for field in 0..5 {
        let mut changed = intro.clone();
        match field {
            0 => changed.network_id[0] ^= 1,
            1 => changed.recipient[0] ^= 1,
            2 => changed.binding.wireguard_key[0] ^= 1,
            3 => changed.token_id[0] ^= 1,
            _ => changed.nonce[0] ^= 1,
        }
        assert_ne!(changed.mac_preimage(), intro.mac_preimage());
    }
    let mut changed_ack = ack.clone();
    changed_ack.nonce[0] ^= 1;
    assert_ne!(changed_ack.mac_preimage(), ack.mac_preimage());
    assert!(
        ack.validate(&secret, &ack.network_id, &ack.issuer, &nonce, 500)
            .is_ok()
    );
}

#[test]
fn invalid_or_stale_nested_bindings_are_rejected() {
    let (mut intro, _, secret, token_id, _) = bodies();
    intro.binding.signature[0] ^= 1;
    intro
        .authenticate(&secret)
        .expect("outer MAC authenticates tampered binding");
    assert_eq!(
        intro.validate(&secret, &intro.network_id, &intro.recipient, &token_id, 500),
        Err(IntroductionValidationError::InvalidBindingSignature)
    );
    let recipient_key = SigningKey::from_bytes(&[2; 32]);
    intro.binding = binding(&recipient_key, intro.network_id, 500);
    intro
        .authenticate(&secret)
        .expect("stale intro authenticates");
    assert_eq!(
        intro.validate(&secret, &intro.network_id, &intro.recipient, &token_id, 500),
        Err(IntroductionValidationError::BindingNotCurrent)
    );
}

#[test]
fn malformed_cbor_is_rejected_before_mac_validation() {
    let (intro, _, secret, token_id, _) = bodies();
    let encoded = intro.encode().expect("intro encodes");
    let mut cases = vec![
        [&[0x9f][..], &encoded[1..]].concat(),
        [&[0x98, 0x06][..], &encoded[1..]].concat(),
        [&[0x85][..], &encoded[1..]].concat(),
    ];
    let mut trailing = encoded.clone();
    trailing.push(0);
    cases.push(trailing);
    let mut wrong_width = encoded;
    wrong_width[2] = 0x1f;
    cases.push(wrong_width);
    for malformed in cases {
        assert_eq!(
            Intro::decode_and_validate(
                &malformed,
                &secret,
                &[1; 32],
                &intro.recipient,
                &token_id,
                500
            ),
            Err(IntroductionInputError::Decode(
                IntroductionDecodeError::InvalidEncoding
            ))
        );
    }
}
