use ed25519_dalek::SigningKey;
use keynet_proto::{
    CommittedKeyBinding, KeyBinding, KeyBindingScope, KeyBindingState, PairingToken,
    PairingTokenAcceptanceError, PairingTokenDecodeError, PairingTokenEncodeError,
    PairingTokenInputError, PairingTokenTextError, derive_pair_psk,
};
use sha2::Digest;

fn binding(signer: &SigningKey, network_id: [u8; 32], generation: u64) -> KeyBinding {
    let mut binding = KeyBinding {
        ver: 1,
        network_id,
        identity: signer.verifying_key().to_bytes(),
        wireguard_key: [0x44; 32],
        generation,
        not_before: 100,
        not_after: 1_000,
        signature: [0; 64],
    };
    binding.sign(signer).expect("test binding signs");
    binding
}

fn token() -> (PairingToken, SigningKey, [u8; 32]) {
    let signer = SigningKey::from_bytes(&[7; 32]);
    let recipient = SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes();
    let network_id = [9; 32];
    let mut token = PairingToken {
        ver: 1,
        network_id,
        net_name: "network".to_owned(),
        issuer: signer.verifying_key().to_bytes(),
        binding: binding(&signer, network_id, 3),
        issuer_name: Some("issuer".to_owned()),
        relay: "relay.example:443".to_owned(),
        endpoint: Some("[2001:db8::1]:51820".to_owned()),
        secret: [0x55; 32],
        not_after: 900,
        recipient: Some(recipient),
        signature: [0; 64],
    };
    token.sign(&signer).expect("test token signs");
    (token, signer, recipient)
}

#[test]
fn signed_twelve_field_token_round_trips_all_optional_combinations() {
    let (base, signer, _) = token();
    for mask in 0..8 {
        let mut value = base.clone();
        value.issuer_name = (mask & 1 != 0).then(|| "issuer".to_owned());
        value.endpoint = (mask & 2 != 0).then(|| "endpoint".to_owned());
        value.recipient = (mask & 4 != 0).then_some([0x33; 32]);
        value.sign(&signer).expect("optional token signs");
        let encoded = value.encode().expect("optional token encodes");
        assert_eq!(PairingToken::decode(&encoded), Ok(value.clone()));
        assert_eq!(
            PairingToken::from_text(&value.to_text().expect("text")),
            Ok(value)
        );
    }
}

#[test]
fn text_and_token_bounds_are_enforced() {
    let (mut value, signer, _) = token();
    value.net_name = "é".repeat(127) + "a";
    assert_eq!(value.net_name.len(), 255);
    value.sign(&signer).expect("255-byte text signs");
    assert!(value.encode().is_ok());
    value.net_name.push('b');
    assert_eq!(value.encode(), Err(PairingTokenEncodeError::TextTooLong));

    let (base, signer, _) = token();
    for field_index in 0..4 {
        let mut boundary_value = base.clone();
        match field_index {
            0 => boundary_value.net_name = "a".repeat(255),
            1 => boundary_value.issuer_name = Some("a".repeat(255)),
            2 => boundary_value.relay = "a".repeat(255),
            _ => boundary_value.endpoint = Some("a".repeat(255)),
        }
        boundary_value.sign(&signer).expect("255-byte field signs");
        assert!(boundary_value.encode().is_ok());
        match field_index {
            0 => boundary_value.net_name.push('a'),
            1 => boundary_value
                .issuer_name
                .as_mut()
                .expect("present")
                .push('a'),
            2 => boundary_value.relay.push('a'),
            _ => boundary_value.endpoint.as_mut().expect("present").push('a'),
        }
        assert_eq!(
            boundary_value.encode(),
            Err(PairingTokenEncodeError::TextTooLong)
        );
    }

    let (mut large, signer, _) = token();
    large.net_name = "n".repeat(255);
    large.issuer_name = Some("i".repeat(255));
    large.relay = "r".repeat(255);
    large.endpoint = Some("e".repeat(255));
    large.sign(&signer).expect("large token signs");
    assert_eq!(
        large.to_text(),
        Err(PairingTokenEncodeError::TextRepresentationTooLong)
    );

    let boundary = format!("kn1{}", "A".repeat(1_021));
    assert_eq!(boundary.len(), 1_024);
    assert_ne!(
        PairingToken::from_text(&boundary),
        Err(PairingTokenTextError::TooLong)
    );
    assert_eq!(
        PairingToken::from_text(&(boundary + "A")),
        Err(PairingTokenTextError::TooLong)
    );
}

#[test]
fn text_form_rejects_padding_whitespace_alphabet_and_trailing_bits() {
    let (value, _, _) = token();
    let text = value.to_text().expect("token text");
    for invalid in [
        format!("{text}="),
        format!("{text} "),
        format!("{}+", &text[..text.len() - 1]),
        "kn1AB".to_owned(),
    ] {
        assert_eq!(
            PairingToken::from_text(&invalid),
            Err(PairingTokenTextError::InvalidText)
        );
    }
}

#[test]
fn strict_acceptance_checks_signature_binding_time_scope_and_recipient() {
    let (value, _, recipient) = token();
    assert!(value.validate(&recipient, 500).is_ok());
    assert_eq!(
        value.validate(&recipient, 900),
        Err(PairingTokenAcceptanceError::Expired)
    );
    assert_eq!(
        value.validate(&[1; 32], 500),
        Err(PairingTokenAcceptanceError::RecipientMismatch)
    );

    let mut tampered = value.clone();
    tampered.relay.push('x');
    assert!(matches!(
        tampered.validate(&recipient, 500),
        Err(PairingTokenAcceptanceError::InvalidSignature(_))
    ));
    let mut stale = value.clone();
    stale.binding.not_after = 500;
    stale
        .sign(&SigningKey::from_bytes(&[7; 32]))
        .expect("token re-signs");
    assert_eq!(
        stale.validate(&recipient, 500),
        Err(PairingTokenAcceptanceError::InvalidBindingSignature)
    );
    stale
        .binding
        .sign(&SigningKey::from_bytes(&[7; 32]))
        .expect("binding re-signs");
    stale
        .sign(&SigningKey::from_bytes(&[7; 32]))
        .expect("token re-signs");
    assert_eq!(
        stale.validate(&recipient, 500),
        Err(PairingTokenAcceptanceError::BindingNotCurrent)
    );
}

#[test]
fn signature_covers_every_unsigned_token_field() {
    let (value, _, recipient) = token();
    let mut changed = Vec::new();
    let mut candidate = value.clone();
    candidate.network_id[0] ^= 1;
    changed.push(candidate);
    let mut candidate = value.clone();
    candidate.net_name.push('x');
    changed.push(candidate);
    let mut candidate = value.clone();
    candidate.issuer[0] ^= 1;
    changed.push(candidate);
    let mut candidate = value.clone();
    candidate.binding.wireguard_key[0] ^= 1;
    changed.push(candidate);
    let mut candidate = value.clone();
    candidate.issuer_name = None;
    changed.push(candidate);
    let mut candidate = value.clone();
    candidate.relay.push('x');
    changed.push(candidate);
    let mut candidate = value.clone();
    candidate.endpoint = None;
    changed.push(candidate);
    let mut candidate = value.clone();
    candidate.secret[0] ^= 1;
    changed.push(candidate);
    let mut candidate = value.clone();
    candidate.not_after += 1;
    changed.push(candidate);
    let mut candidate = value.clone();
    candidate.recipient = None;
    changed.push(candidate);
    for candidate in changed {
        assert!(candidate.validate(&recipient, 500).is_err());
    }
    let preimage = value.signing_preimage().expect("preimage");
    assert!(preimage.starts_with(b"keynet/pairing-token/v1\x8b"));
}

#[test]
fn malformed_cbor_is_rejected_before_signature_acceptance() {
    let (value, _, recipient) = token();
    let encoded = value.encode().expect("token encodes");
    let mut cases = vec![
        [&[0x9f][..], &encoded[1..]].concat(),
        [&[0x98, 0x0c][..], &encoded[1..]].concat(),
        [&[0x8b][..], &encoded[1..]].concat(),
        [&[0x8c, 0x18, 0x01][..], &encoded[2..]].concat(),
    ];
    let mut trailing = encoded.clone();
    trailing.push(0);
    cases.push(trailing);
    let mut wrong_type = encoded;
    wrong_type[1] = 0x61;
    cases.push(wrong_type);
    for malformed in cases {
        assert!(matches!(
            PairingToken::decode_and_validate(&malformed, &recipient, 500),
            Err(PairingTokenInputError::Decode(
                PairingTokenDecodeError::InvalidEncoding
            ))
        ));
    }
}

#[test]
fn token_id_uses_signed_cbor_and_psk_identity_order_is_fixed() {
    let (value, _, recipient) = token();
    let token_id = value.token_id().expect("token id");
    let text_hash: [u8; 32] = sha2::Sha256::digest(value.to_text().expect("text")).into();
    assert_ne!(token_id, text_hash);
    let forward = derive_pair_psk(&value.secret, &value.network_id, &value.issuer, &recipient);
    let reverse = derive_pair_psk(&value.secret, &value.network_id, &recipient, &value.issuer);
    assert_ne!(forward, reverse);
}

#[test]
fn rejected_input_proposes_no_state_transition() {
    let (mut value, _, recipient) = token();
    let state = KeyBindingState {
        scope: KeyBindingScope {
            network_id: value.network_id,
            identity: value.issuer,
        },
        committed: Some(CommittedKeyBinding {
            generation: 4,
            wireguard_key: [0x99; 32],
        }),
        revoked_through: None,
        conflict: None,
    };
    let original = state;
    assert!(matches!(
        value.validate_for_import(&recipient, 500, &state),
        Err(PairingTokenAcceptanceError::BindingState(_))
    ));
    assert_eq!(state, original);
    value.signature[0] ^= 1;
    assert!(value.validate_for_import(&recipient, 500, &state).is_err());
    assert_eq!(state, original);
}
