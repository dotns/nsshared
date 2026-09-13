use super::*;

fn keys() -> [SigningKey; 2] {
    let mut keys = [
        SigningKey::from_bytes(&[1; 32]),
        SigningKey::from_bytes(&[2; 32]),
    ];
    keys.sort_by_key(|key| key.verifying_key().to_bytes());
    keys
}

fn binding() -> MeshV2PairBinding {
    let keys = keys();
    MeshV2PairBinding {
        realm: mesh_v2_realm_id(&[9; 32]),
        first: MeshV2NodeIdentity {
            signing_pub: keys[0].verifying_key().to_bytes(),
            wg_pub: [3; 32],
        },
        second: MeshV2NodeIdentity {
            signing_pub: keys[1].verifying_key().to_bytes(),
            wg_pub: [4; 32],
        },
        first_generation: 2,
        second_generation: 3,
        operation_id: [5; 16],
    }
}

fn grant() -> MeshV2PairGrant {
    let binding = binding();
    let keys = keys();
    let input = binding.signing_input().unwrap();
    MeshV2PairGrant {
        binding,
        first_signature: keys[0].sign(&input).to_bytes(),
        second_signature: keys[1].sign(&input).to_bytes(),
    }
}

#[test]
fn pair_transcript_matches_independent_binary_vector() {
    let binding = binding();
    let mut input = b"nsmesh-v2-pair-grant\0".to_vec();
    input.extend_from_slice(&2_u64.to_be_bytes());
    input.extend_from_slice(&binding.realm);
    input.extend_from_slice(&binding.first.signing_pub);
    input.extend_from_slice(&[3; 32]);
    input.extend_from_slice(&binding.second.signing_pub);
    input.extend_from_slice(&[4; 32]);
    input.extend_from_slice(&2_u64.to_be_bytes());
    input.extend_from_slice(&3_u64.to_be_bytes());
    input.extend_from_slice(&[5; 16]);
    assert_eq!(binding.signing_input().unwrap(), input);
    assert_eq!(
        binding.digest().unwrap().as_slice(),
        Sha256::digest(&input).as_slice()
    );
    let identity = binding.first.encode().unwrap();
    let mut expected = vec![0xa3, 0, 2, 1, 0x58, 0x20];
    expected.extend_from_slice(&binding.first.signing_pub);
    expected.extend_from_slice(&[2, 0x58, 0x20]);
    expected.extend_from_slice(&[3; 32]);
    assert_eq!(identity, expected);
}

#[test]
fn pair_grant_requires_both_signatures_and_exact_bound_fields() {
    let good = grant();
    good.verify().unwrap();
    assert_eq!(
        MeshV2PairGrant::decode(&good.encode().unwrap()).unwrap(),
        good
    );
    for change in 0..8 {
        let mut bad = good.clone();
        match change {
            0 => bad.first_signature[0] ^= 1,
            1 => bad.second_signature = bad.first_signature,
            2 => bad.binding.realm[0] ^= 1,
            3 => bad.binding.first.wg_pub[0] ^= 1,
            4 => bad.binding.second.wg_pub[0] ^= 1,
            5 => bad.binding.first_generation += 1,
            6 => bad.binding.second_generation += 1,
            _ => bad.binding.operation_id[0] ^= 1,
        }
        assert!(bad.verify().is_err(), "mutation {change}");
    }
    let mut self_pair = binding();
    self_pair.second = self_pair.first.clone();
    assert!(self_pair.encode().is_err());
}

#[test]
fn pair_decoder_rejects_old_groups_unknown_fields_and_versions() {
    let good = grant();
    let mut old = good.encode().unwrap();
    old[2] = 1;
    assert!(MeshV2PairGrant::decode(&old).is_err());
    let mut extra = good.encode().unwrap();
    extra[0] += 1;
    extra.extend_from_slice(&[4, 0]);
    assert!(MeshV2PairGrant::decode(&extra).is_err());
    let mut reordered = good.to_value();
    if let Value::Map(fields) = &mut reordered {
        fields.swap(1, 2);
    }
    assert!(MeshV2PairGrant::decode(&codec::encode(&reordered).unwrap()).is_err());
    let mut nested = good.to_value();
    if let Value::Map(fields) = &mut nested {
        if let Value::Map(binding) = &mut fields[1].1 {
            binding.push((99_u64.to_value(), 0_u64.to_value()));
        } else {
            panic!("binding map");
        }
    }
    assert!(MeshV2PairGrant::decode(&codec::encode(&nested).unwrap()).is_err());
    let old = super::super::Join {
        pin: "AB-12345678".into(),
        joiner_wg: [3; 32],
        capabilities: 0,
        expires_at: 120,
        cookie: None,
        request_id: [5; 16],
    }
    .encode()
    .unwrap();
    assert!(MeshV2PairRequest::decode(&old).is_err());
    assert!(MeshV2PairGrant::decode(&old).is_err());
}

#[test]
fn pair_revocation_is_unilateral_scoped_and_monotonic() {
    let binding = binding();
    binding.verify_floors(&binding.realm, 1, 2).unwrap();
    assert!(binding.verify_floors(&binding.realm, 2, 0).is_err());
    assert!(binding.verify_floors(&binding.realm, 0, 3).is_err());
    assert!(binding.verify_floors(&[8; 32], 0, 0).is_err());
    let mut revoke = MeshV2PairRevocation {
        realm: binding.realm,
        owner: binding.first,
        peer: binding.second,
        revoked_through: 2,
        signature: [0; 64],
    };
    revoke.signature = keys()[0].sign(&revoke.signing_input().unwrap()).to_bytes();
    revoke.verify().unwrap();
    revoke.revoked_through += 1;
    assert!(revoke.verify().is_err());
}

#[test]
fn pair_session_proves_wg_secret_and_current_bilateral_challenges() {
    let grant = grant();
    let mut session = MeshV2PairSession {
        grant_digest: grant.binding.digest().unwrap(),
        sender: grant.binding.first.signing_pub,
        sender_challenge: [10; 32],
        receiver_challenge: [11; 32],
        capabilities: 3,
        wg_proof: [0; 32],
        signature: [0; 64],
    };
    session.sign(&keys()[0], &[12; 32]).unwrap();
    let verify = |s: &MeshV2PairSession, secret: &[u8; 32]| {
        s.verify(
            &grant,
            &grant.binding.second.signing_pub,
            &[10; 32],
            &[11; 32],
            secret,
        )
    };
    verify(&session, &[12; 32]).unwrap();
    let mut invalid_proof = session.clone();
    invalid_proof.wg_proof[0] ^= 1;
    invalid_proof.signature = keys()[0]
        .sign(&invalid_proof.signing_input().unwrap())
        .to_bytes();
    invalid_proof.verify_sender(&grant).unwrap();
    assert!(verify(&invalid_proof, &[12; 32]).is_err());
    assert!(verify(&session, &[13; 32]).is_err());
    assert!(verify(&session, &[0; 32]).is_err());
    assert!(session.sign(&keys()[0], &[0; 32]).is_err());
    assert!(
        session
            .verify(
                &grant,
                &grant.binding.second.signing_pub,
                &[10; 32],
                &[14; 32],
                &[12; 32]
            )
            .is_err()
    );
    let mut reflected = session.clone();
    reflected.sender = grant.binding.second.signing_pub;
    assert!(verify(&reflected, &[12; 32]).is_err());
    let mut changed = session.clone();
    changed.capabilities = 1;
    assert!(verify(&changed, &[12; 32]).is_err());
    changed.capabilities = 4;
    assert!(changed.encode().is_err());
}

fn request() -> MeshV2PairRequest {
    let b = binding();
    let mut request = MeshV2PairRequest {
        realm: b.realm,
        applicant: b.first,
        target: b.second,
        operation_id: b.operation_id,
        applicant_generation: b.first_generation,
        pin_generation: [7; 16],
        issued_at: 100,
        expires_at: 220,
        signature: [0; 64],
    };
    request.signature = keys()[0].sign(&request.signing_input().unwrap()).to_bytes();
    request
}

#[test]
fn pair_offer_cannot_replace_request_identity_generation_pin_or_deadline() {
    let request = request();
    let grant = grant();
    let mut offer = MeshV2PairOffer {
        binding: grant.binding.clone(),
        initiator: request.target.signing_pub,
        pin_generation: request.pin_generation,
        issued_at: 110,
        expires_at: 220,
        grant_signature: grant.second_signature,
        signature: [0; 64],
    };
    offer.signature = keys()[1].sign(&offer.signing_input().unwrap()).to_bytes();
    offer.verify_request(&request, 120).unwrap();
    assert!(offer.verify_request(&request, 220).is_err());
    let mut old_pin = offer.clone();
    old_pin.pin_generation[0] ^= 1;
    old_pin.signature = keys()[1].sign(&old_pin.signing_input().unwrap()).to_bytes();
    assert!(old_pin.verify_request(&request, 120).is_err());
    let mut changed = offer;
    changed.binding.first_generation += 1;
    changed.grant_signature = keys()[1]
        .sign(&changed.binding.signing_input().unwrap())
        .to_bytes();
    changed.signature = keys()[1].sign(&changed.signing_input().unwrap()).to_bytes();
    assert!(changed.verify_request(&request, 120).is_err());
}

#[test]
fn pair_full_signed_delivery_fits_udp_and_wss_control_limits() {
    use crate::envelope::ControlEnvelope;
    let payload = MeshV2PairApproved { grant: grant() }.encode().unwrap();
    let envelope = ControlEnvelope::sign_request(
        MeshV2PairApproved::API,
        None,
        keys()[0].verifying_key().to_bytes(),
        payload,
        |bytes| keys()[0].sign(bytes).to_bytes(),
    )
    .unwrap();
    let mut original = Vec::new();
    ciborium::ser::into_writer(&envelope, &mut original).unwrap();
    let delivered = MeshV2PairDelivery {
        nonce: [1; 16],
        delivery_id: Some([2; 16]),
        original: Some(original),
    }
    .encode()
    .unwrap();
    let reply = ControlEnvelope::sign_response(
        MeshV2PairDelivery::API,
        None,
        keys()[1].verifying_key().to_bytes(),
        delivered,
        |bytes| keys()[1].sign(bytes).to_bytes(),
    )
    .unwrap();
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&reply, &mut bytes).unwrap();
    super::super::encode_udp(&bytes).unwrap();
    super::super::encode_wss(super::super::WssFrame::Control(&bytes), 0).unwrap();
}

#[test]
fn node_pin_is_bounded_and_redacted_in_nested_debug() {
    let pin = MeshV2NodePin {
        value: MeshV2Pin::new("AB-12345678".into()).unwrap(),
        generation: [1; 16],
        expires_at: 100,
    };
    assert!(!format!("{pin:?}").contains("12345678"));
    assert_eq!(MeshV2NodePin::decode(&pin.encode().unwrap()).unwrap(), pin);
    assert!(MeshV2Pin::new("AB-123456789".into()).is_err());
    assert!(MeshV2Pin::new("IO-12345678".into()).is_err());
    let request = MeshV2PinSet {
        realm: [1; 32],
        node: binding().first,
        ttl_secs: 0,
    };
    request.encode().unwrap();
    assert!(
        MeshV2PinSet {
            ttl_secs: 3601,
            ..request
        }
        .encode()
        .is_err()
    );
}

#[test]
fn pair_hello_and_session_use_real_x25519_bound_node_keys() {
    use ring::{agreement, rand::SystemRandom};
    let first =
        agreement::EphemeralPrivateKey::generate(&agreement::X25519, &SystemRandom::new()).unwrap();
    let second =
        agreement::EphemeralPrivateKey::generate(&agreement::X25519, &SystemRandom::new()).unwrap();
    let first_pub = first.compute_public_key().unwrap();
    let second_pub = second.compute_public_key().unwrap();
    let mut binding = binding();
    binding.first.wg_pub.copy_from_slice(first_pub.as_ref());
    binding.second.wg_pub.copy_from_slice(second_pub.as_ref());
    let first_secret: [u8; 32] = agreement::agree_ephemeral(
        first,
        &agreement::UnparsedPublicKey::new(&agreement::X25519, second_pub),
        |secret| secret.try_into().unwrap(),
    )
    .unwrap();
    let second_secret: [u8; 32] = agreement::agree_ephemeral(
        second,
        &agreement::UnparsedPublicKey::new(&agreement::X25519, first_pub),
        |secret| secret.try_into().unwrap(),
    )
    .unwrap();
    let input = binding.signing_input().unwrap();
    let grant = MeshV2PairGrant {
        binding,
        first_signature: keys()[0].sign(&input).to_bytes(),
        second_signature: keys()[1].sign(&input).to_bytes(),
    };
    let mut hello = MeshV2PairHello {
        realm: grant.binding.realm,
        sender: grant.binding.first.clone(),
        receiver: grant.binding.second.clone(),
        grant_digest: grant.binding.digest().unwrap(),
        challenge: [10; 32],
        signature: [0; 64],
    };
    hello.signature = keys()[0].sign(&hello.signing_input().unwrap()).to_bytes();
    hello.verify(&grant).unwrap();
    let mut wrong = hello.clone();
    wrong.receiver.wg_pub[0] ^= 1;
    assert!(wrong.verify(&grant).is_err());
    let mut session = MeshV2PairSession {
        grant_digest: hello.grant_digest,
        sender: hello.sender.signing_pub,
        sender_challenge: hello.challenge,
        receiver_challenge: [11; 32],
        capabilities: 1,
        wg_proof: [0; 32],
        signature: [0; 64],
    };
    session.sign(&keys()[0], &first_secret).unwrap();
    session
        .verify(
            &grant,
            &hello.receiver.signing_pub,
            &hello.challenge,
            &[11; 32],
            &second_secret,
        )
        .unwrap();
}
