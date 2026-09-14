use super::*;

fn begin() -> MeshV2RegistrationBegin {
    MeshV2RegistrationBegin {
        node: MeshV2NodeIdentity {
            signing_pub: SigningKey::from_bytes(&[1; 32]).verifying_key().to_bytes(),
            wg_pub: [3; 32],
        },
        request_id: [4; 16],
        cookie: None,
    }
}
fn challenge() -> MeshV2RegistrationChallenge {
    MeshV2RegistrationChallenge {
        nonce: [5; 16],
        realm: [6; 32],
        node: begin().node,
        request_id: [4; 16],
        relay_ephemeral_wg: [7; 32],
        challenge: [8; 32],
        issued_at: 1000,
        expires_at: 1060,
    }
}

#[test]
fn registration_proof_transcript_has_fixed_fields_and_retry_stability() {
    let good = challenge();
    let mut expected = b"nsmesh-v2-registration-wg-proof\0".to_vec();
    expected.extend_from_slice(&2_u64.to_be_bytes());
    expected.extend_from_slice(&[6; 32]);
    expected.extend_from_slice(&good.node.signing_pub);
    expected.extend_from_slice(&[3; 32]);
    expected.extend_from_slice(&[4; 16]);
    expected.extend_from_slice(&[7; 32]);
    expected.extend_from_slice(&[8; 32]);
    expected.extend_from_slice(&1000_u64.to_be_bytes());
    expected.extend_from_slice(&1060_u64.to_be_bytes());
    assert_eq!(good.proof_input().unwrap(), expected);
    let proof = good.prove(&[9; 32]).unwrap();
    assert_eq!(
        hex::encode(proof),
        "139a4a3c323fffefa2e64bed852359f821449fce91a7a88a4a1cc58424c260e5"
    );
    let mut retry = good.clone();
    retry.nonce[0] ^= 1;
    assert_eq!(retry.prove(&[9; 32]).unwrap(), proof);
    good.verify_proof(&proof, &[9; 32], 1000).unwrap();
    for now in [999, 1060, u64::MAX] {
        assert!(good.verify_proof(&proof, &[9; 32], now).is_err());
    }
    assert!(good.prove(&[0; 32]).is_err());
    assert!(good.verify_proof(&proof, &[0; 32], 1000).is_err());
    assert!(good.verify_proof(&proof, &[10; 32], 1000).is_err());
    for change in 0..8 {
        let mut bad = good.clone();
        match change {
            0 => bad.realm[0] ^= 1,
            1 => bad.node.signing_pub = SigningKey::from_bytes(&[2; 32]).verifying_key().to_bytes(),
            2 => bad.node.wg_pub[0] ^= 1,
            3 => bad.request_id[0] ^= 1,
            4 => bad.relay_ephemeral_wg[0] ^= 1,
            5 => bad.challenge[0] ^= 1,
            6 => bad.issued_at += 1,
            _ => bad.expires_at -= 1,
        }
        assert!(bad.verify_proof(&proof, &[9; 32], 1002).is_err());
    }
}

#[test]
fn registration_proof_uses_real_x25519_and_checks_pinned_response_correlation() {
    use ring::{agreement, rand::SystemRandom};
    let own =
        agreement::EphemeralPrivateKey::generate(&agreement::X25519, &SystemRandom::new()).unwrap();
    let relay =
        agreement::EphemeralPrivateKey::generate(&agreement::X25519, &SystemRandom::new()).unwrap();
    let own_pub = own.compute_public_key().unwrap();
    let relay_pub = relay.compute_public_key().unwrap();
    let own_secret: [u8; 32] = agreement::agree_ephemeral(
        own,
        &agreement::UnparsedPublicKey::new(&agreement::X25519, &relay_pub),
        |s| s.try_into().unwrap(),
    )
    .unwrap();
    let relay_secret: [u8; 32] = agreement::agree_ephemeral(
        relay,
        &agreement::UnparsedPublicKey::new(&agreement::X25519, &own_pub),
        |s| s.try_into().unwrap(),
    )
    .unwrap();
    let mut begin = begin();
    begin.node.wg_pub.copy_from_slice(own_pub.as_ref());
    let mut good = challenge();
    good.node = begin.node.clone();
    good.relay_ephemeral_wg.copy_from_slice(relay_pub.as_ref());
    good.verify_begin(&begin, &[5; 16], &[6; 32], 1000).unwrap();
    good.verify_proof(&good.prove(&own_secret).unwrap(), &relay_secret, 1001)
        .unwrap();
    assert!(good.verify_begin(&begin, &[4; 16], &[6; 32], 1000).is_err());
    assert!(good.verify_begin(&begin, &[5; 16], &[7; 32], 1000).is_err());
    assert!(good.verify_begin(&begin, &[5; 16], &[6; 32], 1060).is_err());
    begin.request_id[0] ^= 1;
    assert!(good.verify_begin(&begin, &[5; 16], &[6; 32], 1000).is_err());
}

#[test]
fn registration_proof_records_reject_legacy_unknown_and_reordered_fields() {
    let begin = begin();
    let challenge = challenge();
    let finish = MeshV2RegistrationFinish {
        node: begin.node.clone(),
        request_id: begin.request_id,
        challenge: challenge.challenge,
        wg_proof: challenge.prove(&[9; 32]).unwrap(),
        cookie: Some([10; 16]),
    };
    assert_eq!(
        MeshV2RegistrationBegin::decode(&begin.encode().unwrap()).unwrap(),
        begin
    );
    assert_eq!(
        MeshV2RegistrationChallenge::decode(&challenge.encode().unwrap()).unwrap(),
        challenge
    );
    assert_eq!(
        MeshV2RegistrationFinish::decode(&finish.encode().unwrap()).unwrap(),
        finish
    );
    let mut old_begin = begin.encode().unwrap();
    old_begin[2] = 1;
    assert!(MeshV2RegistrationBegin::decode(&old_begin).is_err());
    let mut extra_begin = begin.encode().unwrap();
    extra_begin[0] += 1;
    extra_begin.extend_from_slice(&[4, 0]);
    assert!(MeshV2RegistrationBegin::decode(&extra_begin).is_err());
    let mut old = finish.encode().unwrap();
    old[2] = 1;
    assert!(MeshV2RegistrationFinish::decode(&old).is_err());
    let mut extra = challenge.encode().unwrap();
    extra[0] += 1;
    extra.extend_from_slice(&[9, 0]);
    assert!(MeshV2RegistrationChallenge::decode(&extra).is_err());
    let mut reordered = finish.to_value();
    if let Value::Map(fields) = &mut reordered {
        fields.swap(1, 2);
    }
    assert!(MeshV2RegistrationFinish::decode(&codec::encode(&reordered).unwrap()).is_err());
}
