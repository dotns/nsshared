use ed25519_dalek::{Signer, SigningKey};
use keynet_proto::{
    CommittedKeyBinding, CurrentKeyBinding, InstallationDecision, KeyBinding,
    KeyBindingDecodeError, KeyBindingScope, KeyBindingState, KeyBindingTimeError,
    KeyBindingTransitionError, KeyBindingVerificationError,
};

fn signer() -> SigningKey {
    SigningKey::from_bytes(&[7; 32])
}

fn signed_binding(
    generation: u64,
    wireguard_key: u8,
    not_before: u64,
    not_after: u64,
) -> KeyBinding {
    let signing_key = signer();
    let mut binding = KeyBinding {
        ver: 1,
        network_id: [1; 32],
        identity: signing_key.verifying_key().to_bytes(),
        wireguard_key: [wireguard_key; 32],
        generation,
        not_before,
        not_after,
        signature: [0; 64],
    };
    binding.sign(&signing_key).unwrap();
    binding
}

fn current(generation: u64, wireguard_key: u8) -> CurrentKeyBinding {
    signed_binding(generation, wireguard_key, 10, 20)
        .verify()
        .unwrap()
        .validate_current(10)
        .unwrap()
}

fn scope() -> KeyBindingScope {
    KeyBindingScope {
        network_id: [1; 32],
        identity: signer().verifying_key().to_bytes(),
    }
}

fn state(committed: Option<CommittedKeyBinding>) -> KeyBindingState {
    KeyBindingState {
        scope: scope(),
        committed,
        revoked_through: None,
        conflict: None,
    }
}

#[test]
fn key_binding_encodes_the_eight_field_v1_schema() {
    let binding = signed_binding(0, 3, 1, 2);

    assert_eq!(binding.encode().len(), 173);
    assert_eq!(binding.unsigned_bytes().len(), 107);
    assert_eq!(KeyBinding::decode(&binding.encode()), Ok(binding));
    assert!(binding.verify().is_ok());
}

#[test]
fn signatures_cover_every_authenticated_field_and_the_exact_context() {
    let binding = signed_binding(8, 3, 10, 20);
    let mut mutations = Vec::new();
    let mut altered = binding;
    altered.ver = 2;
    mutations.push(altered);
    let mut altered = binding;
    altered.network_id[0] ^= 1;
    mutations.push(altered);
    let mut altered = binding;
    altered.identity[0] ^= 1;
    mutations.push(altered);
    let mut altered = binding;
    altered.wireguard_key[0] ^= 1;
    mutations.push(altered);
    let mut altered = binding;
    altered.generation += 1;
    mutations.push(altered);
    let mut altered = binding;
    altered.not_before += 1;
    mutations.push(altered);
    let mut altered = binding;
    altered.not_after += 1;
    mutations.push(altered);
    let mut altered = binding;
    altered.signature[0] ^= 1;
    mutations.push(altered);
    assert!(
        mutations
            .into_iter()
            .all(|binding| binding.verify().is_err())
    );

    let mut wrong_context = binding;
    wrong_context.signature = signer().sign(b"keynet/key-binding/v0").to_bytes();
    assert!(wrong_context.verify().is_err());
    let wrong_signer = SigningKey::from_bytes(&[8; 32]);
    assert!(wrong_context.sign(&wrong_signer).is_err());
    let mut malformed_identity = binding;
    malformed_identity.identity = [0xff; 32];
    assert!(malformed_identity.verify().is_err());
    let mut malformed_signature = binding;
    malformed_signature.signature = [0; 64];
    assert!(malformed_signature.verify().is_err());
}

#[test]
fn canonical_decoder_rejects_malformed_data_before_signature_verification() {
    let binding = signed_binding(24, 3, 10, 20);
    let encoded = binding.encode();
    let malformed = [
        vec![0xa8],
        vec![0xc1],
        vec![0xf6],
        vec![0xfb],
        vec![0x9f],
        vec![0x88, 0x18, 0x01],
        vec![0x88, 0x81],
    ];
    for mut prefix in malformed {
        prefix.extend_from_slice(&encoded);
        assert_eq!(
            KeyBinding::decode(&prefix),
            Err(KeyBindingDecodeError::InvalidEncoding)
        );
    }
    let mut nonminimal = encoded.clone();
    nonminimal.splice(1..2, [0x18, 0x01]);
    assert_eq!(
        KeyBinding::decode(&nonminimal),
        Err(KeyBindingDecodeError::InvalidEncoding)
    );
    let mut indefinite_bytes = encoded.clone();
    indefinite_bytes[2] = 0x5f;
    assert_eq!(
        KeyBinding::decode(&indefinite_bytes),
        Err(KeyBindingDecodeError::InvalidEncoding)
    );
    let mut huge_length = encoded.clone();
    huge_length[2] = 0x5b;
    assert_eq!(
        KeyBinding::decode(&huge_length),
        Err(KeyBindingDecodeError::InvalidEncoding)
    );
    let mut wrong_length = encoded.clone();
    wrong_length[0] = 0x87;
    assert_eq!(
        KeyBinding::decode(&wrong_length),
        Err(KeyBindingDecodeError::InvalidEncoding)
    );
    let mut extra_field = encoded.clone();
    extra_field[0] = 0x89;
    assert_eq!(
        KeyBinding::decode(&extra_field),
        Err(KeyBindingDecodeError::InvalidEncoding)
    );
    assert_eq!(
        KeyBinding::decode(&encoded[..encoded.len() - 1]),
        Err(KeyBindingDecodeError::InvalidEncoding)
    );
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert_eq!(
        KeyBinding::decode(&trailing),
        Err(KeyBindingDecodeError::InvalidEncoding)
    );
    let mut unsupported = encoded.clone();
    unsupported[1] = 2;
    assert_eq!(
        KeyBinding::decode(&unsupported),
        Err(KeyBindingDecodeError::UnsupportedVersion)
    );
    assert_eq!(
        KeyBinding::decode_and_verify(&nonminimal),
        Err(KeyBindingVerificationError::Decode(
            KeyBindingDecodeError::InvalidEncoding
        ))
    );
}

#[test]
fn widths_sizes_and_intervals_are_exact() {
    for generation in [
        0,
        23,
        24,
        255,
        256,
        65_535,
        65_536,
        u64::from(u32::MAX),
        u64::from(u32::MAX) + 1,
        u64::MAX,
    ] {
        let binding = signed_binding(generation, 3, 10, 20);
        assert_eq!(KeyBinding::decode(&binding.encode()), Ok(binding));
    }
    let minimum = signed_binding(0, 3, 0, 1);
    assert_eq!(
        (minimum.unsigned_bytes().len(), minimum.encode().len()),
        (107, 173)
    );
    let maximum = signed_binding(u64::MAX, 3, u64::MAX - 1, u64::MAX);
    assert_eq!(
        (maximum.unsigned_bytes().len(), maximum.encode().len()),
        (131, 197)
    );
    assert!(
        maximum
            .verify()
            .unwrap()
            .validate_current(u64::MAX - 1)
            .is_ok()
    );
    assert_eq!(minimum.validate_current(0).unwrap().binding(), minimum);
    assert_eq!(
        minimum.validate_current(1),
        Err(KeyBindingTimeError::NotCurrent)
    );
    assert_eq!(
        minimum.validate_current(2),
        Err(KeyBindingTimeError::NotCurrent)
    );
    assert_eq!(
        signed_binding(1, 3, 10, 10).validate_interval(),
        Err(KeyBindingTimeError::InvalidInterval)
    );
    assert_eq!(
        signed_binding(1, 3, 11, 10).validate_interval(),
        Err(KeyBindingTimeError::InvalidInterval)
    );
}

#[test]
fn installation_is_scoped_pure_and_handles_conflicts() {
    let initial = state(None);
    let first = current(0, 3);
    let installed = first.installation_decision(&initial).unwrap();
    let after_first = match installed {
        InstallationDecision::Install(proposal) => proposal.next_state,
        _ => panic!("initial generation must install"),
    };
    assert_eq!(initial, state(None));
    assert_eq!(
        current(0, 3).installation_decision(&after_first),
        Ok(InstallationDecision::Idempotent)
    );
    assert!(
        current(0, 4)
            .installation_decision(&after_first)
            .unwrap()
            .is_latch_conflict()
    );
    assert_eq!(
        current(0, 3).installation_decision(&after_first),
        Ok(InstallationDecision::Idempotent)
    );
    assert_eq!(
        current(0, 4).installation_decision(&after_first),
        current(0, 4).installation_decision(&after_first)
    );
    let conflict_state = match current(0, 4).installation_decision(&after_first).unwrap() {
        InstallationDecision::LatchConflict(proposal) => proposal.next_state,
        _ => panic!("different equal generation must conflict"),
    };
    assert!(conflict_state.committed.is_none());
    for candidate in [current(0, 3), current(0, 4)] {
        assert_eq!(
            candidate.installation_decision(&conflict_state),
            Err(KeyBindingTransitionError::ConflictLatched)
        );
    }
    assert!(
        current(1, 5)
            .installation_decision(&conflict_state)
            .unwrap()
            .is_install()
    );
    assert_eq!(
        current(0, 3).installation_decision(&after_first),
        Ok(InstallationDecision::Idempotent)
    );
    assert_eq!(
        current(0, 3).installation_decision(&state(Some(CommittedKeyBinding {
            generation: 1,
            wireguard_key: [3; 32]
        }))),
        Err(KeyBindingTransitionError::Rollback)
    );
    let revoked = KeyBindingState {
        revoked_through: Some(0),
        ..initial
    };
    assert_eq!(
        first.installation_decision(&revoked),
        Err(KeyBindingTransitionError::Revoked)
    );
    let maximum = state(Some(CommittedKeyBinding {
        generation: u64::MAX,
        wireguard_key: [9; 32],
    }));
    assert_eq!(
        current(u64::MAX, 9).installation_decision(&maximum),
        Ok(InstallationDecision::Idempotent)
    );
}

#[test]
fn only_checked_current_bindings_can_be_installed_and_scopes_are_independent() {
    let invalid_higher = signed_binding(5, 3, 10, 20);
    let mut invalid_higher = invalid_higher;
    invalid_higher.signature[0] ^= 1;
    let original = state(Some(CommittedKeyBinding {
        generation: 1,
        wireguard_key: [2; 32],
    }));
    assert!(invalid_higher.verify().is_err());
    assert_eq!(
        original,
        state(Some(CommittedKeyBinding {
            generation: 1,
            wireguard_key: [2; 32]
        }))
    );
    let mut different_scope = state(None);
    different_scope.scope.network_id = [9; 32];
    assert_eq!(
        current(0, 3).installation_decision(&different_scope),
        Err(KeyBindingTransitionError::ScopeMismatch)
    );
    let other = KeyBindingState {
        scope: KeyBindingScope {
            network_id: [1; 32],
            identity: SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes(),
        },
        committed: None,
        revoked_through: None,
        conflict: None,
    };
    let other_signer = SigningKey::from_bytes(&[8; 32]);
    let mut other_binding = KeyBinding {
        ver: 1,
        network_id: [1; 32],
        identity: other_signer.verifying_key().to_bytes(),
        wireguard_key: [6; 32],
        generation: 0,
        not_before: 10,
        not_after: 20,
        signature: [0; 64],
    };
    other_binding.sign(&other_signer).unwrap();
    let other_current = other_binding
        .verify()
        .unwrap()
        .validate_current(10)
        .unwrap();
    assert!(current(0, 3).installation_decision(&state(None)).is_ok());
    assert!(other_current.installation_decision(&other).is_ok());
    assert!(other.committed.is_none());
}

trait DecisionExt {
    fn is_install(&self) -> bool;
    fn is_latch_conflict(&self) -> bool;
}

impl DecisionExt for InstallationDecision {
    fn is_install(&self) -> bool {
        matches!(self, Self::Install(_))
    }
    fn is_latch_conflict(&self) -> bool {
        matches!(self, Self::LatchConflict(_))
    }
}
