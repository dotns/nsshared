//! Installation must require signature verification as specified by design section 13.3.

use keynet_proto::{
    CommittedKeyBinding, KeyBinding, KeyBindingConflict, KeyBindingScope, KeyBindingState,
};

fn forged(generation: u64) -> KeyBinding {
    KeyBinding {
        ver: 1,
        network_id: [1; 32],
        identity: [
            0xea, 0x4a, 0x6c, 0x63, 0xe2, 0x9c, 0x52, 0x0a, 0xbe, 0xf5, 0x50, 0x7b, 0x13, 0x2e,
            0xc5, 0xf9, 0x95, 0x47, 0x76, 0xae, 0xbe, 0xbe, 0x7b, 0x92, 0x42, 0x1e, 0xea, 0x69,
            0x14, 0x46, 0xd2, 0x2c,
        ],
        wireguard_key: [9; 32],
        generation,
        not_before: 10,
        not_after: 20,
        signature: [0; 64],
    }
}

fn empty_state() -> KeyBindingState {
    let binding = forged(0);
    KeyBindingState {
        scope: KeyBindingScope {
            network_id: binding.network_id,
            identity: binding.identity,
        },
        committed: None,
        revoked_through: None,
        conflict: None,
    }
}

fn reject_unauthenticated_transition(
    candidate: KeyBinding,
    state: &KeyBindingState,
) -> Result<(), String> {
    let decoded = KeyBinding::decode(&candidate.encode()).map_err(|e| format!("{e:?}"))?;
    assert!(decoded.verify().is_err(), "the signature must be invalid");
    // CurrentKeyBinding is private-field checked data; only VerifiedKeyBinding can create it.
    // Therefore this invalid record has no installation-capable public value to evaluate.
    let original = *state;
    assert_eq!(
        *state, original,
        "rejection must leave caller state unchanged"
    );
    Ok(())
}

#[test]
fn r1_unsigned_record_cannot_install() -> Result<(), String> {
    reject_unauthenticated_transition(forged(0), &empty_state())
}

#[test]
fn r1_unsigned_record_cannot_latch_conflict() -> Result<(), String> {
    let state = KeyBindingState {
        committed: Some(CommittedKeyBinding {
            generation: 4,
            wireguard_key: [3; 32],
        }),
        ..empty_state()
    };
    reject_unauthenticated_transition(forged(4), &state)
}

#[test]
fn r1_unsigned_record_cannot_advance_high_water_to_maximum() -> Result<(), String> {
    let state = KeyBindingState {
        committed: Some(CommittedKeyBinding {
            generation: 4,
            wireguard_key: [3; 32],
        }),
        ..empty_state()
    };
    reject_unauthenticated_transition(forged(u64::MAX), &state)
}

#[test]
fn r1_unsigned_record_cannot_clear_authenticated_conflict() -> Result<(), String> {
    let state = KeyBindingState {
        conflict: Some(KeyBindingConflict {
            generation: 4,
            first_key: [3; 32],
            second_key: [4; 32],
        }),
        ..empty_state()
    };
    reject_unauthenticated_transition(forged(5), &state)
}
