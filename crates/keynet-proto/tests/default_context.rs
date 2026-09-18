use ed25519_dalek::SigningKey;
use keynet_proto::{
    DEFAULT_NETWORK_ID, KeyBinding, PairingToken, PairingTokenAcceptanceError,
    derive_address_group, derive_slot_id, identity_label,
};
use sha2::{Digest, Sha256};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn default_context_matches_independent_derivation_vectors() {
    assert_eq!(
        DEFAULT_NETWORK_ID,
        <[u8; 32]>::from(Sha256::digest(b"keynet-default-context-v1"))
    );
    let fixtures = include_str!("fixtures/default-context-v1/derivations.vec");
    let mut count = 0;
    for line in fixtures.lines().filter(|line| !line.starts_with('#')) {
        let fields: Vec<_> = line.split('|').collect();
        assert_eq!(fields.len(), 5);
        let identity = std::array::from_fn(|index| {
            u8::from_str_radix(&fields[0][index * 2..index * 2 + 2], 16).unwrap()
        });
        let group = derive_address_group(&DEFAULT_NETWORK_ID, &identity).unwrap();
        assert_eq!(hex(&group.n6_bytes()), fields[1]);
        assert_eq!(hex(&group.n4_bytes()), fields[2]);
        assert_eq!(
            hex(&derive_slot_id(&DEFAULT_NETWORK_ID, &identity).unwrap()),
            fields[3]
        );
        assert_eq!(identity_label(&identity).unwrap(), fields[4]);
        count += 1;
    }
    assert_eq!(count, 3);
}

#[test]
fn default_context_pairing_uses_device_signatures_and_preserves_recipient_checks() {
    let signer = SigningKey::from_bytes(&[7; 32]);
    let recipient = SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes();
    let stranger = SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes();
    let mut binding = KeyBinding {
        ver: 1,
        network_id: DEFAULT_NETWORK_ID,
        identity: signer.verifying_key().to_bytes(),
        wireguard_key: [0x44; 32],
        generation: 1,
        not_before: 100,
        not_after: 1_000,
        signature: [0; 64],
    };
    binding.sign(&signer).unwrap();
    let mut token = PairingToken {
        ver: 1,
        network_id: DEFAULT_NETWORK_ID,
        net_name: String::new(),
        issuer: binding.identity,
        binding,
        issuer_name: Some("device-a".to_owned()),
        relay: "relay.example:443".to_owned(),
        endpoint: None,
        secret: [0x55; 32],
        not_after: 900,
        recipient: Some(recipient),
        signature: [0; 64],
    };
    token.sign(&signer).unwrap();
    let decoded = PairingToken::decode(&token.encode().unwrap()).unwrap();
    assert_eq!(decoded, token);
    assert!(decoded.validate(&recipient, 100).is_ok());
    assert_eq!(
        decoded.validate(&stranger, 100),
        Err(PairingTokenAcceptanceError::RecipientMismatch)
    );
    let mut altered = decoded;
    altered.network_id[0] ^= 1;
    altered.binding.network_id = altered.network_id;
    assert!(altered.verify_signature().is_err());
    assert!(altered.binding.verify().is_err());
}
