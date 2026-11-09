use ed25519_dalek::SigningKey;
use nsshared_identity::{
    keys::IdentitySecret,
    realm::RealmId,
    record::{NetworkNodeRecord, NodeRecord, NodeRecordFields, derive_network_identity},
    relay_id::RelayId,
};

#[allow(
    clippy::unwrap_used,
    reason = "test fixture requires valid relay and record"
)]
fn record(signer: &SigningKey, relay: &str) -> NodeRecord {
    NodeRecord::sign(
        signer,
        NodeRecordFields {
            wg_key: [9; 32],
            generation: 1,
            issued_at: 100,
            expires: 200,
            relays: vec![RelayId::parse(relay).unwrap()],
        },
    )
    .unwrap()
}

#[test]
fn network_identities_have_distinct_relay_slots() {
    let root = IdentitySecret::from_seed([20; 32]);
    let a = RealmId::from_bytes([1; 16]);
    let b = RealmId::from_bytes([2; 16]);
    let a_key = derive_network_identity(&root, a);
    let repeated = derive_network_identity(&root, a);
    let b_key = derive_network_identity(&root, b);
    assert_eq!(a_key.public(), repeated.public());
    assert_ne!(a_key.public(), b_key.public());
    assert_ne!(a_key.public(), root.public());
    assert_eq!(
        a_key.expose_seed(),
        &[
            0xc8, 0x71, 0xb9, 0x23, 0xd0, 0x55, 0x6e, 0x92, 0x3c, 0x79, 0x9a, 0x05, 0xe6, 0xf3,
            0x77, 0x1f, 0x41, 0xe8, 0xc0, 0x21, 0x9a, 0xec, 0x52, 0x95, 0x3c, 0xd4, 0x0e, 0xda,
            0xbb, 0xd8, 0x48, 0xf6,
        ]
    );
}

#[test]
fn same_node_can_sign_distinct_network_relay_sets() {
    let signer = SigningKey::from_bytes(&[17; 32]);
    let a = RealmId::from_bytes([1; 16]);
    let b = RealmId::from_bytes([2; 16]);
    let first =
        NetworkNodeRecord::sign(&signer, a, record(&signer, "relay-a.example:443")).unwrap();
    let second =
        NetworkNodeRecord::sign(&signer, b, record(&signer, "relay-b.example:443")).unwrap();
    assert_eq!(NetworkNodeRecord::decode(first.as_bytes()).unwrap(), first);
    assert_eq!(
        NetworkNodeRecord::decode(second.as_bytes()).unwrap(),
        second
    );
    assert!(first.verify_for(a).is_ok());
    assert!(second.verify_for(b).is_ok());
    assert!(first.verify_for(b).is_err());
    assert_ne!(first.record().relays(), second.record().relays());
    assert_ne!(first.key(), second.key());
    assert_eq!(first.key().node, second.key().node);
}

#[test]
fn network_or_inner_record_substitution_fails_verification() {
    let signer = SigningKey::from_bytes(&[18; 32]);
    let network = RealmId::from_bytes([3; 16]);
    let signed =
        NetworkNodeRecord::sign(&signer, network, record(&signer, "relay-c.example:443")).unwrap();
    let mut changed = signed.as_bytes().to_vec();
    let network_offset = changed
        .windows(16)
        .position(|slice| slice == [3; 16])
        .unwrap();
    changed[network_offset] ^= 1;
    assert!(NetworkNodeRecord::decode(&changed).is_err());
    let replacement = record(&signer, "relay-d.example:443");
    let inner_offset = signed
        .as_bytes()
        .windows(signed.record().as_bytes().len())
        .position(|slice| slice == signed.record().as_bytes())
        .unwrap();
    let mut changed = signed.as_bytes().to_vec();
    changed[inner_offset..inner_offset + replacement.as_bytes().len()]
        .copy_from_slice(replacement.as_bytes());
    assert!(NetworkNodeRecord::decode(&changed).is_err());
    assert!(signed.verify_current_for(network, 200).is_err());
    assert!(signed.verify_current_for(network, 199).is_ok());
    assert!(
        NetworkNodeRecord::sign(
            &SigningKey::from_bytes(&[19; 32]),
            network,
            record(&signer, "relay-c.example:443"),
        )
        .is_err()
    );
}
