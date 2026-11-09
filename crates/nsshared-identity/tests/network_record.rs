use ed25519_dalek::SigningKey;
use nsshared_identity::{
    realm::RealmId,
    record::{NetworkNodeRecord, NodeRecord, NodeRecordFields},
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
