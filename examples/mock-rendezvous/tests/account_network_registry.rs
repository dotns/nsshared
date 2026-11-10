//! The mock's Account registry keeps signed Network records separate from Quick records.

#![allow(clippy::unwrap_used, clippy::panic, reason = "wire fixture assertions")]

mod support;

use nsshared_identity::{
    identity::NodeId,
    realm::RealmId,
    record::{NetworkNodeRecord, NodeRecord, NodeRecordFields},
};
use nsshared_rendezvous::{
    error::ErrorCode,
    message::LookupNetworkNodeRequest,
    registry::publish_network_request,
    transport::{Request, Response},
};
use support::{Mock, key, now, relaxed_limits};

fn record(
    signing: &ed25519_dalek::SigningKey,
    network: RealmId,
    relay: nsshared_identity::relay_id::RelayId,
) -> NetworkNodeRecord {
    NetworkNodeRecord::sign(
        signing,
        network,
        NodeRecord::sign(
            signing,
            NodeRecordFields {
                wg_key: [3; 32],
                generation: 1,
                issued_at: now() - 1,
                expires: now() + 3_600,
                relays: vec![relay],
            },
        )
        .unwrap(),
    )
    .unwrap()
}

#[tokio::test]
async fn network_registry_requires_actor_scope_and_rejects_cross_network_slot_reuse() {
    let mock = Mock::start(relaxed_limits()).await;
    let network = RealmId::from_bytes([1; 16]);
    let other = RealmId::from_bytes([2; 16]);
    let alice = key(31);
    let bob = key(32);
    let alice_record = record(&alice, network, mock.authority());
    let bob_record = record(&bob, network, mock.authority());
    let mut alice_connection = mock.actor(&alice).await;
    let mut bob_connection = mock.actor(&bob).await;
    for (client, signer, envelope) in [
        (&mut alice_connection, &alice, &alice_record),
        (&mut bob_connection, &bob, &bob_record),
    ] {
        let request = Request::PublishNetwork(publish_network_request(
            signer,
            &client.nonce(),
            &client.challenge.authority,
            envelope,
        ));
        assert!(matches!(
            client.request(&request).await,
            Response::Published(_)
        ));
    }
    let lookup = |network: RealmId| {
        Request::LookupNetworkNode(LookupNetworkNodeRequest {
            network: *network.as_bytes(),
            node_id: *NodeId::derive(&bob.verifying_key().to_bytes()).as_bytes(),
        })
    };
    assert!(matches!(alice_connection.request(&lookup(network)).await,
        Response::NetworkRecord(value) if value.record.as_deref() == Some(bob_record.as_bytes())));
    assert_eq!(
        alice_connection.error(&lookup(other)).await,
        ErrorCode::InvalidActor
    );

    let cross = record(&alice, other, mock.authority());
    let request = Request::PublishNetwork(publish_network_request(
        &alice,
        &alice_connection.nonce(),
        &alice_connection.challenge.authority,
        &cross,
    ));
    assert_eq!(alice_connection.error(&request).await, ErrorCode::Conflict);
    mock.stop().await;
}
