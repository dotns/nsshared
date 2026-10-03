//! Two simulated nodes over the UDP carrier: register, exchange DATA both ways and get
//! STATUS 1 for an unknown destination (quick-v2 §8.3, §8.4).
#![allow(clippy::unwrap_used, clippy::panic, reason = "test fixture helpers")]

#[allow(
    dead_code,
    reason = "each test crate uses a subset of the shared helpers"
)]
mod common;

use common::{Link, register, start, stop, unix_now};
use nsshared_mock_relay::testing::{TestNode, data_packet};
use nsshared_wire::{NODE_ID_BYTES, NodeId, RelayBody, RelayType, StatusCode};
use std::net::SocketAddr;

#[tokio::test]
async fn two_udp_nodes_exchange_data_both_ways() {
    let relay = start().await;
    let alice = TestNode::new([1; 32], relay.relay_id(), unix_now() - 60).unwrap();
    let bob = TestNode::new([2; 32], relay.relay_id(), unix_now() - 60).unwrap();
    let mut alice_link = Link::udp(&relay).await;
    let mut bob_link = Link::udp(&relay).await;

    let (registered, alice_session) = register(&mut alice_link, &relay, &alice, [11; 32]).await;
    assert_eq!(registered.capabilities, ["udp", "wss"]);
    let observed = registered.observed_addr.unwrap();
    assert_eq!(
        Some(SocketAddr::from(observed)),
        alice_link.local_udp_addr()
    );
    let (_, bob_session) = register(&mut bob_link, &relay, &bob, [12; 32]).await;
    assert_eq!(relay.sessions().iter().filter(|s| s.confirmed).count(), 2);

    let to_bob = data_packet(alice.node_id(), bob.node_id(), &[1, 0, 0, 0, 0xaa, 0xbb]).unwrap();
    alice_link.send(&to_bob).await;
    let received = bob_link.recv().await;
    assert_eq!(received, to_bob);
    assert_eq!(
        bob_session.open(&received).unwrap(),
        RelayBody::Data(vec![1, 0, 0, 0, 0xaa, 0xbb])
    );

    let to_alice = data_packet(bob.node_id(), alice.node_id(), &[2, 0, 0, 0, 0xcc]).unwrap();
    bob_link.send(&to_alice).await;
    let received = alice_link.recv().await;
    assert_eq!(received, to_alice);
    assert_eq!(
        alice_session.open(&received).unwrap(),
        RelayBody::Data(vec![2, 0, 0, 0, 0xcc])
    );
    stop(relay).await;
}

#[tokio::test]
async fn data_to_an_unknown_destination_gets_status_1() {
    let relay = start().await;
    let alice = TestNode::new([1; 32], relay.relay_id(), unix_now() - 60).unwrap();
    let mut link = Link::udp(&relay).await;
    let (_, session) = register(&mut link, &relay, &alice, [11; 32]).await;

    // A 148-byte handshake initiation: STATUS is never larger than its trigger, so a
    // tiny DATA packet would get no answer.
    let mut initiation = [0; 148];
    initiation[0] = 1;
    let unknown = NodeId::from_bytes([0x5a; NODE_ID_BYTES]);
    link.send(&data_packet(alice.node_id(), unknown, &initiation).unwrap())
        .await;
    match session.open(&link.recv().await).unwrap() {
        RelayBody::Status(status) => {
            assert_eq!(status.status, StatusCode::NoDestination);
            assert_eq!(status.status as u8, 1);
            assert_eq!(status.type_in, RelayType::Data.as_u8());
            assert_eq!(status.destination, unknown);
        }
        other => panic!("no STATUS: {other:?}"),
    }
    stop(relay).await;
}
