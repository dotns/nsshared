//! Two simulated nodes over the WSS carrier, and one UDP plus one WSS node, registering
//! and exchanging DATA (quick-v2 §8.3-§8.5).
#![allow(clippy::unwrap_used, clippy::panic, reason = "test fixture helpers")]

#[allow(
    dead_code,
    reason = "each test crate uses a subset of the shared helpers"
)]
mod common;

use common::{Link, register, start, stop, unix_now};
use nsshared_mock_relay::{
    Carrier,
    testing::{NodeSession, TestNode, data_packet},
};
use nsshared_wire::RelayBody;

/// Sends DATA from `from` to `to` and checks it arrives byte-identical.
async fn exchange(from: (&mut Link, &NodeSession), to: (&mut Link, &NodeSession), payload: &[u8]) {
    let packet = data_packet(from.1.node_id(), to.1.node_id(), payload).unwrap();
    from.0.send(&packet).await;
    let received = to.0.recv().await;
    assert_eq!(received, packet);
    assert_eq!(
        to.1.open(&received).unwrap(),
        RelayBody::Data(payload.to_vec())
    );
}

#[tokio::test]
async fn two_wss_nodes_exchange_data_both_ways() {
    let relay = start().await;
    let alice = TestNode::new([1; 32], relay.relay_id(), unix_now() - 60).unwrap();
    let bob = TestNode::new([2; 32], relay.relay_id(), unix_now() - 60).unwrap();
    let mut alice_link = Link::wss(&relay).await;
    let mut bob_link = Link::wss(&relay).await;

    let (registered, alice_session) = register(&mut alice_link, &relay, &alice, [11; 32]).await;
    assert_eq!(registered.capabilities, ["udp", "wss"]);
    assert!(registered.observed_addr.is_none());
    let (registered, bob_session) = register(&mut bob_link, &relay, &bob, [12; 32]).await;
    assert!(registered.observed_addr.is_none());
    let sessions = relay.sessions();
    assert_eq!(sessions.len(), 2);
    assert!(
        sessions
            .iter()
            .all(|s| s.confirmed && s.carrier == Carrier::Wss)
    );

    exchange(
        (&mut alice_link, &alice_session),
        (&mut bob_link, &bob_session),
        &[1, 0, 0, 0, 0xaa],
    )
    .await;
    exchange(
        (&mut bob_link, &bob_session),
        (&mut alice_link, &alice_session),
        &[2, 0, 0, 0, 0xbb, 0xcc],
    )
    .await;
    stop(relay).await;
}

#[tokio::test]
async fn udp_and_wss_nodes_exchange_data_both_ways() {
    let relay = start().await;
    let alice = TestNode::new([1; 32], relay.relay_id(), unix_now() - 60).unwrap();
    let bob = TestNode::new([2; 32], relay.relay_id(), unix_now() - 60).unwrap();
    let mut alice_link = Link::udp(&relay).await;
    let mut bob_link = Link::wss(&relay).await;

    let (registered, alice_session) = register(&mut alice_link, &relay, &alice, [11; 32]).await;
    assert!(registered.observed_addr.is_some());
    let (registered, bob_session) = register(&mut bob_link, &relay, &bob, [12; 32]).await;
    assert!(registered.observed_addr.is_none());

    exchange(
        (&mut alice_link, &alice_session),
        (&mut bob_link, &bob_session),
        &[1, 0, 0, 0, 0xaa],
    )
    .await;
    exchange(
        (&mut bob_link, &bob_session),
        (&mut alice_link, &alice_session),
        &[4, 0, 0, 0, 0xdd],
    )
    .await;
    stop(relay).await;
}
