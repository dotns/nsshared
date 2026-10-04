//! The ns `RelayClient` byte layout against the mock. The client side is rebuilt here from
//! `nsshared-proto` calls that mirror ns `crates/overlay/src/relay/{session,data}.rs` and
//! `carrier/{udp,wss}.rs`, without depending on ns and without the `testing` helpers, so
//! it checks the wire layout independently.
#![allow(clippy::unwrap_used, clippy::panic, reason = "test fixture helpers")]

#[allow(
    dead_code,
    reason = "each test crate uses a subset of the shared helpers"
)]
mod common;

use common::{Link, start, stop, unix_now};
use ed25519_dalek::SigningKey;
use nsshared_mock_relay::MockRelay;
use nsshared_proto::rendezvous::capability::{self, Capabilities, Capability};
use nsshared_proto::{
    NodeId, NodeRecord, constants::RELAY_HEADER_BYTES, constants::RELAY_MAGIC,
    record::NodeRecordFields, relay::Presence, relay::RELAY_SLOT, relay::Register,
    relay::RelayBody, relay::RelayPacket, relay::RelayType, relay::SessionKey,
    relay::accept_relayed_data, relay::ephemeral_public,
};
use std::net::SocketAddr;

/// A one-week record lifetime, like the ns session tests' default record.
const RECORD_SECONDS: u64 = 604_800;

/// A WireGuard handshake initiation: message type 1, three reserved zero bytes, then
/// opaque bytes. Only the leading type byte matters to the relay.
const HANDSHAKE_INITIATION: [u8; 12] = [1, 0, 0, 0, 9, 8, 7, 6, 5, 4, 3, 2];

/// The node side of one confirmed ns relay session.
struct NsNode {
    own: NodeId,
    incarnation: u64,
    key: SessionKey,
    link: Link,
}

/// Registers like ns `RelaySession`: `start` builds REGISTER, `handle` /
/// `on_tentative` checks the tentative REGISTERED and sends the confirming PRESENCE,
/// `on_acknowledged` checks the acknowledgement.
async fn ns_register(relay: &MockRelay, mut link: Link, seed: u8, secret: [u8; 32]) -> NsNode {
    // ns session.rs tests `record()`: NodeRecord::sign over NodeRecordFields listing the
    // relay identifier; ns identity.rs derives the node ID from the identity.
    let signer = SigningKey::from_bytes(&[seed; 32]);
    let issued_at = unix_now() - 60;
    let record = NodeRecord::sign(
        &signer,
        NodeRecordFields {
            wg_key: ephemeral_public(&[seed.wrapping_add(100); 32]),
            generation: 1,
            issued_at,
            expires: issued_at + RECORD_SECONDS,
            relays: vec![relay.relay_id().clone()],
        },
    )
    .unwrap();
    let own = record.node_id();

    // ns session.rs `RelaySession::start`: a fresh ephemeral from the rng (fixed here),
    // `Register::sign(signer, record, incarnation, now.unix, ephemeral_public(secret),
    // &self.relay)` with relay_name = the relay identifier, then
    // `RelayPacket { src: own, dst: RELAY_SLOT, body: Register }.encode()`.
    let incarnation = 1;
    let ts = unix_now();
    let register = Register::sign(
        &signer,
        &record,
        incarnation,
        ts,
        ephemeral_public(&secret),
        relay.relay_id(),
    )
    .unwrap();
    assert_eq!(register.record(), record.as_bytes());
    assert_eq!(register.incarnation(), incarnation);
    assert_eq!(register.ts(), ts);
    assert_eq!(register.node_ephemeral(), &ephemeral_public(&secret));
    assert_eq!(register.relay_name(), relay.relay_id().as_str());
    register.verify_signature().unwrap();
    let packet = RelayPacket {
        src: own,
        dst: RELAY_SLOT,
        body: RelayBody::Register(register.clone()),
    }
    .encode()
    .unwrap();
    // The 29-byte header: magic, type 1, src = own node ID, dst = relay slot (zero).
    assert_eq!(packet[..4], RELAY_MAGIC);
    assert_eq!(packet[4], RelayType::Register.as_u8());
    assert_eq!(packet[5..17], *own.as_bytes());
    assert_eq!(packet[17..RELAY_HEADER_BYTES], *RELAY_SLOT.as_bytes());
    // ns carrier/udp.rs `send` / carrier/wss.rs `send`: one datagram / binary message.
    link.send(&packet).await;

    // ns session.rs `handle`: decode, drop unless dst = own, dispatch REGISTERED with
    // ack_seq 0 to `on_tentative`.
    let reply = RelayPacket::decode(&link.recv().await).unwrap();
    assert_eq!(reply.src, RELAY_SLOT);
    assert_eq!(reply.dst, own);
    let RelayBody::Registered(tentative) = &reply.body else {
        panic!("no REGISTERED: {:?}", reply.body);
    };
    assert_eq!(tentative.ack_seq, 0);
    // ns session.rs `on_tentative`: the incarnation echoes the attempt, observed_addr is
    // present exactly on UDP, the reply MAC verifies under the node session key, and the
    // capabilities parse like ns `parse_capabilities`.
    assert_eq!(tentative.incarnation, incarnation);
    match link.local_udp_addr() {
        Some(local) => {
            assert_eq!(tentative.observed_addr.map(SocketAddr::from), Some(local));
        }
        None => assert!(tentative.observed_addr.is_none()),
    }
    let key = register
        .node_session_key(&secret, &tentative.relay_ephemeral)
        .unwrap();
    reply.verify_mac(&key).unwrap();
    let capabilities = Capabilities::new(
        tentative
            .capabilities
            .iter()
            .map(|token| Capability::parse(token))
            .collect::<Result<Vec<_>, _>>()
            .unwrap(),
    )
    .unwrap();
    assert!(capabilities.contains(&capability::UDP));
    assert!(capabilities.contains(&capability::WSS));

    // ns session.rs `presence` + `seal_encode`: the first PRESENCE takes seq 1
    // (`next_seq: 1`), is sealed under the session key and sent on the same carrier.
    let mut presence = RelayPacket {
        src: own,
        dst: RELAY_SLOT,
        body: RelayBody::Presence(Presence {
            incarnation,
            seq: 1,
            mac: [0; 32],
        }),
    };
    presence.seal(&key).unwrap();
    link.send(&presence.encode().unwrap()).await;

    // ns session.rs `on_acknowledged`: same incarnation, MAC under the session key and
    // ack_seq naming the outstanding PRESENCE.
    let ack = RelayPacket::decode(&link.recv().await).unwrap();
    assert_eq!(ack.dst, own);
    let RelayBody::Registered(acknowledged) = &ack.body else {
        panic!("no acknowledgement: {:?}", ack.body);
    };
    assert_eq!(acknowledged.incarnation, incarnation);
    assert_eq!(acknowledged.ack_seq, 1);
    ack.verify_mac(&key).unwrap();

    NsNode {
        own,
        incarnation,
        key,
        link,
    }
}

/// ns data.rs `wrap_data`: `RelayPacket { src: own, dst: peer, body: Data(wireguard) }`.
fn wrap_data(own: NodeId, peer: NodeId, wireguard: &[u8]) -> Vec<u8> {
    RelayPacket {
        src: own,
        dst: peer,
        body: RelayBody::Data(wireguard.to_vec()),
    }
    .encode()
    .unwrap()
}

/// Sends a handshake initiation from `from` to `to` and applies the receive-side checks
/// of ns data.rs `unwrap_data`.
async fn ns_data(from: &mut NsNode, to: &mut NsNode) {
    let packet = wrap_data(from.own, to.own, &HANDSHAKE_INITIATION);
    // The 29-byte header with the src / dst node-ID slots, then the raw WireGuard bytes.
    assert_eq!(
        packet.len(),
        RELAY_HEADER_BYTES + HANDSHAKE_INITIATION.len()
    );
    assert_eq!(packet[..4], RELAY_MAGIC);
    assert_eq!(packet[4], RelayType::Data.as_u8());
    assert_eq!(packet[5..17], *from.own.as_bytes());
    assert_eq!(packet[17..RELAY_HEADER_BYTES], *to.own.as_bytes());
    assert_eq!(packet[RELAY_HEADER_BYTES..], HANDSHAKE_INITIATION);
    assert_eq!(packet[RELAY_HEADER_BYTES], 1);
    from.link.send(&packet).await;

    let received = to.link.recv().await;
    assert_eq!(received, packet);
    // ns data.rs `unwrap_data`: decode, then `accept_relayed_data` requires dst = own
    // and src = an installed peer; the header is stripped.
    let decoded = RelayPacket::decode(&received).unwrap();
    let wireguard = accept_relayed_data(&decoded, &to.own, |src| *src == from.own).unwrap();
    assert_eq!(wireguard, HANDSHAKE_INITIATION);
    assert_eq!(decoded.src, from.own);
    // The same packet is dropped by a node that has not installed the sender.
    assert!(accept_relayed_data(&decoded, &to.own, |_| false).is_err());
}

#[tokio::test]
async fn ns_relay_client_layout_over_udp_and_wss() {
    let relay = start().await;
    let udp = Link::udp(&relay).await;
    let wss = Link::wss(&relay).await;
    let mut alice = ns_register(&relay, udp, 1, [21; 32]).await;
    let mut bob = ns_register(&relay, wss, 2, [22; 32]).await;
    assert_eq!(alice.incarnation, bob.incarnation);
    assert_ne!(alice.key, bob.key);
    assert_eq!(relay.sessions().iter().filter(|s| s.confirmed).count(), 2);

    ns_data(&mut alice, &mut bob).await;
    ns_data(&mut bob, &mut alice).await;
    stop(relay).await;
}
