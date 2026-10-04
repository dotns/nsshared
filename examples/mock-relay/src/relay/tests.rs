use super::*;
use crate::testing::{NodeSession, TestNode, TestRng, data_packet};
use nsshared_proto::{
    RelayId, record::NodeRecordFields, relay::ObservedAddr, relay::RelayType, relay::RevokeReason,
    relay::budget::RateLimit,
};
use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};

const UNIX: u64 = 1_800_000_000;

fn relay_id() -> RelayId {
    RelayId::parse("relay.test:51822").unwrap()
}

fn udp(port: u16) -> Peer {
    Peer::Udp(SocketAddr::from(([198, 51, 100, 7], port)))
}

fn wss(connection: u64) -> Peer {
    Peer::Wss {
        connection,
        remote: SocketAddr::from(([203, 0, 113, 9], 40_000)),
    }
}

fn node(seed: u8) -> TestNode {
    TestNode::new([seed; 32], &relay_id(), UNIX - 60).unwrap()
}

struct Harness {
    relay: Relay<TestRng>,
    start: Instant,
}

impl Harness {
    fn new() -> Self {
        Self::with_config(RelayConfig::new(relay_id()))
    }

    fn with_config(config: RelayConfig) -> Self {
        Self {
            relay: Relay::new(config, TestRng::new(7)).unwrap(),
            start: Instant::now(),
        }
    }

    fn at(&self, secs: u64) -> Now {
        Now {
            instant: self.start + Duration::from_secs(secs),
            unix: UNIX + secs,
        }
    }

    fn send(&mut self, secs: u64, from: Peer, packet: &[u8]) -> Vec<Transmit> {
        let now = self.at(secs);
        self.relay.handle(now, from, packet)
    }

    /// Registers and confirms `node` from `peer` at `secs`; the confirming PRESENCE uses
    /// `seq` 1.
    fn connect(&mut self, node: &TestNode, peer: Peer, incarnation: u64, secs: u64) -> NodeSession {
        let attempt = node
            .register(
                &relay_id(),
                incarnation,
                UNIX + secs,
                [incarnation as u8; 32],
            )
            .unwrap();
        let reply = single(self.send(secs, peer, attempt.packet()), peer);
        let (_, session) = attempt.accept(&reply).unwrap();
        let ack = single(self.send(secs, peer, &session.presence(1).unwrap()), peer);
        assert_eq!(registered(&session, &ack).ack_seq, 1);
        session
    }

    fn reason(&self, reason: Reason) -> u64 {
        self.relay.counters().rejected(reason)
    }
}

/// Asserts exactly one transmit to `to` and returns its packet.
fn single(out: Vec<Transmit>, to: Peer) -> Vec<u8> {
    let [transmit] = out.as_slice() else {
        panic!("expected one transmit, got {out:?}");
    };
    assert_eq!(transmit.to, to);
    transmit.packet.clone()
}

fn registered(session: &NodeSession, packet: &[u8]) -> Registered {
    match session.open(packet).unwrap() {
        RelayBody::Registered(registered) => registered,
        other => panic!("expected REGISTERED, got {other:?}"),
    }
}

/// Asserts exactly one STATUS to `to`, addressed to `sender`, and returns it.
fn status(out: Vec<Transmit>, to: Peer, sender: NodeId) -> Status {
    let packet = RelayPacket::decode(&single(out, to)).unwrap();
    assert_eq!(packet.src, RELAY_SLOT);
    assert_eq!(packet.dst, sender);
    match packet.body {
        RelayBody::Status(status) => status,
        other => panic!("expected STATUS, got {other:?}"),
    }
}

fn payload(first: u8) -> Vec<u8> {
    let mut payload = vec![0x55; 64];
    payload[0] = first;
    payload
}

#[test]
fn register_tentative_then_confirm() {
    let mut h = Harness::new();
    let a = node(1);
    let attempt = a.register(&relay_id(), 1, UNIX, [1; 32]).unwrap();
    let reply = single(h.send(0, udp(1), attempt.packet()), udp(1));
    let (tentative, session) = attempt.accept(&reply).unwrap();
    assert_eq!(tentative.ack_seq, 0);
    assert_eq!(tentative.capabilities, ["udp", "wss"]);
    assert_eq!(tentative.presence_ttl_s, 90);
    assert_eq!(
        tentative.observed_addr,
        Some(ObservedAddr {
            ip: [198, 51, 100, 7].into(),
            port: 1,
        })
    );
    let [provisional] = h.relay.sessions().try_into().unwrap();
    assert_eq!(provisional.node_id, a.node_id());
    assert_eq!(provisional.identity, *a.identity());
    assert!(!provisional.confirmed);
    assert_eq!(provisional.carrier, Carrier::Udp);

    let ack = single(h.send(1, udp(1), &session.presence(1).unwrap()), udp(1));
    let confirmed = registered(&session, &ack);
    assert_eq!(confirmed.ack_seq, 1);
    assert!(confirmed.capabilities.is_empty());
    assert_eq!(confirmed.relay_ephemeral, tentative.relay_ephemeral);
    let [info] = h.relay.sessions().try_into().unwrap();
    assert!(info.confirmed);
    assert_eq!((info.incarnation, info.generation), (1, 1));
    assert_eq!(info.peer, udp(1));

    // Later PRESENCE: gaps are accepted, replays dropped silently.
    let ack = single(h.send(2, udp(1), &session.presence(5).unwrap()), udp(1));
    assert_eq!(registered(&session, &ack).ack_seq, 5);
    assert!(h.send(2, udp(1), &session.presence(5).unwrap()).is_empty());
    assert!(h.send(2, udp(1), &session.presence(3).unwrap()).is_empty());
    assert_eq!(h.reason(Reason::StaleSeq), 2);
    let counters = h.relay.counters();
    assert_eq!(
        (
            counters.registered,
            counters.confirmed,
            counters.presence_acked
        ),
        (1, 1, 1)
    );
}

#[test]
fn wss_registration_has_no_observed_addr() {
    let mut h = Harness::new();
    let a = node(1);
    let attempt = a.register(&relay_id(), 1, UNIX, [1; 32]).unwrap();
    let reply = single(h.send(0, wss(3), attempt.packet()), wss(3));
    let (tentative, session) = attempt.accept(&reply).unwrap();
    assert_eq!(tentative.observed_addr, None);
    let ack = single(h.send(0, wss(3), &session.presence(1).unwrap()), wss(3));
    assert_eq!(registered(&session, &ack).observed_addr, None);
    assert_eq!(h.relay.sessions()[0].carrier, Carrier::Wss);
}

#[test]
fn identical_retransmission_gets_identical_reply_without_extending_lifetime() {
    let mut h = Harness::new();
    let a = node(1);
    let attempt = a.register(&relay_id(), 1, UNIX, [1; 32]).unwrap();
    let first = single(h.send(0, udp(1), attempt.packet()), udp(1));
    let again = single(h.send(5, udp(1), attempt.packet()), udp(1));
    assert_eq!(first, again);
    assert_eq!(h.relay.counters().registered, 1);
    assert_eq!(h.relay.counters().retransmitted, 1);

    // The lifetime still ends 10 s after the first REGISTER.
    let (_, session) = attempt.accept(&first).unwrap();
    let out = h.send(10, udp(1), &session.presence(1).unwrap());
    assert_eq!(
        status(out, udp(1), a.node_id()).status,
        StatusCode::NotRegistered
    );
    assert!(h.relay.sessions().is_empty());
}

#[test]
fn retransmission_after_confirmation_is_idempotent() {
    let mut h = Harness::new();
    let a = node(1);
    let attempt = a.register(&relay_id(), 1, UNIX, [1; 32]).unwrap();
    let first = single(h.send(0, udp(1), attempt.packet()), udp(1));
    let (_, session) = attempt.accept(&first).unwrap();
    h.send(0, udp(1), &session.presence(1).unwrap());
    let again = single(h.send(2, udp(1), attempt.packet()), udp(1));
    assert_eq!(first, again);
    assert_eq!(h.reason(Reason::Stale), 0);
}

#[test]
fn another_source_cannot_move_a_registration() {
    let mut h = Harness::new();
    let a = node(1);
    let attempt = a.register(&relay_id(), 1, UNIX, [1; 32]).unwrap();
    let reply = single(h.send(0, udp(1), attempt.packet()), udp(1));
    let (_, session) = attempt.accept(&reply).unwrap();
    // The same REGISTER from another source gets its own challenge.
    let other = single(h.send(0, udp(2), attempt.packet()), udp(2));
    assert_ne!(other, reply);
    // A PRESENCE under the first key from the other source does not confirm anything.
    assert!(h.send(1, udp(2), &session.presence(1).unwrap()).is_empty());
    assert_eq!(h.reason(Reason::BadMac), 1);
    assert!(h.relay.sessions().iter().all(|info| !info.confirmed));
    single(h.send(1, udp(1), &session.presence(1).unwrap()), udp(1));
    let confirmed: Vec<_> = h
        .relay
        .sessions()
        .into_iter()
        .filter(|info| info.confirmed)
        .collect();
    assert_eq!(confirmed.len(), 1);
    assert_eq!(confirmed[0].peer, udp(1));
}

#[test]
fn register_rejections_are_silent() {
    let mut h = Harness::new();
    let a = node(1);

    let mut bad_signature = a
        .register(&relay_id(), 1, UNIX, [1; 32])
        .unwrap()
        .packet()
        .to_vec();
    *bad_signature.last_mut().unwrap() ^= 1;
    assert!(h.send(0, udp(1), &bad_signature).is_empty());
    assert_eq!(h.reason(Reason::RegisterSignature), 1);

    let other_relay = RelayId::parse("other.test:51822").unwrap();
    let wrong_name = a.register(&other_relay, 1, UNIX, [1; 32]).unwrap();
    assert!(h.send(0, udp(1), wrong_name.packet()).is_empty());
    assert_eq!(h.reason(Reason::RegisterRelayName), 1);

    let stale_ts = a.register(&relay_id(), 1, UNIX - 121, [1; 32]).unwrap();
    assert!(h.send(0, udp(1), stale_ts.packet()).is_empty());
    assert_eq!(h.reason(Reason::RegisterTimestamp), 1);

    // 120 s of skew is still accepted.
    let edge = a.register(&relay_id(), 1, UNIX + 120, [1; 32]).unwrap();
    single(h.send(0, udp(1), edge.packet()), udp(1));
    assert_eq!(h.relay.counters().registered, 1);
}

#[test]
fn slot_collision_with_another_identity_is_rejected() {
    let mut h = Harness::new();
    let a = node(1);
    let squatter = [9; 32];
    h.relay.owners.insert(
        a.node_id(),
        Owner {
            identity: squatter,
            marks: RecordMarks::new(squatter),
            incarnation: None,
        },
    );
    let attempt = a.register(&relay_id(), 1, UNIX, [1; 32]).unwrap();
    assert!(h.send(0, udp(1), attempt.packet()).is_empty());
    assert_eq!(h.reason(Reason::SlotCollision), 1);
    assert!(h.relay.sessions().is_empty());
}

#[test]
fn data_is_forwarded_between_confirmed_nodes() {
    let mut h = Harness::new();
    let (a, b) = (node(1), node(2));
    h.connect(&a, udp(1), 1, 0);
    h.connect(&b, wss(4), 1, 0);
    let to_b = data_packet(a.node_id(), b.node_id(), &payload(4)).unwrap();
    assert_eq!(single(h.send(1, udp(1), &to_b), wss(4)), to_b);
    let to_a = data_packet(b.node_id(), a.node_id(), &payload(1)).unwrap();
    assert_eq!(single(h.send(1, wss(4), &to_a), udp(1)), to_a);
    assert_eq!(h.relay.counters().forwarded, 2);
}

#[test]
fn unconfirmed_slots_never_forward() {
    let mut h = Harness::new();
    let (a, b) = (node(1), node(2));
    h.connect(&a, udp(1), 1, 0);
    let attempt = b.register(&relay_id(), 1, UNIX, [2; 32]).unwrap();
    single(h.send(0, udp(2), attempt.packet()), udp(2));
    let to_b = data_packet(a.node_id(), b.node_id(), &payload(4)).unwrap();
    let out = h.send(0, udp(1), &to_b);
    assert_eq!(
        status(out, udp(1), a.node_id()).status,
        StatusCode::NoDestination
    );
    let from_b = data_packet(b.node_id(), a.node_id(), &payload(4)).unwrap();
    let out = h.send(0, udp(2), &from_b);
    assert_eq!(
        status(out, udp(2), b.node_id()).status,
        StatusCode::NotRegistered
    );
}

#[test]
fn data_from_unregistered_sender_gets_status_6() {
    let mut h = Harness::new();
    let (a, c) = (node(1), node(3));
    h.connect(&a, udp(1), 1, 0);
    let from_c = data_packet(c.node_id(), a.node_id(), &payload(4)).unwrap();
    let got = status(h.send(1, udp(3), &from_c), udp(3), c.node_id());
    assert_eq!(
        got,
        Status {
            type_in: RelayType::Data.as_u8(),
            destination: a.node_id(),
            status: StatusCode::NotRegistered,
        }
    );
    // A registered sender from another source is a source mismatch.
    let spoofed = data_packet(a.node_id(), a.node_id(), &payload(4)).unwrap();
    let got = status(h.send(1, udp(9), &spoofed), udp(9), a.node_id());
    assert_eq!(got.status, StatusCode::NotRegistered);
    assert_eq!(h.reason(Reason::NotRegistered), 2);
    assert_eq!(h.relay.counters().forwarded, 0);
}

#[test]
fn data_to_unknown_destination_gets_status_1() {
    let mut h = Harness::new();
    let (a, c) = (node(1), node(3));
    h.connect(&a, udp(1), 1, 0);
    let to_c = data_packet(a.node_id(), c.node_id(), &payload(4)).unwrap();
    let got = status(h.send(1, udp(1), &to_c), udp(1), a.node_id());
    assert_eq!(got.status, StatusCode::NoDestination);
    assert_eq!(got.destination, c.node_id());
}

#[test]
fn data_over_budget_gets_status_2() {
    let mut config = RelayConfig::new(relay_id());
    config.limits.data_packets = RateLimit {
        per_second: 1,
        burst: 2,
    };
    let mut h = Harness::with_config(config);
    let (a, b) = (node(1), node(2));
    h.connect(&a, udp(1), 1, 0);
    h.connect(&b, udp(2), 1, 0);
    let to_b = data_packet(a.node_id(), b.node_id(), &payload(4)).unwrap();
    single(h.send(1, udp(1), &to_b), udp(2));
    single(h.send(1, udp(1), &to_b), udp(2));
    let got = status(h.send(1, udp(1), &to_b), udp(1), a.node_id());
    assert_eq!(got.status, StatusCode::RateLimited);
    // One second refills one packet.
    single(h.send(2, udp(1), &to_b), udp(2));
    assert_eq!(h.reason(Reason::RateLimited), 1);
}

#[test]
fn handshake_initiations_over_budget_get_status_2() {
    let mut config = RelayConfig::new(relay_id());
    config.limits.handshake_initiations = RateLimit {
        per_second: 1,
        burst: 1,
    };
    let mut h = Harness::with_config(config);
    let (a, b) = (node(1), node(2));
    h.connect(&a, udp(1), 1, 0);
    h.connect(&b, udp(2), 1, 0);
    let initiation = data_packet(a.node_id(), b.node_id(), &payload(1)).unwrap();
    single(h.send(1, udp(1), &initiation), udp(2));
    let got = status(h.send(1, udp(1), &initiation), udp(1), a.node_id());
    assert_eq!(got.status, StatusCode::RateLimited);
    // Other WireGuard messages are not counted against the initiation budget.
    let transport = data_packet(a.node_id(), b.node_id(), &payload(4)).unwrap();
    single(h.send(1, udp(1), &transport), udp(2));
}

#[test]
fn reflect_on_udp_once_per_presence_interval() {
    let mut h = Harness::new();
    let a = node(1);
    let session = h.connect(&a, udp(1), 1, 0);
    let reply = single(
        h.send(1, udp(1), &session.reflect(2, [7; 16]).unwrap()),
        udp(1),
    );
    let RelayBody::Reflected(reflected) = session.open(&reply).unwrap() else {
        panic!("expected REFLECTED");
    };
    assert_eq!((reflected.incarnation, reflected.seq), (1, 2));
    assert_eq!(reflected.nonce, [7; 16]);
    assert_eq!(
        SocketAddr::from(reflected.observed_addr),
        "198.51.100.7:1".parse().unwrap()
    );

    // The interval is min(90 / 3, 25) = 25 s.
    let out = h.send(25, udp(1), &session.reflect(3, [8; 16]).unwrap());
    assert_eq!(
        status(out, udp(1), a.node_id()).status,
        StatusCode::RateLimited
    );
    single(
        h.send(26, udp(1), &session.reflect(4, [9; 16]).unwrap()),
        udp(1),
    );
    assert_eq!(h.relay.counters().reflected, 2);
}

#[test]
fn reflect_on_wss_is_refused() {
    let mut h = Harness::new();
    let a = node(1);
    let session = h.connect(&a, wss(5), 1, 0);
    let out = h.send(1, wss(5), &session.reflect(2, [7; 16]).unwrap());
    let got = status(out, wss(5), a.node_id());
    assert_eq!(got.status, StatusCode::UnsupportedType);
    assert_eq!(got.type_in, RelayType::Reflect.as_u8());
    assert_eq!(h.reason(Reason::ReflectOnWss), 1);
}

#[test]
fn revoke_removes_the_session() {
    let mut h = Harness::new();
    let (a, b) = (node(1), node(2));
    let session = h.connect(&a, udp(1), 1, 0);
    h.connect(&b, udp(2), 1, 0);

    // A REVOKE under another key is dropped.
    let forged = NodeSession::new(a.node_id(), 1, SessionKey::from_bytes([3; 32]));
    assert!(
        h.send(1, udp(1), &forged.revoke(2, RevokeReason::Close).unwrap())
            .is_empty()
    );
    assert_eq!(h.reason(Reason::BadMac), 1);
    assert_eq!(h.relay.sessions().len(), 2);

    assert!(
        h.send(1, udp(1), &session.revoke(2, RevokeReason::Close).unwrap())
            .is_empty()
    );
    assert_eq!(h.relay.counters().revoked, 1);
    assert_eq!(h.relay.sessions().len(), 1);
    let to_a = data_packet(b.node_id(), a.node_id(), &payload(4)).unwrap();
    let out = h.send(2, udp(2), &to_a);
    assert_eq!(
        status(out, udp(2), b.node_id()).status,
        StatusCode::NoDestination
    );
    // The marks survive: the revoked incarnation cannot come back.
    let attempt = a.register(&relay_id(), 1, UNIX + 3, [1; 32]).unwrap();
    assert!(h.send(3, udp(1), attempt.packet()).is_empty());
    assert_eq!(h.reason(Reason::Stale), 1);
}

#[test]
fn presence_expires_after_ttl_without_control() {
    let mut h = Harness::new();
    let a = node(1);
    let session = h.connect(&a, udp(1), 1, 0);
    let now = h.at(89);
    h.relay.tick(now);
    assert_eq!(h.relay.sessions().len(), 1);
    // An accepted PRESENCE refreshes liveness.
    single(h.send(89, udp(1), &session.presence(2).unwrap()), udp(1));
    let now = h.at(178);
    h.relay.tick(now);
    assert_eq!(h.relay.sessions().len(), 1);
    let now = h.at(179);
    h.relay.tick(now);
    assert!(h.relay.sessions().is_empty());
    assert_eq!(h.relay.counters().expired, 1);
    let out = h.send(180, udp(1), &session.presence(3).unwrap());
    assert_eq!(
        status(out, udp(1), a.node_id()).status,
        StatusCode::NotRegistered
    );
}

#[test]
fn presence_expires_with_the_record() {
    let mut h = Harness::new();
    let a = TestNode::with_fields(
        [1; 32],
        NodeRecordFields {
            wg_key: [5; 32],
            generation: 1,
            issued_at: UNIX - 60,
            expires: UNIX + 30,
            relays: vec![relay_id()],
        },
    )
    .unwrap();
    let session = h.connect(&a, udp(1), 1, 0);
    single(h.send(29, udp(1), &session.presence(2).unwrap()), udp(1));
    let now = h.at(30);
    h.relay.tick(now);
    assert!(h.relay.sessions().is_empty());
}

#[test]
fn new_incarnation_replaces_the_session_across_carriers() {
    let mut h = Harness::new();
    let a = node(1);
    let old = h.connect(&a, udp(1), 1, 0);
    h.connect(&a, wss(6), 2, 5);
    let [info] = h.relay.sessions().try_into().unwrap();
    assert_eq!(
        (info.peer, info.incarnation, info.confirmed),
        (wss(6), 2, true)
    );

    // The old source is no longer registered.
    let out = h.send(6, udp(1), &old.presence(2).unwrap());
    assert_eq!(
        status(out, udp(1), a.node_id()).status,
        StatusCode::NotRegistered
    );
    // A non-increasing incarnation is stale: STATUS 4 to the session source only.
    let stale = a.register(&relay_id(), 2, UNIX + 7, [2; 32]).unwrap();
    let got = status(h.send(7, wss(6), stale.packet()), wss(6), a.node_id());
    assert_eq!(got.status, StatusCode::Stale);
    assert_eq!(got.type_in, RelayType::Register.as_u8());
    assert!(h.send(7, udp(1), stale.packet()).is_empty());
    assert_eq!(h.reason(Reason::Stale), 2);
}

#[test]
fn stale_incarnation_on_presence_gets_status_4() {
    let mut h = Harness::new();
    let a = node(1);
    let session = h.connect(&a, udp(1), 2, 0);
    let wrong = NodeSession::new(a.node_id(), 1, session.key().clone());
    let out = h.send(1, udp(1), &wrong.presence(2).unwrap());
    assert_eq!(status(out, udp(1), a.node_id()).status, StatusCode::Stale);
}

#[test]
fn higher_generation_resets_the_incarnation() {
    let mut h = Harness::new();
    let mut a = node(1);
    h.connect(&a, udp(1), 5, 0);
    a.resign(NodeRecordFields {
        wg_key: [6; 32],
        generation: 2,
        issued_at: UNIX,
        expires: UNIX + 3600,
        relays: vec![relay_id()],
    })
    .unwrap();
    h.connect(&a, udp(1), 1, 1);
    let [info] = h.relay.sessions().try_into().unwrap();
    assert_eq!((info.generation, info.incarnation), (2, 1));
}

#[test]
fn unknown_type_oversize_and_status_handling() {
    let mut h = Harness::new();
    let (a, c) = (node(1), node(3));
    let session = h.connect(&a, udp(1), 1, 0);

    let mut unknown = session.presence(2).unwrap();
    unknown[RELAY_MAGIC.len()] = 9;
    let got = status(h.send(1, udp(1), &unknown), udp(1), a.node_id());
    assert_eq!((got.type_in, got.status), (9, StatusCode::UnsupportedType));
    // Not from a registered source: dropped.
    assert!(h.send(1, udp(2), &unknown).is_empty());

    let mut oversize = session.presence(2).unwrap();
    oversize.resize(1201, 0);
    let got = status(h.send(1, udp(1), &oversize), udp(1), a.node_id());
    assert_eq!(got.status, StatusCode::TooLarge);

    // STATUS is never answered; garbage is dropped.
    let status_packet = RelayPacket {
        src: RELAY_SLOT,
        dst: c.node_id(),
        body: RelayBody::Status(Status {
            type_in: 6,
            destination: a.node_id(),
            status: StatusCode::NoDestination,
        }),
    }
    .encode()
    .unwrap();
    assert!(h.send(1, udp(1), &status_packet).is_empty());
    assert!(
        h.send(1, udp(1), b"NSR1 not a relay packet at all..")
            .is_empty()
    );
    assert_eq!(h.reason(Reason::Unexpected), 1);
    assert_eq!(h.reason(Reason::Malformed), 1);
    assert_eq!(h.reason(Reason::UnknownType), 2);
}

#[test]
fn disconnect_removes_sessions_on_the_connection() {
    let mut h = Harness::new();
    let (a, b) = (node(1), node(2));
    h.connect(&a, wss(1), 1, 0);
    h.connect(&b, udp(2), 1, 0);
    h.relay.disconnect(&wss(1));
    let [info] = h.relay.sessions().try_into().unwrap();
    assert_eq!(info.node_id, b.node_id());
    assert_eq!(h.relay.counters().disconnected, 1);
}

#[test]
fn provisional_limit_per_ip() {
    let mut config = RelayConfig::new(relay_id());
    config.limits.provisional_per_ip = 1;
    let mut h = Harness::with_config(config);
    let (a, b) = (node(1), node(2));
    let first = a.register(&relay_id(), 1, UNIX, [1; 32]).unwrap();
    single(h.send(0, udp(1), first.packet()), udp(1));
    let second = b.register(&relay_id(), 1, UNIX, [2; 32]).unwrap();
    assert!(h.send(0, udp(2), second.packet()).is_empty());
    assert_eq!(h.reason(Reason::Capacity), 1);
}

#[test]
fn config_validates_ttl_and_limits() {
    let mut config = RelayConfig::new(relay_id());
    assert_eq!(config.validate(), Ok(()));
    config.presence_ttl_s = 29;
    assert_eq!(config.validate(), Err(ConfigError::PresenceTtl(29)));
    config.presence_ttl_s = 3601;
    assert!(Relay::new(config.clone(), TestRng::new(1)).is_err());
    config.presence_ttl_s = 3600;
    config.limits.max_sessions = 0;
    assert_eq!(config.validate(), Err(ConfigError::ZeroLimit));
}
