//! Cross-repository wire fixtures for the unified-node contracts (NODE-001).
//!
//! Every literal here is a pinned wire shape. `ns`, `nsd`, and `nsgw` mirror
//! these bytes, so a change to one of these strings is a contract change that
//! must be coordinated across all four repositories — not a test edit.
//!
//! The compatibility half of the file proves the additive claim the other way
//! round: existing service, capture, GatewayExit, GatewayEgress, direct-P2P,
//! and relay payloads decode and re-encode byte-for-byte with the new fields
//! absent.

use common::{NodeCapability, recognized_node_capabilities};
use control::api::{AuthPayload, from_cbor, to_cbor};
use control::envelope::api as envelope_api;
use control::messages::ControlMessage;
use control::subnet_route::{
    ApprovedSubnetRoute, NodeSubnetRouteAdvertisement, NodeSubnetRouteReport,
    NodeSubnetRouteReportAck, OverlayReservedRanges, SubnetRouteAuthorizationScope,
    SubnetRouteConfig, SubnetRouteForwardingMode, canonical_subnet_route_id,
};
use control::types::WssLegRole;
use serde::Deserialize;

// ── pinned wire fixtures ─────────────────────────────────────────────────────

const NODE_SUBNET_ROUTE_REPORT_JSON: &str = concat!(
    r#"{"generation":7,"routes":["#,
    r#"{"route_id":"snr1-89f1bf77cf5eebe2ddeb7706079e7b84","prefix":"192.168.10.0/24","#,
    r#""generation":7,"requested_forwarding":"snat"}"#,
    r#"]}"#
);

const SUBNET_ROUTE_CONFIG_JSON: &str = concat!(
    r#"{"generation":11,"routes":["#,
    r#"{"route_id":"snr1-89f1bf77cf5eebe2ddeb7706079e7b84","realm_id":"realm-a","#,
    r#""owner_machine_id":"machine-provider","prefix":"192.168.10.0/24","#,
    r#""next_hop_wg_public_key":"AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=","#,
    r#""generation":11,"forwarding":"snat","scope":"consumer"}"#,
    r#"]}"#
);

const SUBNET_ROUTE_CONFIG_MESSAGE_JSON: &str = concat!(
    r#"{"type":"subnet_route_config.v1","generation":11,"routes":["#,
    r#"{"route_id":"snr1-89f1bf77cf5eebe2ddeb7706079e7b84","realm_id":"realm-a","#,
    r#""owner_machine_id":"machine-provider","prefix":"192.168.10.0/24","#,
    r#""next_hop_wg_public_key":"AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=","#,
    r#""generation":11,"forwarding":"snat","scope":"consumer"}"#,
    r#"]}"#
);

const REPORT_ACK_JSON: &str =
    r#"{"accepted_route_ids":["snr1-a"],"rejected_route_ids":["snr1-b"]}"#;

fn fixture_report() -> NodeSubnetRouteReport {
    NodeSubnetRouteReport {
        generation: 7,
        routes: vec![NodeSubnetRouteAdvertisement {
            route_id: "snr1-89f1bf77cf5eebe2ddeb7706079e7b84".to_owned(),
            prefix: "192.168.10.0/24".parse().unwrap(),
            generation: 7,
            requested_forwarding: SubnetRouteForwardingMode::Snat,
        }],
    }
}

fn fixture_config() -> SubnetRouteConfig {
    SubnetRouteConfig {
        generation: 11,
        routes: vec![ApprovedSubnetRoute {
            route_id: "snr1-89f1bf77cf5eebe2ddeb7706079e7b84".to_owned(),
            realm_id: "realm-a".to_owned(),
            owner_machine_id: "machine-provider".to_owned(),
            prefix: "192.168.10.0/24".parse().unwrap(),
            next_hop_wg_public_key: [3u8; 32],
            generation: 11,
            forwarding: SubnetRouteForwardingMode::Snat,
            scope: SubnetRouteAuthorizationScope::Consumer,
        }],
    }
}

#[test]
fn node_subnet_route_report_matches_the_pinned_json() {
    assert_eq!(
        serde_json::to_string(&fixture_report()).unwrap(),
        NODE_SUBNET_ROUTE_REPORT_JSON
    );
    assert_eq!(
        serde_json::from_str::<NodeSubnetRouteReport>(NODE_SUBNET_ROUTE_REPORT_JSON).unwrap(),
        fixture_report()
    );
}

#[test]
fn subnet_route_config_matches_the_pinned_json() {
    assert_eq!(
        serde_json::to_string(&fixture_config()).unwrap(),
        SUBNET_ROUTE_CONFIG_JSON
    );
    assert_eq!(
        serde_json::from_str::<SubnetRouteConfig>(SUBNET_ROUTE_CONFIG_JSON).unwrap(),
        fixture_config()
    );
}

#[test]
fn the_subnet_route_control_message_carries_its_pinned_tag() {
    let message = ControlMessage::SubnetRouteConfig(fixture_config());

    assert_eq!(
        serde_json::to_string(&message).unwrap(),
        SUBNET_ROUTE_CONFIG_MESSAGE_JSON
    );
    assert_eq!(message.event_type(), "subnet_route_config.v1");

    let decoded: ControlMessage = serde_json::from_str(SUBNET_ROUTE_CONFIG_MESSAGE_JSON).unwrap();
    match decoded {
        ControlMessage::SubnetRouteConfig(config) => assert_eq!(config, fixture_config()),
        other => panic!("expected subnet_route_config, got {}", other.event_type()),
    }
}

#[test]
fn the_report_ack_matches_the_pinned_json() {
    let ack = NodeSubnetRouteReportAck {
        accepted_route_ids: vec!["snr1-a".to_owned()],
        rejected_route_ids: vec!["snr1-b".to_owned()],
    };

    assert_eq!(serde_json::to_string(&ack).unwrap(), REPORT_ACK_JSON);
    assert_eq!(
        serde_json::from_str::<NodeSubnetRouteReportAck>("{}").unwrap(),
        NodeSubnetRouteReportAck::default()
    );
}

#[test]
fn the_subnet_route_shapes_round_trip_through_cbor() {
    let report_cbor = to_cbor(&fixture_report()).unwrap();
    assert_eq!(
        from_cbor::<NodeSubnetRouteReport>(&report_cbor).unwrap(),
        fixture_report()
    );

    let config_cbor = to_cbor(&fixture_config()).unwrap();
    assert_eq!(
        from_cbor::<SubnetRouteConfig>(&config_cbor).unwrap(),
        fixture_config()
    );
}

#[test]
fn the_report_envelope_api_id_is_pinned() {
    assert_eq!(
        envelope_api::NODE_SUBNET_ROUTES_REPORT,
        "node.subnet_routes.report.v1"
    );
}

#[test]
fn the_canonical_route_id_is_pinned_across_repositories() {
    assert_eq!(
        canonical_subnet_route_id(
            "realm-a",
            "machine-provider",
            "192.168.10.0/24".parse().unwrap()
        ),
        "snr1-89f1bf77cf5eebe2ddeb7706079e7b84"
    );
}

// ── capability vocabulary ────────────────────────────────────────────────────

#[test]
fn the_node_capability_tokens_are_pinned() {
    assert_eq!(
        NodeCapability::ALL.map(NodeCapability::as_str),
        [
            "node.consume-services.v1",
            "node.publish-services.v1",
            "node.advertise-subnet-routes.v1",
            "node.accept-subnet-routes.v1",
        ]
    );
}

#[test]
fn one_identity_can_advertise_consumer_and_provider_capabilities_together() {
    let advertised = [
        NodeCapability::ConsumeServices.as_str(),
        NodeCapability::PublishServices.as_str(),
        NodeCapability::AdvertiseSubnetRoutes.as_str(),
        NodeCapability::AcceptSubnetRoutes.as_str(),
    ];

    let resolved = recognized_node_capabilities(advertised);

    assert_eq!(resolved.len(), NodeCapability::ALL.len());
    for capability in NodeCapability::ALL {
        assert!(resolved.contains(&capability), "missing {capability:?}");
    }
}

#[test]
fn an_unknown_capability_neither_activates_a_role_nor_authorizes_a_route() {
    // An invented token resolves to nothing...
    let resolved = recognized_node_capabilities(["node.route-authority.v1", "node.approve.v1"]);
    assert!(resolved.is_empty());

    // ...and no capability, known or unknown, can produce an approved route.
    // Authority is a separate message that only NSD emits.
    let advertised = NodeSubnetRouteReport {
        generation: 3,
        routes: vec![NodeSubnetRouteAdvertisement {
            route_id: "snr1-self-approved".to_owned(),
            prefix: "192.168.77.0/24".parse().unwrap(),
            generation: 3,
            requested_forwarding: SubnetRouteForwardingMode::NoSnat,
        }],
    };
    let ranges = OverlayReservedRanges::new(
        "100.64.0.0/10".parse().unwrap(),
        "10.100.0.0/24".parse().unwrap(),
    );
    advertised.validate(&ranges).unwrap();

    // The advertisement is a distinct type from the projection; there is no
    // conversion from one to the other, and an empty projection authorizes
    // nothing regardless of what was advertised.
    let authorized = SubnetRouteConfig::default();
    assert!(authorized.routes.is_empty());
}

// ── machine.auth leg role ────────────────────────────────────────────────────

#[test]
fn a_legacy_auth_payload_is_unchanged_on_the_wire() {
    let legacy = r#"{"purpose":"wss"}"#;

    let decoded: AuthPayload = serde_json::from_str(legacy).unwrap();
    assert_eq!(decoded.purpose.as_deref(), Some("wss"));
    assert_eq!(decoded.leg_role, None);
    assert_eq!(serde_json::to_string(&decoded).unwrap(), legacy);
}

#[test]
fn a_leg_scoped_auth_payload_matches_its_pinned_json() {
    for (leg, pinned) in [
        (
            WssLegRole::Client,
            r#"{"purpose":"wss","leg_role":"client"}"#,
        ),
        (WssLegRole::Relay, r#"{"purpose":"wss","leg_role":"relay"}"#),
    ] {
        let payload = AuthPayload {
            purpose: Some("wss".to_owned()),
            leg_role: Some(leg),
        };
        assert_eq!(serde_json::to_string(&payload).unwrap(), pinned);

        let decoded: AuthPayload = serde_json::from_str(pinned).unwrap();
        assert_eq!(decoded.leg_role, Some(leg));
    }
}

#[test]
fn the_leg_role_tokens_match_the_gateway_session_roles() {
    // NSGW's `SessionRole::as_str` compares the minted token's `role` claim
    // against these exact strings.
    assert_eq!(WssLegRole::Client.as_str(), "client");
    assert_eq!(WssLegRole::Relay.as_str(), "relay");
    assert_eq!(WssLegRole::parse("client"), Some(WssLegRole::Client));
    assert_eq!(WssLegRole::parse("relay"), Some(WssLegRole::Relay));
    assert_eq!(WssLegRole::parse("gateway"), None);
    assert_eq!(WssLegRole::parse("Client"), None);
}

#[test]
fn a_leg_role_round_trips_through_cbor() {
    let payload = AuthPayload {
        purpose: Some("wss".to_owned()),
        leg_role: Some(WssLegRole::Relay),
    };

    let decoded: AuthPayload = from_cbor(&to_cbor(&payload).unwrap()).unwrap();
    assert_eq!(decoded.leg_role, Some(WssLegRole::Relay));
}

// ── additive compatibility for existing messages ─────────────────────────────

/// Decode a legacy payload and re-encode it; the bytes must be identical.
///
/// This is the byte-for-byte claim: nothing added by NODE-001 appears in the
/// output of a payload that predates it.
fn assert_legacy_json_round_trips<T>(legacy: &str)
where
    T: serde::Serialize + for<'de> Deserialize<'de>,
{
    let decoded: T = serde_json::from_str(legacy).unwrap();
    assert_eq!(serde_json::to_string(&decoded).unwrap(), legacy);
}

#[test]
fn a_legacy_service_routing_config_is_byte_identical() {
    assert_legacy_json_round_trips::<control::messages::RoutingConfig>(
        r#"{"routes":[{"domain":"web.n.ns","site":"site-a","service":"web","port":80}]}"#,
    );
}

#[test]
fn a_legacy_gateway_exit_service_route_is_byte_identical() {
    assert_legacy_json_round_trips::<control::messages::RouteEntry>(concat!(
        r#"{"domain":"exit.n.ns","site":"site-a","service":"exit","port":443,"#,
        r#""backend":{"gateway_exit":{"profile_ref":"corp-egress","#,
        r#""scope":{"cidrs":{"cidrs":["10.20.0.0/16"]}}}}}"#
    ));
}

#[test]
fn a_legacy_capture_route_is_byte_identical() {
    assert_legacy_json_round_trips::<control::messages::CaptureRoute>(concat!(
        r#"{"route_id":"capture-default","generation":42,"realm_id":"realm-a","#,
        r#""gateway_id":"gw-exit-a","profile_ref":"corp-egress","#,
        r#""destination_cidrs":["10.20.0.0/16"],"#,
        r#""source":{"address":"100.64.0.7","prefix_len":32},"#,
        r#""table_policy":{"table":{"dedicated":{"table_id":20100}},"priority":10100},"#,
        r#""kill_switch":"fail_closed"}"#
    ));
}

#[test]
fn a_legacy_gateway_egress_config_is_byte_identical() {
    assert_legacy_json_round_trips::<control::messages::GatewayEgressWgConfig>(concat!(
        r#"{"pairings":[{"realm_id":"realm-a","source_vip":"100.64.0.7","#,
        r#""service_vip":"100.64.1.9","protocol":"tcp","port":8443,"#,
        r#""service_ref":"svc-a","generation":5}]}"#
    ));
}

#[test]
fn a_legacy_direct_p2p_update_is_byte_identical() {
    assert_legacy_json_round_trips::<control::messages::PeerCandidatesUpdate>(concat!(
        r#"{"machine_id":"m-1","epoch":3,"#,
        r#""peer_key_pub":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=","#,
        r#""candidates":[{"kind":"host","endpoint":"192.0.2.10:51820","priority":100,"#,
        r#""observed_at_unix_ms":1700000000000}]}"#
    ));
}

#[test]
fn a_legacy_wss_relay_table_is_byte_identical() {
    assert_legacy_json_round_trips::<control::messages::GatewayWssRelayConfig>(concat!(
        r#"{"relay_pairs":[{"nsc_machine_id":"m-nsc","nsn_machine_id":"m-nsn","#,
        r#""nsc_pubkey":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","#,
        r#""nsn_pubkey":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="}]}"#
    ));
}

// ── pinned CBOR address encodings ────────────────────────────────────────────

/// Hex of the CBOR a `ControlMessage` carries for one address-shaped field.
///
/// Every address-shaped field on the config stream is a **CBOR text string**,
/// the same spelling JSON uses. It is not `ciborium`'s Rust-native form
/// (`{"V4": [[a,b,c,d], port]}` for a `SocketAddr`, a four-octet array for an
/// `Ipv4Addr`, `{"V4": [a,b,c,d,prefix]}` for an `IpNet`): `ControlMessage` is
/// internally tagged, and serde re-deserializes the variant through a
/// `ContentDeserializer` that always reports `is_human_readable() == true`, so
/// the native form is written and then rejected.
///
/// These are the literals `ns`, `nsd` and `nsgw` mirror. IPv6 in particular:
/// the bracketed `[addr]:port` spelling, and **no `%zone` suffix** — the zone
/// index is dropped on the way out, because the form this contract replaced
/// could not carry one.
fn cbor_hex<T: serde::Serialize>(value: &T) -> String {
    to_cbor(value)
        .unwrap()
        .iter()
        .fold(String::new(), |mut acc, byte| {
            use std::fmt::Write as _;
            let _ = write!(acc, "{byte:02x}");
            acc
        })
}

fn assert_cbor_carries_text(bytes: &[u8], text: &str) {
    let encoded = bytes.iter().fold(String::new(), |mut acc, byte| {
        use std::fmt::Write as _;
        let _ = write!(acc, "{byte:02x}");
        acc
    });
    let needle = text.as_bytes().iter().fold(String::new(), |mut acc, byte| {
        use std::fmt::Write as _;
        let _ = write!(acc, "{byte:02x}");
        acc
    });
    assert!(
        encoded.contains(&needle),
        "expected the CBOR text {text:?} in {encoded}"
    );
}

#[test]
fn the_control_message_address_fields_are_cbor_text_strings() {
    use std::net::{Ipv4Addr, SocketAddr};

    use control::messages::{
        ControlMessage, P2pCandidate, P2pCandidateKind, PeerCandidatesUpdate, PeerConfig, WgConfig,
    };

    let wg = ControlMessage::WgConfig(WgConfig {
        ip_address: Ipv4Addr::new(10, 0, 0, 1),
        listen_port: 51820,
        peers: vec![PeerConfig {
            public_key: [2u8; 32],
            endpoint: Some("198.51.100.7:51820".parse().unwrap()),
            allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
            persistent_keepalive: 25,
            wss_relay: None,
            wss_relay_fallback: None,
        }],
    });
    let bytes = to_cbor(&wg).unwrap();
    assert_cbor_carries_text(&bytes, "10.0.0.1");
    assert_cbor_carries_text(&bytes, "198.51.100.7:51820");
    assert_cbor_carries_text(&bytes, "10.0.0.0/24");
    // The Rust-native `Ipv4Addr` form is a four-octet array, `84 0a 00 00 01`.
    assert!(
        !cbor_hex(&wg).contains("840a000001"),
        "the native octet-array form must not reach the wire"
    );

    let candidates = ControlMessage::PeerCandidates(PeerCandidatesUpdate {
        machine_id: "m-1".to_owned(),
        epoch: 3,
        peer_key_pub: [2u8; 32],
        candidates: vec![
            P2pCandidate {
                kind: P2pCandidateKind::Host,
                endpoint: "192.0.2.10:51820".parse().unwrap(),
                priority: 100,
                observed_at_unix_ms: 1_700_000_000_000,
                source: None,
                relay_url: None,
            },
            P2pCandidate {
                kind: P2pCandidateKind::ServerReflexive,
                endpoint: "[2001:db8::10]:51820".parse().unwrap(),
                priority: 90,
                observed_at_unix_ms: 1_700_000_000_000,
                source: None,
                relay_url: None,
            },
        ],
    });
    let bytes = to_cbor(&candidates).unwrap();
    assert_cbor_carries_text(&bytes, "192.0.2.10:51820");
    assert_cbor_carries_text(&bytes, "[2001:db8::10]:51820");
    // `a1 62 5634` is `{"V4": ...` — serde's native `SocketAddr` map.
    assert!(
        !cbor_hex(&candidates).contains("a1625634"),
        "the native SocketAddr enum-map form must not reach the wire"
    );

    let decoded: ControlMessage = from_cbor(&bytes).unwrap();
    match decoded {
        ControlMessage::PeerCandidates(update) => {
            assert_eq!(
                update.candidates[1].endpoint,
                "[2001:db8::10]:51820".parse::<SocketAddr>().unwrap()
            );
        }
        other => panic!("expected peer_candidates, got {}", other.event_type()),
    }
}

/// `peer_candidates.report` is the one hop whose bytes this contract moved.
///
/// It is raw `ciborium` on both ends, so unlike the config stream the shape a
/// producer writes is the shape a consumer must read. A consumer that predates
/// this contract expects the native enum map here and will reject the string —
/// **deploy the consumer before the producer**. New consumers read both.
#[test]
fn the_peer_candidates_report_endpoint_is_a_cbor_text_string() {
    use control::messages::{P2pCandidate, P2pCandidateKind, PeerCandidatesReport};

    let report = PeerCandidatesReport {
        epoch: 7,
        peer_key_pub: [3u8; 32],
        candidates: vec![P2pCandidate {
            kind: P2pCandidateKind::ServerReflexive,
            endpoint: "192.0.2.10:51820".parse().unwrap(),
            priority: 100,
            observed_at_unix_ms: 1_700_000_000_000,
            source: None,
            relay_url: None,
        }],
    };
    let bytes = to_cbor(&report).unwrap();
    assert_cbor_carries_text(&bytes, "192.0.2.10:51820");
    assert_eq!(from_cbor::<PeerCandidatesReport>(&bytes).unwrap(), report);
    assert_eq!(
        envelope_api::PEER_CANDIDATES_REPORT,
        "peer_candidates.report"
    );
}

/// The `ControlMessage` shape a pre-NODE-001 consumer compiled against: it
/// knows nothing about `subnet_route_config.v1` and falls back on
/// `#[serde(other)]`.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum PreNodeControlMessage {
    Ping,
    Pong,
    #[serde(other)]
    Unknown,
}

#[test]
fn an_older_consumer_decodes_the_new_message_as_unknown() {
    // Forward compatibility: the new tag must not poison an old consumer's
    // stream, it must land on the catch-all.
    let decoded: PreNodeControlMessage =
        serde_json::from_str(SUBNET_ROUTE_CONFIG_MESSAGE_JSON).unwrap();
    assert!(matches!(decoded, PreNodeControlMessage::Unknown));

    // And the reverse still holds after the variant was added: a tag this
    // build does not know still decodes to `Unknown`.
    let future: ControlMessage =
        serde_json::from_str(r#"{"type":"subnet_route_config.v2","generation":1}"#).unwrap();
    assert!(matches!(future, ControlMessage::Unknown));
}
