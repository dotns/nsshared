use keynet_proto::{
    AcknowledgedControlType, BindingControl, CONTROL_RETRANSMISSION_SECONDS, CONTROL_VERSION,
    ControlDecodeError, ControlEncodeError, ControlRecord, ControlType,
    DEFAULT_NEW_BINDING_LIFETIME_SECONDS, DEFAULT_RELAY_SESSIONS_PER_NODE,
    DEFAULT_ROTATION_LEAD_SECONDS, EndpointCandidate, EndpointHint, EndpointKind,
    EndpointRevisionError, IN_BAND_CONTROL_PORT, INITIAL_ENDPOINT_REVISION, LegacyEndpoints,
    MAX_CONTROL_DATAGRAM_BYTES, MAX_CURRENT_BINDING_IMPORT_BYTES, MAX_ENDPOINT_CANDIDATES,
    MAX_ENDPOINT_RELAYS, MAX_LIVE_PROBES_PER_NODE, MAX_LIVE_PROBES_PER_PEER,
    MAX_UNACKNOWLEDGED_CONTROL_RECORDS, MIN_BINDING_REMAINING_AT_CUTOVER_SECONDS,
    MIN_PREVIOUS_BINDING_OVERLAP_SECONDS, MIN_ROTATION_LEAD_SECONDS, OLD_DATA_KEY_GRACE_SECONDS,
    ObservedAddr, OrderedEndpoints, PROBE_CANDIDATE_INTERVAL_MS, PROBE_NONCE_BYTES,
    PROBE_REPLIES_PER_SECOND_PER_NODE, PROBE_REPLIES_PER_SECOND_PER_PEER,
    PROBE_REPLY_BURST_PER_NODE, PROBE_REPLY_BURST_PER_PEER, PROBE_REQUEST_BURST_PER_NODE,
    PROBE_REQUEST_DEADLINE_MS, PROBE_REQUESTS_PER_SECOND, PROBE_ROUND_SECONDS, RelayIdentifier,
    control_ack_hash, next_endpoint_revision, select_ordered_endpoints, sort_endpoint_candidates,
};
use std::collections::BTreeMap;

const CONTROL_VECTORS: &str = include_str!("fixtures/keynet-v1/control_records.vec");
const IDENTIFIER_VECTORS: &str = include_str!("fixtures/keynet-v1/relay_identifiers.vec");

fn hex_bytes(input: &str) -> Vec<u8> {
    assert_eq!(input.len() % 2, 0);
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).expect("fixture hex is ASCII");
            u8::from_str_radix(text, 16).expect("fixture hex is valid")
        })
        .collect()
}

fn vectors() -> BTreeMap<&'static str, Vec<u8>> {
    CONTROL_VECTORS
        .lines()
        .filter(|line| !line.starts_with('#') && !line.is_empty())
        .map(|line| {
            let (name, value) = line.split_once('|').expect("fixture line has separator");
            (name, hex_bytes(value))
        })
        .collect()
}

fn candidate(address: ObservedAddr, kind: EndpointKind) -> EndpointCandidate {
    EndpointCandidate { address, kind }
}

fn maximum_authority(label: char) -> String {
    format!(
        "{}.{}.{}.{}:1",
        label.to_string().repeat(63),
        label.to_string().repeat(63),
        label.to_string().repeat(63),
        label.to_string().repeat(61)
    )
}

#[test]
fn all_eight_records_match_independent_literal_bytes() {
    let values = vectors();
    let cases = [
        ("ack", ControlType::Ack),
        ("legacy_endpoints", ControlType::Endpoints),
        ("binding", ControlType::Binding),
        ("revocation", ControlType::Revocation),
        ("name", ControlType::Name),
        ("ordered_endpoints", ControlType::OrderedEndpoints),
        ("probe_request", ControlType::ProbeRequest),
        ("probe_reply", ControlType::ProbeReply),
    ];
    for (name, message_type) in cases {
        let decoded = ControlRecord::decode(&values[name]).expect("literal record decodes");
        assert_eq!(decoded.message_type(), message_type);
        assert_eq!(decoded.encode(), Ok(values[name].clone()));
    }
    let ControlRecord::Ack(ack) = ControlRecord::decode(&values["ack"]).expect("ACK") else {
        panic!("expected ACK");
    };
    assert_eq!(ack.type_in, AcknowledgedControlType::OrderedEndpoints);
    assert_eq!(ack.hash.as_slice(), values["ordered_hash"]);
    assert_eq!(ack.hash, control_ack_hash(&values["ordered_endpoints"]));
    let ControlRecord::Binding(binding) =
        ControlRecord::decode(&values["binding"]).expect("BINDING")
    else {
        panic!("expected BINDING");
    };
    assert_eq!(binding.cutover, binding.binding.not_before);
    let ControlRecord::Endpoints(legacy) =
        ControlRecord::decode(&values["legacy_endpoints"]).expect("legacy ENDPOINTS")
    else {
        panic!("expected legacy ENDPOINTS");
    };
    assert_eq!(legacy.relays, ["Relay.EXAMPLE:443/Path"]);
    assert!(RelayIdentifier::parse(&legacy.relays[0]).is_err());
}

#[test]
fn relay_identifier_and_endpoint_vectors_are_strict() {
    for line in IDENTIFIER_VECTORS
        .lines()
        .filter(|line| !line.starts_with('#') && !line.is_empty())
    {
        let mut fields = line.split('|');
        let kind = fields.next().expect("kind");
        let _case = fields.next().expect("case");
        let input = fields.next().expect("input");
        let expected = fields.next().expect("expected");
        assert!(fields.next().is_none());
        match kind {
            "relay" => assert_eq!(
                RelayIdentifier::parse(input).map(|value| value.to_string()),
                Ok(expected.to_owned())
            ),
            "endpoint" => assert_eq!(
                EndpointHint::parse(input).map(|value| value.to_string()),
                Ok(expected.to_owned())
            ),
            "local" => {
                assert_eq!(
                    RelayIdentifier::canonicalize(input).map(|value| value.to_string()),
                    Ok(expected.to_owned())
                );
                assert!(RelayIdentifier::parse(input).is_err());
            }
            "invalid" => {
                assert_eq!(expected, "error");
                if _case == "site_local_ipv6" {
                    assert!(RelayIdentifier::parse(input).is_err());
                    assert!(EndpointHint::parse(input).is_err());
                    assert!(RelayIdentifier::canonicalize(input).is_err());
                    assert!(EndpointHint::canonicalize(input).is_err());
                } else if line.contains("short_endpoint") {
                    assert!(EndpointHint::parse(input).is_err());
                } else {
                    assert!(RelayIdentifier::parse(input).is_err());
                }
            }
            _ => panic!("unknown fixture kind"),
        }
    }
}

#[test]
fn identifier_length_label_port_and_address_boundaries_are_exact() {
    assert!(RelayIdentifier::parse(&"a".repeat(63)).is_ok());
    assert!(RelayIdentifier::parse(&"a".repeat(64)).is_err());
    for value in [
        "a:1",
        "a:65535",
        "127.0.0.1:1",
        "10.0.0.1:65535",
        "[fc00::1]:1",
        "[::1]:1",
    ] {
        assert!(RelayIdentifier::parse(value).is_ok(), "{value}");
        assert!(EndpointHint::parse(value).is_ok(), "{value}");
    }
    for value in [
        "a:0",
        "a:65536",
        "a:01",
        "169.254.1.1:1",
        "224.0.0.1:1",
        "1.2.3:1",
        "[2001:0db8::1]:1",
    ] {
        assert!(RelayIdentifier::parse(value).is_err(), "{value}");
    }
    assert!(RelayIdentifier::parse(&format!("{}.b:1", "a".repeat(63))).is_ok());
    assert!(RelayIdentifier::parse(&format!("{}.b:1", "a".repeat(64))).is_err());
    let maximum_dns = format!(
        "{}.{}.{}.{}:1",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61)
    );
    assert_eq!(maximum_dns.len(), 255);
    assert_eq!(
        RelayIdentifier::canonicalize(&maximum_dns.replacen(":1", ".:1", 1))
            .map(|value| value.to_string()),
        Ok(maximum_dns)
    );
    assert_eq!(
        EndpointHint::canonicalize("[FC00:0:0:0:0:0:0:1]:1").map(|value| value.to_string()),
        Ok("[fc00::1]:1".to_owned())
    );
}

#[test]
fn decoder_rejects_outer_schema_versions_types_widths_and_trailing_data() {
    let values = vectors();
    let mut value = values["ack"].clone();
    value[1] = 2;
    assert_eq!(
        ControlRecord::decode(&value),
        Err(ControlDecodeError::UnsupportedVersion)
    );
    value = values["ack"].clone();
    value[2] = 8;
    assert_eq!(
        ControlRecord::decode(&value),
        Err(ControlDecodeError::UnsupportedType)
    );
    value = values["ack"].clone();
    value[0] = 0x82;
    assert!(ControlRecord::decode(&value).is_err());
    value = values["ack"].clone();
    value.splice(1..2, [0x18, 0x01]);
    assert!(ControlRecord::decode(&value).is_err());
    value = values["probe_request"].clone();
    value[5] = 31;
    assert_eq!(
        ControlRecord::decode(&value),
        Err(ControlDecodeError::InvalidBody)
    );
    value = values["ack"].clone();
    value.push(0);
    assert_eq!(
        ControlRecord::decode(&value),
        Err(ControlDecodeError::NonCanonical)
    );
    assert_eq!(
        ControlRecord::decode(&[]),
        Err(ControlDecodeError::InvalidLength)
    );
    assert_eq!(
        ControlRecord::decode(&vec![0; MAX_CONTROL_DATAGRAM_BYTES + 1]),
        Err(ControlDecodeError::InvalidLength)
    );
}

#[test]
fn body_enums_counts_ports_binding_equality_and_order_are_enforced() {
    let values = vectors();
    let ControlRecord::Binding(binding) =
        ControlRecord::decode(&values["binding"]).expect("binding")
    else {
        panic!("expected binding");
    };
    assert_eq!(
        ControlRecord::Binding(BindingControl {
            cutover: 2,
            ..binding
        })
        .encode(),
        Err(ControlEncodeError::InvalidBody)
    );
    let base = candidate(ObservedAddr::V4([1, 2, 3, 4], 1), EndpointKind::Configured);
    assert_eq!(
        ControlRecord::Endpoints(LegacyEndpoints {
            candidates: vec![base; MAX_ENDPOINT_CANDIDATES + 1],
            relays: Vec::new()
        })
        .encode(),
        Err(ControlEncodeError::InvalidBody)
    );
    assert_eq!(
        ControlRecord::Endpoints(LegacyEndpoints {
            candidates: Vec::new(),
            relays: vec!["r".to_owned(); MAX_ENDPOINT_RELAYS + 1]
        })
        .encode(),
        Err(ControlEncodeError::InvalidBody)
    );
    assert_eq!(
        ControlRecord::Endpoints(LegacyEndpoints {
            candidates: vec![candidate(
                ObservedAddr::V4([1, 2, 3, 4], 0),
                EndpointKind::Configured
            )],
            relays: Vec::new()
        })
        .encode(),
        Err(ControlEncodeError::InvalidBody)
    );
    assert_eq!(
        ControlRecord::OrderedEndpoints(OrderedEndpoints {
            revision: 1,
            candidates: vec![
                candidate(ObservedAddr::V6([0; 16], 1), EndpointKind::Configured),
                base
            ],
            relays: Vec::new()
        })
        .encode(),
        Err(ControlEncodeError::InvalidBody)
    );
    assert_eq!(
        ControlRecord::OrderedEndpoints(OrderedEndpoints {
            revision: 0,
            candidates: Vec::new(),
            relays: Vec::new()
        })
        .encode(),
        Err(ControlEncodeError::InvalidBody)
    );
    let mut invalid_kind = values["legacy_endpoints"].clone();
    let index = invalid_kind
        .windows(3)
        .position(|window| window == [1, 1, 0])
        .expect("kind bytes")
        + 2;
    invalid_kind[index] = 3;
    assert_eq!(
        ControlRecord::decode(&invalid_kind),
        Err(ControlDecodeError::InvalidBody)
    );
    assert_eq!(
        ControlRecord::decode(&[0x83, 0x01, 0x01, 0x82, 0x89]),
        Err(ControlDecodeError::InvalidBody)
    );
    let mut invalid_ack_type = values["ack"].clone();
    invalid_ack_type[4] = 6;
    assert_eq!(
        ControlRecord::decode(&invalid_ack_type),
        Err(ControlDecodeError::InvalidBody)
    );
    let mut noncanonical_relay = values["ordered_endpoints"].clone();
    let relay = noncanonical_relay
        .windows(b"relay.example:443".len())
        .position(|window| window == b"relay.example:443")
        .expect("ordered relay");
    noncanonical_relay[relay] = b'R';
    assert_eq!(
        ControlRecord::decode(&noncanonical_relay),
        Err(ControlDecodeError::InvalidBody)
    );
    let site_local_relay = hex_bytes("830105830180816b5b666563303a3a315d3a31");
    assert_eq!(
        ControlRecord::decode(&site_local_relay),
        Err(ControlDecodeError::InvalidBody)
    );
}

#[test]
fn canonical_selection_orders_deduplicates_and_applies_caps() {
    let v4_low = candidate(ObservedAddr::V4([1, 1, 1, 1], 9), EndpointKind::Reflected);
    let v4_kind = candidate(ObservedAddr::V4([1, 1, 1, 1], 9), EndpointKind::Configured);
    let v6 = candidate(ObservedAddr::V6([0; 16], 1), EndpointKind::LocalInterface);
    let mut candidates = vec![v6, v4_kind, v4_low];
    sort_endpoint_candidates(&mut candidates);
    assert_eq!(candidates, [v4_low, v4_kind, v6]);
    let home = RelayIdentifier::parse("relay-z").expect("relay");
    let selection = select_ordered_endpoints(
        1,
        &[v6, v4_kind, v4_low, v4_low],
        &[
            RelayIdentifier::parse("relay-b").expect("relay"),
            home.clone(),
            RelayIdentifier::parse("relay-a").expect("relay"),
            RelayIdentifier::parse("relay-c").expect("relay"),
            RelayIdentifier::parse("relay-d").expect("relay"),
        ],
        Some(&home),
    )
    .expect("selection");
    assert_eq!(selection.snapshot.candidates, [v4_low, v4_kind, v6]);
    assert_eq!(
        selection
            .snapshot
            .relays
            .iter()
            .map(RelayIdentifier::as_str)
            .collect::<Vec<_>>(),
        ["relay-z", "relay-a", "relay-b", "relay-c"]
    );
    assert_eq!(
        (selection.omitted_candidates, selection.omitted_relays),
        (0, 1)
    );
    assert!(
        ControlRecord::OrderedEndpoints(selection.snapshot)
            .encode()
            .expect("bounded")
            .len()
            <= MAX_CONTROL_DATAGRAM_BYTES
    );
}

#[test]
fn relay_selection_skips_oversized_entries_and_continues_in_canonical_order() {
    let values = vectors();
    let candidates = (1..=8)
        .map(|suffix| {
            let mut ip = [0; 16];
            ip[..4].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
            ip[15] = suffix;
            candidate(ObservedAddr::V6(ip, u16::MAX), EndpointKind::Configured)
        })
        .collect::<Vec<_>>();
    let relays = ['d', 'z', 'c', 'b', 'a', 'd']
        .into_iter()
        .map(|label| {
            let text = if label == 'z' {
                "z".to_owned()
            } else {
                maximum_authority(label)
            };
            RelayIdentifier::parse(&text).expect("valid relay fixture")
        })
        .collect::<Vec<_>>();
    let selection = select_ordered_endpoints(1, &candidates, &relays, None).expect("selection");
    assert_eq!(
        selection
            .snapshot
            .relays
            .iter()
            .map(RelayIdentifier::as_str)
            .collect::<Vec<_>>(),
        [
            maximum_authority('a'),
            maximum_authority('b'),
            maximum_authority('c'),
            "z".to_owned(),
        ]
    );
    assert_eq!(
        selection.omitted_relays,
        usize::from(values["greedy_omitted_relays"][0])
    );
    assert_eq!(
        ControlRecord::OrderedEndpoints(selection.snapshot).encode(),
        Ok(values["greedy_ordered_endpoints"].clone())
    );
}

#[test]
fn exact_record_and_nonce_limits_are_enforced() {
    let legacy = ControlRecord::Endpoints(LegacyEndpoints {
        candidates: Vec::new(),
        relays: vec!["x".repeat(255); 4],
    });
    assert!(legacy.encode().expect("four legacy names fit").len() <= MAX_CONTROL_DATAGRAM_BYTES);
    let oversized = ControlRecord::Endpoints(LegacyEndpoints {
        candidates: vec![candidate(ObservedAddr::V6([1; 16], 65_535), EndpointKind::Configured); 8],
        relays: vec!["x".repeat(255); 4],
    });
    assert_eq!(
        oversized.encode(),
        Err(ControlEncodeError::DatagramTooLarge)
    );
    assert_eq!(
        ControlRecord::ProbeRequest([7; 32])
            .encode()
            .expect("nonce")
            .len(),
        38
    );
}

#[test]
fn version_seven_constants_and_revision_edges_are_exact() {
    assert_eq!(CONTROL_VERSION, 1);
    assert_eq!(IN_BAND_CONTROL_PORT, 47_900);
    assert_eq!(
        (
            MAX_CONTROL_DATAGRAM_BYTES,
            MAX_ENDPOINT_CANDIDATES,
            MAX_ENDPOINT_RELAYS
        ),
        (1_200, 8, 4)
    );
    assert_eq!(MAX_UNACKNOWLEDGED_CONTROL_RECORDS, 4);
    assert_eq!(CONTROL_RETRANSMISSION_SECONDS, [1, 2, 4]);
    assert_eq!(DEFAULT_RELAY_SESSIONS_PER_NODE, 8);
    assert_eq!((INITIAL_ENDPOINT_REVISION, PROBE_NONCE_BYTES), (1, 32));
    assert_eq!(
        (
            PROBE_REQUEST_DEADLINE_MS,
            PROBE_CANDIDATE_INTERVAL_MS,
            PROBE_ROUND_SECONDS
        ),
        (1_000, 250, 30)
    );
    assert_eq!(
        (MAX_LIVE_PROBES_PER_PEER, MAX_LIVE_PROBES_PER_NODE),
        (8, 4_096)
    );
    assert_eq!(
        (PROBE_REQUESTS_PER_SECOND, PROBE_REQUEST_BURST_PER_NODE),
        (256, 256)
    );
    assert_eq!(
        (
            PROBE_REPLIES_PER_SECOND_PER_PEER,
            PROBE_REPLY_BURST_PER_PEER
        ),
        (32, 32)
    );
    assert_eq!(
        (
            PROBE_REPLIES_PER_SECOND_PER_NODE,
            PROBE_REPLY_BURST_PER_NODE
        ),
        (256, 256)
    );
    assert_eq!(
        (MIN_ROTATION_LEAD_SECONDS, DEFAULT_ROTATION_LEAD_SECONDS),
        (300, 300)
    );
    assert_eq!(DEFAULT_NEW_BINDING_LIFETIME_SECONDS, 2_592_000);
    assert_eq!(MIN_BINDING_REMAINING_AT_CUTOVER_SECONDS, 600);
    assert_eq!(MIN_PREVIOUS_BINDING_OVERLAP_SECONDS, 240);
    assert_eq!(OLD_DATA_KEY_GRACE_SECONDS, 0);
    assert_eq!(MAX_CURRENT_BINDING_IMPORT_BYTES, 512);
    assert_eq!(next_endpoint_revision(None), Ok(1));
    assert_eq!(
        next_endpoint_revision(Some(0)),
        Err(EndpointRevisionError::InvalidCurrent)
    );
    assert_eq!(next_endpoint_revision(Some(1)), Ok(2));
    assert_eq!(
        next_endpoint_revision(Some(u64::MAX)),
        Err(EndpointRevisionError::Exhausted)
    );
}
