//! Generated in-tunnel control message vectors (quick-v2 §9, §12.1, §12.3).

#![allow(clippy::unwrap_used, clippy::panic, reason = "test fixture helpers")]

mod support;

use ns_wire::{
    Ack, AckedType, CborError, ControlError, ControlMessage, EndpointCandidate, EndpointKind,
    Endpoints, NodeRecord, NodeRecordError, RelayId, ack_hash,
};
use std::net::{IpAddr, Ipv6Addr};
use support::vectors::{Vector, decode_hex, load};

fn count(v: &Vector, key: &str) -> usize {
    usize::try_from(v.u64(key)).unwrap()
}

fn candidates(v: &Vector) -> Vec<EndpointCandidate> {
    let ips = v.all("candidate_ip");
    let ports = v.all("candidate_port");
    let kinds = v.all("candidate_kind");
    assert_eq!(ips.len(), count(v, "candidate_count"));
    assert!(ports.len() == ips.len() && kinds.len() == ips.len());
    ips.iter()
        .zip(ports)
        .zip(kinds)
        .map(|((ip, port), kind)| {
            let ip = match decode_hex(ip).unwrap().as_slice() {
                &[a, b, c, d] => IpAddr::from([a, b, c, d]),
                bytes => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(bytes).unwrap())),
            };
            EndpointCandidate {
                ip,
                port: port.parse().unwrap(),
                kind: match kind {
                    "0" => EndpointKind::Local,
                    "1" => EndpointKind::Reflected,
                    "2" => EndpointKind::Configured,
                    other => panic!("{}: kind {other}", v.name()),
                },
            }
        })
        .collect()
}

fn acked_type(value: u64) -> AckedType {
    match value {
        1 => AckedType::Endpoints,
        2 => AckedType::Record,
        other => panic!("type_in {other}"),
    }
}

/// Builds the typed message of a positive vector.
fn build(v: &Vector) -> ControlMessage {
    match v.u64("type") {
        0 => ControlMessage::Ack(Ack {
            type_in: acked_type(v.u64("type_in")),
            hash: v.hex_array("hash"),
        }),
        1 => {
            let relays = v.all("relay");
            assert_eq!(relays.len(), count(v, "relay_count"));
            ControlMessage::Endpoints(Endpoints {
                revision: v.u64("revision"),
                candidates: candidates(v),
                relays: relays.iter().map(|r| RelayId::parse(r).unwrap()).collect(),
            })
        }
        2 => ControlMessage::Record(NodeRecord::decode(&v.hex("record")).unwrap()),
        3 => ControlMessage::ProbeRequest(v.hex_array("nonce")),
        4 => ControlMessage::ProbeReply(v.hex_array("nonce")),
        other => panic!("{}: type {other}", v.name()),
    }
}

#[test]
fn control_messages_match_vectors() {
    let vectors = load("control_messages");
    let mut types = Vec::new();
    for v in vectors.iter().filter(|v| !v.is_reject()) {
        let name = v.name();
        let message = build(v);
        let datagram = v.hex("datagram");
        assert_eq!(datagram.len(), count(v, "datagram_len"), "{name}");

        // Encode equals the fixture; decode then re-encode equals the fixture.
        assert_eq!(message.encode().unwrap(), datagram, "{name}");
        let decoded = ControlMessage::decode(&datagram).unwrap();
        assert_eq!(decoded, message, "{name}");
        assert_eq!(decoded.encode().unwrap(), datagram, "{name}");

        if let Some(hash) = v.opt("ack_hash") {
            assert_eq!(
                ack_hash(&datagram).as_slice(),
                decode_hex(hash).unwrap(),
                "{name}"
            );
        }
        if let ControlMessage::Ack(ack) = &message {
            let acked = v.hex("acked");
            assert_eq!(ack_hash(&acked), ack.hash, "{name}");
            assert!(ack.acknowledges(ack.type_in, &acked), "{name}");
            assert_eq!(Ack::for_datagram(ack.type_in, &acked), *ack, "{name}");
        }
        types.push(v.u64("type"));
    }
    types.sort_unstable();
    types.dedup();
    assert_eq!(types, [0, 1, 2, 3, 4]);
}

#[test]
fn rejected_control_messages_match_vectors() {
    let vectors = load("control_messages");
    let mut negatives = 0;
    for v in vectors.iter().filter(|v| v.is_reject()) {
        negatives += 1;
        let error = ControlMessage::decode(&v.hex("datagram")).unwrap_err();
        let matched = match v.reason() {
            "too_large" => matches!(error, ControlError::TooLarge(_)),
            "trailing_bytes" => error == ControlError::Cbor(CborError::TrailingBytes),
            "non_canonical" | "schema" => matches!(error, ControlError::Cbor(_)),
            "version" => matches!(error, ControlError::Version(_)),
            "unknown_type" => matches!(error, ControlError::UnknownType(_)),
            "ack_type" => matches!(error, ControlError::AckType(_)),
            "zero_revision" => error == ControlError::ZeroRevision,
            "too_many_candidates" => error == ControlError::TooManyCandidates(9),
            "too_many_relays" => error == ControlError::TooManyRelays(5),
            "candidate_ip_length" => matches!(error, ControlError::CandidateIpLength(_)),
            "candidate_port" => matches!(error, ControlError::CandidatePort(_)),
            "candidate_kind" => matches!(error, ControlError::CandidateKind(_)),
            "candidate_order" => error == ControlError::CandidateOrder,
            "relay_order" => error == ControlError::RelayOrder,
            "relay_id" => matches!(error, ControlError::RelayId(_)),
            "record" => matches!(
                error,
                ControlError::Record(
                    NodeRecordError::BadSignature | NodeRecordError::Cbor(CborError::TrailingBytes)
                )
            ),
            other => panic!("{}: unknown reason {other}", v.name()),
        };
        assert!(matched, "{}: {error:?}", v.name());
    }
    assert!(negatives >= 25);
}
