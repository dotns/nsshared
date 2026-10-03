//! In-tunnel control channel: quick-v2 §9 and the inherited quick-protocol §12.7 rules.

#![allow(clippy::unwrap_used, clippy::panic, reason = "test fixture helpers")]

use ed25519_dalek::SigningKey;
use nsshared_wire::{
    Ack, AckedType, CONTROL_PORT, CborError, ControlError, ControlMessage, ControlReceiveError,
    ControlType, DIRECT_LOSS_SECONDS, EndpointAcceptance, EndpointCandidate, EndpointKind,
    EndpointRevisionExhausted, EndpointState, Endpoints, MAX_CONTROL_MESSAGE_BYTES,
    MAX_ENDPOINT_CANDIDATES, MAX_ENDPOINT_RELAYS, NodeRecord, NodeRecordError, NodeRecordFields,
    PROBE_CANDIDATE_INTERVAL_MS, PROBE_DEADLINE_MS, PROBE_ROUND_SECONDS, ProbeAttempt,
    ProbeMismatch, ProbeReplyObservation, RecordDecision, RecordMarks, RelayId, RelayIdError,
    accept_endpoints, ack_hash, next_endpoint_revision, receive_record, select_endpoints,
};
use proptest::prelude::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

fn signer(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn relay(text: &str) -> RelayId {
    RelayId::parse(text).unwrap()
}

/// A 255-byte relay identifier whose first label starts with `first`.
fn long_relay(first: char) -> RelayId {
    let label = "q".repeat(62);
    let text = format!("{first}{label}.{label}q.{label}q.{}:51822", "q".repeat(57));
    assert_eq!(text.len(), 255);
    relay(&text)
}

fn v4(octets: [u8; 4], port: u16, kind: EndpointKind) -> EndpointCandidate {
    EndpointCandidate {
        ip: IpAddr::V4(Ipv4Addr::from(octets)),
        port,
        kind,
    }
}

fn v6(octets: [u8; 16], port: u16, kind: EndpointKind) -> EndpointCandidate {
    EndpointCandidate {
        ip: IpAddr::V6(Ipv6Addr::from(octets)),
        port,
        kind,
    }
}

fn record(key: &SigningKey, generation: u64, wg: u8, issued_at: u64) -> NodeRecord {
    NodeRecord::sign(
        key,
        NodeRecordFields {
            wg_key: [wg; 32],
            generation,
            issued_at,
            expires: issued_at + 86_400,
            relays: vec![relay("hkg-a1.relay.ns.io:51822")],
        },
    )
    .unwrap()
}

fn record_datagram(record: &NodeRecord) -> Vec<u8> {
    ControlMessage::Record(record.clone()).encode().unwrap()
}

fn endpoints_datagram(revision: u64, candidates: Vec<EndpointCandidate>) -> Vec<u8> {
    ControlMessage::Endpoints(Endpoints {
        revision,
        candidates,
        relays: vec![],
    })
    .encode()
    .unwrap()
}

/// `[2, 1, [revision, candidates, relays]]` with raw candidate and relay items.
fn raw_endpoints(revision: &[u8], candidates: &[&[u8]], relays: &[&[u8]]) -> Vec<u8> {
    let mut out = vec![0x83, 0x02, 0x01, 0x83];
    out.extend_from_slice(revision);
    out.push(0x80 | u8::try_from(candidates.len()).unwrap());
    for candidate in candidates {
        out.extend_from_slice(candidate);
    }
    out.push(0x80 | u8::try_from(relays.len()).unwrap());
    for relay in relays {
        out.extend_from_slice(relay);
    }
    out
}

fn text_item(text: &str) -> Vec<u8> {
    let mut out = vec![0x60 | u8::try_from(text.len()).unwrap()];
    out.extend_from_slice(text.as_bytes());
    out
}

const V4_CANDIDATE: &[u8] = &[0x83, 0x44, 192, 0, 2, 1, 0x19, 0x01, 0xbb, 0x00];

#[test]
fn constants_match_the_spec() {
    assert_eq!(CONTROL_PORT, 47_900);
    assert_eq!(MAX_CONTROL_MESSAGE_BYTES, 1_200);
    assert_eq!(PROBE_CANDIDATE_INTERVAL_MS, 250);
    assert_eq!(PROBE_DEADLINE_MS, 1_000);
    assert_eq!(PROBE_ROUND_SECONDS, 30);
    assert_eq!(DIRECT_LOSS_SECONDS, 15);
}

#[test]
fn exact_encodings() {
    let ack = ControlMessage::Ack(Ack {
        type_in: AckedType::Record,
        hash: [7; 16],
    });
    let mut expected = vec![0x83, 0x02, 0x00, 0x82, 0x02, 0x50];
    expected.extend_from_slice(&[7; 16]);
    assert_eq!(ack.encode().unwrap(), expected);

    let probe = ControlMessage::ProbeReply([9; 32]);
    let mut expected = vec![0x83, 0x02, 0x04, 0x81, 0x58, 0x20];
    expected.extend_from_slice(&[9; 32]);
    assert_eq!(probe.encode().unwrap(), expected);

    let endpoints = endpoints_datagram(1, vec![v4([192, 0, 2, 1], 443, EndpointKind::Local)]);
    assert_eq!(endpoints, raw_endpoints(&[0x01], &[V4_CANDIDATE], &[]));
    assert_eq!(
        ControlMessage::decode(&endpoints).unwrap().message_type(),
        ControlType::Endpoints
    );

    let key = signer(1);
    let record = record(&key, 1, 1, 1_000);
    let datagram = record_datagram(&record);
    assert_eq!(datagram[..4], [0x83, 0x02, 0x02, 0x81]);
    assert_eq!(&datagram[4..], record.as_bytes());
    assert_eq!(
        ControlMessage::decode(&datagram).unwrap(),
        ControlMessage::Record(record)
    );
}

#[test]
fn ack_hash_is_unkeyed_blake2s_128_of_the_datagram() {
    // RFC 7693 style check: BLAKE2s-128 of the empty input.
    let empty = ack_hash(&[]);
    assert_eq!(
        empty,
        [
            0x64, 0x55, 0x0d, 0x6f, 0xfe, 0x2c, 0x0a, 0x01, 0xa1, 0x4a, 0xba, 0x1e, 0xad, 0xe0,
            0x20, 0x0c
        ]
    );
    let datagram = endpoints_datagram(3, vec![]);
    let ack = Ack::for_datagram(AckedType::Endpoints, &datagram);
    assert_eq!(ack.hash, ack_hash(&datagram));
    assert!(ack.acknowledges(AckedType::Endpoints, &datagram));
    assert!(!ack.acknowledges(AckedType::Record, &datagram));
    assert!(!ack.acknowledges(AckedType::Endpoints, &endpoints_datagram(4, vec![])));
}

#[test]
fn refutation_oversize_datagram() {
    let input = vec![0; MAX_CONTROL_MESSAGE_BYTES + 1];
    assert_eq!(
        ControlMessage::decode(&input),
        Err(ControlError::TooLarge(1_201))
    );
}

#[test]
fn refutation_non_canonical_cbor() {
    let input = raw_endpoints(&[0x18, 0x01], &[], &[]);
    assert_eq!(
        ControlMessage::decode(&input),
        Err(ControlError::Cbor(CborError::NonShortest))
    );
    let indefinite = [0x9f, 0x02, 0x03, 0x81, 0x40, 0xff];
    assert_eq!(
        ControlMessage::decode(&indefinite),
        Err(ControlError::Cbor(CborError::IndefiniteLength))
    );
}

#[test]
fn refutation_version() {
    for version in [0x01, 0x03] {
        let mut input = endpoints_datagram(1, vec![]);
        input[1] = version;
        assert_eq!(
            ControlMessage::decode(&input),
            Err(ControlError::Version(u64::from(version)))
        );
    }
}

#[test]
fn refutation_unknown_type() {
    let input = [0x83, 0x02, 0x05, 0x81, 0x00];
    assert_eq!(
        ControlMessage::decode(&input),
        Err(ControlError::UnknownType(5))
    );
}

#[test]
fn refutation_wrong_arity() {
    assert_eq!(
        ControlMessage::decode(&[0x82, 0x02, 0x03]),
        Err(ControlError::Cbor(CborError::ArrayLength {
            expected: 3,
            actual: 2
        }))
    );
    let mut ack = vec![0x83, 0x02, 0x00, 0x83, 0x01, 0x50];
    ack.extend_from_slice(&[0; 16]);
    ack.push(0x00);
    assert_eq!(
        ControlMessage::decode(&ack),
        Err(ControlError::Cbor(CborError::ArrayLength {
            expected: 2,
            actual: 3
        }))
    );
    let mut probe = vec![0x83, 0x02, 0x03, 0x82, 0x58, 0x20];
    probe.extend_from_slice(&[0; 32]);
    probe.push(0x00);
    assert!(matches!(
        ControlMessage::decode(&probe),
        Err(ControlError::Cbor(CborError::ArrayLength { .. }))
    ));
    let candidate = [0x82, 0x44, 192, 0, 2, 1, 0x19, 0x01, 0xbb];
    assert!(matches!(
        ControlMessage::decode(&raw_endpoints(&[0x01], &[&candidate], &[])),
        Err(ControlError::Cbor(CborError::ArrayLength { .. }))
    ));
}

#[test]
fn refutation_trailing_bytes() {
    for message in [
        ControlMessage::ProbeRequest([1; 32]),
        ControlMessage::Ack(Ack {
            type_in: AckedType::Endpoints,
            hash: [0; 16],
        }),
    ] {
        let mut input = message.encode().unwrap();
        input.push(0x00);
        assert_eq!(
            ControlMessage::decode(&input),
            Err(ControlError::Cbor(CborError::TrailingBytes))
        );
    }
    let mut input = endpoints_datagram(1, vec![]);
    input.push(0x00);
    assert_eq!(
        ControlMessage::decode(&input),
        Err(ControlError::Cbor(CborError::TrailingBytes))
    );
    let mut input = record_datagram(&record(&signer(1), 1, 1, 1_000));
    input.push(0x00);
    assert_eq!(
        ControlMessage::decode(&input),
        Err(ControlError::Record(NodeRecordError::Cbor(
            CborError::TrailingBytes
        )))
    );
}

#[test]
fn refutation_ack_type_in() {
    for type_in in [0x00, 0x03, 0x04] {
        let mut input = vec![0x83, 0x02, 0x00, 0x82, type_in, 0x50];
        input.extend_from_slice(&[0; 16]);
        assert_eq!(
            ControlMessage::decode(&input),
            Err(ControlError::AckType(u64::from(type_in)))
        );
    }
}

#[test]
fn refutation_ack_hash_length() {
    let mut input = vec![0x83, 0x02, 0x00, 0x82, 0x01, 0x4f];
    input.extend_from_slice(&[0; 15]);
    assert!(matches!(
        ControlMessage::decode(&input),
        Err(ControlError::Cbor(CborError::StringLength {
            expected: 16,
            actual: 15
        }))
    ));
}

#[test]
fn refutation_probe_nonce_length() {
    let mut input = vec![0x83, 0x02, 0x04, 0x81, 0x58, 0x1f];
    input.extend_from_slice(&[0; 31]);
    assert!(matches!(
        ControlMessage::decode(&input),
        Err(ControlError::Cbor(CborError::StringLength {
            expected: 32,
            actual: 31
        }))
    ));
}

#[test]
fn refutation_zero_revision() {
    assert_eq!(
        ControlMessage::decode(&raw_endpoints(&[0x00], &[], &[])),
        Err(ControlError::ZeroRevision)
    );
    let message = ControlMessage::Endpoints(Endpoints {
        revision: 0,
        candidates: vec![],
        relays: vec![],
    });
    assert_eq!(message.encode(), Err(ControlError::ZeroRevision));
    assert_eq!(
        select_endpoints(0, &[], &[], None),
        Err(ControlError::ZeroRevision)
    );
}

#[test]
fn refutation_candidate_ip_length() {
    for length in [0_u8, 3, 5, 15, 17] {
        let mut candidate = vec![0x83, 0x40 | length];
        candidate.extend(std::iter::repeat_n(1, usize::from(length)));
        candidate.extend_from_slice(&[0x19, 0x01, 0xbb, 0x00]);
        assert_eq!(
            ControlMessage::decode(&raw_endpoints(&[0x01], &[&candidate], &[])),
            Err(ControlError::CandidateIpLength(usize::from(length)))
        );
    }
}

#[test]
fn refutation_candidate_port() {
    let zero = [0x83, 0x44, 192, 0, 2, 1, 0x00, 0x00];
    assert_eq!(
        ControlMessage::decode(&raw_endpoints(&[0x01], &[&zero], &[])),
        Err(ControlError::CandidatePort(0))
    );
    let large = [0x83, 0x44, 192, 0, 2, 1, 0x1a, 0x00, 0x01, 0x00, 0x00, 0x00];
    assert_eq!(
        ControlMessage::decode(&raw_endpoints(&[0x01], &[&large], &[])),
        Err(ControlError::CandidatePort(65_536))
    );
    let candidate = v4([192, 0, 2, 1], 0, EndpointKind::Local);
    assert_eq!(
        ControlMessage::Endpoints(Endpoints {
            revision: 1,
            candidates: vec![candidate],
            relays: vec![],
        })
        .encode(),
        Err(ControlError::CandidatePort(0))
    );
    assert_eq!(
        select_endpoints(1, &[candidate], &[], None),
        Err(ControlError::CandidatePort(0))
    );
}

#[test]
fn refutation_candidate_kind() {
    let candidate = [0x83, 0x44, 192, 0, 2, 1, 0x19, 0x01, 0xbb, 0x03];
    assert_eq!(
        ControlMessage::decode(&raw_endpoints(&[0x01], &[&candidate], &[])),
        Err(ControlError::CandidateKind(3))
    );
}

#[test]
fn refutation_too_many_candidates() {
    let candidates: Vec<Vec<u8>> = (1..=9_u8)
        .map(|last| vec![0x83, 0x44, 192, 0, 2, last, 0x19, 0x01, 0xbb, 0x00])
        .collect();
    let items: Vec<&[u8]> = candidates.iter().map(Vec::as_slice).collect();
    assert_eq!(
        ControlMessage::decode(&raw_endpoints(&[0x01], &items, &[])),
        Err(ControlError::TooManyCandidates(9))
    );
    let message = ControlMessage::Endpoints(Endpoints {
        revision: 1,
        candidates: (1..=9)
            .map(|last| v4([192, 0, 2, last], 443, EndpointKind::Local))
            .collect(),
        relays: vec![],
    });
    assert_eq!(message.encode(), Err(ControlError::TooManyCandidates(9)));
}

#[test]
fn refutation_too_many_relays() {
    let texts: Vec<Vec<u8>> = ["a.io:1", "b.io:1", "c.io:1", "d.io:1", "e.io:1"]
        .iter()
        .map(|text| text_item(text))
        .collect();
    let items: Vec<&[u8]> = texts.iter().map(Vec::as_slice).collect();
    assert_eq!(
        ControlMessage::decode(&raw_endpoints(&[0x01], &[], &items)),
        Err(ControlError::TooManyRelays(5))
    );
    let message = ControlMessage::Endpoints(Endpoints {
        revision: 1,
        candidates: vec![],
        relays: ["a.io:1", "b.io:1", "c.io:1", "d.io:1", "e.io:1"]
            .map(relay)
            .to_vec(),
    });
    assert_eq!(message.encode(), Err(ControlError::TooManyRelays(5)));
}

#[test]
fn refutation_invalid_relay_identifier() {
    let item = text_item("Relay.io:1");
    assert_eq!(
        ControlMessage::decode(&raw_endpoints(&[0x01], &[], &[&item])),
        Err(ControlError::RelayId(RelayIdError::DnsName))
    );
}

#[test]
fn refutation_oversize_endpoints_encoding() {
    let message = ControlMessage::Endpoints(Endpoints {
        revision: u64::MAX,
        candidates: (1..=8)
            .map(|last| v6([last; 16], 443, EndpointKind::Local))
            .collect(),
        relays: ['a', 'b', 'c', 'd'].map(long_relay).to_vec(),
    });
    assert!(matches!(message.encode(), Err(ControlError::TooLarge(length)) if length > 1_200));
}

#[test]
fn refutation_candidate_order() {
    let low = [0x83, 0x44, 192, 0, 2, 1, 0x19, 0x01, 0xbb, 0x00];
    let high = [0x83, 0x44, 192, 0, 2, 2, 0x19, 0x01, 0xbb, 0x00];
    for items in [[&high[..], &low[..]], [&low[..], &low[..]]] {
        assert_eq!(
            ControlMessage::decode(&raw_endpoints(&[0x01], &items, &[])),
            Err(ControlError::CandidateOrder)
        );
    }
    // IPv4 sorts before IPv6 regardless of bytes.
    let message = ControlMessage::Endpoints(Endpoints {
        revision: 1,
        candidates: vec![
            v6([0; 16], 1, EndpointKind::Local),
            v4([255; 4], 1, EndpointKind::Local),
        ],
        relays: vec![],
    });
    assert_eq!(message.encode(), Err(ControlError::CandidateOrder));
}

#[test]
fn refutation_relay_order() {
    let a = text_item("a.io:1");
    let b = text_item("b.io:1");
    let c = text_item("c.io:1");
    // The first relay may be out of order (home relay), the rest must be ascending.
    assert!(ControlMessage::decode(&raw_endpoints(&[0x01], &[], &[&c, &a, &b])).is_ok());
    for items in [[&a, &c, &b], [&a, &b, &b], [&b, &a, &b]] {
        let items: Vec<&[u8]> = items.iter().map(|item| item.as_slice()).collect();
        assert_eq!(
            ControlMessage::decode(&raw_endpoints(&[0x01], &[], &items)),
            Err(ControlError::RelayOrder)
        );
    }
}

#[test]
fn refutation_invalid_nested_record() {
    let mut input = record_datagram(&record(&signer(1), 1, 1, 1_000));
    let last = input.len() - 1;
    input[last] ^= 1;
    assert_eq!(
        ControlMessage::decode(&input),
        Err(ControlError::Record(NodeRecordError::BadSignature))
    );
    assert_eq!(
        receive_record(
            &RecordMarks::new(signer(1).verifying_key().to_bytes()),
            &input
        ),
        Err(ControlReceiveError::Malformed(ControlError::Record(
            NodeRecordError::BadSignature
        )))
    );
}

#[test]
fn refutation_record_wrong_identity() {
    let datagram = record_datagram(&record(&signer(2), 1, 1, 1_000));
    let peer = RecordMarks::new(signer(1).verifying_key().to_bytes());
    assert_eq!(
        receive_record(&peer, &datagram),
        Err(ControlReceiveError::PeerIdentity)
    );
}

#[test]
fn refutation_unexpected_message_type() {
    let probe = ControlMessage::ProbeRequest([0; 32]).encode().unwrap();
    let peer = RecordMarks::new(signer(1).verifying_key().to_bytes());
    assert_eq!(
        receive_record(&peer, &probe),
        Err(ControlReceiveError::UnexpectedType(
            ControlType::ProbeRequest
        ))
    );
    let record = record_datagram(&record(&signer(1), 1, 1, 1_000));
    assert_eq!(
        accept_endpoints(None, &record),
        Err(ControlReceiveError::UnexpectedType(ControlType::Record))
    );
}

#[test]
fn record_handling_follows_section_3_3() {
    let key = signer(1);
    let mut peer = RecordMarks::new(key.verifying_key().to_bytes());
    let first = record_datagram(&record(&key, 2, 1, 1_000));

    let receipt = receive_record(&peer, &first).unwrap();
    assert_eq!(receipt.decision, RecordDecision::Advanced);
    assert!(receipt.ack.unwrap().acknowledges(AckedType::Record, &first));
    assert_eq!(peer.committed_gen(), 0, "receive_record is pure");
    peer.apply(&receipt.record).unwrap();

    let receipt = receive_record(&peer, &first).unwrap();
    assert_eq!(receipt.decision, RecordDecision::Unchanged);
    assert!(receipt.ack.is_some());

    let refresh = record_datagram(&record(&key, 2, 1, 2_000));
    let receipt = receive_record(&peer, &refresh).unwrap();
    assert_eq!(receipt.decision, RecordDecision::Refreshed);
    assert!(receipt.ack.is_some());
}

#[test]
fn refutation_record_stale_gets_no_ack() {
    let key = signer(1);
    let mut peer = RecordMarks::new(key.verifying_key().to_bytes());
    peer.apply(&record(&key, 2, 1, 1_000)).unwrap();
    let receipt = receive_record(&peer, &record_datagram(&record(&key, 1, 1, 5_000))).unwrap();
    assert_eq!(receipt.decision, RecordDecision::Stale);
    assert_eq!(receipt.ack, None);
}

#[test]
fn refutation_record_conflict_gets_no_ack() {
    let key = signer(1);
    let mut peer = RecordMarks::new(key.verifying_key().to_bytes());
    peer.apply(&record(&key, 2, 1, 1_000)).unwrap();
    let receipt = receive_record(&peer, &record_datagram(&record(&key, 2, 9, 5_000))).unwrap();
    assert_eq!(receipt.decision, RecordDecision::Conflict);
    assert_eq!(receipt.ack, None);
}

fn replaced(datagram: &[u8]) -> EndpointState {
    match accept_endpoints(None, datagram).unwrap() {
        EndpointAcceptance::Replaced { state, ack, .. } => {
            assert!(ack.acknowledges(AckedType::Endpoints, datagram));
            state
        }
        other => panic!("expected Replaced, got {other:?}"),
    }
}

#[test]
fn endpoints_first_snapshot_is_accepted() {
    let datagram = endpoints_datagram(5, vec![v4([192, 0, 2, 1], 443, EndpointKind::Local)]);
    let state = replaced(&datagram);
    assert_eq!(state.revision, 5);
    assert_eq!(state.snapshot_hash, ack_hash(&datagram));
}

#[test]
fn refutation_endpoints_lower_revision_is_ignored() {
    let state = replaced(&endpoints_datagram(5, vec![]));
    let acceptance = accept_endpoints(Some(&state), &endpoints_datagram(4, vec![])).unwrap();
    assert_eq!(acceptance, EndpointAcceptance::Stale);
    assert_eq!(acceptance.ack(), None);
}

#[test]
fn endpoints_same_revision_same_bytes_is_idempotent() {
    let datagram = endpoints_datagram(5, vec![v4([192, 0, 2, 1], 443, EndpointKind::Local)]);
    let state = replaced(&datagram);
    let acceptance = accept_endpoints(Some(&state), &datagram).unwrap();
    let EndpointAcceptance::Duplicate { endpoints, ack } = &acceptance else {
        panic!("expected Duplicate, got {acceptance:?}");
    };
    assert_eq!(endpoints.revision, 5);
    assert!(ack.acknowledges(AckedType::Endpoints, &datagram));
}

#[test]
fn refutation_endpoints_same_revision_different_bytes_conflicts() {
    let state = replaced(&endpoints_datagram(5, vec![]));
    let other = endpoints_datagram(5, vec![v4([192, 0, 2, 1], 443, EndpointKind::Local)]);
    let acceptance = accept_endpoints(Some(&state), &other).unwrap();
    assert_eq!(acceptance, EndpointAcceptance::Conflict);
    assert_eq!(acceptance.ack(), None);
}

#[test]
fn endpoints_higher_revision_replaces_with_empty_lists() {
    let state = replaced(&endpoints_datagram(
        5,
        vec![v4([192, 0, 2, 1], 443, EndpointKind::Local)],
    ));
    let withdrawal = endpoints_datagram(6, vec![]);
    let acceptance = accept_endpoints(Some(&state), &withdrawal).unwrap();
    let EndpointAcceptance::Replaced {
        endpoints,
        state,
        ack,
    } = acceptance
    else {
        panic!("expected Replaced");
    };
    assert!(endpoints.candidates.is_empty() && endpoints.relays.is_empty());
    assert_eq!(state.revision, 6);
    assert_eq!(state.snapshot_hash, ack_hash(&withdrawal));
    assert!(ack.acknowledges(AckedType::Endpoints, &withdrawal));
}

#[test]
fn refutation_endpoints_malformed_gets_no_ack() {
    assert_eq!(
        accept_endpoints(None, &raw_endpoints(&[0x00], &[], &[])),
        Err(ControlReceiveError::Malformed(ControlError::ZeroRevision))
    );
}

#[test]
fn endpoint_revisions_start_at_one_and_increase() {
    assert_eq!(next_endpoint_revision(None), Ok(1));
    assert_eq!(next_endpoint_revision(Some(1)), Ok(2));
    assert_eq!(next_endpoint_revision(Some(u64::MAX - 1)), Ok(u64::MAX));
}

#[test]
fn refutation_endpoint_revision_exhausted() {
    assert_eq!(
        next_endpoint_revision(Some(u64::MAX)),
        Err(EndpointRevisionExhausted)
    );
}

#[test]
fn selection_orders_dedupes_and_puts_the_home_relay_first() {
    let candidates = [
        v6([1; 16], 1, EndpointKind::Local),
        v4([10, 0, 0, 2], 1, EndpointKind::Local),
        v4([10, 0, 0, 1], 2, EndpointKind::Local),
        v4([10, 0, 0, 1], 1, EndpointKind::Configured),
        v4([10, 0, 0, 1], 1, EndpointKind::Reflected),
        v4([10, 0, 0, 1], 1, EndpointKind::Reflected),
    ];
    let relays = ["c.io:1", "a.io:1", "b.io:1", "a.io:1"].map(relay);
    let home = relay("c.io:1");
    let selection = select_endpoints(7, &candidates, &relays, Some(&home)).unwrap();
    assert_eq!(
        selection.endpoints.candidates,
        [
            v4([10, 0, 0, 1], 1, EndpointKind::Reflected),
            v4([10, 0, 0, 1], 1, EndpointKind::Configured),
            v4([10, 0, 0, 1], 2, EndpointKind::Local),
            v4([10, 0, 0, 2], 1, EndpointKind::Local),
            v6([1; 16], 1, EndpointKind::Local),
        ]
    );
    assert_eq!(
        selection.endpoints.relays,
        ["c.io:1", "a.io:1", "b.io:1"].map(relay)
    );
    assert!(selection.omitted_candidates.is_empty() && selection.omitted_relays.is_empty());
    assert_eq!(
        ControlMessage::decode(&selection.datagram).unwrap(),
        ControlMessage::Endpoints(selection.endpoints.clone())
    );

    // An inactive or unlisted home relay does not reorder.
    let selection = select_endpoints(7, &[], &relays, Some(&relay("z.io:1"))).unwrap();
    assert_eq!(
        selection.endpoints.relays,
        ["a.io:1", "b.io:1", "c.io:1"].map(relay)
    );
}

#[test]
fn selection_skips_relays_that_do_not_fit_and_keeps_scanning() {
    let candidates: Vec<_> = (1..=8)
        .map(|last| v6([last; 16], 443, EndpointKind::Local))
        .collect();
    let relays = [
        long_relay('a'),
        long_relay('b'),
        long_relay('c'),
        long_relay('d'),
        relay("z.io:1"),
    ];
    let selection = select_endpoints(u64::MAX, &candidates, &relays, None).unwrap();
    assert_eq!(selection.endpoints.candidates.len(), 8);
    assert_eq!(
        selection.endpoints.relays,
        [
            long_relay('a'),
            long_relay('b'),
            long_relay('c'),
            relay("z.io:1")
        ]
    );
    assert_eq!(selection.omitted_relays, [long_relay('d')]);
    assert!(selection.datagram.len() <= MAX_CONTROL_MESSAGE_BYTES);
}

#[test]
fn selection_reports_entries_beyond_the_count_limits() {
    let candidates: Vec<_> = (1..=10)
        .map(|last| v4([10, 0, 0, last], 1, EndpointKind::Local))
        .collect();
    let relays = ["a.io:1", "b.io:1", "c.io:1", "d.io:1", "e.io:1", "f.io:1"].map(relay);
    let selection = select_endpoints(1, &candidates, &relays, None).unwrap();
    assert_eq!(selection.endpoints.candidates, candidates[..8]);
    assert_eq!(selection.omitted_candidates, candidates[8..]);
    assert_eq!(selection.endpoints.relays, relays[..4]);
    assert_eq!(selection.omitted_relays, relays[4..]);
}

fn attempt() -> ProbeAttempt {
    ProbeAttempt {
        peer: [1; 32],
        session: 7,
        candidate: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 51_820),
        nonce: [9; 32],
        sent_at_ms: 10_000,
    }
}

fn reply() -> ProbeReplyObservation {
    let attempt = attempt();
    ProbeReplyObservation {
        peer: attempt.peer,
        session: attempt.session,
        source: attempt.candidate,
        nonce: attempt.nonce,
        received_at_ms: 10_999,
    }
}

#[test]
fn probe_reply_correlates_before_the_deadline() {
    assert_eq!(attempt().deadline_ms(), 11_000);
    assert_eq!(attempt().correlate(&reply()), Ok(()));
}

#[test]
fn refutation_probe_reply_mismatches() {
    let attempt = attempt();
    let cases = [
        (
            ProbeReplyObservation {
                peer: [2; 32],
                ..reply()
            },
            ProbeMismatch::Peer,
        ),
        (
            ProbeReplyObservation {
                session: 8,
                ..reply()
            },
            ProbeMismatch::Session,
        ),
        (
            ProbeReplyObservation {
                source: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 51_821),
                ..reply()
            },
            ProbeMismatch::Source,
        ),
        (
            ProbeReplyObservation {
                nonce: [8; 32],
                ..reply()
            },
            ProbeMismatch::Nonce,
        ),
        (
            ProbeReplyObservation {
                received_at_ms: 11_000,
                ..reply()
            },
            ProbeMismatch::Deadline,
        ),
    ];
    for (reply, expected) in cases {
        assert_eq!(attempt.correlate(&reply), Err(expected));
    }
}

fn candidate_strategy() -> impl Strategy<Value = EndpointCandidate> {
    let kind = prop_oneof![
        Just(EndpointKind::Local),
        Just(EndpointKind::Reflected),
        Just(EndpointKind::Configured)
    ];
    let ip = prop_oneof![
        any::<[u8; 4]>().prop_map(|octets| IpAddr::V4(Ipv4Addr::from(octets))),
        any::<[u8; 16]>().prop_map(|octets| IpAddr::V6(Ipv6Addr::from(octets))),
    ];
    (ip, 1..=u16::MAX, kind).prop_map(|(ip, port, kind)| EndpointCandidate { ip, port, kind })
}

fn relay_strategy() -> impl Strategy<Value = RelayId> {
    (
        prop::collection::vec("[a-z][a-z0-9]{0,62}", 1..=4),
        1..=u16::MAX,
    )
        .prop_filter_map("relay identifier too long", |(labels, port)| {
            RelayId::parse(&format!("{}:{port}", labels.join("."))).ok()
        })
}

fn selection_input() -> impl Strategy<Value = (u64, Vec<EndpointCandidate>, Vec<RelayId>, usize)> {
    (
        1..=u64::MAX,
        prop::collection::vec(candidate_strategy(), 0..=12),
        prop::collection::vec(relay_strategy(), 0..=7),
        any::<usize>(),
    )
}

proptest! {
    #[test]
    fn ack_round_trips(record_type in any::<bool>(), hash in any::<[u8; 16]>()) {
        let type_in = if record_type { AckedType::Record } else { AckedType::Endpoints };
        let message = ControlMessage::Ack(Ack { type_in, hash });
        let encoded = message.encode().unwrap();
        prop_assert_eq!(ControlMessage::decode(&encoded).unwrap(), message);
    }

    #[test]
    fn probes_round_trip(nonce in any::<[u8; 32]>(), reply in any::<bool>()) {
        let message = if reply {
            ControlMessage::ProbeReply(nonce)
        } else {
            ControlMessage::ProbeRequest(nonce)
        };
        let encoded = message.encode().unwrap();
        prop_assert_eq!(ControlMessage::decode(&encoded).unwrap(), message);
    }

    #[test]
    fn records_round_trip(
        seed in any::<u8>(),
        generation in 1..=u64::MAX,
        issued_at in 0..u64::MAX,
        period in 1..=604_800_u64,
        relays in prop::collection::vec(relay_strategy(), 0..=1),
    ) {
        let fields = NodeRecordFields {
            wg_key: [seed; 32],
            generation,
            issued_at,
            expires: issued_at.saturating_add(period).max(issued_at + 1),
            relays,
        };
        let record = NodeRecord::sign(&signer(seed), fields).unwrap();
        let message = ControlMessage::Record(record);
        let encoded = message.encode().unwrap();
        prop_assert!(encoded.len() <= MAX_CONTROL_MESSAGE_BYTES);
        prop_assert_eq!(ControlMessage::decode(&encoded).unwrap(), message);
    }

    #[test]
    fn selection_round_trips_fits_and_respects_limits(
        (revision, candidates, relays, home) in selection_input()
    ) {
        let home = relays.get(home % relays.len().max(1)).cloned();
        let selection = select_endpoints(revision, &candidates, &relays, home.as_ref()).unwrap();
        prop_assert!(selection.datagram.len() <= MAX_CONTROL_MESSAGE_BYTES);
        prop_assert!(selection.endpoints.candidates.len() <= MAX_ENDPOINT_CANDIDATES);
        prop_assert!(selection.endpoints.relays.len() <= MAX_ENDPOINT_RELAYS);
        let message = ControlMessage::Endpoints(selection.endpoints.clone());
        prop_assert_eq!(message.encode().unwrap(), selection.datagram.clone());
        prop_assert_eq!(ControlMessage::decode(&selection.datagram).unwrap(), message);

        // Selected and omitted entries partition the deduplicated input.
        let mut unique = candidates.clone();
        unique.sort_by_key(|c| (c.ip.is_ipv6(), c.ip, c.port, c.kind));
        unique.dedup();
        prop_assert_eq!(
            selection.endpoints.candidates.len() + selection.omitted_candidates.len(),
            unique.len()
        );
        let mut unique = relays.clone();
        unique.sort();
        unique.dedup();
        prop_assert_eq!(
            selection.endpoints.relays.len() + selection.omitted_relays.len(),
            unique.len()
        );
        if let (Some(home), Some(first)) = (&home, selection.endpoints.relays.first()) {
            prop_assert_eq!(home, first);
        }
    }

    #[test]
    fn selection_is_independent_of_input_order(
        ((revision, candidates, relays, home), shuffled_candidates, shuffled_relays) in
            selection_input().prop_flat_map(|input| {
                let mut candidates = input.1.clone();
                candidates.extend(input.1.iter().take(3).copied());
                let mut relays = input.2.clone();
                relays.extend(input.2.iter().take(2).cloned());
                (
                    Just(input),
                    Just(candidates).prop_shuffle(),
                    Just(relays).prop_shuffle(),
                )
            })
    ) {
        let home = relays.get(home % relays.len().max(1)).cloned();
        let original = select_endpoints(revision, &candidates, &relays, home.as_ref()).unwrap();
        let shuffled = select_endpoints(
            revision,
            &shuffled_candidates,
            &shuffled_relays,
            home.as_ref(),
        )
        .unwrap();
        prop_assert_eq!(original, shuffled);
    }

    #[test]
    fn endpoints_decode_never_panics(input in prop::collection::vec(any::<u8>(), 0..64)) {
        let mut datagram = vec![0x83, 0x02, 0x01];
        datagram.extend_from_slice(&input);
        let _ = ControlMessage::decode(&datagram);
    }
}
