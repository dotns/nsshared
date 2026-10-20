//! Consumer checks ported from node revision 50f8e3fd95fac8bbc72aea9b132459103c3b206a.
#![allow(clippy::unwrap_used)]
use nsshared_proto::{IdentitySecret, record::NodeRecordFields};

use nsshared_proto::node_control::*;
use nsshared_proto::{
    NodeRecord, RelayId,
    encoding::{CborError, CborWriter},
    record::NodeRecordError,
};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};

pub(crate) fn record(seed: u8, generation: u64) -> NodeRecord {
    let secret = IdentitySecret::from_seed([seed; 32]);
    NodeRecord::sign(
        secret.signing_key(),
        NodeRecordFields {
            wg_key: [generation as u8; 32],
            generation,
            issued_at: 1_000 + generation,
            expires: 2_000 + generation,
            relays: vec![RelayId::parse("relay.example:443").unwrap()],
        },
    )
    .unwrap()
}

fn endpoints() -> Endpoints {
    Endpoints {
        revision: 7,
        candidates: vec![
            Candidate {
                addr: "192.0.2.1:51820".parse().unwrap(),
                kind: CandidateKind::Local,
            },
            Candidate {
                addr: "[2001:db8::1]:4500".parse().unwrap(),
                kind: CandidateKind::Reflected,
            },
        ],
        relays: vec![RelayId::parse("relay.example:443").unwrap()],
    }
}

fn all() -> Vec<Message> {
    vec![
        Message::Ack {
            type_in: kind::ENDPOINTS,
            hash: [3; 16],
        },
        Message::Endpoints(endpoints()),
        Message::Record(record(1, 1)),
        Message::ProbeRequest([4; 32]),
        Message::ProbeReply([5; 32]),
    ]
}

#[test]
fn control_codec_round_trips() {
    for message in all() {
        let bytes = message.encode().unwrap();
        assert_eq!(Message::decode(&bytes).unwrap(), message);
    }
}

#[test]
fn control_codec_known_bytes() {
    let bytes = Message::ProbeReply([0xaa; 32]).encode().unwrap();
    let mut expected = vec![0x83, 0x02, 0x04, 0x81, 0x58, 0x20];
    expected.extend_from_slice(&[0xaa; 32]);
    assert_eq!(bytes, expected);
    let ack = Message::Ack {
        type_in: 2,
        hash: [0; 16],
    }
    .encode()
    .unwrap();
    assert_eq!(&ack[..6], &[0x83, 0x02, 0x00, 0x82, 0x02, 0x50]);
}

#[test]
fn control_codec_rejects_unknown_version_and_type() {
    let mut bytes = Message::ProbeRequest([1; 32]).encode().unwrap();
    bytes[1] = 0x01;
    assert_eq!(Message::decode(&bytes), Err(CodecError::Version(1)));
    bytes[1] = 0x02;
    bytes[2] = 0x05;
    assert_eq!(Message::decode(&bytes), Err(CodecError::Type(5)));
}

#[test]
fn control_codec_rejects_trailing_bytes() {
    for message in all() {
        let mut bytes = message.encode().unwrap();
        bytes.push(0);
        assert_eq!(
            Message::decode(&bytes),
            Err(CodecError::Cbor(CborError::TrailingBytes))
        );
    }
}

#[test]
fn control_codec_rejects_non_canonical() {
    // Version 2 written with a one-byte head.
    let mut bytes = vec![0x83, 0x18, 0x02];
    bytes.extend_from_slice(&Message::ProbeRequest([1; 32]).encode().unwrap()[2..]);
    assert_eq!(
        Message::decode(&bytes),
        Err(CodecError::Cbor(CborError::NonShortest))
    );
    // Indefinite-length outer array.
    let mut bytes = Message::ProbeRequest([1; 32]).encode().unwrap();
    bytes[0] = 0x9f;
    assert!(matches!(Message::decode(&bytes), Err(CodecError::Cbor(_))));
    // A truncated message.
    let bytes = Message::Endpoints(endpoints()).encode().unwrap();
    assert!(Message::decode(&bytes[..bytes.len() - 1]).is_err());
    // A nonce of the wrong length.
    let mut bytes = vec![0x83, 0x02, 0x03, 0x81, 0x58, 0x1f];
    bytes.extend_from_slice(&[0; 31]);
    assert!(matches!(
        Message::decode(&bytes),
        Err(CodecError::Cbor(CborError::StringLength { .. }))
    ));
}

#[test]
fn control_codec_rejects_oversize() {
    let mut bytes = Message::ProbeRequest([1; 32]).encode().unwrap();
    bytes.resize(MAX_MESSAGE_BYTES + 1, 0);
    assert_eq!(
        Message::decode(&bytes),
        Err(CodecError::TooLarge(MAX_MESSAGE_BYTES + 1))
    );
}

#[test]
fn control_codec_rejects_bad_endpoints() {
    let mut too_many = endpoints();
    too_many.candidates = vec![too_many.candidates[0]; MAX_CANDIDATES + 1];
    assert_eq!(
        Message::Endpoints(too_many).encode(),
        Err(CodecError::TooMany)
    );
    let mut zero = endpoints();
    zero.candidates[0].addr.set_port(0);
    assert_eq!(
        Message::Endpoints(zero).encode(),
        Err(CodecError::Candidate)
    );
    // An IP of 5 bytes.
    let mut writer = CborWriter::default();
    writer.array(3).uint(2).uint(1).array(3).uint(1).array(1);
    writer.array(3).bytes(&[1; 5]).uint(1).uint(0).array(0);
    assert_eq!(
        Message::decode(&writer.into_bytes()),
        Err(CodecError::Candidate)
    );
}

#[test]
fn control_codec_rejects_tampered_record() {
    let mut bytes = Message::Record(record(1, 1)).encode().unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    assert!(matches!(
        Message::decode(&bytes),
        Err(CodecError::Record(NodeRecordError::BadSignature))
    ));
}

#[test]
fn control_ack_hash_is_unkeyed_blake2s_128() {
    // BLAKE2s-128 of the empty input.
    assert_eq!(
        ack_hash(b""),
        [
            0x64, 0x55, 0x0d, 0x6f, 0xfe, 0x2c, 0x0a, 0x01, 0xa1, 0x4a, 0xba, 0x1e, 0xad, 0xe0,
            0x20, 0x0c
        ]
    );
}

#[test]
fn control_endpoints_select_is_canonical() {
    let v6 = Candidate {
        addr: "[2001:db8::1]:1".parse().unwrap(),
        kind: CandidateKind::Local,
    };
    let v4b = Candidate {
        addr: "192.0.2.2:1".parse().unwrap(),
        kind: CandidateKind::Local,
    };
    let v4a = Candidate {
        addr: "192.0.2.1:2".parse().unwrap(),
        kind: CandidateKind::Configured,
    };
    let relay = |text: &str| RelayId::parse(text).unwrap();
    let home = relay("z.example:443");
    let (snapshot, omitted) = Endpoints::select(
        3,
        Some(&home),
        &[v6, v4b, v4a, v4b],
        &[
            relay("b.example:443"),
            home.clone(),
            relay("a.example:443"),
            relay("c.example:443"),
            relay("d.example:443"),
        ],
    );
    assert_eq!(snapshot.candidates, vec![v4a, v4b, v6]);
    assert_eq!(
        snapshot.relays,
        vec![
            home,
            relay("a.example:443"),
            relay("b.example:443"),
            relay("c.example:443")
        ]
    );
    assert_eq!(omitted, 1);
    assert!(Message::Endpoints(snapshot).encode().is_ok());
}

#[test]
fn control_selection_respects_byte_budget_and_omits_unique_entries() {
    let candidates: Vec<_> = (1..=9)
        .map(|last| Candidate {
            addr: SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, last)),
                65535,
            ),
            kind: CandidateKind::Configured,
        })
        .collect();
    let relays: Vec<_> = (0..4)
        .map(|index| {
            RelayId::parse(&format!(
                "{}.{}.{}.{}.r{index}:443",
                "a".repeat(63),
                "b".repeat(63),
                "c".repeat(63),
                "d".repeat(53)
            ))
            .unwrap()
        })
        .collect();
    let too_large = Endpoints {
        revision: u64::MAX,
        candidates: candidates[..8].to_vec(),
        relays: relays.clone(),
    };
    assert!(matches!(
        Message::Endpoints(too_large).encode(),
        Err(CodecError::TooLarge(_))
    ));
    let (snapshot, omitted) = Endpoints::select(u64::MAX, Some(&relays[3]), &candidates, &relays);
    assert_eq!(snapshot.candidates.len(), 8);
    assert_eq!(
        snapshot.relays,
        vec![relays[3].clone(), relays[0].clone(), relays[1].clone()]
    );
    assert_eq!(omitted, 2);
    let bytes = Message::Endpoints(snapshot).encode().unwrap();
    assert!(bytes.len() <= MAX_MESSAGE_BYTES);
    assert_eq!(Message::decode(&bytes).unwrap().encode().unwrap(), bytes);
}
