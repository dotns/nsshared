//! Region rendezvous forwarding bodies, types 10-12: quick-v2 §7.1, §8.5 and
//! rendezvous §5.3.

#![allow(clippy::unwrap_used, reason = "test fixture helpers")]

use ed25519_dalek::SigningKey;
use nsshared_rendezvous::{
    auth::Hello,
    error::ErrorCode,
    message::{MailboxId, Published, SendRequest},
    region::{
        ClientAddr, RegionBodyError, RegistryRecord, RendezvousRequest, RendezvousResponse,
        check_owner_epoch,
    },
    registry::{self, RegistryEntry},
    transport::{self, Operation, Request, Response},
};
use nsshared_wire::{
    CborError, MAX_REGION_FRAME_BYTES, MAX_REGION_RENDEZVOUS_FRAME_BYTES, NodeRecord,
    NodeRecordFields, RegionChannel, RegionFrameError, RegionFrameType, RelayId,
    decode_region_envelope, encode_region_envelope,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const NOW: u64 = 1_800_000_000;
const NONCE: [u8; 32] = [7; 32];
const ACTOR: [u8; 32] = [9; 32];
const LOOKUP_NODE: &str = r#"{"operation":"lookup_node","value":{"node_id":"AAAAAAAAAAAAAAAA"}}"#;
const OK: &str = r#"{"result":"ok","value":null}"#;

fn authority() -> RelayId {
    RelayId::parse("hkg.relay.ns.io:443").unwrap()
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn v4() -> ClientAddr {
    ClientAddr {
        ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
        port: 50_000,
    }
}

fn v6() -> ClientAddr {
    ClientAddr {
        ip: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        port: 443,
    }
}

fn request(text: &str, actor: Option<[u8; 32]>) -> Result<RendezvousRequest, RegionBodyError> {
    RendezvousRequest::new(1, 3, v4(), NONCE, actor, text.to_owned())
}

/// A `send` request whose JSON is larger than a 4096-byte frame.
fn large_send() -> String {
    transport::encode_request(&Request::Send(SendRequest {
        id: MailboxId([5; 16]),
        data: vec![0xa5; 8192],
    }))
    .unwrap()
}

/// Minimal canonical CBOR writer for hand-made bodies.
#[derive(Default)]
struct Raw(Vec<u8>);

impl Raw {
    fn head(mut self, major: u8, value: u64) -> Self {
        let major = major << 5;
        match value {
            0..=23 => self.0.push(major | value as u8),
            24..=0xff => self.0.extend_from_slice(&[major | 24, value as u8]),
            0x100..=0xffff => {
                self.0.push(major | 25);
                self.0.extend_from_slice(&(value as u16).to_be_bytes());
            }
            0x1_0000..=0xffff_ffff => {
                self.0.push(major | 26);
                self.0.extend_from_slice(&(value as u32).to_be_bytes());
            }
            _ => {
                self.0.push(major | 27);
                self.0.extend_from_slice(&value.to_be_bytes());
            }
        }
        self
    }
    fn uint(self, value: u64) -> Self {
        self.head(0, value)
    }
    fn bytes(mut self, value: &[u8]) -> Self {
        self = self.head(2, value.len() as u64);
        self.0.extend_from_slice(value);
        self
    }
    fn text(mut self, value: &str) -> Self {
        self = self.head(3, value.len() as u64);
        self.0.extend_from_slice(value.as_bytes());
        self
    }
    fn array(self, length: u64) -> Self {
        self.head(4, length)
    }
    fn null(mut self) -> Self {
        self.0.push(0xf6);
        self
    }
    fn boolean(mut self, value: bool) -> Self {
        self.0.push(if value { 0xf5 } else { 0xf4 });
        self
    }
    fn raw(mut self, value: &[u8]) -> Self {
        self.0.extend_from_slice(value);
        self
    }
}

/// A request body with every field given: `[id, epoch, [ip, port], nonce, actor, text]`.
fn request_body(ip: &[u8], port: u64, actor: Option<&[u8]>, text: &str) -> Vec<u8> {
    let raw = Raw::default()
        .array(6)
        .uint(1)
        .uint(3)
        .array(2)
        .bytes(ip)
        .uint(port)
        .bytes(&NONCE);
    let raw = match actor {
        Some(actor) => raw.bytes(actor),
        None => raw.null(),
    };
    raw.text(text).0
}

// ---------------------------------------------------------------------------
// RENDEZVOUS_REQUEST
// ---------------------------------------------------------------------------

#[test]
fn request_round_trips_with_ipv4_and_null_actor() {
    let forwarded = request(LOOKUP_NODE, None).unwrap();
    assert_eq!(forwarded.request_id(), 1);
    assert_eq!(forwarded.owner_epoch(), 3);
    assert_eq!(forwarded.client_addr(), v4());
    assert_eq!(forwarded.challenge_nonce(), &NONCE);
    assert_eq!(forwarded.actor(), None);
    assert_eq!(forwarded.text(), LOOKUP_NODE);
    assert_eq!(forwarded.request().operation(), Operation::LookupNode);

    let body = forwarded.encode_body();
    assert_eq!(
        body,
        request_body(&[203, 0, 113, 7], 50_000, None, LOOKUP_NODE)
    );
    assert_eq!(RendezvousRequest::decode_body(&body), Ok(forwarded.clone()));

    let frame = forwarded.encode_frame().unwrap();
    let envelope = decode_region_envelope(&frame, RegionChannel::Control).unwrap();
    assert_eq!(envelope.frame_type, 10);
    assert_eq!(envelope.body, body.as_slice());
    assert_eq!(RendezvousRequest::decode_frame(&frame), Ok(forwarded));
}

#[test]
fn request_round_trips_with_ipv6_and_actor() {
    let text = r#"{"operation":"lookup","value":"01234567"}"#;
    let forwarded = RendezvousRequest::new(
        u64::MAX,
        u64::MAX,
        v6(),
        NONCE,
        Some(ACTOR),
        text.to_owned(),
    )
    .unwrap();
    assert_eq!(forwarded.actor(), Some(&ACTOR));
    let body = forwarded.encode_body();
    let ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets();
    assert_eq!(
        RendezvousRequest::decode_body(&body).unwrap().client_addr(),
        v6()
    );
    assert_eq!(
        &body[body.len() - text.len()..],
        text.as_bytes(),
        "the exact JSON text is carried"
    );
    assert!(body.windows(16).any(|window| window == ip));
    assert_eq!(
        RendezvousRequest::decode_frame(&forwarded.encode_frame().unwrap()),
        Ok(forwarded)
    );
}

#[test]
fn request_frames_above_4096_bytes_on_control_only() {
    let forwarded = request(&large_send(), Some(ACTOR)).unwrap();
    let frame = forwarded.encode_frame().unwrap();
    assert!(frame.len() > MAX_REGION_FRAME_BYTES);
    assert!(frame.len() <= MAX_REGION_RENDEZVOUS_FRAME_BYTES);
    assert_eq!(RendezvousRequest::decode_frame(&frame), Ok(forwarded));
    assert_eq!(
        decode_region_envelope(&frame, RegionChannel::Data),
        Err(RegionFrameError::TooLarge(frame.len()))
    );
}

#[test]
fn request_publish_carries_the_proof_nonce() {
    let record = record(1, 1, NOW - 10);
    let publish = registry::publish_request(&key(1), &NONCE, &authority(), &record, true);
    let text = transport::encode_request(&Request::Publish(publish.clone())).unwrap();
    let forwarded = request(&text, None).unwrap();
    let Request::Publish(decoded) = forwarded.request() else {
        panic!("not a publish");
    };
    assert!(
        registry::verify_publish(decoded, forwarded.challenge_nonce(), &authority(), NOW).is_ok()
    );
}

#[test]
fn refutation_request_zero_id_and_zero_nonce() {
    assert_eq!(
        RendezvousRequest::new(0, 3, v4(), NONCE, None, LOOKUP_NODE.to_owned()),
        Err(RegionBodyError::ZeroRequestId)
    );
    assert_eq!(
        RendezvousRequest::new(1, 3, v4(), [0; 32], None, LOOKUP_NODE.to_owned()),
        Err(RegionBodyError::ZeroChallengeNonce)
    );
    let mut body = request_body(&[203, 0, 113, 7], 1, None, LOOKUP_NODE);
    body[1] = 0;
    assert_eq!(
        RendezvousRequest::decode_body(&body),
        Err(RegionBodyError::ZeroRequestId)
    );
}

#[test]
fn refutation_request_wrong_arity_and_trailing_bytes() {
    let body = request_body(&[203, 0, 113, 7], 1, None, LOOKUP_NODE);
    let mut five = body.clone();
    five[0] = 0x85;
    assert!(matches!(
        RendezvousRequest::decode_body(&five),
        Err(RegionBodyError::Cbor(CborError::ArrayLength { .. }))
    ));
    let mut trailing = body.clone();
    trailing.push(0);
    assert_eq!(
        RendezvousRequest::decode_body(&trailing),
        Err(RegionBodyError::Cbor(CborError::TrailingBytes))
    );
    let seven = Raw::default().array(7).raw(&body[1..]).uint(0).0;
    assert!(matches!(
        RendezvousRequest::decode_body(&seven),
        Err(RegionBodyError::Cbor(CborError::ArrayLength { .. }))
    ));
    // client_addr must be a two-element array.
    let flat = Raw::default()
        .array(6)
        .uint(1)
        .uint(3)
        .bytes(&[203, 0, 113, 7])
        .0;
    assert!(matches!(
        RendezvousRequest::decode_body(&flat),
        Err(RegionBodyError::Cbor(CborError::UnexpectedType))
    ));
}

#[test]
fn refutation_request_client_addr() {
    for length in [0, 3, 5, 15] {
        assert_eq!(
            RendezvousRequest::decode_body(&request_body(&vec![1; length], 1, None, LOOKUP_NODE)),
            Err(RegionBodyError::ClientAddrLength(length))
        );
    }
    assert!(matches!(
        RendezvousRequest::decode_body(&request_body(&[1; 17], 1, None, LOOKUP_NODE)),
        Err(RegionBodyError::Cbor(CborError::StringLength { .. }))
    ));
    assert_eq!(
        RendezvousRequest::decode_body(&request_body(&[1; 4], 65_536, None, LOOKUP_NODE)),
        Err(RegionBodyError::FieldWidth {
            field: "port",
            value: 65_536
        })
    );
    let mapped = Ipv4Addr::new(203, 0, 113, 7).to_ipv6_mapped();
    assert_eq!(
        RendezvousRequest::decode_body(&request_body(&mapped.octets(), 1, None, LOOKUP_NODE)),
        Err(RegionBodyError::MappedClientAddr)
    );
    let client = ClientAddr {
        ip: IpAddr::V6(mapped),
        port: 1,
    };
    assert_eq!(
        RendezvousRequest::new(1, 3, client, NONCE, None, LOOKUP_NODE.to_owned()),
        Err(RegionBodyError::MappedClientAddr)
    );
}

#[test]
fn refutation_request_actor_shape() {
    assert!(matches!(
        RendezvousRequest::decode_body(&request_body(&[1; 4], 1, Some(&[9; 31]), LOOKUP_NODE)),
        Err(RegionBodyError::Cbor(CborError::StringLength { .. }))
    ));
    let text = r#"{"operation":"lookup","value":"01234567"}"#;
    assert_eq!(
        RendezvousRequest::decode_body(&request_body(&[1; 4], 1, None, text)),
        Err(RegionBodyError::MissingActor(Operation::Lookup))
    );
    assert!(RendezvousRequest::decode_body(&request_body(&[1; 4], 1, Some(&ACTOR), text)).is_ok());
}

#[test]
fn refutation_request_oversize_json() {
    let oversize = "x".repeat(16_385);
    assert_eq!(
        request(&oversize, Some(ACTOR)),
        Err(RegionBodyError::MessageTooLarge(16_385))
    );
    assert_eq!(
        RendezvousRequest::decode_body(&request_body(&[1; 4], 1, None, &oversize)),
        Err(RegionBodyError::MessageTooLarge(16_385))
    );
    // A 16384-byte text passes the size check and reaches the JSON parser.
    let largest = request_body(&[1; 4], 1, None, &"x".repeat(16_384));
    assert_eq!(
        RendezvousRequest::decode_body(&largest),
        Err(RegionBodyError::Message(ErrorCode::InvalidMessage))
    );
    // A body larger than a 20480-byte frame is refused before parsing.
    let too_large = vec![0; MAX_REGION_RENDEZVOUS_FRAME_BYTES + 1];
    assert!(matches!(
        RendezvousRequest::decode_body(&too_large),
        Err(RegionBodyError::Cbor(CborError::TooLarge { .. }))
    ));
}

#[test]
fn refutation_request_invalid_json() {
    for text in [
        "",
        "{",
        r#"{"operation":"poll","value":null}"#,
        r#"{"operation":"lookup_node","value":{"node_id":"AAAAAAAAAAAAAAAA"},"extra":1}"#,
        OK,
    ] {
        assert_eq!(
            request(text, Some(ACTOR)),
            Err(RegionBodyError::Message(ErrorCode::InvalidMessage)),
            "{text}"
        );
    }
    let mut body = request_body(&[1; 4], 1, None, "x");
    let last = body.len() - 1;
    body[last] = 0xff;
    assert_eq!(
        RendezvousRequest::decode_body(&body),
        Err(RegionBodyError::Cbor(CborError::InvalidUtf8))
    );
}

#[test]
fn refutation_request_hello_and_directory_are_never_forwarded() {
    let hello =
        transport::encode_request(&Request::Hello(Hello::sign(&key(4), &NONCE, &authority())))
            .unwrap();
    let directory = transport::encode_request(&Request::Directory).unwrap();
    for (text, operation) in [(hello, Operation::Hello), (directory, Operation::Directory)] {
        for actor in [None, Some(ACTOR)] {
            assert_eq!(
                request(&text, actor),
                Err(RegionBodyError::NotForwarded(operation))
            );
            assert_eq!(
                RendezvousRequest::decode_body(&request_body(
                    &[1; 4],
                    1,
                    actor.as_ref().map(<[u8; 32]>::as_slice),
                    &text
                )),
                Err(RegionBodyError::NotForwarded(operation))
            );
        }
    }
}

#[test]
fn refutation_request_frame_type_and_channel_size() {
    let forwarded = request(LOOKUP_NODE, None).unwrap();
    let body = forwarded.encode_body();
    let frame = encode_region_envelope(11, &body, RegionChannel::Control).unwrap();
    assert_eq!(
        RendezvousRequest::decode_frame(&frame),
        Err(RegionBodyError::WrongType {
            expected: RegionFrameType::RendezvousRequest,
            actual: 11
        })
    );
    let mut trailing = forwarded.encode_frame().unwrap();
    trailing.push(0);
    assert_eq!(
        RendezvousRequest::decode_frame(&trailing),
        Err(RegionBodyError::Cbor(CborError::TrailingBytes))
    );
    let oversize = vec![0; MAX_REGION_RENDEZVOUS_FRAME_BYTES + 1];
    assert_eq!(
        RendezvousRequest::decode_frame(&oversize),
        Err(RegionBodyError::Frame(RegionFrameError::TooLarge(
            oversize.len()
        )))
    );
}

// ---------------------------------------------------------------------------
// RENDEZVOUS_RESPONSE
// ---------------------------------------------------------------------------

#[test]
fn response_round_trips() {
    let response = RendezvousResponse::new(9, 3, OK.to_owned()).unwrap();
    assert_eq!(response.request_id(), 9);
    assert_eq!(response.owner_epoch(), 3);
    assert_eq!(response.text(), OK);
    assert_eq!(response.response(), &Response::Ok);
    let body = response.encode_body();
    assert_eq!(body, Raw::default().array(3).uint(9).uint(3).text(OK).0);
    assert_eq!(RendezvousResponse::decode_body(&body), Ok(response.clone()));
    let frame = response.encode_frame().unwrap();
    assert_eq!(
        decode_region_envelope(&frame, RegionChannel::Control)
            .unwrap()
            .frame_type,
        11
    );
    assert_eq!(RendezvousResponse::decode_frame(&frame), Ok(response));
}

#[test]
fn response_frames_above_4096_bytes() {
    let found = format!(
        r#"{{"result":"found","value":{{"id":"{}","kind":"pairing","expires":{NOW},"intro":"{}"}}}}"#,
        transport::encode_base64url(&[1; 16]),
        transport::encode_base64url(&[2; 4096]),
    );
    let response = RendezvousResponse::new(1, 1, found).unwrap();
    let frame = response.encode_frame().unwrap();
    assert!(frame.len() > MAX_REGION_FRAME_BYTES);
    assert_eq!(RendezvousResponse::decode_frame(&frame), Ok(response));
}

#[test]
fn response_owner_epoch_fencing() {
    assert_eq!(check_owner_epoch(3, 3), Ok(()));
    assert_eq!(check_owner_epoch(3, 4), Err(ErrorCode::Unavailable));
    assert_eq!(check_owner_epoch(4, 3), Err(ErrorCode::Unavailable));

    let forwarded = request(LOOKUP_NODE, None).unwrap();
    let unavailable = RendezvousResponse::unavailable(&forwarded);
    assert_eq!(unavailable.request_id(), forwarded.request_id());
    assert_eq!(unavailable.owner_epoch(), forwarded.owner_epoch());
    assert_eq!(
        unavailable.text(),
        transport::encode_response(&Response::Error(ErrorCode::Unavailable)).unwrap()
    );
    assert_eq!(
        RendezvousResponse::decode_body(&unavailable.encode_body()),
        Ok(unavailable.clone())
    );

    let response = RendezvousResponse::new(1, 3, OK.to_owned()).unwrap();
    assert_eq!(response.client_response(3), Response::Ok);
    assert_eq!(
        response.client_response(4),
        Response::Error(ErrorCode::Unavailable)
    );
}

#[test]
fn refutation_response_rules() {
    assert_eq!(
        RendezvousResponse::new(0, 3, OK.to_owned()),
        Err(RegionBodyError::ZeroRequestId)
    );
    assert_eq!(
        RendezvousResponse::new(1, 3, "x".repeat(16_385)),
        Err(RegionBodyError::MessageTooLarge(16_385))
    );
    for text in ["{", LOOKUP_NODE, r#"{"result":"error","value":"bogus"}"#] {
        assert_eq!(
            RendezvousResponse::new(1, 3, text.to_owned()),
            Err(RegionBodyError::Message(ErrorCode::InvalidMessage)),
            "{text}"
        );
    }
    let challenge = format!(
        r#"{{"result":"challenge","value":{{"nonce":"{}","authority":"hkg.relay.ns.io:443","capabilities":["mailbox"]}}}}"#,
        transport::encode_base64url(&NONCE)
    );
    let directory = r#"{"result":"directory","value":{"version":1,"relays":[{"id":1,"code":"KT","host":"hkg-a1.relay.ns.io","ips":["203.0.113.1"],"port":443,"capabilities":["udp","mailbox"]}]}}"#;
    for text in [challenge.as_str(), directory] {
        assert!(transport::decode_response(text).is_ok());
        assert_eq!(
            RendezvousResponse::new(1, 3, text.to_owned()),
            Err(RegionBodyError::ResponseNotForwarded)
        );
    }
}

#[test]
fn refutation_response_shape() {
    let body = Raw::default().array(3).uint(1).uint(3).text(OK).0;
    let mut trailing = body.clone();
    trailing.push(0);
    assert_eq!(
        RendezvousResponse::decode_body(&trailing),
        Err(RegionBodyError::Cbor(CborError::TrailingBytes))
    );
    assert!(matches!(
        RendezvousResponse::decode_body(&Raw::default().array(2).uint(1).text(OK).0),
        Err(RegionBodyError::Cbor(CborError::ArrayLength { .. }))
    ));
    assert!(matches!(
        RendezvousResponse::decode_body(&Raw::default().array(4).raw(&body[1..]).uint(0).0),
        Err(RegionBodyError::Cbor(CborError::ArrayLength { .. }))
    ));
    assert_eq!(
        RendezvousResponse::decode_body(&Raw::default().array(3).uint(0).uint(3).text(OK).0),
        Err(RegionBodyError::ZeroRequestId)
    );
    assert_eq!(
        RendezvousResponse::decode_body(
            &Raw::default()
                .array(3)
                .uint(1)
                .uint(3)
                .text(&"x".repeat(16_385))
                .0
        ),
        Err(RegionBodyError::MessageTooLarge(16_385))
    );
    let frame = encode_region_envelope(10, &body, RegionChannel::Control).unwrap();
    assert_eq!(
        RendezvousResponse::decode_frame(&frame),
        Err(RegionBodyError::WrongType {
            expected: RegionFrameType::RendezvousResponse,
            actual: 10
        })
    );
}

// ---------------------------------------------------------------------------
// REGISTRY_RECORD
// ---------------------------------------------------------------------------

fn record_with(signer: &SigningKey, generation: u64, wg: u8, issued_at: u64) -> NodeRecord {
    NodeRecord::sign(
        signer,
        NodeRecordFields {
            wg_key: [wg; 32],
            generation,
            issued_at,
            expires: issued_at + 3600,
            relays: vec![authority()],
        },
    )
    .unwrap()
}

fn record(generation: u64, wg: u8, issued_at: u64) -> NodeRecord {
    record_with(&key(1), generation, wg, issued_at)
}

fn replica(record: &NodeRecord, dns: bool) -> RegistryRecord {
    let publish = registry::publish_request(&key(1), &NONCE, &authority(), record, dns);
    RegistryRecord::new(&publish, NONCE).unwrap()
}

fn empty_entry() -> RegistryEntry {
    RegistryEntry::new(*key(1).verifying_key().as_bytes())
}

#[test]
fn registry_record_round_trips() {
    let record = record(1, 1, NOW - 10);
    let publish = registry::publish_request(&key(1), &NONCE, &authority(), &record, true);
    let replica = RegistryRecord::new(&publish, NONCE).unwrap();
    assert_eq!(replica.record(), &record);
    assert!(replica.dns());
    assert_eq!(replica.challenge_nonce(), &NONCE);
    assert_eq!(replica.proof(), &publish.proof);
    assert_eq!(replica.publish_request(), publish);

    let body = replica.encode_body();
    let expected = Raw::default()
        .array(4)
        .raw(record.as_bytes())
        .boolean(true)
        .bytes(&NONCE)
        .bytes(&publish.proof)
        .0;
    assert_eq!(body, expected);
    assert_eq!(RegistryRecord::decode_body(&body), Ok(replica.clone()));
    let frame = replica.encode_frame().unwrap();
    assert!(frame.len() <= MAX_REGION_FRAME_BYTES);
    assert_eq!(
        decode_region_envelope(&frame, RegionChannel::Control)
            .unwrap()
            .frame_type,
        12
    );
    assert_eq!(RegistryRecord::decode_frame(&frame), Ok(replica));
}

#[test]
fn refutation_registry_record_shape() {
    let replica = replica(&record(1, 1, NOW - 10), false);
    let body = replica.encode_body();
    let mut trailing = body.clone();
    trailing.push(0);
    assert_eq!(
        RegistryRecord::decode_body(&trailing),
        Err(RegionBodyError::Cbor(CborError::TrailingBytes))
    );
    let mut three = body.clone();
    three[0] = 0x83;
    assert!(matches!(
        RegistryRecord::decode_body(&three),
        Err(RegionBodyError::Cbor(_))
    ));
    let five = Raw::default().array(5).raw(&body[1..]).uint(0).0;
    assert!(matches!(
        RegistryRecord::decode_body(&five),
        Err(RegionBodyError::Cbor(CborError::ArrayLength { .. }))
    ));
    // The record nested as a byte string, not as its array.
    let as_bytes = Raw::default()
        .array(4)
        .bytes(replica.record().as_bytes())
        .raw(&body[1 + replica.record().as_bytes().len()..])
        .0;
    assert_eq!(
        RegistryRecord::decode_body(&as_bytes),
        Err(RegionBodyError::Cbor(CborError::UnexpectedType))
    );
    let mut zero_nonce = body.clone();
    let start = 1 + replica.record().as_bytes().len() + 1 + 2;
    zero_nonce[start..start + 32].fill(0);
    assert_eq!(
        RegistryRecord::decode_body(&zero_nonce),
        Err(RegionBodyError::ZeroChallengeNonce)
    );
    let publish = replica.publish_request();
    assert_eq!(
        RegistryRecord::new(&publish, [0; 32]),
        Err(RegionBodyError::ZeroChallengeNonce)
    );
    let too_large = vec![0; MAX_REGION_FRAME_BYTES + 1];
    assert!(matches!(
        RegistryRecord::decode_body(&too_large),
        Err(RegionBodyError::Cbor(CborError::TooLarge { .. }))
    ));
    let frame = encode_region_envelope(11, &body, RegionChannel::Control).unwrap();
    assert_eq!(
        RegistryRecord::decode_frame(&frame),
        Err(RegionBodyError::WrongType {
            expected: RegionFrameType::RegistryRecord,
            actual: 11
        })
    );
}

#[test]
fn refutation_registry_record_invalid_nested_record() {
    let replica = replica(&record(1, 1, NOW - 10), false);
    let mut body = replica.encode_body();
    // The last byte of the record's signature.
    body[replica.record().as_bytes().len()] ^= 1;
    assert!(matches!(
        RegistryRecord::decode_body(&body),
        Err(RegionBodyError::Record(_))
    ));
    let mut publish = replica.publish_request();
    publish.record.pop();
    assert!(matches!(
        RegistryRecord::new(&publish, NONCE),
        Err(RegionBodyError::Record(_))
    ));
}

#[test]
fn registry_record_applies_through_the_registry_entry() {
    let mut entry = empty_entry();
    let first = record(1, 1, NOW - 10);
    assert_eq!(
        replica(&first, true).apply(&mut entry, &authority(), NOW),
        Ok(Published {
            expires: first.expires()
        })
    );
    assert_eq!(entry.record(), Some(&first));
    assert!(entry.dns());

    // A higher generation wins and takes its dns choice.
    let second = record(2, 2, NOW - 5);
    replica(&second, false)
        .apply(&mut entry, &authority(), NOW)
        .unwrap();
    assert_eq!(entry.record(), Some(&second));
    assert!(!entry.dns());

    // A lower generation is stale.
    assert_eq!(
        replica(&first, true).apply(&mut entry, &authority(), NOW),
        Err(ErrorCode::Conflict)
    );
    assert_eq!(entry.record(), Some(&second));
    assert!(!entry.dns());
}

#[test]
fn registry_record_dns_follows_the_winning_record() {
    let older = record(1, 1, NOW - 20);
    let newer = record(1, 1, NOW - 10);
    let mut entry = empty_entry();
    replica(&newer, true)
        .apply(&mut entry, &authority(), NOW)
        .unwrap();
    // An older record of the same generation and key changes nothing.
    assert_eq!(
        replica(&older, false).apply(&mut entry, &authority(), NOW),
        Ok(Published {
            expires: newer.expires()
        })
    );
    assert_eq!(entry.record(), Some(&newer));
    assert!(entry.dns());

    // Either arrival order converges on the newer record and its choice.
    let mut other = empty_entry();
    replica(&older, false)
        .apply(&mut other, &authority(), NOW)
        .unwrap();
    replica(&newer, true)
        .apply(&mut other, &authority(), NOW)
        .unwrap();
    assert_eq!(other, entry);

    // On identical records the last accepted publish wins.
    replica(&newer, false)
        .apply(&mut entry, &authority(), NOW)
        .unwrap();
    assert!(!entry.dns());
}

#[test]
fn registry_record_conflict_is_latched_locally() {
    let mut entry = empty_entry();
    replica(&record(1, 1, NOW - 10), true)
        .apply(&mut entry, &authority(), NOW)
        .unwrap();
    assert_eq!(
        replica(&record(1, 2, NOW - 10), true).apply(&mut entry, &authority(), NOW),
        Err(ErrorCode::Conflict)
    );
    assert!(entry.marks().is_conflicted());
    assert_eq!(
        registry::lookup(Some(&entry), NOW),
        Err(ErrorCode::Conflict)
    );
    // An older record during a conflict is still refused, not silently ignored.
    assert_eq!(
        replica(&record(1, 1, NOW - 20), true).apply(&mut entry, &authority(), NOW),
        Err(ErrorCode::Conflict)
    );
    // A higher generation clears it.
    replica(&record(2, 3, NOW - 5), true)
        .apply(&mut entry, &authority(), NOW)
        .unwrap();
    assert!(!entry.marks().is_conflicted());
}

#[test]
fn refutation_registry_record_apply() {
    let record = record(1, 1, NOW - 10);
    let mut entry = empty_entry();
    // The proof is bound to the region identity and the nonce.
    let other = RelayId::parse("sin.relay.ns.io:443").unwrap();
    assert_eq!(
        replica(&record, true).apply(&mut entry, &other, NOW),
        Err(ErrorCode::InvalidMessage)
    );
    let publish = registry::publish_request(&key(1), &NONCE, &authority(), &record, true);
    let wrong_nonce = RegistryRecord::new(&publish, [8; 32]).unwrap();
    assert_eq!(
        wrong_nonce.apply(&mut entry, &authority(), NOW),
        Err(ErrorCode::InvalidMessage)
    );
    // A forged dns choice does not verify.
    let mut forged = publish.clone();
    forged.dns = false;
    assert_eq!(
        RegistryRecord::new(&forged, NONCE)
            .unwrap()
            .apply(&mut entry, &authority(), NOW),
        Err(ErrorCode::InvalidMessage)
    );
    // Expired at the receiver.
    assert_eq!(
        replica(&record, true).apply(&mut entry, &authority(), record.expires() + 1),
        Err(ErrorCode::InvalidMessage)
    );
    // Another identity's entry.
    let mut foreign = RegistryEntry::new(*key(2).verifying_key().as_bytes());
    assert_eq!(
        replica(&record, true).apply(&mut foreign, &authority(), NOW),
        Err(ErrorCode::InvalidMessage)
    );
    assert_eq!(entry, empty_entry());
}
