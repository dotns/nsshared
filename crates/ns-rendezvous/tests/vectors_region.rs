//! Generated region frame vectors for types 10-12 (quick-v2 §7.1, §8.5, §12.1;
//! rendezvous §5.3).

#![allow(clippy::unwrap_used, clippy::panic, reason = "test fixture helpers")]

mod support;

use ns_rendezvous::{
    message::PublishRequest,
    region::{ClientAddr, RegionBodyError, RegistryRecord, RendezvousRequest, RendezvousResponse},
    registry::RegistryEntry,
};
use ns_wire::{CborError, NodeRecordError, RegionFrameType, RelayId};
use support::vectors::{Vector, load};

fn check_frame(v: &Vector, body: &[u8], frame: &[u8]) {
    let name = v.name();
    assert_eq!(body, v.hex("body").as_slice(), "{name}");
    assert_eq!(
        body.len(),
        usize::try_from(v.u64("body_len")).unwrap(),
        "{name}"
    );
    assert_eq!(frame, v.hex("frame").as_slice(), "{name}");
}

#[test]
fn valid_bodies_match_vectors() {
    let vectors = load("region_bodies");
    let mut kinds = [0; 3];
    for v in vectors.iter().filter(|v| !v.is_reject()) {
        let name = v.name();
        match v.get("kind") {
            "request" => {
                kinds[0] += 1;
                assert_eq!(v.u64("type"), 10);
                let request = RendezvousRequest::new(
                    v.u64("request_id"),
                    v.u64("owner_epoch"),
                    ClientAddr {
                        ip: v.get("client_ip").parse().unwrap(),
                        port: u16::try_from(v.u64("client_port")).unwrap(),
                    },
                    v.hex_array("challenge_nonce"),
                    v.opt("actor").map(|_| v.hex_array("actor")),
                    v.get("message").to_owned(),
                )
                .unwrap();
                check_frame(v, &request.encode_body(), &request.encode_frame().unwrap());
                let decoded = RendezvousRequest::decode_body(&v.hex("body")).unwrap();
                assert_eq!(decoded, request, "{name}");
                assert_eq!(decoded.encode_body(), v.hex("body"));
                assert_eq!(
                    RendezvousRequest::decode_frame(&v.hex("frame")).unwrap(),
                    request
                );
            }
            "response" => {
                kinds[1] += 1;
                assert_eq!(v.u64("type"), 11);
                let response = RendezvousResponse::new(
                    v.u64("request_id"),
                    v.u64("owner_epoch"),
                    v.get("message").to_owned(),
                )
                .unwrap();
                check_frame(
                    v,
                    &response.encode_body(),
                    &response.encode_frame().unwrap(),
                );
                let decoded = RendezvousResponse::decode_body(&v.hex("body")).unwrap();
                assert_eq!(decoded, response, "{name}");
                assert_eq!(decoded.encode_body(), v.hex("body"));
                assert_eq!(
                    RendezvousResponse::decode_frame(&v.hex("frame")).unwrap(),
                    response
                );
            }
            "registry_record" => {
                kinds[2] += 1;
                assert_eq!(v.u64("type"), 12);
                let publish = PublishRequest {
                    record: v.hex("record"),
                    dns: v.bool("dns"),
                    proof: v.hex_array("proof"),
                };
                let replica =
                    RegistryRecord::new(&publish, v.hex_array("challenge_nonce")).unwrap();
                check_frame(v, &replica.encode_body(), &replica.encode_frame().unwrap());
                let decoded = RegistryRecord::decode_body(&v.hex("body")).unwrap();
                assert_eq!(decoded, replica, "{name}");
                assert_eq!(decoded.encode_body(), v.hex("body"));
                assert_eq!(
                    RegistryRecord::decode_frame(&v.hex("frame")).unwrap(),
                    replica
                );
                // The proof binds the fixture nonce and authority (quick-v2 §7.2).
                let mut entry = RegistryEntry::new(*decoded.record().identity());
                let authority = RelayId::parse(v.get("authority")).unwrap();
                decoded.apply(&mut entry, &authority, v.u64("now")).unwrap();
                assert_eq!(entry.dns(), v.bool("dns"), "{name}");
            }
            other => panic!("{name}: kind {other}"),
        }
    }
    assert!(kinds.iter().all(|&count| count >= 2), "{kinds:?}");
}

#[test]
fn rejected_bodies_match_vectors() {
    let vectors = load("region_bodies");
    let mut negatives = 0;
    for v in vectors.iter().filter(|v| v.is_reject()) {
        negatives += 1;
        let name = v.name();
        let error = match v.get("kind") {
            "request" => RendezvousRequest::decode_body(&v.hex("body")).map(|_| ()),
            "response" => RendezvousResponse::decode_body(&v.hex("body")).map(|_| ()),
            "registry_record" => RegistryRecord::decode_body(&v.hex("body")).map(|_| ()),
            "frame" => {
                assert_eq!(v.u64("expected_type"), 11);
                RendezvousResponse::decode_frame(&v.hex("frame")).map(|_| ())
            }
            other => panic!("{name}: kind {other}"),
        }
        .unwrap_err();
        let expected = match v.reason() {
            "zero_request_id" => matches!(error, RegionBodyError::ZeroRequestId),
            "zero_challenge_nonce" => matches!(error, RegionBodyError::ZeroChallengeNonce),
            "mapped_client_addr" => matches!(error, RegionBodyError::MappedClientAddr),
            "client_addr_length" => matches!(error, RegionBodyError::ClientAddrLength(5)),
            "port_width" => matches!(
                error,
                RegionBodyError::FieldWidth {
                    field: "port",
                    value: 65536
                }
            ),
            "not_forwarded" => matches!(error, RegionBodyError::NotForwarded(_)),
            "missing_actor" => matches!(error, RegionBodyError::MissingActor(_)),
            "message" => matches!(error, RegionBodyError::Message(_)),
            "trailing_bytes" => matches!(error, RegionBodyError::Cbor(CborError::TrailingBytes)),
            "response_not_forwarded" => matches!(error, RegionBodyError::ResponseNotForwarded),
            "record" => matches!(
                error,
                RegionBodyError::Record(NodeRecordError::BadSignature)
            ),
            "wrong_type" => matches!(
                error,
                RegionBodyError::WrongType {
                    expected: RegionFrameType::RendezvousResponse,
                    actual: 12
                }
            ),
            other => panic!("{name}: unknown reason {other}"),
        };
        assert!(expected, "{name}: {error:?}");
    }
    assert!(negatives >= 15);
}
