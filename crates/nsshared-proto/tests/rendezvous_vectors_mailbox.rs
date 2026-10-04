//! Generated `/rendezvous/v1` JSON vectors: one message per request and result kind, valid and
//! rejected (rendezvous §3, §3.1, §4, §5.2, §5.4; quick-v2 §7.2).

#![allow(clippy::unwrap_used, clippy::panic, reason = "test fixture helpers")]

mod support;

use nsshared_proto::RelayId;
use nsshared_proto::rendezvous::{
    auth::{Challenge, Hello},
    capability::{Capabilities, Capability},
    error::ErrorCode,
    message::{
        Admission, AdmitRequest, CloseRequest, Digits, DnsPublication, Found, JoinRequest, Kind,
        LookupNodeRequest, MailboxId, MailboxMessage, MailboxView, OpenRequest, Opened,
        PublishRequest, Published, RecordResult, RecvRequest, RejectRequest, SendRequest, Sent,
        Stage, Waiting,
    },
    transport::{self, Request, Response},
};
use std::collections::BTreeSet;
use support::vectors::{Vector, decode_hex, load};

fn id(v: &Vector) -> MailboxId {
    MailboxId(v.hex_array("id"))
}

fn admission(v: &Vector) -> Admission {
    match v.get("admission") {
        "first" => Admission::First,
        "owner" => Admission::Owner,
        other => panic!("{}: admission {other}", v.name()),
    }
}

fn stage(v: &Vector) -> Stage {
    match v.get("stage") {
        "open" => Stage::Open,
        "admitted" => Stage::Admitted,
        "closing" => Stage::Closing,
        other => panic!("{}: stage {other}", v.name()),
    }
}

/// The request built from the vector's fields, independently of its JSON text.
fn request(v: &Vector) -> Request {
    match v.get("operation") {
        "directory" => Request::Directory,
        "publish" => Request::Publish(PublishRequest {
            record: v.hex("record"),
            dns: dns_level(v),
            proof: v.hex_array("proof"),
        }),
        "lookup_node" => Request::LookupNode(LookupNodeRequest {
            node_id: v.hex_array("node_id"),
        }),
        "hello" => Request::Hello(Hello {
            actor: v.hex_array("actor"),
            signature: v.hex_array("signature"),
        }),
        "open" => Request::Open(OpenRequest {
            kind: Kind::parse(v.get("mailbox_kind")).unwrap(),
            ttl: v.u64("ttl"),
            admission: admission(v),
            candidates: u8::try_from(v.u64("candidates")).unwrap(),
            intro: v.hex_or_empty("intro"),
        }),
        "lookup" => Request::Lookup(Digits::parse(v.get("digits")).unwrap()),
        "join" => Request::Join(JoinRequest {
            id: id(v),
            intro: v.hex_or_empty("intro"),
        }),
        "admit" => Request::Admit(AdmitRequest {
            id: id(v),
            actor: v.hex_array("actor"),
        }),
        "reject" => Request::Reject(RejectRequest {
            id: id(v),
            actor: v.hex_array("actor"),
        }),
        "send" => Request::Send(SendRequest {
            id: id(v),
            data: v.hex("data"),
        }),
        "recv" => Request::Recv(RecvRequest {
            id: id(v),
            after: v.u64("after"),
            wait_ms: v.u64("wait_ms"),
        }),
        "close" => Request::Close(CloseRequest { id: id(v) }),
        other => panic!("{}: operation {other}", v.name()),
    }
}

/// The response built from the vector's fields; `None` for the directory, whose fields
/// are checked after decoding.
fn response(v: &Vector) -> Option<Response> {
    Some(match v.get("result") {
        "challenge" => Response::Challenge(Challenge {
            nonce: v.hex_array("nonce"),
            authority: RelayId::parse(v.get("authority")).unwrap(),
            capabilities: Capabilities::new(
                v.all("capability")
                    .iter()
                    .map(|token| Capability::parse(token).unwrap())
                    .collect(),
            )
            .unwrap(),
        }),
        "directory" => return None,
        "published" => Response::Published(Published {
            expires: v.u64("expires"),
        }),
        "record" => Response::Record(RecordResult {
            record: v.opt("record").map(|_| v.hex("record")),
        }),
        "ok" => Response::Ok,
        "opened" => Response::Opened(Opened {
            id: id(v),
            digits: Digits::parse(v.get("digits")).unwrap(),
            expires: v.u64("expires"),
        }),
        "found" => Response::Found(Found {
            id: id(v),
            kind: Kind::parse(v.get("mailbox_kind")).unwrap(),
            expires: v.u64("expires"),
            intro: v.hex_or_empty("intro"),
        }),
        "sent" => Response::Sent(Sent { seq: v.u64("seq") }),
        "mailbox" => Response::Mailbox(MailboxView {
            stage: stage(v),
            waiting: v
                .all("waiting_actor")
                .iter()
                .zip(v.all("waiting_intro"))
                .map(|(actor, intro)| Waiting {
                    actor: decode_hex(actor).unwrap().try_into().unwrap(),
                    intro: decode_hex(intro).unwrap(),
                })
                .collect(),
            peer: v.opt("peer").map(|_| v.hex_array("peer")),
            messages: v
                .all("message_seq")
                .iter()
                .zip(v.all("message_data"))
                .map(|(seq, data)| MailboxMessage {
                    seq: seq.parse().unwrap(),
                    data: decode_hex(data).unwrap(),
                })
                .collect(),
        }),
        "error" => Response::Error(v.get("error").parse::<ErrorCode>().unwrap()),
        other => panic!("{}: result {other}", v.name()),
    })
}

/// The `dns` level of a vector, as written in the fixture.
fn dns_level(v: &Vector) -> DnsPublication {
    match v.get("dns") {
        "none" => DnsPublication::None,
        "address" => DnsPublication::Address,
        "record" => DnsPublication::Record,
        other => panic!("{}: dns {other}", v.name()),
    }
}

#[test]
fn valid_requests_match_vectors() {
    let vectors = load("mailbox_json");
    let mut operations = BTreeSet::new();
    for v in vectors
        .iter()
        .filter(|v| !v.is_reject() && v.get("kind") == "request")
    {
        let name = v.name();
        let json = v.get("json");
        let decoded = transport::decode_request(json).unwrap();
        assert_eq!(decoded, request(v), "{name}");
        if v.opt("decode_only").is_some() {
            continue;
        }
        operations.insert(decoded.operation().as_str());
        assert_eq!(
            transport::encode_request(&request(v)).unwrap(),
            json,
            "{name}"
        );
        assert_eq!(transport::encode_request(&decoded).unwrap(), json, "{name}");
    }
    assert_eq!(operations.len(), 12, "one vector per request kind");
}

#[test]
fn valid_responses_match_vectors() {
    let vectors = load("mailbox_json");
    let mut results = BTreeSet::new();
    for v in vectors
        .iter()
        .filter(|v| !v.is_reject() && v.get("kind") == "response")
    {
        let name = v.name();
        let json = v.get("json");
        results.insert(v.get("result"));
        let decoded = transport::decode_response(json).unwrap();
        match response(v) {
            Some(expected) => {
                assert_eq!(decoded, expected, "{name}");
                assert_eq!(
                    transport::encode_response(&expected).unwrap(),
                    json,
                    "{name}"
                );
            }
            None => {
                let Response::Directory(directory) = &decoded else {
                    panic!("{name}: {decoded:?}");
                };
                assert_eq!(directory.version(), v.u64("version"), "{name}");
                assert_eq!(
                    directory.relays().len(),
                    usize::try_from(v.u64("relay_count")).unwrap()
                );
            }
        }
        assert_eq!(
            transport::encode_response(&decoded).unwrap(),
            json,
            "{name}"
        );
    }
    assert_eq!(results.len(), 10, "one vector per result kind");
}

#[test]
fn rejected_messages_match_vectors() {
    let vectors = load("mailbox_json");
    let mut negatives = 0;
    for v in vectors.iter().filter(|v| v.is_reject()) {
        negatives += 1;
        let name = v.name();
        assert!(
            matches!(
                v.reason(),
                "unknown_field"
                    | "missing_field"
                    | "base64"
                    | "unknown_name"
                    | "range"
                    | "type"
                    | "oversize"
            ),
            "{name}: unknown reason {}",
            v.reason()
        );
        let json = v.get("json");
        let error = match v.get("kind") {
            "request" => transport::decode_request(json).map(|_| ()),
            "response" => transport::decode_response(json).map(|_| ()),
            other => panic!("{name}: kind {other}"),
        };
        assert_eq!(error, Err(ErrorCode::InvalidMessage), "{name}");
    }
    assert!(negatives >= 30);
}
