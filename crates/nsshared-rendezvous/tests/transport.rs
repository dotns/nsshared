//! JSON framing and payload decoding: rendezvous §3, §5.2, §7 and quick-v2 §7.2.

#![allow(clippy::unwrap_used, reason = "test fixture helpers")]

use ed25519_dalek::SigningKey;
use nsshared_rendezvous::{
    auth::{Challenge, Hello},
    capability::{self, Capabilities, Capability},
    directory::{Directory, RelayEntry},
    error::ErrorCode,
    message::{
        Admission, AdmitRequest, CloseRequest, Digits, Found, JoinRequest, Kind, LookupNodeRequest,
        MailboxId, MailboxMessage, MailboxView, OpenRequest, Opened, PublishRequest, Published,
        RecordResult, RecvRequest, RejectRequest, SendRequest, Sent, Stage, Waiting,
    },
    transport::{
        MAX_MESSAGE_BYTES, Operation, PATH, Request, Response, SUBPROTOCOL, decode_base64url,
        decode_request, decode_response, encode_base64url, encode_request, encode_response,
    },
};
use nsshared_wire::RelayId;

const ID: MailboxId = MailboxId([7; 16]);

fn b64(bytes: &[u8]) -> String {
    encode_base64url(bytes)
}

fn authority() -> RelayId {
    RelayId::parse("hkg-a1.relay.ns.io:443").unwrap()
}

fn open_request() -> OpenRequest {
    OpenRequest {
        kind: Kind::parse("pairing").unwrap(),
        ttl: 600,
        admission: Admission::Owner,
        candidates: 4,
        intro: vec![1, 2, 3],
    }
}

fn directory() -> Directory {
    Directory::new(
        1,
        vec![
            RelayEntry::new(
                1,
                "KT".into(),
                "hkg-a1.relay.ns.io".into(),
                vec!["203.0.113.1".parse().unwrap()],
                443,
                Capabilities::new(vec![capability::UDP, capability::MAILBOX]).unwrap(),
            )
            .unwrap(),
        ],
    )
    .unwrap()
}

fn requests() -> Vec<Request> {
    vec![
        Request::Directory,
        Request::Publish(PublishRequest {
            record: vec![0x8a; 40],
            dns: true,
            proof: [5; 64],
        }),
        Request::LookupNode(LookupNodeRequest { node_id: [9; 12] }),
        Request::Hello(Hello::sign(
            &SigningKey::from_bytes(&[1; 32]),
            &[2; 32],
            &authority(),
        )),
        Request::Open(open_request()),
        Request::Lookup(Digits::parse("01234567").unwrap()),
        Request::Join(JoinRequest {
            id: ID,
            intro: vec![],
        }),
        Request::Admit(AdmitRequest {
            id: ID,
            actor: [3; 32],
        }),
        Request::Reject(RejectRequest {
            id: ID,
            actor: [4; 32],
        }),
        Request::Send(SendRequest {
            id: ID,
            data: vec![0xff; 100],
        }),
        Request::Recv(RecvRequest {
            id: ID,
            after: 3,
            wait_ms: 20_000,
        }),
        Request::Close(CloseRequest { id: ID }),
    ]
}

fn responses() -> Vec<Response> {
    vec![
        Response::Challenge(Challenge {
            nonce: [1; 32],
            authority: authority(),
            capabilities: Capabilities::new(vec![
                capability::MAILBOX,
                Capability::parse("future.x-1").unwrap(),
            ])
            .unwrap(),
        }),
        Response::Directory(directory()),
        Response::Published(Published {
            expires: 1_800_000_000,
        }),
        Response::Record(RecordResult {
            record: Some(vec![0x8a; 30]),
        }),
        Response::Record(RecordResult { record: None }),
        Response::Ok,
        Response::Opened(Opened {
            id: ID,
            digits: Digits::parse("00000001").unwrap(),
            expires: u64::MAX,
        }),
        Response::Found(Found {
            id: ID,
            kind: Kind::parse("transfer").unwrap(),
            expires: 1,
            intro: vec![2; 4096],
        }),
        Response::Sent(Sent { seq: 1 }),
        Response::Mailbox(MailboxView {
            stage: Stage::Admitted,
            waiting: vec![Waiting {
                actor: [8; 32],
                intro: vec![1],
            }],
            peer: Some([6; 32]),
            messages: vec![MailboxMessage {
                seq: 2,
                data: vec![3; 8],
            }],
        }),
        Response::Mailbox(MailboxView {
            stage: Stage::Closing,
            waiting: vec![],
            peer: None,
            messages: vec![],
        }),
        Response::Error(ErrorCode::Unavailable),
    ]
}

#[test]
fn constants() {
    assert_eq!(PATH, "/quick/v2");
    assert_eq!(SUBPROTOCOL, "ns-quick-v2");
    assert_eq!(MAX_MESSAGE_BYTES, 16_384);
}

#[test]
fn every_request_round_trips() {
    let requests = requests();
    assert_eq!(requests.len(), 12);
    for request in requests {
        let text = encode_request(&request).unwrap();
        assert!(text.starts_with(&format!(
            "{{\"operation\":\"{}\",\"value\":",
            request.operation().as_str()
        )));
        assert_eq!(decode_request(&text).unwrap(), request, "{text}");
    }
}

#[test]
fn every_response_round_trips() {
    for response in responses() {
        let text = encode_response(&response).unwrap();
        assert!(text.starts_with("{\"result\":\""));
        assert_eq!(decode_response(&text).unwrap(), response, "{text}");
    }
}

#[test]
fn encodings_are_compact_and_in_spec_field_order() {
    assert_eq!(
        encode_request(&Request::Directory).unwrap(),
        r#"{"operation":"directory","value":null}"#
    );
    assert_eq!(
        encode_response(&Response::Ok).unwrap(),
        r#"{"result":"ok","value":null}"#
    );
    assert_eq!(
        encode_response(&Response::Error(ErrorCode::InvalidMessage)).unwrap(),
        r#"{"result":"error","value":"invalid_message"}"#
    );
    assert_eq!(
        encode_request(&Request::Lookup(Digits::parse("01234567").unwrap())).unwrap(),
        r#"{"operation":"lookup","value":"01234567"}"#
    );
    assert_eq!(
        encode_request(&Request::Open(open_request())).unwrap(),
        r#"{"operation":"open","value":{"kind":"pairing","ttl":600,"admission":"owner","candidates":4,"intro":"AQID"}}"#
    );
    assert_eq!(
        encode_request(&Request::LookupNode(LookupNodeRequest { node_id: [0; 12] })).unwrap(),
        r#"{"operation":"lookup_node","value":{"node_id":"AAAAAAAAAAAAAAAA"}}"#
    );
    assert_eq!(
        encode_response(&Response::Record(RecordResult { record: None })).unwrap(),
        r#"{"result":"record","value":{"record":null}}"#
    );
    let challenge = encode_response(&responses()[0]).unwrap();
    assert_eq!(
        challenge,
        format!(
            r#"{{"result":"challenge","value":{{"nonce":"{}","authority":"hkg-a1.relay.ns.io:443","capabilities":["mailbox","future.x-1"]}}}}"#,
            b64(&[1; 32])
        )
    );
    assert_eq!(
        encode_response(&Response::Directory(directory())).unwrap(),
        r#"{"result":"directory","value":{"version":1,"relays":[{"id":1,"code":"KT","host":"hkg-a1.relay.ns.io","ips":["203.0.113.1"],"port":443,"capabilities":["udp","mailbox"]}]}}"#
    );
    let view = encode_response(&responses()[10]).unwrap();
    assert_eq!(
        view,
        r#"{"result":"mailbox","value":{"stage":"closing","waiting":[],"peer":null,"messages":[]}}"#
    );
}

#[test]
fn envelope_keys_are_required_and_unknown_keys_rejected() {
    for text in [
        r#"{"operation":"directory"}"#,
        r#"{"value":null}"#,
        r#"{"operation":"directory","value":null,"extra":1}"#,
        r#"{"operation":"directory","value":{}}"#,
        r#"{"operation":"directory","value":null,"value":null}"#,
        r#"{"operation":"poll","value":null}"#,
        r#"{"operation":"Directory","value":null}"#,
        r#"{"result":"ok","value":null}"#,
        r#"["directory",null]"#,
        "",
        "null",
    ] {
        assert_eq!(
            decode_request(text),
            Err(ErrorCode::InvalidMessage),
            "{text}"
        );
    }
    for text in [
        r#"{"result":"ok"}"#,
        r#"{"result":"ok","value":null,"extra":1}"#,
        r#"{"result":"ok","value":0}"#,
        r#"{"result":"state","value":null}"#,
        r#"{"result":"error","value":"bogus"}"#,
        r#"{"result":"error","value":null}"#,
        r#"{"operation":"directory","value":null}"#,
    ] {
        assert_eq!(
            decode_response(text),
            Err(ErrorCode::InvalidMessage),
            "{text}"
        );
    }
}

#[test]
fn payload_fields_are_required_and_unknown_fields_rejected() {
    let id = b64(&[7; 16]);
    let actor = b64(&[3; 32]);
    for text in [
        r#"{"operation":"close","value":{}}"#.to_owned(),
        format!(r#"{{"operation":"close","value":{{"id":"{id}","extra":true}}}}"#),
        format!(r#"{{"operation":"admit","value":{{"id":"{id}"}}}}"#),
        format!(r#"{{"operation":"admit","value":{{"id":"{id}","actor":"{actor}","x":1}}}}"#),
        format!(r#"{{"operation":"recv","value":{{"id":"{id}","after":0}}}}"#),
        format!(r#"{{"operation":"join","value":{{"id":"{id}"}}}}"#),
        r#"{"operation":"open","value":{"kind":"pairing","ttl":60,"admission":"owner","candidates":1}}"#.to_owned(),
        r#"{"operation":"open","value":{"kind":"pairing","ttl":60,"admission":"owner","candidates":1,"intro":"","x":0}}"#.to_owned(),
        format!(r#"{{"operation":"hello","value":{{"actor":"{actor}"}}}}"#),
        r#"{"operation":"publish","value":{"record":"AA","dns":false}}"#.to_owned(),
        r#"{"operation":"lookup_node","value":{}}"#.to_owned(),
        format!(r#"{{"operation":"close","value":{{"id":"{id}","id":"{id}"}}}}"#),
    ] {
        assert_eq!(
            decode_request(&text),
            Err(ErrorCode::InvalidMessage),
            "{text}"
        );
    }
    for text in [
        r#"{"result":"record","value":{}}"#.to_owned(),
        r#"{"result":"mailbox","value":{"stage":"open","waiting":[],"messages":[]}}"#.to_owned(),
        r#"{"result":"sent","value":{"seq":1,"extra":0}}"#.to_owned(),
        r#"{"result":"published","value":{}}"#.to_owned(),
        format!(
            r#"{{"result":"challenge","value":{{"nonce":"{}","authority":"a.b:1"}}}}"#,
            b64(&[1; 32])
        ),
        r#"{"result":"directory","value":{"version":1}}"#.to_owned(),
    ] {
        assert_eq!(
            decode_response(&text),
            Err(ErrorCode::InvalidMessage),
            "{text}"
        );
    }
}

#[test]
fn structs_are_objects_and_names_are_strings() {
    let id = b64(&[7; 16]);
    let actor = b64(&[1; 32]);
    for text in [
        r#"["directory",null]"#.to_owned(),
        r#"{"operation":{"directory":null},"value":null}"#.to_owned(),
        format!(r#"{{"operation":"close","value":["{id}"]}}"#),
        format!(r#"{{"operation":"admit","value":["{id}","{actor}"]}}"#),
        r#"{"operation":"open","value":["pairing",60,"owner",1,""]}"#.to_owned(),
        r#"{"operation":"open","value":{"kind":"pairing","ttl":60,"admission":{"owner":null},"candidates":1,"intro":""}}"#.to_owned(),
    ] {
        assert_eq!(decode_request(&text), Err(ErrorCode::InvalidMessage), "{text}");
    }
    for text in [
        r#"["ok",null]"#.to_owned(),
        r#"{"result":{"ok":null},"value":null}"#.to_owned(),
        r#"{"result":"error","value":{"unavailable":null}}"#.to_owned(),
        r#"{"result":"sent","value":[1]}"#.to_owned(),
        r#"{"result":"mailbox","value":{"stage":{"open":null},"waiting":[],"peer":null,"messages":[]}}"#.to_owned(),
        format!(r#"{{"result":"mailbox","value":{{"stage":"open","waiting":[["{actor}",""]],"peer":null,"messages":[]}}}}"#),
        r#"{"result":"mailbox","value":{"stage":"open","waiting":[],"peer":null,"messages":[[1,""]]}}"#.to_owned(),
        r#"{"result":"directory","value":[1,[[1,"KT","a.ns.io",["203.0.113.1"],443,[]]]]}"#.to_owned(),
        r#"{"result":"directory","value":{"version":1,"relays":[[1,"KT","a.ns.io",["203.0.113.1"],443,[]]]}}"#.to_owned(),
    ] {
        assert_eq!(decode_response(&text), Err(ErrorCode::InvalidMessage), "{text}");
    }
    // Leading whitespace before the envelope object is still JSON.
    assert_eq!(
        decode_request(" {\"operation\":\"directory\",\"value\":null}"),
        Ok(Request::Directory)
    );
}

#[test]
fn oversize_messages_are_rejected_before_parsing() {
    // Not JSON at all: only a pre-parse size check can classify it as oversize.
    let garbage = "x".repeat(MAX_MESSAGE_BYTES + 1);
    assert_eq!(decode_request(&garbage), Err(ErrorCode::InvalidMessage));
    assert_eq!(decode_response(&garbage), Err(ErrorCode::InvalidMessage));

    // A valid message padded with whitespace to exactly the limit is accepted, one byte
    // more is not.
    let base = r#"{"operation":"directory","value":null}"#;
    let at_limit = format!("{base}{}", " ".repeat(MAX_MESSAGE_BYTES - base.len()));
    assert_eq!(decode_request(&at_limit), Ok(Request::Directory));
    assert_eq!(
        decode_request(&format!("{at_limit} ")),
        Err(ErrorCode::InvalidMessage)
    );

    // Encoding refuses to produce an oversize message.
    let view = Response::Mailbox(MailboxView {
        stage: Stage::Admitted,
        waiting: vec![],
        peer: None,
        messages: vec![
            MailboxMessage {
                seq: 1,
                data: vec![0; 8192],
            },
            MailboxMessage {
                seq: 2,
                data: vec![0; 8192],
            },
        ],
    });
    assert_eq!(encode_response(&view), Err(ErrorCode::InvalidMessage));
}

#[test]
fn byte_strings_are_strict_unpadded_base64url() {
    assert_eq!(decode_base64url("AQID", 3), Ok(vec![1, 2, 3]));
    assert_eq!(decode_base64url("_-8", 2), Ok(vec![0xff, 0xef]));
    for bad in ["AQ==", "AQ=", "AR", "/+8", "AQ D", "A", "AQID\n"] {
        assert!(decode_base64url(bad, 16).is_err(), "{bad}");
    }
    assert!(decode_base64url("AQID", 2).is_err());

    let id = b64(&[7; 16]);
    let padded = format!("{id}==");
    let standard = b64(&[0xfb; 16]).replace('-', "+").replace('_', "/");
    let short = b64(&[7; 15]);
    let long = b64(&[7; 17]);
    // Non-canonical trailing bits: the last character of 16 bytes carries 2 unused bits.
    let mut trailing = id.clone();
    trailing.pop();
    trailing.push('D');
    for value in [padded, standard, short, long, trailing, "".to_owned()] {
        let text = format!(r#"{{"operation":"close","value":{{"id":"{value}"}}}}"#);
        assert_eq!(
            decode_request(&text),
            Err(ErrorCode::InvalidMessage),
            "{text}"
        );
    }
    // Byte strings are never JSON arrays.
    let text = format!(
        r#"{{"operation":"close","value":{{"id":{:?}}}}}"#,
        [7_u8; 16]
    );
    assert_eq!(decode_request(&text), Err(ErrorCode::InvalidMessage));
}

#[test]
fn out_of_range_values_are_rejected() {
    let id = b64(&[7; 16]);
    let open = |ttl: &str, admission: &str, candidates: &str, intro: &str| {
        format!(
            r#"{{"operation":"open","value":{{"kind":"pairing","ttl":{ttl},"admission":"{admission}","candidates":{candidates},"intro":"{intro}"}}}}"#
        )
    };
    assert!(decode_request(&open("1", "owner", "1", "")).is_ok());
    assert!(decode_request(&open("900", "first", "1", "")).is_ok());
    assert!(decode_request(&open("60", "owner", "4", &b64(&[0; 4096]))).is_ok());
    for text in [
        open("0", "owner", "1", ""),
        open("901", "owner", "1", ""),
        open("-1", "owner", "1", ""),
        open("60.0", "owner", "1", ""),
        open("6e1", "owner", "1", ""),
        open("18446744073709551616", "owner", "1", ""),
        open("\"60\"", "owner", "1", ""),
        open("60", "owner", "0", ""),
        open("60", "owner", "5", ""),
        open("60", "owner", "256", ""),
        open("60", "anyone", "1", ""),
        open("60", "owner", "1", &b64(&[0; 4097])),
        // admission = first requires candidates = 1.
        open("60", "first", "2", ""),
        open("60", "first", "4", ""),
    ] {
        assert_eq!(
            decode_request(&text),
            Err(ErrorCode::InvalidMessage),
            "{text}"
        );
    }
    let recv = |after: &str, wait: &str| {
        format!(
            r#"{{"operation":"recv","value":{{"id":"{id}","after":{after},"wait_ms":{wait}}}}}"#
        )
    };
    assert!(decode_request(&recv("0", "0")).is_ok());
    assert!(decode_request(&recv("18446744073709551615", "20000")).is_ok());
    for text in [
        recv("0", "20001"),
        recv("-1", "0"),
        recv("1.5", "0"),
        recv("0", "1e3"),
    ] {
        assert_eq!(
            decode_request(&text),
            Err(ErrorCode::InvalidMessage),
            "{text}"
        );
    }
    let send = |data: &[u8]| {
        format!(
            r#"{{"operation":"send","value":{{"id":"{id}","data":"{}"}}}}"#,
            b64(data)
        )
    };
    assert!(decode_request(&send(&[0; 8192])).is_ok());
    assert_eq!(
        decode_request(&send(&[0; 8193])),
        Err(ErrorCode::InvalidMessage)
    );

    let publish = |record: &[u8]| {
        format!(
            r#"{{"operation":"publish","value":{{"record":"{}","dns":false,"proof":"{}"}}}}"#,
            b64(record),
            b64(&[0; 64])
        )
    };
    assert!(decode_request(&publish(&[0; 600])).is_ok());
    assert_eq!(
        decode_request(&publish(&[0; 601])),
        Err(ErrorCode::InvalidMessage)
    );
    let record = |record: &[u8]| {
        format!(
            r#"{{"result":"record","value":{{"record":"{}"}}}}"#,
            b64(record)
        )
    };
    assert!(decode_response(&record(&[0; 600])).is_ok());
    assert_eq!(
        decode_response(&record(&[0; 601])),
        Err(ErrorCode::InvalidMessage)
    );

    for text in [
        r#"{"result":"sent","value":{"seq":0}}"#.to_owned(),
        r#"{"result":"published","value":{"expires":-1}}"#.to_owned(),
        r#"{"result":"mailbox","value":{"stage":"done","waiting":[],"peer":null,"messages":[]}}"#
            .to_owned(),
        r#"{"result":"mailbox","value":{"stage":"open","waiting":[],"peer":null,"messages":[{"seq":0,"data":""}]}}"#.to_owned(),
        format!(
            r#"{{"result":"mailbox","value":{{"stage":"open","waiting":[{}],"peer":null,"messages":[]}}}}"#,
            vec![format!(r#"{{"actor":"{}","intro":""}}"#, b64(&[1; 32])); 5].join(",")
        ),
        format!(
            r#"{{"result":"mailbox","value":{{"stage":"open","waiting":[],"peer":null,"messages":[{}]}}}}"#,
            vec![r#"{"seq":1,"data":""}"#; 17].join(",")
        ),
        format!(
            r#"{{"result":"mailbox","value":{{"stage":"open","waiting":[],"peer":"{}","messages":[]}}}}"#,
            b64(&[1; 31])
        ),
    ] {
        assert_eq!(
            decode_response(&text),
            Err(ErrorCode::InvalidMessage),
            "{text}"
        );
    }
}

#[test]
fn lookup_digits_and_kind_are_validated() {
    for digits in [
        "\"0123456\"",
        "\"012345678\"",
        "\"0123456a\"",
        "1234567",
        "\"０１２３４５６７\"",
    ] {
        let text = format!(r#"{{"operation":"lookup","value":{digits}}}"#);
        assert_eq!(
            decode_request(&text),
            Err(ErrorCode::InvalidMessage),
            "{text}"
        );
    }
    let Ok(Request::Lookup(digits)) =
        decode_request(r#"{"operation":"lookup","value":"00000000"}"#)
    else {
        panic!("lookup did not decode");
    };
    assert_eq!(digits.as_str(), "00000000");
    assert!(!format!("{digits:?}").contains('0'));

    for kind in ["", "Pairing", "pair_ing", "pairing.v2", &"a".repeat(33)] {
        let text = format!(
            r#"{{"operation":"open","value":{{"kind":"{kind}","ttl":60,"admission":"owner","candidates":1,"intro":""}}}}"#
        );
        assert_eq!(
            decode_request(&text),
            Err(ErrorCode::InvalidMessage),
            "{text}"
        );
    }
    assert!(Kind::parse(&"a".repeat(32)).is_ok());
    assert!(Kind::parse("file-transfer-2").is_ok());
}

#[test]
fn only_directory_publish_and_lookup_node_skip_hello() {
    let without_hello: Vec<_> = requests()
        .iter()
        .map(Request::operation)
        .filter(|operation| !operation.requires_hello())
        .collect();
    assert_eq!(
        without_hello,
        [
            Operation::Directory,
            Operation::Publish,
            Operation::LookupNode
        ]
    );
    assert!(Operation::Lookup.requires_hello());
    assert!(Operation::Hello.requires_hello());
}
