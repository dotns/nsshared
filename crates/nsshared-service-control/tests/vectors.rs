#![allow(clippy::unwrap_used)]

use nsshared_service_control::{
    BackendHost, Declaration, ListenerIntent, Message, MessageBody, PortMode, Protocols,
    ReportContent, ServiceRef, Value, decode_canonical, encode_canonical, snapshot_digest,
};
use serde_json::Value as Json;

fn vectors() -> Json {
    serde_json::from_str(include_str!("../vectors/service-control-v1.json")).unwrap()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn field<'a>(vectors: &'a Json, key: &str) -> &'a str {
    vectors[key].as_str().unwrap()
}

fn sample() -> (ReportContent, ListenerIntent) {
    let nsd_id = std::array::from_fn(|index| index as u8);
    let network_id = std::array::from_fn(|index| (index + 16) as u8);
    let service_id = std::array::from_fn(|index| (index + 32) as u8);
    let protocols = Protocols {
        tcp: true,
        udp: true,
    };
    let backend_host = BackendHost::Ipv4([127, 0, 0, 1]);
    let publisher_identity = std::array::from_fn(|index| index as u8);
    let report = ReportContent {
        publisher_identity,
        nsd_id,
        network_id,
        strict_mode: true,
        declarations: vec![Declaration {
            declaration_key: "alpha".into(),
            display_name: Some("Alpha".into()),
            description: None,
            enabled: true,
            protocols,
            backend_host: backend_host.clone(),
            backend_port: 8080,
            port_mode: PortMode::Auto,
        }],
    };
    let listener = ListenerIntent {
        service_ref: ServiceRef {
            nsd_id,
            network_id,
            service_id,
        },
        publisher_identity,
        listener_revision: 1,
        port: 8080,
        protocols,
        backend_host,
        backend_port: 8080,
        enforcement_policy_version: 1,
        enforcement_policy_digest: [0x5a; 32],
    };
    (report, listener)
}

#[test]
fn independent_report_and_listener_vectors() {
    let vectors = vectors();
    let (report, listener) = sample();
    let (report_bytes, report_digest) = report.canonical().unwrap();
    let (listener_bytes, listener_digest) = listener.canonical().unwrap();
    assert_eq!(hex(&report_bytes), field(&vectors, "report_cbor"));
    assert_eq!(hex(&report_digest), field(&vectors, "report_sha256"));
    assert_eq!(hex(&listener_bytes), field(&vectors, "listener_cbor"));
    assert_eq!(hex(&listener_digest), field(&vectors, "listener_sha256"));
    assert_eq!(
        encode_canonical(&decode_canonical(&report_bytes).unwrap()).unwrap(),
        report_bytes
    );
    assert_eq!(ReportContent::decode(&report_bytes).unwrap(), report);
    assert_eq!(ListenerIntent::decode(&listener_bytes).unwrap(), listener);

    let mut renamed = report;
    renamed.declarations[0].display_name = Some("Renamed".into());
    assert_eq!(
        hex(&renamed.canonical().unwrap().1),
        field(&vectors, "report_renamed_sha256")
    );
    assert_eq!(listener.canonical().unwrap().1, listener_digest);
    let mut changed_backend = listener;
    changed_backend.backend_port = 8081;
    assert_eq!(
        hex(&changed_backend.canonical().unwrap().1),
        field(&vectors, "listener_backend_changed_sha256")
    );
}

#[test]
fn independent_snapshot_vector() {
    let vectors = vectors();
    let publisher: [u8; 32] = std::array::from_fn(|index| index as u8);
    let nsd: [u8; 16] = std::array::from_fn(|index| index as u8);
    let network: [u8; 16] = std::array::from_fn(|index| (index + 16) as u8);
    let snapshot = Value::Map(vec![
        ("withdrawals".into(), Value::Array(vec![])),
        ("resources".into(), Value::Array(vec![])),
        ("routes".into(), Value::Array(vec![])),
        (
            "scope".into(),
            Value::Array(vec![
                Value::Bytes(publisher.to_vec()),
                Value::Bytes(nsd.to_vec()),
                Value::Bytes(network.to_vec()),
            ]),
        ),
        ("snapshot_revision".into(), Value::UInt(1)),
        ("grants".into(), Value::Array(vec![])),
        ("listeners".into(), Value::Array(vec![])),
    ]);
    assert_eq!(
        hex(&encode_canonical(&snapshot).unwrap()),
        field(&vectors, "snapshot_empty_cbor")
    );
    assert_eq!(
        hex(&snapshot_digest(&snapshot).unwrap()),
        field(&vectors, "snapshot_empty_sha256")
    );
}

#[test]
fn rejects_noncanonical_and_unknown_fields() {
    assert!(decode_canonical(&[0x18, 0x01]).is_err());
    assert!(decode_canonical(&[0xa2, 0x61, b'a', 0x01, 0x61, b'a', 0x02]).is_err());
    assert!(decode_canonical(&[0xa2, 0x61, b'b', 0x01, 0x61, b'a', 0x02]).is_err());
    assert!(decode_canonical(&[0xbf, 0xff]).is_err());
    assert!(decode_canonical(&[0xf9, 0x3c, 0x00]).is_err());

    let envelope = Message {
        nsd_id: [1; 16],
        network_id: [2; 16],
        subject_identity: [3; 32],
        runtime_generation: None,
        runtime_id: None,
        authority_epoch: None,
        request_id: [4; 16],
        session_seq: None,
        body: MessageBody::RuntimeFloor,
    };
    let mut decoded = decode_canonical(&envelope.encode().unwrap()).unwrap();
    if let Value::Map(ref mut fields) = decoded {
        fields.push(("future_field".into(), Value::Bool(true)));
    }
    assert!(Message::decode(&encode_canonical(&decoded).unwrap()).is_err());
}
