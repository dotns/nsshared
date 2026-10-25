//! Independent specification vectors and predecessor fixture byte equivalence.
#![allow(clippy::unwrap_used)]

use nsshared_codec::cbor::CborError;
use nsshared_control::{
    node_control, node_control::CodecError, node_control::Message, node_control::ack_hash,
};

#[test]
fn node_control_vectors() {
    assert_eq!(node_control::VERSION, 2);
    assert_eq!(node_control::CONTROL_PORT, 47900);
    assert_eq!(node_control::MAX_MESSAGE_BYTES, 1200);
    assert_eq!(node_control::MAX_CANDIDATES, 8);
    assert_eq!(node_control::MAX_RELAYS, 4);
    for vector in nsshared_testkit::vectors!("node_control/messages") {
        if vector.opt("hash_input").is_some() {
            assert_eq!(ack_hash(b""), vector.hex_array::<16>("ack_hash"));
            continue;
        }
        let encoded = vector.hex("encoded");
        if vector.is_reject() {
            let error = Message::decode(&encoded).unwrap_err();
            let matches = match vector.reason() {
                "version" => error == CodecError::Version(1),
                "type" => error == CodecError::Type(5),
                "ack-type-overflow" => error == CodecError::Type(0),
                "oversize" => error == CodecError::TooLarge(1201),
                "candidate-count" | "relay-count" => error == CodecError::TooMany,
                "candidate-ip"
                | "candidate-port-zero"
                | "candidate-port-overflow"
                | "candidate-kind" => error == CodecError::Candidate,
                "relay" => matches!(error, CodecError::Relay(_)),
                "record-signature" => matches!(error, CodecError::Record(_)),
                "non-shortest" => error == CodecError::Cbor(CborError::NonShortest),
                "trailing" => error == CodecError::Cbor(CborError::TrailingBytes),
                _ => matches!(error, CodecError::Cbor(_)),
            };
            assert!(matches, "{}: {error:?}", vector.name());
        } else {
            let message = Message::decode(&encoded).unwrap();
            assert_eq!(message.encode().unwrap(), encoded, "{}", vector.name());
            assert_eq!(ack_hash(&encoded), vector.hex_array::<16>("ack_hash"));
        }
    }
}

#[test]
fn node_control_matches_pinned_gateway_bytes() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/node_control/predecessor.json"
    )))
    .unwrap();
    assert_eq!(
        fixture["source_commit"],
        "50f8e3fd95fac8bbc72aea9b132459103c3b206a"
    );
    let generated = nsshared_testkit::vectors!("node_control/messages");
    for (name, value) in fixture["vectors"].as_object().unwrap() {
        let bytes = nsshared_testkit::hex::decode(value.as_str().unwrap()).unwrap();
        let independent = generated
            .iter()
            .find(|vector| vector.name() == name)
            .unwrap();
        assert_eq!(independent.hex("encoded"), bytes, "{name}");
        assert_eq!(
            Message::decode(&bytes).unwrap().encode().unwrap(),
            bytes,
            "{name}"
        );
    }
}
