#![allow(clippy::unwrap_used, clippy::panic)]
use nsshared_control::account::AccountError;

use nsshared_codec::{cbor::CborError, cbor::CborReader, cbor::CborWriter};
use nsshared_control::{
    account::control::BootstrapDiscovery, account::control::BootstrapEnvelope,
    account::control::BootstrapError, account::control::ConfidentialCarrier,
    account::control::ControlBoundary, account::control::EnvelopeDirection,
    account::control::EnvelopeExpectation, account::control::EnvelopePins,
    account::control::validate_control_input,
};
use nsshared_testkit::fixture::identity_hex as identity;
use nsshared_testkit::hex::unhex as bytes;
use std::collections::{BTreeMap, BTreeSet};

type Vector = BTreeMap<&'static str, &'static str>;

fn fixtures() -> Vec<Vector> {
    nsshared_testkit::vector_fields!("account/control/envelope")
        .into_iter()
        .filter(|fields| {
            fields
                .get("kind")
                .is_some_and(|kind| kind.starts_with("bootstrap-"))
        })
        .collect()
}

fn pins(value: &str) -> Vec<String> {
    let raw = bytes(value);
    let mut reader = CborReader::new(&raw, raw.len()).unwrap();
    let count = reader.array_up_to(raw.len()).unwrap();
    let result = (0..count)
        .map(|_| reader.text_up_to(256).unwrap().to_owned())
        .collect();
    reader.finish().unwrap();
    result
}

fn evaluate(v: &Vector) -> Result<(), BootstrapError> {
    let raw = bytes(v["bytes"]);
    match v["kind"] {
        "bootstrap-discovery" => {
            let value = BootstrapDiscovery::decode(&raw)?;
            let effective = value.effective_envelope_pins(&pins(v["local_pins"]))?;
            assert_eq!(value.canonical()?, bytes(v["canonical"]));
            assert_eq!(value.https_origin, v["origin"]);
            let mut endpoints = CborWriter::default();
            endpoints.array(value.endpoints.len());
            for endpoint in &value.endpoints {
                endpoints
                    .array(2)
                    .uint(endpoint.kind as u64)
                    .text(&endpoint.origin);
            }
            assert_eq!(endpoints.into_bytes(), bytes(v["endpoints"]));
            let mut noise = CborWriter::default();
            if let Some(key) = value.noise_key {
                noise.bytes(&key);
            } else {
                noise.null();
            }
            assert_eq!(noise.into_bytes(), bytes(v["noise"]));
            let supported_raw = bytes(v["supported"]);
            let mut reader = CborReader::new(&supported_raw, 16).unwrap();
            let count = reader.array_up_to(3).unwrap();
            let supported: Vec<_> = (0..count)
                .map(|_| match reader.uint().unwrap() {
                    0 => ConfidentialCarrier::Https,
                    1 => ConfidentialCarrier::Noise,
                    2 => ConfidentialCarrier::Quic,
                    other => panic!("unknown carrier {other}"),
                })
                .collect();
            reader.finish().unwrap();
            let mut selected = CborWriter::default();
            if let Some(endpoint) = value.first_supported(&supported)? {
                selected
                    .array(2)
                    .uint(endpoint.kind as u64)
                    .text(&endpoint.origin);
            } else {
                selected.null();
            }
            assert_eq!(selected.into_bytes(), bytes(v["selected"]));
            assert_eq!(value.quic_spki_pins, pins(v["quic_pins"]));
            assert_eq!(effective.as_slice(), pins(v["effective_pins"]));
        }
        "bootstrap-envelope" => {
            let effective =
                EnvelopePins::intersect(&pins(v["discovered_pins"]), &pins(v["local_pins"]))?;
            let value = BootstrapEnvelope::decode(&raw)?;
            let seen_raw = bytes(v["seen"]);
            let mut seen_reader = CborReader::new(&seen_raw, 16).unwrap();
            let seen = if seen_reader.take_null() {
                None
            } else {
                Some(seen_reader.uint().unwrap())
            };
            seen_reader.finish().unwrap();
            value.verify(&EnvelopeExpectation {
                pins: &effective,
                direction: if v["direction"] == "0" {
                    EnvelopeDirection::Request
                } else {
                    EnvelopeDirection::Response
                },
                recipient: identity(v["recipient"]),
                kind: v["expected_kind"],
                now_seconds: v["now"].parse().unwrap(),
                previous_acceptance_seconds: seen,
            })?;
            assert_eq!(value.canonical()?, bytes(v["canonical"]));
            assert_eq!(value.signer, identity(v["issuer"]));
            let mut recipient = CborWriter::default();
            if let Some(key) = value.recipient {
                recipient.bytes(key.as_bytes());
            } else {
                recipient.null();
            }
            assert_eq!(recipient.into_bytes(), bytes(v["named_recipient"]));
            assert_eq!(value.payload, bytes(v["payload"]));
            assert_eq!(value.nonce.as_slice(), bytes(v["nonce"]));
            assert_eq!(value.unix_seconds, v["timestamp"].parse::<u64>().unwrap());
        }
        "bootstrap-boundary" => {
            let boundary = match v["boundary"] {
                "0" => ControlBoundary::Discovery,
                "1" => ControlBoundary::CallBody,
                "2" => ControlBoundary::Headers,
                "3" => ControlBoundary::EncodedSubscription,
                "4" => ControlBoundary::NoisePayload,
                "5" => ControlBoundary::NoiseFrame,
                other => panic!("unknown boundary {other}"),
            };
            validate_control_input(boundary, &raw)?;
        }
        other => panic!("unknown fixture kind {other}"),
    }
    Ok(())
}

fn decision(value: Result<(), BootstrapError>) -> &'static str {
    match value {
        Ok(()) => "accepted",
        Err(BootstrapError::Version) => "version",
        Err(BootstrapError::Origin) => "origin",
        Err(BootstrapError::Endpoints) => "endpoints",
        Err(BootstrapError::EndpointKind) => "endpoint-kind",
        Err(BootstrapError::NoiseKey) => "noise-key",
        Err(BootstrapError::QuicPins) => "quic-pins",
        Err(BootstrapError::Pins) => "pins",
        Err(BootstrapError::EmptyPins) => "empty-pins",
        Err(BootstrapError::EmptyIntersection) => "empty-intersection",
        Err(BootstrapError::Signer) => "signer",
        Err(BootstrapError::Recipient) => "recipient",
        Err(BootstrapError::Kind) => "kind",
        Err(BootstrapError::Direction) => "direction",
        Err(BootstrapError::Clock) => "clock",
        Err(BootstrapError::Replay) => "replay",
        Err(BootstrapError::Signature) => "signature",
        Err(BootstrapError::Bounds) => "bounds",
        Err(BootstrapError::Contract(AccountError::Cbor(CborError::NonShortest))) => "nonminimal",
        Err(BootstrapError::Contract(AccountError::Cbor(CborError::TrailingBytes))) => "trailing",
        other => panic!("unexpected decision {other:?}"),
    }
}

#[test]
fn bootstrap_envelope_vectors() {
    let vectors = fixtures();
    assert!(vectors.len() >= 60);
    for v in &vectors {
        assert_eq!(decision(evaluate(v)), v["decision"], "{}", v["name"]);
    }
}

#[test]
fn trust_downgrade_refusals() {
    let vectors = fixtures();
    let mut names = BTreeSet::new();
    for v in vectors.iter().filter(|v| v["expect"] == "reject") {
        let result = evaluate(v);
        assert!(result.is_err(), "{}", v["name"]);
        assert_eq!(decision(result), v["decision"], "{}", v["name"]);
        names.insert(v["name"]);
    }
    for name in [
        "plaintext-discovery",
        "plaintext-kind",
        "unknown-kind",
        "noise-without-key",
        "quic-without-pins",
        "missing-envelope-version",
        "unsupported-envelope-version",
        "envelope-missing-version",
        "envelope-unsupported-version",
        "unpinned-signer",
        "empty-intersection",
        "wrong-domain",
        "wrong-recipient",
        "stale",
        "future",
        "noncanonical-envelope-pin",
        "duplicate-envelope-pins",
        "discovery-oversize",
        "declared-carrier-oversize",
        "envelope-trailing",
        "content-nonminimal",
    ] {
        assert!(
            names.contains(format!("bootstrap-{name}").as_str()),
            "missing refusal {name}"
        );
    }
}

#[test]
fn canonical_carriers_refuse_altered_encodings() {
    for v in fixtures()
        .iter()
        .filter(|v| v["expect"] == "accept" && v["kind"] != "bootstrap-boundary")
    {
        let original = bytes(v["canonical"]);
        let decode = |raw: &[u8]| match v["kind"] {
            "bootstrap-discovery" => BootstrapDiscovery::decode(raw).map(|_| ()),
            "bootstrap-envelope" => BootstrapEnvelope::decode(raw).map(|_| ()),
            other => panic!("unknown canonical kind {other}"),
        };
        let mut trailing = original.clone();
        trailing.push(0);
        assert!(
            matches!(
                decode(&trailing),
                Err(BootstrapError::Contract(AccountError::Cbor(
                    CborError::TrailingBytes
                )))
            ),
            "{}",
            v["name"]
        );
        let mut nonminimal = vec![0x98, original[0] & 31];
        nonminimal.extend_from_slice(&original[1..]);
        assert!(
            matches!(
                decode(&nonminimal),
                Err(BootstrapError::Contract(AccountError::Cbor(
                    CborError::NonShortest
                )))
            ),
            "{}",
            v["name"]
        );
    }
}

#[test]
fn constructed_contracts_enforce_trust_before_selection_and_verification() {
    let vectors = fixtures();
    let v = vectors
        .iter()
        .find(|v| v["name"] == "bootstrap-discovery")
        .unwrap();
    let valid = BootstrapDiscovery::decode(&bytes(v["bytes"])).unwrap();
    let mut duplicate = valid.clone();
    duplicate.endpoints.push(duplicate.endpoints[0].clone());
    assert!(matches!(
        duplicate.canonical(),
        Err(BootstrapError::Endpoints)
    ));
    assert!(matches!(
        duplicate.first_supported(&[ConfidentialCarrier::Https]),
        Err(BootstrapError::Endpoints)
    ));
    let mut missing_noise = valid.clone();
    missing_noise.noise_key = None;
    assert!(matches!(
        missing_noise.effective_envelope_pins(&[]),
        Err(BootstrapError::NoiseKey)
    ));
    let mut missing_quic = valid.clone();
    missing_quic.quic_spki_pins.clear();
    assert!(matches!(
        missing_quic.canonical(),
        Err(BootstrapError::QuicPins)
    ));
    let mut missing_pins = valid.clone();
    missing_pins.envelope_pins.clear();
    assert!(matches!(
        missing_pins.canonical(),
        Err(BootstrapError::EmptyPins)
    ));
    let effective = valid.effective_envelope_pins(&[]).unwrap();
    let v = vectors
        .iter()
        .find(|v| v["name"] == "bootstrap-response")
        .unwrap();
    let mut carrier = BootstrapEnvelope::decode(&bytes(v["bytes"])).unwrap();
    let expected = EnvelopeExpectation {
        pins: &effective,
        direction: EnvelopeDirection::Response,
        recipient: identity(v["recipient"]),
        kind: v["expected_kind"],
        now_seconds: 1000,
        previous_acceptance_seconds: None,
    };
    carrier.kind.clear();
    assert!(matches!(carrier.canonical(), Err(BootstrapError::Kind)));
    assert!(matches!(
        carrier.verify(&expected),
        Err(BootstrapError::Kind)
    ));
    carrier.kind = expected.kind.to_owned();
    carrier.payload.push(0);
    assert!(matches!(
        carrier.verify(&expected),
        Err(BootstrapError::Signature)
    ));
    carrier.payload = vec![0; nsshared_control::account::control::MAX_CONTROL_BODY];
    assert!(matches!(carrier.canonical(), Err(BootstrapError::Bounds)));
    assert!(matches!(
        carrier.verify(&expected),
        Err(BootstrapError::Bounds)
    ));
}

fn discovery_fields(raw: &[u8]) -> BootstrapDiscovery {
    // Read fixture fields independently so construction paths also receive the
    // invalid origins that the public decoder must refuse.
    let mut input = CborReader::new(raw, raw.len()).unwrap();
    input.array(8).unwrap();
    assert_eq!(input.uint().unwrap(), 1);
    assert_eq!(input.uint().unwrap(), 1);
    let https_origin = input.text_up_to(raw.len()).unwrap().to_owned();
    input.array(1).unwrap();
    assert_eq!(input.uint().unwrap(), 1);
    let count = input.array_up_to(raw.len()).unwrap();
    let endpoints = (0..count)
        .map(|_| {
            input.array(2).unwrap();
            let kind = match input.uint().unwrap() {
                0 => ConfidentialCarrier::Https,
                1 => ConfidentialCarrier::Noise,
                2 => ConfidentialCarrier::Quic,
                other => panic!("unknown endpoint kind {other}"),
            };
            let origin = input.text_up_to(raw.len()).unwrap().to_owned();
            nsshared_control::account::control::BootstrapEndpoint { kind, origin }
        })
        .collect();
    let noise_key = if input.take_null() {
        None
    } else {
        Some(input.fixed_bytes().unwrap())
    };
    let mut string_array = || {
        let count = input.array_up_to(raw.len()).unwrap();
        (0..count)
            .map(|_| input.text_up_to(raw.len()).unwrap().to_owned())
            .collect()
    };
    let quic_spki_pins = string_array();
    let envelope_pins = string_array();
    input.finish().unwrap();
    BootstrapDiscovery {
        https_origin,
        endpoints,
        noise_key,
        quic_spki_pins,
        envelope_pins,
    }
}

#[test]
fn canonical_idna_origin_vectors() {
    let vectors = fixtures();
    let origins: Vec<_> = vectors
        .iter()
        .filter(|v| v.contains_key("origin_site"))
        .collect();
    for site in ["source", "https", "noise", "quic"] {
        for case in [
            "valid-dns",
            "valid-dns-hyphens",
            "valid-umlaut",
            "valid-accent",
            "valid-cjk",
            "valid-sharp-s",
            "valid-rtl",
            "forbidden-control",
            "incomplete-punycode",
            "forbidden-controls",
            "noncanonical-case",
            "noncanonical-nfc",
            "leading-combining-mark",
            "forbidden-joiner",
            "invalid-bidi",
            "unassigned-codepoint",
            "mapped-codepoint",
            "unicode-not-ascii",
        ] {
            let name = format!("bootstrap-idna-{case}-{site}");
            assert!(
                origins
                    .iter()
                    .any(|v| v["name"] == name && v["origin_site"] == site),
                "missing {name}"
            );
        }
    }
    for v in origins {
        let raw = bytes(v["bytes"]);
        let value = discovery_fields(&raw);
        let results = [
            BootstrapDiscovery::decode(&raw).map(|_| ()),
            value.canonical().map(|_| ()),
            value
                .first_supported(&[
                    ConfidentialCarrier::Https,
                    ConfidentialCarrier::Noise,
                    ConfidentialCarrier::Quic,
                ])
                .map(|_| ()),
            value.effective_envelope_pins(&[]).map(|_| ()),
        ];
        for (path, result) in [
            "decode",
            "canonical",
            "first_supported",
            "effective_envelope_pins",
        ]
        .into_iter()
        .zip(results)
        {
            assert_eq!(decision(result), v["decision"], "{}: {path}", v["name"]);
        }
        if v["decision"] == "accepted" {
            assert_eq!(value.canonical().unwrap(), raw, "{}", v["name"]);
        }
    }
}
