#![allow(clippy::unwrap_used, clippy::panic)]

use nsshared_control::{
    account::control::BootstrapEnvelope, account::control::EDGE_AUTH_CONFIG_GET,
    account::control::EDGE_MATERIAL_GET, account::control::EnvelopeDirection,
    account::control::EnvelopeExpectation, account::control::EnvelopePins,
    account::edge::AuthConfigRequest, account::edge::EdgeMaterialError,
    account::edge::EdgeMaterialKind, account::edge::EdgeMaterialRequest,
    account::edge::EdgeMaterialResponse, account::edge::EdgeMaterialValues,
};

#[test]
fn confidential_edge_material_generation() {
    assert_eq!(EDGE_MATERIAL_GET, "edge.material.get");
    assert_eq!(EDGE_AUTH_CONFIG_GET, "edge.auth.config.get");
    let vectors = nsshared_testkit::vectors!("account/edge/material-request");
    for vector in &vectors {
        let raw = vector.hex("bytes");
        let pending = EdgeMaterialRequest::decode(&vector.hex("request")).unwrap();
        if vector.get("kind") == "envelope" {
            let envelope = BootstrapEnvelope::decode(&raw).unwrap();
            assert_ne!(envelope.nonce, pending.request_id);
            let pins = EnvelopePins::intersect(&[vector.get("pin").to_owned()], &[]).unwrap();
            let expected = EnvelopeExpectation {
                pins: &pins,
                direction: envelope.direction,
                recipient: envelope.recipient.unwrap(),
                kind: EDGE_MATERIAL_GET,
                now_seconds: 100,
                previous_acceptance_seconds: None,
            };
            envelope.verify(&expected).unwrap();
            assert!(
                envelope
                    .verify(&EnvelopeExpectation {
                        kind: EDGE_AUTH_CONFIG_GET,
                        ..expected
                    })
                    .is_err()
            );
            if envelope.direction == EnvelopeDirection::Request {
                assert_eq!(
                    EdgeMaterialRequest::decode(&envelope.payload).unwrap(),
                    pending
                );
            } else {
                EdgeMaterialResponse::decode(&envelope.payload)
                    .unwrap()
                    .validate_for(&pending)
                    .unwrap();
            }
            assert_eq!(envelope.canonical().unwrap(), raw);
            continue;
        }
        let result = if vector.get("kind") == "request" {
            EdgeMaterialRequest::decode(&raw).and_then(|value| value.canonical())
        } else {
            EdgeMaterialResponse::decode(&raw).and_then(|value| {
                assert_eq!(value.canonical().unwrap(), raw);
                value.validate_for(&pending)?;
                value.canonical()
            })
        };
        match vector.get("reason") {
            "accept" => assert_eq!(result.unwrap(), raw, "{}", vector.name()),
            reason => {
                let error = result.unwrap_err();
                let actual = match error {
                    EdgeMaterialError::Kind => "kind",
                    EdgeMaterialError::Realm => "realm",
                    EdgeMaterialError::Generation => "generation",
                    EdgeMaterialError::Echo => "echo",
                    EdgeMaterialError::Contract(_) => "contract",
                    _ => panic!("unknown refusal"),
                };
                assert_eq!(actual, reason, "{}", vector.name());
            }
        }
    }
}

#[test]
fn material_values_and_auth_boundary() {
    let vectors = nsshared_testkit::vectors!("account/edge/material-request");
    for label in ["certificate-generation", "client-ca-generation"] {
        let vector = vectors.iter().find(|v| v.name() == label).unwrap();
        let raw = vector.hex("bytes");
        let response = EdgeMaterialResponse::decode(&raw).unwrap();
        assert_eq!(response.request.material.generation, 7);
        assert_eq!(response.hostnames, ["a.example.test", "b.example.test"]);
        assert_eq!(response.not_after_unix_seconds, 200);
        match &response.values {
            EdgeMaterialValues::Certificate {
                fullchain_pem,
                private_key_pem,
            } => {
                assert_eq!(
                    fullchain_pem,
                    "-----BEGIN CERTIFICATE-----\nfixture chain\n-----END CERTIFICATE-----\n"
                );
                assert_eq!(
                    private_key_pem,
                    "-----BEGIN PRIVATE KEY-----\nfixture key\n-----END PRIVATE KEY-----\n"
                );
            }
            EdgeMaterialValues::ClientCa {
                ca_pem,
                trust_domain,
            } => {
                assert!(ca_pem.contains("-----BEGIN X509 CRL-----\nfixture CRL\n"));
                assert_eq!(trust_domain, "example.test");
            }
        }
        let debug = format!("{response:?}");
        for secret in ["fixture chain", "fixture key", "fixture CA", "fixture CRL"] {
            assert!(!debug.contains(secret));
        }
        assert!(AuthConfigRequest::decode(&vector.hex("request")).is_err());
        let mut request = response.request.clone();
        request.material.kind = EdgeMaterialKind::Auth;
        assert!(matches!(request.canonical(), Err(EdgeMaterialError::Kind)));
        assert!(matches!(
            response.validate_for(&request),
            Err(EdgeMaterialError::Kind)
        ));
        let mut invalid = response.clone();
        invalid.hostnames.push("*.test".into());
        assert!(invalid.canonical().is_err());
        let mut oversized = response.clone();
        oversized.values = EdgeMaterialValues::Certificate {
            fullchain_pem: "x".repeat(1_048_576),
            private_key_pem: "key".into(),
        };
        assert!(oversized.canonical().is_err());
    }
    for length in [1_048_577, 1_048_578] {
        assert!(EdgeMaterialRequest::decode(&vec![0; length]).is_err());
        assert!(EdgeMaterialResponse::decode(&vec![0; length]).is_err());
    }
}
