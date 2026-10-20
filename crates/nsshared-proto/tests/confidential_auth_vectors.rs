#![allow(clippy::unwrap_used, clippy::panic)]
mod support;
use nsshared_proto::account::{
    BootstrapEnvelope, EdgeMaterialKind, EdgeMaterialRef, EnvelopeDirection, EnvelopeExpectation,
    EnvelopePins,
    confidential_auth::{
        AuthConfigError, AuthConfigRequest, AuthConfigResponse, AuthConfiguration,
    },
    control_exchange::EDGE_AUTH_CONFIG_GET,
};

#[test]
fn confidential_auth_generation() {
    let vectors = support::vectors::parse(include_str!("fixtures/vectors/confidential-auth.vec"));
    for vector in &vectors {
        let raw = vector.hex("bytes");
        let pending = AuthConfigRequest::decode(&vector.hex("request")).unwrap();
        let result = match vector.get("kind") {
            "request" => AuthConfigRequest::decode(&raw).and_then(|v| v.canonical()),
            "configuration" => AuthConfiguration::decode(&raw).and_then(|v| v.canonical()),
            "response-codec" => AuthConfigResponse::decode(&raw).and_then(|v| v.canonical()),
            "response" => {
                let value = AuthConfigResponse::decode(&raw).unwrap();
                assert_eq!(value.canonical().unwrap(), raw);
                let result = value.validate_for(&pending, pending.realm, &pending.material);
                match vector.name() {
                    "confidential_auth_generation" => result.unwrap(),
                    "wrong-correlation" => {
                        assert!(matches!(result, Err(AuthConfigError::Correlation)))
                    }
                    "wrong-recipient" | "wrong-served-realm" | "wrong-scope" => {
                        assert!(matches!(result, Err(AuthConfigError::Scope)))
                    }
                    "wrong-realm" | "wrong-payload-realm" => {
                        assert!(matches!(result, Err(AuthConfigError::Realm)))
                    }
                    "wrong-reference" => assert!(matches!(result, Err(AuthConfigError::Reference))),
                    "wrong-generation" | "wrong-payload-generation" => {
                        assert!(matches!(result, Err(AuthConfigError::Generation)))
                    }
                    _ => panic!("unknown response vector"),
                }
                continue;
            }
            "envelope" => {
                let envelope = BootstrapEnvelope::decode(&raw).unwrap();
                let pins = EnvelopePins::intersect(&[vector.get("pin").to_owned()], &[]).unwrap();
                let expected = EnvelopeExpectation {
                    pins: &pins,
                    direction: envelope.direction,
                    recipient: envelope.recipient.unwrap(),
                    kind: EDGE_AUTH_CONFIG_GET,
                    now_seconds: 100,
                    previous_acceptance_seconds: None,
                };
                envelope.verify(&expected).unwrap();
                if envelope.direction == EnvelopeDirection::Request {
                    assert_eq!(
                        AuthConfigRequest::decode(&envelope.payload).unwrap(),
                        pending
                    );
                } else {
                    let response = AuthConfigResponse::decode(&envelope.payload).unwrap();
                    response
                        .validate_for(&pending, pending.realm, &pending.material)
                        .unwrap();
                    let wrong_direction = EnvelopeExpectation {
                        direction: EnvelopeDirection::Request,
                        ..expected
                    };
                    assert!(envelope.verify(&wrong_direction).is_err());
                }
                assert_eq!(envelope.canonical().unwrap(), raw);
                continue;
            }
            _ => panic!("unknown vector kind"),
        };
        assert_eq!(
            result.is_ok(),
            vector.get("expect") == "accept",
            "{}: {result:?}",
            vector.name()
        );
        if let Ok(encoded) = result {
            assert_eq!(encoded, raw);
        }
    }
}

#[test]
fn confidential_auth_current_dependency_and_refusals() {
    let vectors = support::vectors::parse(include_str!("fixtures/vectors/confidential-auth.vec"));
    let vector = vectors
        .iter()
        .find(|v| v.name() == "confidential_auth_generation")
        .unwrap();
    let pending = AuthConfigRequest::decode(&vector.hex("request")).unwrap();
    let response = AuthConfigResponse::decode(&vector.hex("bytes")).unwrap();
    assert_eq!(response.configuration.generation, 7);
    assert_eq!(
        response.configuration.providers[0].subject_realm,
        "external namespace"
    );
    assert_eq!(response.configuration.credentials.len(), 4);
    assert_eq!(response.configuration.imports[0].methods.len(), 6);
    assert_eq!(
        response.configuration.imports[0].methods[2].reference,
        "__ns_realm__"
    );
    assert_eq!(
        response.configuration.cookie_keys.current.value,
        "11".repeat(32)
    );
    let debug = format!("{response:?}");
    assert!(!debug.contains("fixture client secret"));
    assert!(!debug.contains(&"11".repeat(32)));
    assert!(!debug.contains(&"22".repeat(32)));
    assert!(matches!(
        response.validate_for(&pending, [9; 16], &pending.material),
        Err(AuthConfigError::Dependency)
    ));
    for material in [
        EdgeMaterialRef {
            generation: 8,
            ..pending.material.clone()
        },
        EdgeMaterialRef {
            reference: "other".into(),
            ..pending.material.clone()
        },
        EdgeMaterialRef {
            kind: EdgeMaterialKind::Certificate,
            ..pending.material.clone()
        },
    ] {
        assert!(matches!(
            response.validate_for(&pending, pending.realm, &material),
            Err(AuthConfigError::Dependency)
        ));
    }
    let mut changed = response.clone();
    changed.request.request_id[0] ^= 1;
    assert!(matches!(
        changed.validate_for(&pending, pending.realm, &pending.material),
        Err(AuthConfigError::Correlation)
    ));
    changed = response.clone();
    changed.configuration.generation += 1;
    assert!(matches!(
        changed.validate_for(&pending, pending.realm, &pending.material),
        Err(AuthConfigError::Generation)
    ));
    for length in [1_048_577, 1_048_578] {
        assert!(AuthConfiguration::decode(&vec![0; length]).is_err());
        assert!(AuthConfigResponse::decode(&vec![0; length]).is_err());
        assert!(AuthConfigRequest::decode(&vec![0; length]).is_err());
    }
}
