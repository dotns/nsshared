#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod support;
use nsshared_proto::{
    IdentityKey,
    account::{control_exchange::*, machine_token::*, *},
};

#[test]
fn candidate_control_exchange_vectors() {
    let vectors = support::vectors::parse(include_str!("fixtures/vectors/control-exchange.vec"));
    for v in &vectors {
        let bytes = v.hex("bytes");
        let accepted = v.get("decision") == "accepted";
        match v.get("kind") {
            "registration" => assert_eq!(
                RegistrationRequest::decode(&bytes).is_ok(),
                accepted,
                "{}",
                v.name()
            ),
            "acceptance" => assert_eq!(
                RegistrationAcceptance::decode(&bytes).is_ok(),
                accepted,
                "{}",
                v.name()
            ),
            "authentication" => assert_eq!(
                AuthenticationRequest::decode(&bytes).is_ok(),
                accepted,
                "{}",
                v.name()
            ),
            "token-response" => assert_eq!(
                AuthenticationResponse::decode(&bytes).is_ok(),
                accepted,
                "{}",
                v.name()
            ),
            "information-request" => assert_eq!(
                InformationRequest::decode(&bytes).is_ok(),
                accepted,
                "{}",
                v.name()
            ),
            "information" => assert_eq!(
                InformationResponse::decode(&bytes).is_ok(),
                accepted,
                "{}",
                v.name()
            ),
            "match" | "signed-request" | "signed-authentication" => {
                let envelope = BootstrapEnvelope::decode(&bytes).unwrap();
                assert_eq!(envelope.signing_input().unwrap(), v.hex("signing_input"));
                assert_eq!(envelope.canonical().unwrap(), bytes);
                let pins = EnvelopePins::intersect(&[v.get("pin").to_owned()], &[]).unwrap();
                let node = IdentityKey::from_bytes(&v.hex("node").try_into().unwrap()).unwrap();
                let expected = EnvelopeExpectation {
                    pins: &pins,
                    direction: envelope.direction,
                    recipient: if v.get("kind") == "match" {
                        node
                    } else {
                        IdentityKey::from_bytes(&v.hex("authority").try_into().unwrap()).unwrap()
                    },
                    kind: if v.get("kind") == "signed-authentication" {
                        MACHINE_AUTH
                    } else {
                        MACHINE_REGISTER
                    },
                    now_seconds: 100,
                    previous_acceptance_seconds: None,
                };
                if v.get("kind") == "match" {
                    let request = RegistrationRequest::decode(&v.hex("request")).unwrap();
                    let committed = v
                        .opt("committed")
                        .map(|_| Enrollment::decode(&v.hex("committed")).unwrap());
                    let rebind = if v.opt("rebind") == Some("yes") {
                        RebindAuthorization::Authorized
                    } else {
                        RebindAuthorization::Denied
                    };
                    let result = compare_registration_acceptance(
                        &envelope,
                        &expected,
                        &request,
                        committed.as_ref().map(|e| &e.binding),
                        rebind,
                    );
                    let decision = match result {
                        Ok(_) => "accepted",
                        Err(ExchangeError::Enrollment(EnrollmentError::RebindUnauthorized)) => {
                            "rebind"
                        }
                        Err(ExchangeError::Scope) => "scope",
                        Err(ExchangeError::Profile) => "profile",
                        Err(ExchangeError::Binding) => "binding",
                        Err(ExchangeError::Capabilities) => "capabilities",
                        Err(ExchangeError::Lifecycle) => "lifecycle",
                        Err(ExchangeError::Envelope(_)) => "authority",
                        other => panic!("unexpected result: {other:?}"),
                    };
                    assert_eq!(decision, v.get("decision"), "{}", v.name());
                } else if v.get("kind") == "signed-authentication" {
                    let payload = AuthenticationRequest::decode(&envelope.payload).unwrap();
                    let request = AuthenticationRequest::from_envelope(
                        &envelope,
                        &expected,
                        &payload.scope,
                        &payload.binding,
                    )
                    .unwrap();
                    assert_eq!(request.binding.identity, node);
                    let mut wrong = request.binding.clone();
                    wrong.wg_key = [99; 32];
                    assert!(matches!(
                        AuthenticationRequest::from_envelope(
                            &envelope,
                            &expected,
                            &request.scope,
                            &wrong
                        ),
                        Err(ExchangeError::Binding)
                    ));
                } else {
                    let request = RegistrationRequest::from_envelope(&envelope, &expected).unwrap();
                    assert_eq!(request.enrollment.binding.identity, node);
                    assert_eq!(request.canonical().unwrap(), envelope.payload);
                }
            }
            "gateway-claims" | "nsd-audience" => {
                let claims = MachineClaims::decode_json(&bytes).unwrap();
                let node = IdentityKey::from_bytes(&v.hex("node").try_into().unwrap()).unwrap();
                let result = if v.get("kind") == "nsd-audience" {
                    claims.validate_nsd_audience()
                } else {
                    claims.validate_gateway("machine-a", node, false, v.get("now").parse().unwrap())
                };
                let decision = match result {
                    Ok(()) => "accepted",
                    Err(TokenError::Audience) => "audience",
                    Err(TokenError::Expired) => "expired",
                    Err(TokenError::Subject) => "subject",
                    Err(TokenError::SelfBinding) => "self-binding",
                    other => panic!("{other:?}"),
                };
                assert_eq!(decision, v.get("decision"), "{}", v.name());
            }
            "trust" => {
                let set = JwkSet::decode_json(&bytes).unwrap();
                let pins: Vec<String> = serde_json::from_str(v.get("pins_json")).unwrap();
                let stored: Option<Vec<String>> =
                    serde_json::from_str(v.get("stored_json")).unwrap();
                let kid: Option<String> = serde_json::from_str(v.get("kid_json")).unwrap();
                let qualified = qualify_key_set(&set, &pins, stored.as_deref());
                let result = match &qualified {
                    Ok(keys) => keys.select(kid.as_deref()).map(|_| ()),
                    Err(TokenError::Untrusted) => Err(TokenError::Untrusted),
                    other => panic!("{other:?}"),
                };
                let decision = match result {
                    Ok(()) => "accepted",
                    Err(TokenError::UnknownKeyId) => "unknown",
                    Err(TokenError::AmbiguousKeyId) => "ambiguous",
                    Err(TokenError::Untrusted) => "untrusted",
                    other => panic!("{other:?}"),
                };
                assert_eq!(decision, v.get("decision"), "{}", v.name());
                if let Ok(keys) = qualified {
                    assert_eq!(
                        keys.learned_pins.is_some(),
                        pins.is_empty() && stored.is_none()
                    );
                    for key in keys.keys {
                        assert!(
                            [v.get("pin_a"), v.get("pin_b")]
                                .contains(&key.thumbprint().unwrap().as_str())
                        );
                    }
                }
            }
            "keys" => {
                let keys = JwkSet::decode_json(&bytes).unwrap();
                assert_eq!(
                    qualify_key_set(&keys, &[], None).is_ok(),
                    accepted,
                    "{}",
                    v.name()
                );
            }
            other => panic!("unknown kind {other}"),
        }
    }
}

#[test]
fn machine_refresh_owner_and_key_selection_boundaries() {
    assert!(machine_refresh_needed(None, 0));
    assert!(!machine_refresh_needed(Some(1000), 699));
    assert!(machine_refresh_needed(Some(1000), 700));
    assert!(machine_refresh_needed(Some(i64::MIN), u64::MAX));
    assert!(!machine_refresh_needed(Some(i64::MAX), 0));
    let owner = KeySetOwner {
        realm: "030C1G60R30C1G60R30C1G60R3".parse().unwrap(),
        address: " https://control.example/keys/// ".into(),
    };
    let same = KeySetOwner {
        realm: "030C1G60R30C1G60R30C1G60R3".parse().unwrap(),
        address: "https://control.example/keys".into(),
    };
    assert!(owner.compare(&same).is_ok());
    assert!(matches!(
        owner.compare(&KeySetOwner {
            realm: "09144GJ289144GJ289144GJ289".parse().unwrap(),
            ..same.clone()
        }),
        Err(TokenError::Owner)
    ));
    assert!(matches!(
        owner.compare(&KeySetOwner {
            address: "https://other.example/keys".into(),
            ..same
        }),
        Err(TokenError::Owner)
    ));
    let empty = QualifiedKeySet {
        keys: vec![],
        learned_pins: None,
    };
    assert!(matches!(empty.select(None), Err(TokenError::MissingKeyId)));
    assert!(matches!(
        empty.select(Some("unknown")),
        Err(TokenError::UnknownKeyId)
    ));
}

#[test]
fn exact_exchange_roundtrips_and_claim_object_refusals() {
    let vectors = support::vectors::parse(include_str!("fixtures/vectors/control-exchange.vec"));
    for v in vectors.iter().filter(|v| v.get("decision") == "accepted") {
        let bytes = v.hex("bytes");
        let canonical = match v.get("kind") {
            "registration" => RegistrationRequest::decode(&bytes)
                .unwrap()
                .canonical()
                .unwrap(),
            "acceptance" => RegistrationAcceptance::decode(&bytes)
                .unwrap()
                .canonical()
                .unwrap(),
            "authentication" => AuthenticationRequest::decode(&bytes)
                .unwrap()
                .canonical()
                .unwrap(),
            "token-response" => AuthenticationResponse::decode(&bytes)
                .unwrap()
                .canonical()
                .unwrap(),
            "information-request" => InformationRequest::decode(&bytes).unwrap().canonical(),
            "information" => InformationResponse::decode(&bytes)
                .unwrap()
                .canonical()
                .unwrap(),
            _ => continue,
        };
        assert_eq!(canonical, bytes, "{}", v.name());
    }
    for malformed in [
        b"[]".as_slice(),
        b"{}",
        b"null",
        b"{\"sub\":\"a\",\"sub\":\"b\"}",
    ] {
        assert!(MachineClaims::decode_json(malformed).is_err());
    }
    assert_eq!(MACHINE_REGISTER, "machine.register");
    assert_eq!(MACHINE_AUTH, "machine.auth");
    assert_eq!(INFO_GET, "info.get");
    assert_eq!(CONTROL_ENVELOPE_PATH, "/api/v1/control");
    assert_eq!(DISCOVERY_PATH, "/api/v1/info");
    assert_eq!(JWKS_PATH, "/.well-known/jwks.json");
}

#[test]
fn machine_header_algorithm_and_owned_rotation() {
    let vectors = support::vectors::parse(include_str!("fixtures/vectors/control-exchange.vec"));
    let set = JwkSet::decode_json(
        &vectors
            .iter()
            .find(|v| v.name() == "key-set")
            .unwrap()
            .hex("bytes"),
    )
    .unwrap();
    let owner = KeySetOwner {
        realm: "030C1G60R30C1G60R30C1G60R3".parse().unwrap(),
        address: "https://control.example/keys".into(),
    };
    let first = qualify_owned_key_set(&set, &owner, &[], None).unwrap();
    let pins = first.learned_pins.clone().unwrap();
    let stored = StoredKeyPins {
        owner: owner.clone(),
        pins: pins.clone(),
    };
    assert!(
        qualify_owned_key_set(&set, &owner, &[], Some(&stored))
            .unwrap()
            .learned_pins
            .is_none()
    );
    let wrong_owner = KeySetOwner {
        realm: "09144GJ289144GJ289144GJ289".parse().unwrap(),
        ..owner
    };
    assert!(matches!(
        qualify_owned_key_set(&set, &wrong_owner, &[], Some(&stored)),
        Err(TokenError::Owner)
    ));
    assert!(qualify_owned_key_set(&set, &wrong_owner, &pins, Some(&stored)).is_ok());
    for algorithm in ["none", "HS256", "ES256", "EdDSA"] {
        let header = MachineTokenHeader {
            alg: algorithm.into(),
            kid: Some("a".into()),
        };
        assert!(matches!(
            header.select_key(&first),
            Err(TokenError::Algorithm)
        ));
    }
    let header = MachineTokenHeader::decode_json(br#"{"alg":"RS256","kid":"a"}"#).unwrap();
    assert_eq!(header.select_key(&first).unwrap().kid.as_deref(), Some("a"));
    assert!(MachineTokenHeader::decode_json(br#"{"alg":"RS256","alg":"none"}"#).is_err());
}

#[test]
fn unbound_policy_never_bypasses_subject_expiry_or_carrier_trust() {
    let vectors = support::vectors::parse(include_str!("fixtures/vectors/control-exchange.vec"));
    let sample = vectors
        .iter()
        .find(|v| v.name() == "gateway-audience-machine")
        .unwrap();
    let mut claims = MachineClaims::decode_json(&sample.hex("bytes")).unwrap();
    let identity = IdentityKey::from_bytes(&sample.hex_array("node")).unwrap();
    claims.mid_kty.clear();
    claims.mid_pub.clear();
    assert!(matches!(
        claims.validate_gateway("machine-a", identity, false, 100),
        Err(TokenError::SelfBinding)
    ));
    assert!(
        claims
            .validate_gateway("machine-a", identity, true, 100)
            .is_ok()
    );
    assert!(matches!(
        claims.validate_gateway("other", identity, true, 100),
        Err(TokenError::Subject)
    ));
    assert!(matches!(
        claims.validate_gateway("machine-a", identity, true, 231),
        Err(TokenError::Expired)
    ));
    let request = RegistrationRequest::decode(
        &vectors
            .iter()
            .find(|v| v.name() == "registration")
            .unwrap()
            .hex("bytes"),
    )
    .unwrap();
    assert!(!format!("{request:?}").contains("provisioned"));
    let token = AuthenticationResponse {
        token: "secret.machine.token".into(),
    };
    assert!(!format!("{token:?}").contains(&token.token));
    let mut envelope = BootstrapEnvelope::decode(
        &vectors
            .iter()
            .find(|v| v.name() == "accept-matching")
            .unwrap()
            .hex("bytes"),
    )
    .unwrap();
    let pins = EnvelopePins::intersect(
        &[vectors
            .iter()
            .find(|v| v.name() == "accept-matching")
            .unwrap()
            .get("pin")
            .into()],
        &[],
    )
    .unwrap();
    let expected = EnvelopeExpectation {
        pins: &pins,
        direction: EnvelopeDirection::Response,
        recipient: identity,
        kind: MACHINE_REGISTER,
        now_seconds: 100,
        previous_acceptance_seconds: None,
    };
    envelope.signature[0] ^= 1;
    assert!(matches!(
        compare_registration_acceptance(
            &envelope,
            &expected,
            &request,
            None,
            RebindAuthorization::Denied
        ),
        Err(ExchangeError::Envelope(BootstrapError::Signature))
    ));
}

#[test]
fn key_set_decode_retains_supported_members_without_weakening_structure() {
    let bytes = br#"{"keys":[{"kty":"EC","crv":"P-256"},{"kty":"RSA","kid":"a","alg":"RS256","use":"sig","n":"AQID","e":"AQAB"}]}"#;
    let set = JwkSet::decode_json(bytes).unwrap();
    assert_eq!(set.keys.len(), 1);
    assert_eq!(qualify_key_set(&set, &[], None).unwrap().keys.len(), 1);
    for malformed in [
        br#"{"keys":[null]}"#.as_slice(),
        br#"{"keys":[],"keys":[]}"#,
        b"[]",
        b"{}",
    ] {
        assert!(JwkSet::decode_json(malformed).is_err());
    }
}
