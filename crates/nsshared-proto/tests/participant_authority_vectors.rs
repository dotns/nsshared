#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "independent contract fixtures"
)]

mod support;
use nsshared_proto::{
    IdentityKey, RealmId,
    account::{
        UsageAnswer, UsageReport, UsageRows,
        directory_binding::{BindingDecision, SignedDirectoryBinding},
        participant_session::{
            Authorization, EXPORTER_LABEL, EnrollmentProvision, Frame, PROOF_DOMAIN,
            PendingResponse, SessionError, exporter_context, proof_input,
        },
        verify_participant_roster,
    },
};
use support::vectors::{self, Vector};

fn key(seed: u8) -> IdentityKey {
    IdentityKey::from_bytes(
        &ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes(),
    )
    .unwrap()
}
fn fixtures() -> Vec<Vector> {
    vectors::load("participant-authority")
}
fn raw(vectors: &[Vector], name: &str) -> Vec<u8> {
    vectors
        .iter()
        .find(|v| v.name() == name)
        .unwrap()
        .hex("bytes")
}
fn authorization(enabled: bool) -> Authorization {
    Authorization {
        issuer: key(1),
        participant: key(2),
        enabled,
        deadline_ms: Some(2000),
    }
}

#[test]
fn participant_authority_independent_vectors() {
    assert_eq!(EXPORTER_LABEL, b"EXPORTER-nsgw-participant-candidate-v1");
    assert_eq!(PROOF_DOMAIN, b"nsgw-participant-candidate-v1\0");
    assert_eq!(&exporter_context(key(1), key(2))[..32], key(1).as_bytes());
    assert_eq!(&proof_input(&[4; 32])[PROOF_DOMAIN.len()..], &[4; 32]);
    let provision = EnrollmentProvision {
        issuer: key(1),
        participant: key(2),
        credential: &[7; 32],
    };
    for v in fixtures() {
        let bytes = v.hex("bytes");
        let expected = v.get("decision") == "accepted";
        match v.get("mode") {
            "frame" => {
                let result = Frame::decode(&bytes);
                assert_eq!(result.is_ok(), expected, "{}: {result:?}", v.name());
                if let Ok(frame) = result {
                    assert_eq!(frame.canonical().unwrap(), bytes);
                }
            }
            "transport" => {
                let frame = Frame::decode(&bytes).unwrap();
                assert_eq!(frame.canonical().unwrap(), bytes);
                let auth = authorization(v.opt("enabled") != Some("0"));
                let result = match v.get("action") {
                    "enroll" => frame.validate_enrollment(&provision, &v.hex_array("exporter")),
                    "authenticate" => {
                        frame.validate_authentication(&auth, &v.hex_array("exporter"), 1000)
                    }
                    "renew" => frame.validate_renewal(&auth, (key(1), key(2)), 1000),
                    "report" => {
                        let report = UsageReport::decode(frame.body()).unwrap();
                        assert_eq!(report.reporter, key(2));
                        assert!(matches!(report.rows, UsageRows::Relay(_)));
                        auth.validate(key(1), report.reporter, 1000)
                    }
                    "response" => {
                        let pending = PendingResponse {
                            kind: if bytes[4] == 8 { 8 } else { 10 },
                            issuer: key(1),
                            participant: key(2),
                            correlation: [6; 16],
                        };
                        frame.validate_response(&pending, 1000).map(|_| ())
                    }
                    other => panic!("unknown action {other}"),
                };
                assert_eq!(result.is_ok(), expected, "{}: {result:?}", v.name());
            }
            "binding" => {
                let previous = v
                    .opt("previous")
                    .map(|_| SignedDirectoryBinding::decode(&v.hex("previous")).unwrap());
                let result = SignedDirectoryBinding::decode(&bytes).and_then(|binding| {
                    let decision = binding.verify(
                        key(1),
                        17,
                        v.u64("floor"),
                        previous.as_ref(),
                        v.u64("now_ms"),
                    )?;
                    assert_eq!(binding.canonical().unwrap(), bytes);
                    assert_eq!(binding.signing_input().unwrap(), v.hex("signing_input"));
                    Ok(decision)
                });
                assert_eq!(result.is_ok(), expected, "{}: {result:?}", v.name());
                if v.name() == "binding-idempotent" {
                    assert_eq!(result.unwrap(), BindingDecision::Idempotent);
                }
            }
            "roster" => {
                let generation =
                    verify_participant_roster(&bytes, key(1), key(2), v.u64("last_version"), 1000)
                        .unwrap();
                assert_eq!(generation.identities.len() as u64, v.u64("identity_count"));
                assert_eq!(generation.version.0, v.u64("version"));
            }
            other => panic!("unknown mode {other}"),
        }
    }
}

#[test]
fn participant_auth_transport() {
    let vectors = fixtures();
    let provision = EnrollmentProvision {
        issuer: key(1),
        participant: key(2),
        credential: &[7; 32],
    };
    Frame::decode(&raw(&vectors, "enroll-authorized"))
        .unwrap()
        .validate_enrollment(&provision, &[4; 32])
        .unwrap();
    assert!(
        Frame::decode(&raw(&vectors, "enroll-unprovisioned-key"))
            .unwrap()
            .validate_enrollment(&provision, &[4; 32])
            .is_err()
    );
    Frame::decode(&raw(&vectors, "authenticate-fresh"))
        .unwrap()
        .validate_authentication(&authorization(true), &[5; 32], 1000)
        .unwrap();
    Frame::decode(&raw(&vectors, "renew"))
        .unwrap()
        .validate_renewal(&authorization(true), (key(1), key(2)), 1000)
        .unwrap();
    for (name, kind) in [("enrolled", 8), ("renewed", 10)] {
        let pending = PendingResponse {
            kind,
            issuer: key(1),
            participant: key(2),
            correlation: [6; 16],
        };
        assert_eq!(
            Frame::decode(&raw(&vectors, name))
                .unwrap()
                .validate_response(&pending, 1000)
                .unwrap(),
            Some(2000)
        );
    }
    let initial =
        verify_participant_roster(&raw(&vectors, "initial-roster"), key(1), key(2), 0, 1000)
            .unwrap();
    assert_eq!(initial.identities.len(), 2);
    let report_frame = Frame::decode(&raw(&vectors, "accepted-report")).unwrap();
    let report = UsageReport::decode(report_frame.body()).unwrap();
    authorization(true)
        .validate(key(1), report.reporter, 1000)
        .unwrap();
    let UsageRows::Relay(rows) = &report.rows else {
        panic!("expected relay report")
    };
    assert_eq!(rows[0].epoch, initial.version);
    let ack = Frame::decode(&raw(&vectors, "accepted-answer")).unwrap();
    UsageAnswer::decode(ack.body())
        .unwrap()
        .validate_for(&report)
        .unwrap();
    let realm_a: RealmId = "030C1G60R30C1G60R30C1G60R3".parse().unwrap();
    let realm_b: RealmId = "09144GJ289144GJ289144GJ289".parse().unwrap();
    let directory: nsshared_proto::rendezvous::directory::Directory = serde_json::from_str(
        vectors
            .iter()
            .find(|v| v.name() == "binding-ab")
            .unwrap()
            .get("directory"),
    )
    .unwrap();
    let directory_bytes = serde_json::to_vec(&directory).unwrap();
    let mut floor = 0;
    let mut previous = None;
    for (name, a, b) in [
        ("binding-ab", true, true),
        ("binding-remove-a", false, true),
        ("binding-empty", false, false),
    ] {
        let binding = SignedDirectoryBinding::decode(&raw(&vectors, name)).unwrap();
        assert_eq!(
            binding
                .verify(key(1), 17, floor, previous.as_ref(), 1000)
                .unwrap(),
            BindingDecision::Replace
        );
        assert_eq!(
            binding.eligible(key(1), 17, key(2), realm_a, 1000).unwrap(),
            a
        );
        assert_eq!(
            binding.eligible(key(1), 17, key(2), realm_b, 1000).unwrap(),
            b
        );
        floor = binding.content.version;
        previous = Some(binding);
        let supplied: nsshared_proto::rendezvous::directory::Directory = serde_json::from_str(
            vectors
                .iter()
                .find(|v| v.name() == name)
                .unwrap()
                .get("directory"),
        )
        .unwrap();
        nsshared_proto::rendezvous::directory::check_update(&directory, &supplied).unwrap();
        assert_eq!(serde_json::to_vec(&supplied).unwrap(), directory_bytes);
    }
    assert_eq!(floor, 3);
    let empty = verify_participant_roster(
        &raw(&vectors, "revocation-empty-roster"),
        key(1),
        key(2),
        initial.version.0,
        1000,
    )
    .unwrap();
    assert!(empty.identities.is_empty());
    for action in ["revoked-authenticate", "revoked-renew", "revoked-report"] {
        let frame = Frame::decode(&raw(&vectors, action)).unwrap();
        let result = match action {
            "revoked-authenticate" => {
                frame.validate_authentication(&authorization(false), &[5; 32], 1000)
            }
            "revoked-renew" => {
                frame.validate_renewal(&authorization(false), (key(1), key(2)), 1000)
            }
            _ => authorization(false).validate(key(1), key(2), 1000),
        };
        assert!(matches!(result, Err(SessionError::Unauthorized)));
    }
    assert!(
        SignedDirectoryBinding::decode(&raw(&vectors, "binding-ab"))
            .unwrap()
            .verify(key(1), 17, floor, None, 1000)
            .is_err()
    );
}

#[test]
fn participant_constructors_correlation_and_deadlines() {
    use nsshared_proto::account::participant_session::{
        ENROLLED, MAX_FRAME_BODY, RENEWED, retained_credential_deadline, validate_header,
    };
    let vectors = fixtures();
    let proof: [u8; 64] = raw(&vectors, "authenticate")[69..].try_into().unwrap();
    assert_eq!(
        Frame::authentication(key(1), key(2), proof)
            .unwrap()
            .canonical()
            .unwrap(),
        raw(&vectors, "authenticate")
    );
    assert_eq!(
        Frame::enrollment(key(1), key(2), [6; 16], &[7; 32], proof)
            .unwrap()
            .canonical()
            .unwrap(),
        raw(&vectors, "enroll-authorized")
    );
    assert_eq!(
        Frame::renewal(key(1), key(2), [6; 16])
            .unwrap()
            .canonical()
            .unwrap(),
        raw(&vectors, "renew")
    );
    let pending = PendingResponse {
        kind: ENROLLED,
        issuer: key(1),
        participant: key(2),
        correlation: [6; 16],
    };
    let response = Frame::response(&pending, Some(2000)).unwrap();
    assert_eq!(response.canonical().unwrap(), raw(&vectors, "enrolled"));
    assert_eq!(response.scope().unwrap(), (key(1), key(2)));
    assert_eq!(response.correlation().unwrap(), [6; 16]);
    assert!(
        response
            .validate_response(
                &PendingResponse {
                    kind: RENEWED,
                    ..pending
                },
                1000
            )
            .is_err()
    );
    assert!(response.validate_response(&pending, 2000).is_err());
    assert_eq!(
        response.validate_response(&pending, 1999).unwrap(),
        Some(2000)
    );
    assert_eq!(
        Frame::response(&pending, None)
            .unwrap()
            .validate_response(&pending, 1000)
            .unwrap(),
        None
    );
    assert_eq!(
        Frame::authenticated(None).unwrap().canonical().unwrap(),
        raw(&vectors, "absent-deadline")
    );
    assert_eq!(
        Frame::authenticated(Some(2000))
            .unwrap()
            .canonical()
            .unwrap(),
        raw(&vectors, "finite-deadline")
    );
    assert!(Frame::renewal(key(1), key(2), [0; 16]).is_err());
    assert!(Frame::authenticated(None).unwrap().scope().is_err());
    assert!(Frame::authenticated(None).unwrap().correlation().is_err());
    for (old, new, expected) in [
        (None, None, None),
        (Some(2000), None, Some(2000)),
        (Some(2000), Some(3000), Some(3000)),
        (Some(2000), Some(0), Some(0)),
    ] {
        assert_eq!(retained_credential_deadline(old, new), expected);
    }
    assert!(authorization(true).validate(key(1), key(2), 2000).is_err());
    assert!(authorization(true).validate(key(1), key(3), 1000).is_err());
    assert!(
        Frame::decode(&raw(&vectors, "renew"))
            .unwrap()
            .validate_renewal(&authorization(true), (key(1), key(3)), 1000)
            .is_err()
    );
    for kind in 4..=6 {
        assert_eq!(validate_header(1_048_577, kind).unwrap(), MAX_FRAME_BODY);
        assert!(validate_header(1_048_578, kind).is_err());
        let frame = Frame::new(kind, vec![42; MAX_FRAME_BODY]).unwrap();
        assert_eq!(Frame::decode(&frame.canonical().unwrap()).unwrap(), frame);
        assert!(Frame::new(kind, vec![42; MAX_FRAME_BODY + 1]).is_err());
    }
    assert!(
        !format!(
            "{:?}",
            Frame::decode(&raw(&vectors, "enroll-authorized")).unwrap()
        )
        .contains("7070707")
    );
}

#[test]
fn binding_signature_covers_every_field_and_scope() {
    let vectors = fixtures();
    let original = SignedDirectoryBinding::decode(&raw(&vectors, "binding-ab")).unwrap();
    for field in 0..7 {
        let mut changed = original.clone();
        match field {
            0 => changed.content.issuer = key(3),
            1 => changed.content.relay_id = 18,
            2 => changed.content.participant = key(3),
            3 => {
                changed.content.realms.remove(0);
            }
            4 => changed.content.version = 2,
            5 => changed.content.issued_at_unix_ms = 999,
            _ => changed.content.expires_at_unix_ms = 3000,
        }
        assert!(
            changed
                .verify(
                    changed.content.issuer,
                    changed.content.relay_id,
                    0,
                    None,
                    1000
                )
                .is_err(),
            "unsigned field {field}"
        );
    }
    assert!(
        original
            .eligible(key(1), 18, key(2), original.content.realms[0], 1000)
            .is_err()
    );
    assert!(
        original
            .eligible(key(1), 17, key(3), original.content.realms[0], 1000)
            .is_err()
    );
    let mut inconsistent = original.clone();
    inconsistent.content.relay_id = 18;
    assert!(
        original
            .verify(key(1), 17, 1, Some(&inconsistent), 1000)
            .is_err()
    );
    assert!(
        original
            .verify(key(1), 17, 2, Some(&original), 1000)
            .is_err()
    );
    assert!(
        original
            .eligible(key(1), 17, key(2), original.content.realms[0], 2000)
            .is_err()
    );
}
