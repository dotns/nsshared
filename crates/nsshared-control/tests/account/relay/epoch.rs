#![allow(clippy::unwrap_used, reason = "independent contract fixtures")]

use nsshared_control::account::relay::{Frame, FrameKind, validate_header};

#[test]
fn epoch_independent_frame_vectors() {
    for v in nsshared_testkit::vectors!("account/relay/epoch") {
        let bytes = v.hex("bytes");
        let accepted = v.get("decision") == "accepted";
        let result = Frame::decode(&bytes);
        assert_eq!(result.is_ok(), accepted, "{}: {result:?}", v.name());
        if let Ok(frame) = result {
            assert_eq!(frame.canonical().unwrap(), bytes);
            let kind = bytes[4];
            let body_len = if kind == 11 { 97 } else { 122 };
            assert_eq!(frame.body().len(), body_len);
            assert_eq!(FrameKind::from_byte(kind).unwrap().byte(), kind);
            assert_eq!(
                validate_header((body_len + 1) as u32, kind).unwrap(),
                body_len
            );
            assert!(validate_header(body_len as u32, kind).is_err());
            assert!(validate_header((body_len + 2) as u32, kind).is_err());
            for length in 0..bytes.len() {
                assert!(
                    Frame::decode(&bytes[..length]).is_err(),
                    "{} {length}",
                    v.name()
                );
            }
            let mut trailing = bytes.clone();
            trailing.push(0);
            assert!(Frame::decode(&trailing).is_err());
        }
    }
}

use nsshared_control::account::relay::{
    EpochOutcome, EpochRequest, EpochResult, ParticipantRosterScope, PendingEpochResponse,
    PendingResponse, SessionError, verify_participant_roster,
};
use nsshared_testkit::fixture::identity as key;

fn scope() -> ParticipantRosterScope {
    ParticipantRosterScope {
        issuer: key(1),
        recipient: key(2),
    }
}
fn request() -> EpochRequest {
    EpochRequest::new(scope(), [6; 16], 17, 23).unwrap()
}

#[test]
fn epoch_typed_vectors_and_constructors() {
    for v in nsshared_testkit::vectors!("account/relay/epoch") {
        let bytes = v.hex("bytes");
        let accepted = v.get("decision") == "accepted";
        let kind = FrameKind::from_byte(bytes[4]).unwrap();
        assert_eq!(
            Frame::new(kind, bytes[5..].to_vec()).is_ok(),
            accepted,
            "{}",
            v.name()
        );
        if kind == FrameKind::EpochRequest {
            let decoded = EpochRequest::decode(&bytes);
            assert_eq!(decoded.is_ok(), accepted, "{}", v.name());
            if let Ok(decoded) = decoded {
                let constructed = EpochRequest::new(
                    decoded.scope(),
                    decoded.correlation(),
                    decoded.owner_generation(),
                    decoded.fenced_epoch(),
                )
                .unwrap();
                assert_eq!(decoded, constructed);
                assert_eq!(decoded.canonical().unwrap(), bytes);
                assert_eq!(
                    EpochRequest::from_frame(&decoded.frame().unwrap()).unwrap(),
                    decoded
                );
                assert_eq!(decoded.frame().unwrap().scope().unwrap(), (key(1), key(2)));
                assert_eq!(decoded.frame().unwrap().correlation().unwrap(), [6; 16]);
                assert!(EpochResult::decode(&bytes).is_err());
            }
        } else {
            let decoded = EpochResult::decode(&bytes);
            assert_eq!(decoded.is_ok(), accepted, "{}", v.name());
            if let Ok(decoded) = decoded {
                let constructed = EpochResult::new(
                    *decoded.request(),
                    decoded.outcome(),
                    decoded.result_epoch(),
                    decoded.publication_version(),
                    decoded.retry_not_before_unix_ms(),
                )
                .unwrap();
                assert_eq!(decoded, constructed);
                assert_eq!(decoded.canonical().unwrap(), bytes);
                assert_eq!(
                    EpochResult::from_frame(&decoded.frame().unwrap()).unwrap(),
                    decoded
                );
                assert_eq!(decoded.outcome().byte(), v.u64("outcome") as u8);
                assert_eq!(
                    EpochOutcome::from_byte(decoded.outcome().byte()),
                    Some(decoded.outcome())
                );
                let pending = PendingEpochResponse::new(*decoded.request());
                assert_eq!(pending.request(), decoded.request());
                decoded.validate_for(&pending).unwrap();
                assert!(EpochRequest::decode(&bytes).is_err());
            }
        }
    }
    for byte in 6..=255 {
        assert_eq!(EpochOutcome::from_byte(byte), None);
    }
    for (correlation, generation, epoch) in [([0; 16], 17, 23), ([6; 16], 0, 23), ([6; 16], 17, 0)]
    {
        assert!(EpochRequest::new(scope(), correlation, generation, epoch).is_err());
    }
    for kind in [11, 12] {
        for length in [0, 1, 1_048_578, u32::MAX] {
            assert!(validate_header(length, kind).is_err());
        }
    }
    for kind in [13, 255] {
        assert_eq!(FrameKind::from_byte(kind), None);
        assert!(validate_header(1, kind).is_err());
        assert!(Frame::decode(&[0, 0, 0, 1, kind]).is_err());
    }
}

#[test]
fn epoch_outcome_construction_matrix() {
    let request = request();
    for outcome in [EpochOutcome::Allocated, EpochOutcome::AlreadyFresh] {
        for fields in [(0, 1, 0), (22, 1, 0), (23, 1, 0), (24, 0, 0), (24, 1, 1)] {
            assert!(EpochResult::new(request, outcome, fields.0, fields.1, fields.2).is_err());
        }
        for (epoch, publication) in [(24, 1), (24, u64::MAX), (u64::MAX, 1)] {
            assert!(EpochResult::new(request, outcome, epoch, publication, 0).is_ok());
        }
        let exhausted = EpochRequest::new(scope(), [6; 16], u64::MAX, u64::MAX).unwrap();
        assert!(EpochResult::new(exhausted, outcome, u64::MAX, 1, 0).is_err());
    }
    for fields in [(0, 0, 0), (1, 0, 2000), (0, 1, 2000)] {
        assert!(
            EpochResult::new(
                request,
                EpochOutcome::RateLimited,
                fields.0,
                fields.1,
                fields.2
            )
            .is_err()
        );
    }
    for outcome in [
        EpochOutcome::StaleCustody,
        EpochOutcome::InvalidEpoch,
        EpochOutcome::Unavailable,
    ] {
        for fields in [(1, 0, 0), (0, 1, 0), (0, 0, 1)] {
            assert!(EpochResult::new(request, outcome, fields.0, fields.1, fields.2).is_err());
        }
    }
    for kind in [FrameKind::EpochRequest, FrameKind::EpochResult] {
        let mut body = if kind == FrameKind::EpochRequest {
            request.frame().unwrap().body().to_vec()
        } else {
            EpochResult::new(request, EpochOutcome::Allocated, 24, 1, 0)
                .unwrap()
                .frame()
                .unwrap()
                .body()
                .to_vec()
        };
        body[80] = 2;
        assert!(matches!(Frame::new(kind, body), Err(SessionError::Version)));
    }
}

#[test]
fn epoch_pending_exact_context_and_operation() {
    let request = request();
    let pending = PendingEpochResponse::new(request);
    let result = EpochResult::new(request, EpochOutcome::AlreadyFresh, 24, 1, 0).unwrap();
    result.validate_for(&pending).unwrap();
    request.validate_for(scope(), 17).unwrap();
    for changed in [
        EpochRequest::new(
            ParticipantRosterScope {
                issuer: key(3),
                ..scope()
            },
            [6; 16],
            17,
            23,
        )
        .unwrap(),
        EpochRequest::new(
            ParticipantRosterScope {
                recipient: key(3),
                ..scope()
            },
            [6; 16],
            17,
            23,
        )
        .unwrap(),
        EpochRequest::new(scope(), [7; 16], 17, 23).unwrap(),
        EpochRequest::new(scope(), [6; 16], 18, 23).unwrap(),
        EpochRequest::new(scope(), [6; 16], 17, 22).unwrap(),
    ] {
        assert!(matches!(
            result.validate_for(&PendingEpochResponse::new(changed)),
            Err(SessionError::Correlation)
        ));
    }
    assert!(
        request
            .validate_for(
                ParticipantRosterScope {
                    issuer: key(3),
                    ..scope()
                },
                17
            )
            .is_err()
    );
    assert!(
        request
            .validate_for(
                ParticipantRosterScope {
                    recipient: key(3),
                    ..scope()
                },
                17
            )
            .is_err()
    );
    assert!(request.validate_for(scope(), 18).is_err());
    assert!(request.validate_for(scope(), 0).is_err());
    let renewal = Frame::renewal(key(1), key(2), [6; 16]).unwrap();
    let renewal_pending = PendingResponse {
        kind: FrameKind::Renewed,
        issuer: key(1),
        participant: key(2),
        correlation: [6; 16],
    };
    let renewed = Frame::response(&renewal_pending, Some(2000)).unwrap();
    for frame in [&renewal, &renewed, &request.frame().unwrap()] {
        assert!(EpochResult::from_frame(frame).is_err());
    }
    assert!(EpochRequest::from_frame(&renewed).is_err());
    let frame = result.frame().unwrap();
    assert!(frame.validate_response(&renewal_pending, 1000).is_err());
    assert!(frame.validate_authenticated(&renewal, 1000).is_err());
    assert!(frame.owner_generation().is_err());
    let stale = EpochResult::new(request, EpochOutcome::StaleCustody, 0, 0, 0).unwrap();
    stale.validate_for(&pending).unwrap();
    assert_eq!(stale.request().owner_generation(), 17);
}

#[test]
fn epoch_recovery_keeps_membership_and_independent_roster_floors() {
    let vectors = nsshared_testkit::vectors!("account/relay/participant-roster");
    let bytes = |name: &str| {
        vectors
            .iter()
            .find(|v| v.name() == name)
            .unwrap()
            .hex("bytes")
    };
    let previous = verify_participant_roster(
        &bytes("participant-roster-repeated-epoch"),
        key(1),
        key(2),
        7,
        3,
        1000,
    )
    .unwrap();
    let fresh = verify_participant_roster(
        &bytes("participant-roster-new-epoch"),
        key(1),
        key(2),
        8,
        3,
        1000,
    )
    .unwrap();
    assert_eq!(previous.identities, fresh.identities);
    assert_eq!(previous.attribution_epoch.0, 3);
    assert_eq!(fresh.attribution_epoch.0, 4);
    let request = EpochRequest::new(scope(), [6; 16], 17, 3).unwrap();
    let result = EpochResult::new(request, EpochOutcome::Allocated, 4, 1, 0).unwrap();
    result
        .validate_for(&PendingEpochResponse::new(request))
        .unwrap();
    // Correlation still accepts an old committed publication after a newer roster.
    assert!(fresh.version.0 > result.publication_version());
    result
        .validate_for(&PendingEpochResponse::new(request))
        .unwrap();
    assert!(
        verify_participant_roster(
            &bytes("participant-roster-new-epoch"),
            key(1),
            key(2),
            9,
            4,
            1000
        )
        .is_err()
    );
    assert!(
        verify_participant_roster(
            &bytes("participant-roster-new-epoch"),
            key(1),
            key(2),
            8,
            100,
            1000
        )
        .is_err()
    );
}

// Representative downstream dispatch shapes remain explicit about unsupported operations.
#[test]
fn epoch_consumer_dispatch_compile_probes() {
    let authority = |kind: FrameKind| {
        matches!(
            kind,
            FrameKind::Enroll
                | FrameKind::Authenticate
                | FrameKind::Renew
                | FrameKind::Report
                | FrameKind::EpochRequest
        )
    };
    let relay = |kind: FrameKind| match kind {
        FrameKind::Roster | FrameKind::Renewed | FrameKind::Answer | FrameKind::EpochResult => true,
        FrameKind::Authenticate
        | FrameKind::Authenticated
        | FrameKind::Refused
        | FrameKind::Report
        | FrameKind::Enroll
        | FrameKind::Enrolled
        | FrameKind::Renew
        | FrameKind::EpochRequest => false,
    };
    assert!(authority(FrameKind::EpochRequest));
    assert!(!authority(FrameKind::EpochResult));
    assert!(relay(FrameKind::EpochResult));
    assert!(!relay(FrameKind::EpochRequest));
}
