use super::*;
use nsshared_control::account::publication::SourceBinding;

#[test]
fn registration_recovery_preserves_original_and_rejects_context_changes() {
    let vectors = nsshared_testkit::vectors!("account/control/exchange");
    let request_vector = vectors.iter().find(|v| v.name() == "registration").unwrap();
    let acceptance_vector = vectors.iter().find(|v| v.name() == "acceptance").unwrap();
    let request = RegistrationRequest::decode(&request_vector.hex("bytes")).unwrap();
    let source = SourceBinding {
        nsd: source_expectation(request.enrollment.binding.identity, [7; 16]).nsd,
        recipient: request.enrollment.binding.identity,
        served_realm: "030C1G60R30C1G60R30C1G60R3".parse().unwrap(),
        scope: "nodes".into(),
        profile: SourceProfile::ExplicitGateway,
        source_node: request.enrollment.binding.identity,
        contribution: [10; 16],
        source_epoch: 1,
        source_generation: 1,
    };
    let query = RegistrationRecoveryQuery::for_request([11; 16], &request).unwrap();
    let attachment = RegistrationRecoveryAttachment {
        query: query.clone(),
        acceptance: RegistrationAcceptance::decode(&acceptance_vector.hex("bytes")).unwrap(),
    };
    let expected = RegistrationRecoveryExpectation {
        query: &query,
        request: &request,
        committed: None,
        rebind: RebindAuthorization::Denied,
        source: &source,
        epoch_floor: 1,
        generation_floor: 1,
    };
    assert!(attachment.validate(&expected).is_ok());
    assert_eq!(
        attachment.acceptance.canonical().unwrap(),
        acceptance_vector.hex("bytes")
    );
    let bytes = attachment.canonical().unwrap();
    assert_eq!(
        RegistrationRecoveryAttachment::decode(&bytes).unwrap(),
        attachment
    );
    assert_eq!(
        RegistrationRecoveryQuery::decode(&query.canonical().unwrap()).unwrap(),
        query
    );
    for vector in vectors.iter().filter(|v| v.get("kind") == "recovery") {
        assert_eq!(query.request_digest.as_slice(), vector.hex("digest"));
        assert_eq!(query.canonical().unwrap(), vector.hex("query"));
        assert_ne!(vector.hex("query_nonce"), [7; 16]);
        let recovered = RegistrationRecoveryAttachment::decode(&vector.hex("bytes"));
        let result = recovered
            .as_ref()
            .ok()
            .and_then(|value| value.validate(&expected).ok());
        assert_eq!(
            result.is_some(),
            vector.get("decision") == "accepted",
            "{}",
            vector.name()
        );
        if let Some(value) = recovered.as_ref().ok().filter(|_| result.is_some()) {
            assert_eq!(value.canonical().unwrap(), vector.hex("bytes"));
            assert_eq!(
                value.acceptance.canonical().unwrap(),
                vector.hex("original")
            );
        }
    }
    for field in [
        "operation",
        "network",
        "nsd",
        "digest",
        "issuer",
        "recipient",
        "wg",
        "profile",
        "capabilities",
        "decision",
        "signature",
        "contribution",
        "epoch",
        "generation",
    ] {
        let mut changed = attachment.clone();
        match field {
            "operation" => changed.query.operation[0] ^= 1,
            "network" => changed.query.scope.network_id[0] ^= 1,
            "nsd" => changed.query.scope.nsd_id[0] ^= 1,
            "digest" => changed.query.request_digest[0] ^= 1,
            "issuer" => changed.acceptance.source_binding.binding.nsd = source.recipient,
            "recipient" => changed.acceptance.source_binding.binding.recipient = source.nsd,
            "wg" => changed.acceptance.enrollment.binding.wg_key[0] ^= 1,
            "profile" => changed.acceptance.profile = "other".into(),
            "capabilities" => changed.acceptance.enrollment.capabilities = vec!["other".into()],
            "decision" => changed.acceptance.decision = EnrollmentDecision::Equal,
            "signature" => changed.acceptance.source_binding.signature[0] ^= 1,
            "contribution" => changed.acceptance.source_binding.binding.contribution[0] ^= 1,
            "epoch" => changed.acceptance.source_binding.binding.source_epoch += 1,
            "generation" => changed.acceptance.source_binding.binding.source_generation += 1,
            _ => unreachable!(),
        }
        assert!(changed.validate(&expected).is_err(), "{field}");
    }
    assert!(
        attachment
            .validate(&RegistrationRecoveryExpectation {
                epoch_floor: 2,
                ..expected
            })
            .is_err()
    );
    assert!(
        attachment
            .validate(&RegistrationRecoveryExpectation {
                generation_floor: 2,
                ..expected
            })
            .is_err()
    );
}

#[test]
fn recovery_uses_retained_lifecycle_and_baseline() {
    let vectors = nsshared_testkit::vectors!("account/control/exchange");
    for vector in vectors
        .iter()
        .filter(|v| v.name().starts_with("lifecycle-"))
    {
        let request = RegistrationRequest::decode(&vector.hex("request")).unwrap();
        let original = BootstrapEnvelope::decode(&vector.hex("bytes")).unwrap();
        let query = RegistrationRecoveryQuery::for_request([11; 16], &request).unwrap();
        let attachment = RegistrationRecoveryAttachment {
            query: query.clone(),
            acceptance: RegistrationAcceptance::decode(&original.payload).unwrap(),
        };
        let baseline = Enrollment::decode(&vector.hex("committed")).unwrap();
        let source = SourceBinding {
            nsd: source_expectation(request.enrollment.binding.identity, [9; 16]).nsd,
            recipient: request.enrollment.binding.identity,
            served_realm: "030C1G60R30C1G60R30C1G60R3".parse().unwrap(),
            scope: "nodes".into(),
            profile: SourceProfile::ExplicitGateway,
            source_node: request.enrollment.binding.identity,
            contribution: [10; 16],
            source_epoch: 1,
            source_generation: 1,
        };
        let expected = RegistrationRecoveryExpectation {
            query: &query,
            request: &request,
            committed: Some(&baseline.binding),
            rebind: if vector.get("rebind") == "yes" {
                RebindAuthorization::Authorized
            } else {
                RebindAuthorization::Denied
            },
            source: &source,
            epoch_floor: 1,
            generation_floor: 1,
        };
        assert_eq!(
            attachment.validate(&expected).is_ok(),
            vector.get("decision") == "accepted",
            "{}",
            vector.name()
        );
        let mut wrong_baseline = baseline.binding.clone();
        wrong_baseline.wg_key[0] ^= 1;
        assert!(
            attachment
                .validate(&RegistrationRecoveryExpectation {
                    committed: Some(&wrong_baseline),
                    ..expected
                })
                .is_err()
        );
        let mut wrong_request = request.clone();
        wrong_request.lifecycle = None;
        if request.lifecycle.is_some() {
            let changed_query =
                RegistrationRecoveryQuery::for_request([11; 16], &wrong_request).unwrap();
            assert!(
                attachment
                    .validate(&RegistrationRecoveryExpectation {
                        query: &changed_query,
                        request: &wrong_request,
                        ..expected
                    })
                    .is_err()
            );
            let changed = RegistrationRecoveryAttachment {
                query: changed_query.clone(),
                acceptance: attachment.acceptance.clone(),
            };
            assert!(
                changed
                    .validate(&RegistrationRecoveryExpectation {
                        query: &changed_query,
                        request: &wrong_request,
                        ..expected
                    })
                    .is_err()
            );
        }
    }
}
