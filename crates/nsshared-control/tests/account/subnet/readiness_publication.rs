#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use nsshared_control::account::{control::*, publication::*};

fn action(decision: &PublicationDecision<'_>) -> &'static str {
    match decision {
        PublicationDecision::Replace(_) => "replace",
        PublicationDecision::Withdraw(_) => "withdraw",
        PublicationDecision::FetchFailed(_) => "fetch_failed",
        PublicationDecision::Refused(_) => "refused",
        other => panic!("unexpected decision {other:?}"),
    }
}

#[test]
fn readiness_public_decision_validates_payload_before_exposing_actions() {
    let mut actual = Vec::new();
    let mut wanted = Vec::new();
    for v in &nsshared_testkit::vectors!("account/subnet/readiness-publication") {
        let current = SignedSourceBinding::decode(&v.hex("source"))
            .unwrap()
            .binding;
        let scopes = [PublicationScope {
            served_realm: current.served_realm,
            scope: &current.scope,
        }];
        let expected = PublicationExpectation {
            issuer: current.nsd,
            recipient: current.recipient,
            scopes: &scopes,
            channel: PublicationChannel::Snapshot,
            now_seconds: 1,
        };
        let raw = v.hex("bytes");
        let decision = decide_publication(&[], Some(&raw), &expected);
        actual.push((v.name().to_owned(), action(&decision).to_owned()));
        wanted.push((v.name().to_owned(), v.get("plain_decision").to_owned()));
    }
    assert_eq!(actual, wanted);
}

#[test]
fn readiness_plain_snapshot_refuses_the_whole_invalid_batch() {
    for v in &nsshared_testkit::vectors!("account/subnet/readiness-publication") {
        let current = SignedSourceBinding::decode(&v.hex("source"))
            .unwrap()
            .binding;
        let scopes = [PublicationScope {
            served_realm: current.served_realm,
            scope: &current.scope,
        }];
        let expected = PublicationExpectation {
            issuer: current.nsd,
            recipient: current.recipient,
            scopes: &scopes,
            channel: PublicationChannel::Snapshot,
            now_seconds: 1,
        };
        let raw = v.hex("plain_snapshot");
        let result = decide_publication_snapshot(&[], &raw, &expected);
        assert_eq!(
            result.is_ok(),
            v.get("plain_decision") != "refused",
            "{}",
            v.name()
        );
        if let Ok(snapshot) = result {
            let actions: Vec<_> = snapshot.decisions().collect();
            assert_eq!(actions.len(), 2);
            assert_eq!(action(&actions[0]), "withdraw");
            assert_eq!(action(&actions[1]), v.get("plain_decision"));
        }
    }
}

#[test]
fn readiness_source_decision_checks_payload_and_nodes_only_source() {
    for v in &nsshared_testkit::vectors!("account/subnet/readiness-publication") {
        let current = SignedSourceBinding::decode(&v.hex("source"))
            .unwrap()
            .binding;
        let pending = DeliveryContext::decode(&v.hex("pending")).unwrap();
        let scopes = [PublicationScope {
            served_realm: current.served_realm,
            scope: &current.scope,
        }];
        let expected = PublicationExpectation {
            issuer: current.nsd,
            recipient: current.recipient,
            scopes: &scopes,
            channel: PublicationChannel::Snapshot,
            now_seconds: 1,
        };
        let raw = v.hex("wrapped");
        let result = decide_source_publication(&[], Some(&raw), &current, &pending, &expected);
        let decision = result.as_ref().map_or("refused", action);
        assert_eq!(decision, v.get("source_decision"), "{}", v.name());
    }
}

#[test]
fn readiness_source_snapshots_refuse_the_whole_invalid_batch() {
    for v in &nsshared_testkit::vectors!("account/subnet/readiness-publication") {
        let current = SignedSourceBinding::decode(&v.hex("source"))
            .unwrap()
            .binding;
        let pending = DeliveryContext::decode(&v.hex("pending")).unwrap();
        let scopes = [PublicationScope {
            served_realm: current.served_realm,
            scope: &current.scope,
        }];
        let expected = PublicationExpectation {
            issuer: current.nsd,
            recipient: current.recipient,
            scopes: &scopes,
            channel: PublicationChannel::Snapshot,
            now_seconds: 1,
        };
        let raw = v.hex("source_snapshot");
        let single = decide_source_snapshot(&[], &raw, &current, &pending, &expected);
        let multi = decide_source_snapshot_scopes(
            &[],
            &raw,
            std::slice::from_ref(&current),
            &pending,
            &expected,
        );
        for result in [single, multi] {
            assert_eq!(
                result.is_ok(),
                v.get("source_decision") != "refused",
                "{}",
                v.name()
            );
            if let Ok(actions) = result {
                assert_eq!(actions.len(), 2);
                assert_eq!(action(&actions[0]), "withdraw");
                assert_eq!(action(&actions[1]), v.get("source_decision"));
            }
        }
    }
}

#[test]
fn readiness_snapshot_response_cannot_delegate_invalid_payload_acceptance() {
    for v in &nsshared_testkit::vectors!("account/subnet/readiness-publication") {
        let current = SignedSourceBinding::decode(&v.hex("source"))
            .unwrap()
            .binding;
        let request = PublicationSnapshotRequest::decode(&v.hex("request")).unwrap();
        let envelope = BootstrapEnvelope::decode(&v.hex("response")).unwrap();
        let pins = EnvelopePins::intersect(&[v.get("pin").into()], &[]).unwrap();
        let carrier = EnvelopeExpectation {
            pins: &pins,
            direction: EnvelopeDirection::Response,
            recipient: current.recipient,
            kind: CONFIG_SNAPSHOT,
            now_seconds: 1,
            previous_acceptance_seconds: None,
        };
        let scopes = [PublicationScope {
            served_realm: current.served_realm,
            scope: &current.scope,
        }];
        let expected = PublicationExpectation {
            issuer: current.nsd,
            recipient: current.recipient,
            scopes: &scopes,
            channel: PublicationChannel::Snapshot,
            now_seconds: 1,
        };
        let result = request.response(
            &envelope,
            &carrier,
            &[],
            std::slice::from_ref(&current),
            &expected,
        );
        assert_eq!(
            result.is_ok(),
            v.get("source_decision") != "refused",
            "{}",
            v.name()
        );
        if let Ok(actions) = result {
            assert_eq!(action(&actions[1]), v.get("source_decision"));
        }
    }
}

#[test]
fn readiness_nodes_only_source_guard_also_covers_empty_withdrawal() {
    let mut refused = Vec::new();
    for v in nsshared_testkit::vectors!("account/subnet/readiness-publication")
        .iter()
        .filter(|v| v.name().starts_with("foreign-source-node"))
    {
        let current = SignedSourceBinding::decode(&v.hex("source"))
            .unwrap()
            .binding;
        let pending = DeliveryContext::decode(&v.hex("pending")).unwrap();
        let scopes = [PublicationScope {
            served_realm: current.served_realm,
            scope: &current.scope,
        }];
        let expected = PublicationExpectation {
            issuer: current.nsd,
            recipient: current.recipient,
            scopes: &scopes,
            channel: PublicationChannel::Snapshot,
            now_seconds: 1,
        };
        let raw = v.hex("wrapped");
        refused.push(matches!(
            decide_source_publication(&[], Some(&raw), &current, &pending, &expected),
            Err(SourceError::Authority)
        ));
    }
    assert_eq!(refused, [true, true]);
}
