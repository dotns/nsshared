#![allow(clippy::unwrap_used)]

use nsshared_codec::cbor::CborWriter;
use nsshared_control::{
    account::control::BootstrapEnvelope, account::control::EnvelopeDirection,
    account::control::EnvelopeExpectation, account::control::EnvelopePins,
    account::publication::DeliveryContext, account::publication::PublicationChannel,
    account::publication::PublicationDecision, account::publication::PublicationExpectation,
    account::publication::PublicationScope, account::publication::PublicationSnapshotRequest,
    account::publication::SignedSourceBinding, account::publication::SourcePublication,
    account::publication::decide_publication, account::publication::decide_publication_snapshot,
    account::publication::decide_source_publication, account::publication::decide_source_snapshot,
    account::publication::decide_source_snapshot_scopes,
};
use std::collections::BTreeMap;

fn hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn mapping_snapshots_validate_every_entry_before_exposing_actions() {
    let fixtures: Vec<BTreeMap<_, _>> =
        include_str!("fixtures/vectors/provider-mapping-actions.vec")
            .split("\n\n")
            .map(|block| {
                block
                    .lines()
                    .filter_map(|line| line.split_once(" = "))
                    .collect()
            })
            .filter(|fields: &BTreeMap<_, _>| fields.contains_key("bytes"))
            .collect();
    assert_eq!(fixtures.len(), 15);
    for fields in fixtures {
        let current = SignedSourceBinding::decode(&hex(fields["source"]))
            .unwrap()
            .binding;
        let request = PublicationSnapshotRequest::decode(&hex(fields["request"])).unwrap();
        let pending = DeliveryContext::Snapshot {
            boot_nonce: request.boot_nonce,
            attempt_counter: request.attempt_counter,
            correlation: request.correlation,
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
            now_seconds: 150,
        };
        let good = fields["decision"] == "accept";
        let adjacent = hex(fields["adjacent"]);
        assert!(matches!(
            decide_source_publication(&[], Some(&adjacent), &current, &pending, &expected).unwrap(),
            PublicationDecision::Replace(_)
        ));
        let mapping = hex(fields["mapping"]);
        let source = SourcePublication::decode(&mapping).unwrap();
        let event = source.event().unwrap();
        let decision = decide_publication(&[], Some(event.canonical()), &expected);
        if good {
            if fields["name"] == "withdrawal" {
                assert!(matches!(decision, PublicationDecision::Withdraw(_)));
            } else {
                assert!(matches!(decision, PublicationDecision::Replace(_)));
            }
        } else {
            assert!(
                matches!(decision, PublicationDecision::Refused(_)),
                "{}: {decision:?}",
                fields["name"]
            );
        }
        let snapshot = hex(fields["snapshot"]);
        let single = decide_source_snapshot(&[], &snapshot, &current, &pending, &expected);
        let scoped = decide_source_snapshot_scopes(
            &[],
            &snapshot,
            std::slice::from_ref(&current),
            &pending,
            &expected,
        );
        assert_eq!(single.is_ok(), good, "{}: {single:?}", fields["name"]);
        assert_eq!(scoped.is_ok(), good, "{}: {scoped:?}", fields["name"]);
        if let Ok(decisions) = single {
            assert_eq!(decisions.len(), 2);
            assert!(matches!(decisions[0], PublicationDecision::Replace(_)));
            assert!(matches!(
                decisions[1],
                PublicationDecision::Replace(_) | PublicationDecision::Withdraw(_)
            ));
        }
        let neighbor = SourcePublication::decode(&adjacent).unwrap();
        let neighbor_event = neighbor.event().unwrap();
        let mut plain = CborWriter::default();
        plain
            .array(2)
            .uint(1)
            .array(2)
            .bytes(neighbor_event.canonical())
            .bytes(event.canonical());
        let plain = plain.into_bytes();
        let result = decide_publication_snapshot(&[], &plain, &expected);
        assert_eq!(result.is_ok(), good, "{}: {result:?}", fields["name"]);
        if let Ok(snapshot) = result {
            assert!(snapshot.decisions().all(|decision| matches!(
                decision,
                PublicationDecision::Replace(_) | PublicationDecision::Withdraw(_)
            )));
        }
        let envelope = BootstrapEnvelope::decode(&hex(fields["bytes"])).unwrap();
        let pins = EnvelopePins::intersect(&[fields["pin"].into()], &[]).unwrap();
        let carrier = EnvelopeExpectation {
            pins: &pins,
            direction: EnvelopeDirection::Response,
            recipient: current.recipient,
            kind: "config.snapshot",
            now_seconds: 150,
            previous_acceptance_seconds: None,
        };
        let result = request.response(
            &envelope,
            &carrier,
            &[],
            std::slice::from_ref(&current),
            &expected,
        );
        assert_eq!(result.is_ok(), good, "{}: {result:?}", fields["name"]);
        if let Ok(decisions) = result {
            assert_eq!(decisions.len(), 2);
            assert!(decisions.iter().all(|decision| matches!(
                decision,
                PublicationDecision::Replace(_) | PublicationDecision::Withdraw(_)
            )));
        }
    }
}
