#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod support;
use nsshared_proto::{
    IdentityKey,
    account::{
        AcceptedPublication, BootstrapEnvelope, EnvelopeDirection, EnvelopeExpectation,
        EnvelopePins, PublicationChannel, PublicationDecision, PublicationError,
        PublicationExpectation, PublicationKey, PublicationScope,
        control_exchange::{CONFIG_SNAPSHOT, CONFIG_SNAPSHOT_PATH, CONTROL_ENVELOPE_PATH},
        publication_snapshot_request::{PublicationSnapshotRequest, SnapshotRequestError},
    },
};

#[test]
fn publication_snapshot_request_vectors() {
    let vectors = support::vectors::parse(include_str!(
        "fixtures/vectors/publication-snapshot-request.vec"
    ));
    let pending = PublicationSnapshotRequest::decode(&vectors[0].hex("bytes")).unwrap();
    for v in &vectors {
        let bytes = v.hex("bytes");
        if v.get("mode") == "request" {
            let result = PublicationSnapshotRequest::decode(&bytes);
            assert_eq!(
                result.is_ok(),
                v.get("decision") == "accepted",
                "{}: {result:?}",
                v.name()
            );
            if let Ok(request) = result {
                assert_eq!(request.canonical().unwrap(), bytes);
                assert_eq!(request.correlation, [5; 16]);
                assert_eq!(request.boot_nonce, [3; 16]);
                assert_eq!(request.attempt_counter, 1);
            }
            continue;
        }
        let envelope = BootstrapEnvelope::decode(&bytes).unwrap();
        assert_eq!(envelope.signing_input().unwrap(), v.hex("signing_input"));
        let pins = EnvelopePins::intersect(&[v.get("pin").into()], &[]).unwrap();
        let issuer = IdentityKey::from_bytes(&v.hex_array("issuer")).unwrap();
        let request_mode = v.get("mode") == "signed-request";
        let expected = EnvelopeExpectation {
            pins: &pins,
            direction: if request_mode {
                EnvelopeDirection::Request
            } else {
                EnvelopeDirection::Response
            },
            recipient: if request_mode {
                issuer
            } else {
                pending.subscriber
            },
            kind: CONFIG_SNAPSHOT,
            now_seconds: 100,
            previous_acceptance_seconds: None,
        };
        if request_mode {
            let result = PublicationSnapshotRequest::from_envelope(&envelope, &expected);
            assert_eq!(
                result.is_ok(),
                v.get("decision") == "accepted",
                "{}: {result:?}",
                v.name()
            );
            if let Ok(request) = result {
                assert_eq!(request, pending);
                let mut tampered = envelope.clone();
                tampered.signature[0] ^= 1;
                assert!(PublicationSnapshotRequest::from_envelope(&tampered, &expected).is_err());
            }
            continue;
        }
        let scopes = [
            PublicationScope {
                served_realm: "realm-a",
                scope: "nodes",
            },
            PublicationScope {
                served_realm: "realm-b",
                scope: "nodes",
            },
        ];
        let publication = PublicationExpectation {
            issuer,
            recipient: pending.subscriber,
            scopes: &scopes,
            channel: PublicationChannel::Snapshot,
            now_seconds: 100,
        };
        let result = pending.response(&envelope, &expected, &[], &publication);
        assert_eq!(
            result.is_ok(),
            v.get("decision") == "accepted",
            "{}",
            v.name()
        );
        match v.name() {
            "response-unrequested-scope" => {
                assert!(matches!(&result, Err(SnapshotRequestError::Scope)))
            }
            "response-event-recipient" | "response-carrier-recipient" => assert!(result.is_err()),
            "response-correlation" => {
                assert!(matches!(&result, Err(SnapshotRequestError::Correlation)))
            }
            "response-stream-kind" => {
                assert!(matches!(&result, Err(SnapshotRequestError::Channel)))
            }
            _ => {}
        }
        if let Ok(snapshot) = result {
            assert_eq!(snapshot.canonical(), v.hex("snapshot"));
            let decisions: Vec<_> = snapshot.decisions().collect();
            if v.name() == "response-empty" {
                assert!(decisions.is_empty());
            } else {
                assert_eq!(decisions.len(), 1);
                let PublicationDecision::Replace(event) = &decisions[0] else {
                    panic!("expected replacement");
                };
                assert_eq!(event.content().key.kind, "node-l3");
                assert_eq!(event.content().payload, b"fixture-node-l3");
                let last = [AcceptedPublication {
                    key: PublicationKey {
                        issuer,
                        recipient: pending.subscriber,
                        served_realm: "realm-a",
                        scope: "nodes",
                        family: 11,
                        kind: "node-l3",
                    },
                    version: 8,
                }];
                assert!(matches!(
                    pending.response(&envelope, &expected, &last, &publication),
                    Err(SnapshotRequestError::Publication(PublicationError::Stale))
                ));
            }
        }
    }
    assert_eq!(CONFIG_SNAPSHOT, "config.snapshot");
    assert_eq!(CONFIG_SNAPSHOT_PATH, CONTROL_ENVELOPE_PATH);
}
