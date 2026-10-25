#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use nsshared_control::{
    account::control::BootstrapEnvelope, account::control::CONFIG_SNAPSHOT,
    account::control::CONFIG_SNAPSHOT_PATH, account::control::CONTROL_ENVELOPE_PATH,
    account::control::EnvelopeDirection, account::control::EnvelopeExpectation,
    account::control::EnvelopePins, account::publication::AcceptedPublication,
    account::publication::PublicationChannel, account::publication::PublicationDecision,
    account::publication::PublicationExpectation, account::publication::PublicationKey,
    account::publication::PublicationScope, account::publication::PublicationSnapshotRequest,
    account::publication::SignedSourceBinding, account::publication::SnapshotRequestError,
};
use nsshared_identity::keys::IdentityKey;

#[test]
fn publication_snapshot_request_vectors() {
    let vectors = nsshared_testkit::vectors!("account/publication/snapshot-request");
    let pending = PublicationSnapshotRequest::decode(&vectors[0].hex("bytes")).unwrap();
    let current: Vec<_> = vectors
        .iter()
        .filter(|v| v.get("mode") == "source")
        .map(|v| {
            SignedSourceBinding::decode(&v.hex("bytes"))
                .unwrap()
                .binding
        })
        .collect();
    for v in &vectors {
        if v.get("mode") == "source" {
            continue;
        }
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
                served_realm: "030C1G60R30C1G60R30C1G60R3".parse().unwrap(),
                scope: "nodes",
            },
            PublicationScope {
                served_realm: "09144GJ289144GJ289144GJ289".parse().unwrap(),
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
        let result = pending.response(&envelope, &expected, &[], &current, &publication);
        assert_eq!(
            result.is_ok(),
            v.get("decision") == "accepted",
            "{}",
            v.name()
        );
        if v.name().contains("correlation") {
            assert!(matches!(&result, Err(SnapshotRequestError::Correlation)));
        }
        if let Ok(snapshot) = result {
            assert_eq!(envelope.payload, v.hex("snapshot"));
            let decisions = snapshot;
            if v.name() == "source-two-scopes" {
                assert_eq!(decisions.len(), 2);
                assert!(
                    decisions
                        .iter()
                        .all(|d| matches!(d, PublicationDecision::Replace(_)))
                );
                continue;
            }
            if v.name() == "source-ordered-large-directory-unknown" {
                assert_eq!(decisions.len(), 3);
                let PublicationDecision::Replace(directory) = &decisions[0] else {
                    panic!("directory");
                };
                assert_eq!(directory.content().key.family, 8);
                assert_eq!(directory.content().key.kind, "directory");
                let payload: serde_json::Value =
                    serde_json::from_slice(directory.content().payload).unwrap();
                assert_eq!(payload["relays"][0]["id"], 17);
                assert_eq!(payload["relays"][0]["code"], "HK");
                let PublicationDecision::Replace(large) = &decisions[1] else {
                    panic!("large entry");
                };
                assert_eq!(large.content().payload.len(), 800_000);
                assert!(matches!(&decisions[2], PublicationDecision::UnknownKind(_)));
                continue;
            }
            if v.name() == "response-empty" {
                assert!(decisions.is_empty());
            } else {
                if let Some(kind) = v.opt("extension_kind") {
                    assert_eq!(decisions.len(), 2);
                    let PublicationDecision::UnknownKind(extension) = &decisions[1] else {
                        panic!("expected authenticated extension");
                    };
                    assert_eq!(extension.content().key.kind, kind);
                    assert_eq!(extension.content().key.family, v.u64("extension_family"));
                    assert_eq!(extension.content().channel, PublicationChannel::Snapshot);
                } else {
                    assert_eq!(decisions.len(), 1);
                }
                let PublicationDecision::Replace(event) = &decisions[0] else {
                    panic!("expected replacement");
                };
                assert_eq!(event.content().key.kind, "node-l3");
                assert_eq!(event.content().payload, b"fixture-node-l3");
                let last = [AcceptedPublication {
                    key: PublicationKey {
                        issuer,
                        recipient: pending.subscriber,
                        served_realm: "030C1G60R30C1G60R30C1G60R3".parse().unwrap(),
                        scope: "nodes",
                        family: 11,
                        kind: "node-l3",
                    },
                    version: 8,
                }];
                assert!(
                    pending
                        .response(&envelope, &expected, &last, &current, &publication)
                        .is_err()
                );
            }
        }
    }
    assert_eq!(CONFIG_SNAPSHOT, "config.snapshot");
    assert_eq!(CONFIG_SNAPSHOT_PATH, CONTROL_ENVELOPE_PATH);
}
