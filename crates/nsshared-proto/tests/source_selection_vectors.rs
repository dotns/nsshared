#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod support;

use nsshared_proto::{
    IdentityKey,
    account::{
        AcceptedPublication, BootstrapEnvelope, EnvelopeDirection, EnvelopeExpectation,
        EnvelopePins, PublicationChannel, PublicationDecision, PublicationExpectation,
        PublicationScope, RebindAuthorization,
        control_exchange::{
            AuthenticationRequest, AuthenticationResponse, ExchangeError, MACHINE_REGISTER,
            RegistrationAcceptance, RegistrationRequest, compare_registration_acceptance,
        },
        route_command::{
            CommittedSelection, RouteCommand, RouteDecision, RouteReceipt, RouteResponse,
            decide_route_command,
        },
        source_binding::{
            DeliveryContext, SignedSourceBinding, SourceBinding, SourceEnrollmentExpectation,
            SourceError,
        },
        source_publication::{
            SourcePublication, decide_source_publication, decide_source_snapshot,
            decide_source_snapshot_scopes, encode_source_publication,
            source_publication_signing_input,
        },
    },
};
use support::vectors::Vector;

fn vectors() -> Vec<Vector> {
    support::vectors::load("source-selection")
}
fn bytes(vectors: &[Vector], name: &str) -> Vec<u8> {
    vectors
        .iter()
        .find(|v| v.name() == name)
        .unwrap()
        .hex("bytes")
}
fn binding(vectors: &[Vector], name: &str) -> SignedSourceBinding {
    SignedSourceBinding::decode(&bytes(vectors, name)).unwrap()
}
fn command(vectors: &[Vector], name: &str) -> RouteCommand {
    RouteCommand::decode(&bytes(vectors, name)).unwrap()
}
fn receipt(vectors: &[Vector], name: &str) -> RouteReceipt {
    RouteReceipt::decode(&bytes(vectors, name)).unwrap()
}
fn pins(identity: IdentityKey) -> EnvelopePins {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use sha2::{Digest as _, Sha256};
    let x = URL_SAFE_NO_PAD.encode(identity.as_bytes());
    let jwk = format!("{{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"{x}\"}}");
    let pin = URL_SAFE_NO_PAD.encode(Sha256::digest(jwk.as_bytes()));
    EnvelopePins::intersect(&[pin], &[]).unwrap()
}
fn context(channel: PublicationChannel) -> DeliveryContext {
    match channel {
        PublicationChannel::Stream => DeliveryContext::Stream {
            boot_nonce: [4; 16],
            attempt_counter: 1,
        },
        PublicationChannel::Snapshot => DeliveryContext::Snapshot {
            boot_nonce: [4; 16],
            attempt_counter: 1,
            correlation: [5; 16],
        },
    }
}

fn action(value: &PublicationDecision<'_>) -> &'static str {
    match value {
        PublicationDecision::Replace(_) => "replace",
        PublicationDecision::UnknownKind(_) => "unknown-kind",
        PublicationDecision::ChannelMismatch(_) => "channel-mismatch",
        PublicationDecision::Refused(_) => "refused",
        other => panic!("unexpected mixed snapshot decision: {other:?}"),
    }
}

fn check_snapshot_channels(v: &Vector, vectors: &[Vector]) {
    use nsshared_proto::encoding::CborReader;
    let b = binding(vectors, "source-b");
    let c = binding(vectors, "source-c");
    let count = usize::try_from(v.u64("scope_count")).unwrap();
    let current = [b.binding, c.binding];
    let scopes = current
        .iter()
        .map(|binding| PublicationScope {
            served_realm: binding.served_realm,
            scope: &binding.scope,
        })
        .collect::<Vec<_>>();
    let expected = PublicationExpectation {
        issuer: current[0].nsd,
        recipient: current[0].recipient,
        scopes: &scopes[..count],
        channel: PublicationChannel::Snapshot,
        now_seconds: 150,
    };
    let pending = context(PublicationChannel::Snapshot);
    let raw = v.hex("bytes");
    let accepted = v.get("decision") == "accepted";
    let mut reader = CborReader::new(&raw, raw.len()).unwrap();
    reader.array(2).unwrap();
    assert_eq!(reader.uint().unwrap(), 1);
    let length = reader.array_up_to(raw.len()).unwrap();
    let mut event_actions = Vec::new();
    let mut previous = None;
    for _ in 0..length {
        let entry = reader.bytes_up_to(raw.len()).unwrap();
        let event = SourcePublication::decode(entry).unwrap();
        let inner = event.event().unwrap();
        let key = inner.content().key;
        assert!(
            previous.is_none_or(|previous| previous < key),
            "{}: independently ordered fixture",
            v.name()
        );
        previous = Some(key);
        let current = current
            .iter()
            .find(|binding| binding.served_realm == key.served_realm)
            .unwrap();
        let decision = decide_source_publication(&[], Some(entry), current, &pending, &expected);
        event_actions.push(decision.as_ref().map_or("refused", action));
    }
    reader.finish().unwrap();
    assert_eq!(
        event_actions.join(","),
        v.get("event_actions"),
        "{}: per-event authentication/control",
        v.name()
    );
    // Both entry points must agree for the single-scope corpus. Only the aggregate
    // result is available to callers, so an error cannot expose adjacent actions.
    let scoped = decide_source_snapshot_scopes(&[], &raw, &current[..count], &pending, &expected);
    let mut results = vec![scoped];
    if count == 1 {
        results.push(decide_source_snapshot(
            &[],
            &raw,
            &current[0],
            &pending,
            &expected,
        ));
    }
    for result in results {
        assert_eq!(
            result.is_ok(),
            accepted,
            "{}: wrong aggregate acceptance",
            v.name()
        );
        if let Ok(decisions) = result {
            assert_eq!(
                decisions.iter().map(action).collect::<Vec<_>>(),
                event_actions,
                "{}: preserved actions",
                v.name()
            );
        } else if v.get("failure") == "channel" {
            assert!(
                matches!(result, Err(SourceError::Context)),
                "{}: channel-specific refusal",
                v.name()
            );
        }
    }
}

fn accept_source(
    v: &Vector,
    source: &SignedSourceBinding,
    nsd_pins: &EnvelopePins,
) -> Result<SignedSourceBinding, ExchangeError> {
    let envelope = BootstrapEnvelope::decode(&v.hex("bytes")).unwrap();
    let expected = EnvelopeExpectation {
        pins: nsd_pins,
        direction: EnvelopeDirection::Response,
        recipient: source.binding.recipient,
        kind: v.get("operation"),
        now_seconds: 100,
        previous_acceptance_seconds: None,
    };
    let pending = SourceEnrollmentExpectation {
        nsd: source.binding.nsd,
        recipient: source.binding.recipient,
        served_realm: v
            .opt("expected_realm")
            .map_or(source.binding.served_realm, |s| s.parse().unwrap()),
        scope: v.opt("expected_scope").unwrap_or(&source.binding.scope),
        profile: source.binding.profile,
        source_node: source.binding.source_node,
        request_id: [6; 16],
    };
    if v.get("operation") == MACHINE_REGISTER {
        let staged = RegistrationRequest::decode(&v.hex("request")).unwrap();
        compare_registration_acceptance(
            &envelope,
            &expected,
            &staged,
            v.opt("committed")
                .map(|_| nsshared_proto::account::Enrollment::decode(&v.hex("committed")).unwrap())
                .as_ref()
                .map(|e| &e.binding),
            RebindAuthorization::Denied,
            &pending,
        )?;
        let response = RegistrationAcceptance::decode(&envelope.payload)?;
        assert_eq!(response.canonical().unwrap(), envelope.payload);
        Ok(response.source_binding)
    } else {
        let response = AuthenticationResponse::from_envelope(&envelope, &expected, &pending)?;
        assert_eq!(response.token, "a.b.c");
        assert_eq!(response.canonical().unwrap(), envelope.payload);
        Ok(response.source_binding)
    }
}

fn check_selected_authentication(
    v: &Vector,
    source: &SignedSourceBinding,
    nsd_pins: &EnvelopePins,
) -> Option<SignedSourceBinding> {
    let raw = v.hex("request");
    let request = AuthenticationRequest::decode(&raw).unwrap();
    assert_eq!(request.canonical().unwrap(), raw);
    let envelope = BootstrapEnvelope::decode(&v.hex("bytes")).unwrap();
    let expected = EnvelopeExpectation {
        pins: nsd_pins,
        direction: EnvelopeDirection::Response,
        recipient: source.binding.recipient,
        kind: "machine.auth",
        now_seconds: 100,
        previous_acceptance_seconds: None,
    };
    assert_eq!(request.source_scope.publication_scope, v.get("scope"));
    let pending = SourceEnrollmentExpectation {
        nsd: source.binding.nsd,
        recipient: source.binding.recipient,
        served_realm: request.source_scope.served_realm,
        scope: &request.source_scope.publication_scope,
        profile: source.binding.profile,
        source_node: source.binding.source_node,
        request_id: v.hex_array("pending_nonce"),
    };
    let response = AuthenticationResponse::from_envelope(&envelope, &expected, &pending);
    assert_eq!(
        response.is_ok(),
        v.get("decision") == "accepted",
        "{}: {response:?}",
        v.name()
    );
    response.ok().map(|response| {
        assert_eq!(response.token, "a.b.c");
        assert_eq!(response.canonical().unwrap(), envelope.payload);
        response.source_binding
    })
}

#[test]
fn independent_source_selection_vectors() {
    let vectors = vectors();
    let a = binding(&vectors, "source-a");
    let b = binding(&vectors, "source-b");
    let issuer = a.binding.nsd;
    let nsd_pins = pins(issuer);
    let node_pins = pins(a.binding.recipient);
    for v in &vectors {
        let raw = v.hex("bytes");
        let accepted = v.get("decision") == "accepted";
        match v.get("mode") {
            "authentication-request" => {
                let request = AuthenticationRequest::decode(&raw).unwrap();
                assert_eq!(request.canonical().unwrap(), raw);
            }
            "selected-authentication" => {
                check_selected_authentication(v, &a, &nsd_pins);
            }
            "snapshot-channel" => check_snapshot_channels(v, &vectors),
            "binding" => {
                let result = SignedSourceBinding::decode(&raw).and_then(|s| {
                    s.verify(issuer)?;
                    Ok(s)
                });
                assert_eq!(result.is_ok(), accepted, "{}: {result:?}", v.name());
                if let Ok(value) = result {
                    assert_eq!(value.canonical().unwrap(), raw);
                    assert_eq!(value.signing_input().unwrap(), v.hex("signing_input"));
                }
            }
            "context" => {
                let result = DeliveryContext::decode(&raw);
                assert_eq!(result.is_ok(), accepted, "{}: {result:?}", v.name());
                if let Ok(value) = result {
                    assert_eq!(value.canonical().unwrap(), raw);
                }
            }
            "acceptance" => {
                let result = accept_source(v, &a, &nsd_pins);
                assert_eq!(result.is_ok(), accepted, "{}: {result:?}", v.name());
                if let Ok(value) = result {
                    assert_eq!(value, a);
                }
            }

            "scoped-snapshot" => {
                let c = binding(&vectors, "source-c");
                let scopes = [
                    PublicationScope {
                        served_realm: b.binding.served_realm,
                        scope: &b.binding.scope,
                    },
                    PublicationScope {
                        served_realm: c.binding.served_realm,
                        scope: &c.binding.scope,
                    },
                ];
                let expected = PublicationExpectation {
                    issuer,
                    recipient: b.binding.recipient,
                    scopes: &scopes,
                    channel: PublicationChannel::Snapshot,
                    now_seconds: 150,
                };
                let current = [b.binding.clone(), c.binding.clone()];
                let result = decide_source_snapshot_scopes(
                    &[],
                    &raw,
                    &current,
                    &context(PublicationChannel::Snapshot),
                    &expected,
                );
                assert_eq!(result.is_ok(), accepted, "{}: {result:?}", v.name());
                if let Ok(decisions) = result {
                    assert_eq!(decisions.len(), 2);
                }
                let ambiguous = [a.binding.clone(), b.binding.clone()];
                assert!(
                    decide_source_snapshot_scopes(
                        &[],
                        &raw,
                        &ambiguous,
                        &context(PublicationChannel::Snapshot),
                        &expected
                    )
                    .is_err()
                );
            }
            "publication" | "snapshot" => {
                let channel = if v.opt("channel") == Some("0") {
                    PublicationChannel::Stream
                } else {
                    PublicationChannel::Snapshot
                };
                let scopes = [PublicationScope {
                    served_realm: b.binding.served_realm,
                    scope: &b.binding.scope,
                }];
                let expected = PublicationExpectation {
                    issuer,
                    recipient: b.binding.recipient,
                    scopes: &scopes,
                    channel,
                    now_seconds: 150,
                };
                let prior_raw = bytes(&vectors, "current-b");
                let prior = SourcePublication::decode(&prior_raw).unwrap();
                let last = [AcceptedPublication {
                    key: prior.event().unwrap().content().key,
                    version: 7,
                }];
                if v.get("mode") == "snapshot" {
                    let result = decide_source_snapshot(
                        &last,
                        &raw,
                        &b.binding,
                        &context(channel),
                        &expected,
                    );
                    assert_eq!(result.is_ok(), accepted, "{}: {result:?}", v.name());
                } else {
                    let result = decide_source_publication(
                        &last,
                        Some(&raw),
                        &b.binding,
                        &context(channel),
                        &expected,
                    );
                    let ok = matches!(
                        result,
                        Ok(PublicationDecision::Replace(_)
                            | PublicationDecision::Withdraw(_)
                            | PublicationDecision::FetchFailed(_))
                    );
                    assert_eq!(ok, accepted, "{}: {result:?}", v.name());
                    if accepted {
                        let decoded = SourcePublication::decode(&raw).unwrap();
                        assert_eq!(decoded.canonical(), raw);
                        let event = decoded.event().unwrap();
                        let signing = source_publication_signing_input(
                            decoded.binding(),
                            decoded.delivery(),
                            event.canonical(),
                        )
                        .unwrap();
                        assert_eq!(signing, decoded.signing_input());
                        if v.opt("signing_input").is_some() {
                            assert_eq!(signing, v.hex("signing_input"));
                        }
                        assert_eq!(
                            encode_source_publication(
                                decoded.binding(),
                                decoded.delivery(),
                                event.canonical(),
                                decoded.signature()
                            )
                            .unwrap(),
                            raw
                        );
                        if v.name() == "complete-empty-b" {
                            assert!(matches!(result, Ok(PublicationDecision::Withdraw(_))));
                        }
                        if v.name() == "failure-b" {
                            assert!(matches!(result, Ok(PublicationDecision::FetchFailed(_))));
                        }
                    }
                }
            }
            "command" => {
                let result = RouteCommand::decode(&raw);
                assert_eq!(result.is_ok(), accepted, "{}: {result:?}", v.name());
                if let Ok(value) = result {
                    assert_eq!(value.canonical().unwrap(), raw);
                }
            }
            "command-carrier" => {
                let envelope = BootstrapEnvelope::decode(&raw).unwrap();
                let expected = EnvelopeExpectation {
                    pins: &node_pins,
                    direction: EnvelopeDirection::Request,
                    recipient: issuer,
                    kind: &envelope.kind,
                    now_seconds: 100,
                    previous_acceptance_seconds: None,
                };
                let result = RouteCommand::from_envelope(&envelope, &expected, issuer);
                assert_eq!(result.is_ok(), accepted, "{}: {result:?}", v.name());
                if accepted {
                    let replayed = EnvelopeExpectation {
                        previous_acceptance_seconds: Some(100),
                        ..expected
                    };
                    assert!(RouteCommand::from_envelope(&envelope, &replayed, issuer).is_err());
                }
            }
            "receipt" => {
                let result = RouteReceipt::decode(&raw);
                assert_eq!(result.is_ok(), accepted, "{}: {result:?}", v.name());
                if let Ok(value) = result {
                    assert_eq!(value.canonical().unwrap(), raw);
                }
            }
            "response" => {
                let envelope = BootstrapEnvelope::decode(&raw).unwrap();
                let pending = if v.name().contains("select-b") {
                    command(&vectors, "select-b")
                } else if v.name().contains("select-a") {
                    command(&vectors, "select-a")
                } else {
                    command(&vectors, "clear-a")
                };
                let expected = EnvelopeExpectation {
                    pins: &nsd_pins,
                    direction: EnvelopeDirection::Response,
                    recipient: a.binding.recipient,
                    kind: pending.operation(),
                    now_seconds: 100,
                    previous_acceptance_seconds: None,
                };
                let pending_nonce = v
                    .opt("pending_nonce")
                    .map_or(pending.request_id, |_| v.hex_array("pending_nonce"));
                let result =
                    RouteResponse::from_envelope(&envelope, &expected, &pending, pending_nonce);
                assert_eq!(result.is_ok(), accepted, "{}: {result:?}", v.name());
                if let Ok(value) = result {
                    assert_eq!(value.canonical().unwrap(), envelope.payload);
                }
            }
            other => panic!("unknown mode {other}"),
        }
    }
}

#[test]
fn source_selection_fence() {
    let vectors = vectors();
    let expected_a = binding(&vectors, "source-a");
    let nsd_pins = pins(expected_a.binding.nsd);
    let register = vectors.iter().find(|v| v.name() == "register-a").unwrap();
    let a = accept_source(register, &expected_a, &nsd_pins).unwrap();
    let equal = vectors
        .iter()
        .find(|v| v.name() == "register-equal")
        .unwrap();
    assert_eq!(accept_source(equal, &expected_a, &nsd_pins).unwrap(), a);
    let retained_sources = vectors
        .iter()
        .filter(|v| v.get("mode") == "selected-authentication")
        .filter_map(|v| check_selected_authentication(v, &a, &nsd_pins))
        .collect::<Vec<_>>();
    assert_eq!(retained_sources.len(), 2);
    assert_eq!(retained_sources[0], a);
    assert_eq!(retained_sources[1], binding(&vectors, "source-egress"));
    assert_eq!(
        retained_sources[0].binding.served_realm,
        retained_sources[1].binding.served_realm
    );
    assert_ne!(
        retained_sources[0].binding.contribution,
        retained_sources[1].binding.contribution
    );
    let auth = vectors.iter().find(|v| v.name() == "auth-a").unwrap();
    assert_eq!(accept_source(auth, &expected_a, &nsd_pins).unwrap(), a);
    for v in vectors
        .iter()
        .filter(|v| v.get("mode") == "acceptance" && v.get("decision") == "refused")
    {
        assert!(
            accept_source(v, &expected_a, &nsd_pins).is_err(),
            "{}",
            v.name()
        );
    }
    let b = binding(&vectors, "source-b");
    // Both source identities imply the same addresses; K stays an independent fixed fact.
    let fixture_a = vectors.iter().find(|v| v.name() == "source-a").unwrap();
    let fixture_b = vectors.iter().find(|v| v.name() == "source-b").unwrap();
    assert_eq!(a.binding.source_node, b.binding.source_node);
    assert_eq!(fixture_a.hex("wg_key"), fixture_b.hex("wg_key"));
    for (binding, fixture) in [(&a, fixture_a), (&b, fixture_b)] {
        let group =
            nsshared_proto::identity::AddressGroup::derive(binding.binding.source_node.as_bytes());
        assert_eq!(group.n4_bytes().as_slice(), fixture.hex("n4"));
        assert_eq!(group.n6_bytes().as_slice(), fixture.hex("n6"));
    }
    assert_eq!(fixture_a.hex("n4"), fixture_b.hex("n4"));
    assert_eq!(fixture_a.hex("n6"), fixture_b.hex("n6"));
    assert_ne!(a.binding.contribution, b.binding.contribution);
    assert!(b.binding.source_generation > a.binding.source_generation);
    let sa = command(&vectors, "select-a");
    let ca = command(&vectors, "clear-a");
    let sb = command(&vectors, "select-b");
    let ra = receipt(&vectors, "receipt-select-a");
    let rc = receipt(&vectors, "receipt-clear-a");
    let rb = receipt(&vectors, "receipt-select-b");
    assert!(matches!(
        decide_route_command(&sa, a.binding.recipient, &a.binding, None, None).unwrap(),
        RouteDecision::Select
    ));
    let selection_a = CommittedSelection {
        command: ra.command.clone(),
        generation: ra.selection_generation,
    };
    assert!(matches!(
        decide_route_command(
            &ca,
            a.binding.recipient,
            &a.binding,
            None,
            Some(&selection_a)
        )
        .unwrap(),
        RouteDecision::Clear
    ));
    assert!(matches!(
        decide_route_command(&sb, b.binding.recipient, &b.binding, None, None).unwrap(),
        RouteDecision::Select
    ));
    let current = CommittedSelection {
        command: rb.command.clone(),
        generation: rb.selection_generation,
    };
    let scopes = [PublicationScope {
        served_realm: b.binding.served_realm,
        scope: &b.binding.scope,
    }];
    let expected = PublicationExpectation {
        issuer: b.binding.nsd,
        recipient: b.binding.recipient,
        scopes: &scopes,
        channel: PublicationChannel::Snapshot,
        now_seconds: 150,
    };
    let delayed = bytes(&vectors, "delayed-a-higher-version");
    let valid = bytes(&vectors, "current-b");
    let old_event = SourcePublication::decode(&delayed)
        .unwrap()
        .event()
        .unwrap();
    let current_event = SourcePublication::decode(&valid).unwrap().event().unwrap();
    assert!(old_event.content().version > current_event.content().version);
    let retained = [AcceptedPublication {
        key: current_event.content().key,
        version: 7,
    }];
    for restored in [false, true] {
        let accepted = if restored {
            SourceBinding::decode(&b.binding.canonical().unwrap()).unwrap()
        } else {
            b.binding.clone()
        };
        let delivery = context(PublicationChannel::Snapshot);
        let delivery = if restored {
            DeliveryContext::decode(&delivery.canonical().unwrap()).unwrap()
        } else {
            delivery
        };
        assert!(matches!(
            decide_source_publication(&retained, Some(&delayed), &accepted, &delivery, &expected),
            Err(SourceError::Authority)
        ));
        let old_receipt = if restored {
            RouteReceipt::decode(&rc.canonical().unwrap()).unwrap()
        } else {
            rc.clone()
        };
        let selection = if restored {
            CommittedSelection {
                command: RouteCommand::decode(&current.command.canonical().unwrap()).unwrap(),
                generation: current.generation,
            }
        } else {
            current.clone()
        };
        let result = decide_route_command(
            &ca,
            a.binding.recipient,
            &accepted,
            Some(&old_receipt),
            Some(&selection),
        )
        .unwrap();
        let RouteDecision::Replay(original) = result else {
            panic!("clear replay acquired mutation authority")
        };
        assert_eq!(*original, rc);
        assert_eq!(selection, current);
        assert_eq!(original.command.binding, a);
    }
    assert!(matches!(
        decide_source_publication(
            &[],
            Some(&valid),
            &b.binding,
            &context(PublicationChannel::Snapshot),
            &expected
        )
        .unwrap(),
        PublicationDecision::Replace(_)
    ));
    let mut conflict = ca.clone();
    conflict.selection_id = [88; 16];
    assert!(
        decide_route_command(
            &conflict,
            a.binding.recipient,
            &b.binding,
            Some(&rc),
            Some(&current)
        )
        .is_err()
    );
    assert!(
        decide_route_command(&ca, a.binding.recipient, &b.binding, None, Some(&current)).is_err()
    );
    let mut wrong_pending = ca.clone();
    wrong_pending.request_id = [90; 16];
    let wire = BootstrapEnvelope::decode(&bytes(&vectors, "receipt-clear-a-replay")).unwrap();
    let nsd_pins = pins(b.binding.nsd);
    let expected = EnvelopeExpectation {
        pins: &nsd_pins,
        direction: EnvelopeDirection::Response,
        recipient: b.binding.recipient,
        kind: "node.route.clear",
        now_seconds: 100,
        previous_acceptance_seconds: None,
    };
    assert!(RouteResponse::from_envelope(&wire, &expected, &wrong_pending, ca.request_id).is_err());
}

#[test]
fn exact_clear_target_and_source_request_namespace() {
    use nsshared_proto::account::route_command::RouteAction;
    let vectors = vectors();
    let a = binding(&vectors, "source-a");
    let b = binding(&vectors, "source-b");
    let select_b = command(&vectors, "select-b");
    let rb = receipt(&vectors, "receipt-select-b");
    let current = CommittedSelection {
        command: select_b.clone(),
        generation: rb.selection_generation,
    };
    let mut clear = command(&vectors, "clear-a");
    clear.binding = b.clone();
    clear.selection_id = select_b.selection_id;
    // An old target generation cannot clear a newer selection even in the current source.
    assert!(matches!(
        decide_route_command(
            &clear,
            b.binding.recipient,
            &b.binding,
            None,
            Some(&current)
        )
        .unwrap(),
        RouteDecision::ClearAbsent
    ));
    clear.action = RouteAction::Clear {
        generation: rb.selection_generation,
    };
    assert!(matches!(
        decide_route_command(
            &clear,
            b.binding.recipient,
            &b.binding,
            None,
            Some(&current)
        )
        .unwrap(),
        RouteDecision::Clear
    ));
    clear.selection_id = [77; 16];
    assert!(matches!(
        decide_route_command(
            &clear,
            b.binding.recipient,
            &b.binding,
            None,
            Some(&current)
        )
        .unwrap(),
        RouteDecision::ClearAbsent
    ));
    assert!(decide_route_command(&clear, b.binding.nsd, &b.binding, None, Some(&current)).is_err());
    let mut selection = select_b;
    // Reusing the numeric request identity under B is a new source-owned request.
    selection.request_id = command(&vectors, "select-a").request_id;
    assert!(matches!(
        decide_route_command(
            &selection,
            b.binding.recipient,
            &b.binding,
            None,
            Some(&current)
        )
        .unwrap(),
        RouteDecision::Select
    ));
    let old_receipt = receipt(&vectors, "receipt-clear-a");
    let wire = BootstrapEnvelope::decode(&bytes(&vectors, "receipt-clear-a-replay")).unwrap();
    let pins = pins(b.binding.nsd);
    let carrier = EnvelopeExpectation {
        pins: &pins,
        direction: EnvelopeDirection::Response,
        recipient: b.binding.recipient,
        kind: "node.route.clear",
        now_seconds: 100,
        previous_acceptance_seconds: None,
    };
    let mut pending = old_receipt.command.clone();
    pending.binding = b.clone();
    assert!(
        RouteResponse::from_envelope(&wire, &carrier, &pending, old_receipt.command.request_id)
            .is_err()
    );
    let mut wrong_source = b.binding;
    wrong_source.source_epoch += 1;
    assert!(
        decide_route_command(&selection, a.binding.recipient, &wrong_source, None, None).is_err()
    );
}

#[test]
fn source_publication_absence_and_measured_bound() {
    use nsshared_proto::account::source_binding::SourceError;
    use nsshared_proto::account::{MAX_PUBLICATION_BYTES, PublicationError};
    let vectors = vectors();
    let b = binding(&vectors, "source-b");
    let scopes = [PublicationScope {
        served_realm: b.binding.served_realm,
        scope: &b.binding.scope,
    }];
    let mut expected = PublicationExpectation {
        issuer: b.binding.nsd,
        recipient: b.binding.recipient,
        scopes: &scopes,
        channel: PublicationChannel::Stream,
        now_seconds: 150,
    };
    assert!(matches!(
        decide_source_publication(
            &[],
            None,
            &b.binding,
            &context(PublicationChannel::Stream),
            &expected
        )
        .unwrap(),
        PublicationDecision::Absent
    ));
    let over = vec![0; MAX_PUBLICATION_BYTES + 1];
    assert!(matches!(
        decide_source_publication(
            &[],
            Some(&over),
            &b.binding,
            &context(PublicationChannel::Stream),
            &expected
        )
        .unwrap(),
        PublicationDecision::TerminateStream
    ));
    expected.channel = PublicationChannel::Snapshot;
    assert!(matches!(
        decide_source_publication(
            &[],
            Some(&over),
            &b.binding,
            &context(PublicationChannel::Snapshot),
            &expected
        ),
        Err(SourceError::Publication(PublicationError::Bounds))
    ));
    let malformed = [0x82, 0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    assert!(
        decide_source_publication(
            &[],
            Some(&malformed),
            &b.binding,
            &context(PublicationChannel::Snapshot),
            &expected
        )
        .is_err()
    );
}
