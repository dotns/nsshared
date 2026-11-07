#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use nsshared_control::account::{publication::*, subnet::*};

#[test]
fn exit_readiness_has_an_independent_snapshot_channel() {
    assert_eq!(
        publication_channel(4, "exit-readiness"),
        Some(PublicationChannel::Snapshot)
    );
    assert_eq!(
        FamilyRegistry
            .replacement(4, "exit-readiness")
            .unwrap()
            .clears,
        "confirmations"
    );
    assert!(ExitInstallationIncarnation([0; 16]).canonical().is_err());
}

fn context() -> ExitInstallContext {
    let vectors = nsshared_testkit::vectors!("account/subnet/readiness");
    ExitInstallContext::decode(
        &vectors
            .iter()
            .find(|v| v.name() == "context-explicit")
            .unwrap()
            .hex("bytes"),
    )
    .unwrap()
}
fn observation() -> ExitInstallObservation {
    let vectors = nsshared_testkit::vectors!("account/subnet/readiness");
    ExitInstallObservation::decode(
        &vectors
            .iter()
            .find(|v| v.name() == "observation-explicit")
            .unwrap()
            .hex("bytes"),
    )
    .unwrap()
}

#[test]
fn independent_readiness_vectors() {
    use nsshared_control::account::grants::ServiceGrant;
    for v in &nsshared_testkit::vectors!("account/subnet/readiness") {
        let raw = v.hex("bytes");
        let accepted = v.get("decision") == "accept";
        macro_rules! check {
            ($ty:ty) => {{
                let result = <$ty>::decode(&raw);
                assert_eq!(result.is_ok(), accepted, "{}: {result:?}", v.name());
                if let Ok(value) = result {
                    assert_eq!(value.canonical().unwrap(), raw, "{}", v.name());
                }
            }};
        }
        match v.get("kind") {
            "context" => {
                check!(ExitInstallContext);
                if accepted {
                    assert_eq!(
                        ExitInstallContext::decode(&raw)
                            .unwrap()
                            .digest()
                            .unwrap()
                            .as_slice(),
                        v.hex("digest")
                    );
                }
            }
            "peer" => check!(ExitPeerReceipt),
            "binding" => check!(ExitBindingReceipt),
            "observation" => {
                check!(ExitInstallObservation);
                if v.name().starts_with("observation-e") || v.name() == "observation-default" {
                    assert_eq!(
                        ExitInstallObservation::decode(&raw)
                            .unwrap()
                            .digest()
                            .unwrap()
                            .as_slice(),
                        v.hex("digest")
                    );
                }
            }
            "confirmation" => check!(ExitProviderConfirmation),
            "publication" => check!(ExitReadinessPublication),
            "grant" => {
                check!(ServiceGrant);
                if accepted {
                    assert_eq!(
                        ServiceGrant::decode(&raw)
                            .unwrap()
                            .digest()
                            .unwrap()
                            .as_slice(),
                        v.hex("digest")
                    );
                }
            }
            "event" => {
                use nsshared_control::account::control::MembershipScope;
                let context = context();
                let source = &context.receipt.command.binding.binding;
                let membership = MembershipScope {
                    nsd_id: context.grant.resource.nsd_id,
                    network_id: context.grant.resource.network_id,
                };
                let result = PublicationEvent::decode(&raw)
                    .and_then(|event| event.validate_exit_readiness_context(source, &membership));
                assert_eq!(result.is_ok(), accepted, "{}: {result:?}", v.name());
                if accepted {
                    let event = PublicationEvent::decode(&raw).unwrap();
                    assert!(
                        event
                            .validate_routing_context(source.recipient, &membership)
                            .is_err()
                    );
                    let mut other = source.clone();
                    other.source_generation += 1;
                    if v.name() == "event-positive" {
                        assert!(
                            event
                                .validate_exit_readiness_context(&other, &membership)
                                .is_err()
                        );
                    }
                    assert!(event.decode_grant_payload().unwrap().is_none());
                    assert!(event.decode_subnet_payload().unwrap().is_none());
                }
            }
            "return" => {
                use nsshared_codec::cbor::CborReader;
                let mapped = v.hex("mapped");
                let mut input = CborReader::new(&mapped, 100).unwrap();
                input.array(3).unwrap();
                assert_eq!(input.uint().unwrap(), 6);
                let address = std::net::Ipv6Addr::from(input.fixed_bytes::<16>().unwrap());
                let prefix = SubnetPrefix {
                    address: address.into(),
                    length: input.uint().unwrap() as u8,
                };
                let expected = {
                    let mut r = CborReader::new(&raw, 100).unwrap();
                    r.fixed_bytes::<16>().unwrap()
                };
                assert_eq!(
                    consumer_return_identity(&v.hex_array("identity"), prefix)
                        .unwrap()
                        .octets(),
                    expected
                );
                let bad = SubnetPrefix {
                    length: 95,
                    ..prefix
                };
                assert!(consumer_return_identity(&v.hex_array("identity"), bad).is_err());
            }
            other => panic!("unknown kind {other}"),
        }
    }
}

#[test]
fn exact_context_fences_reselection_owner_renewal_and_stale_negatives() {
    let context = context();
    let installed = observation();
    installed.validate_for(&context, 9999).unwrap();
    assert!(installed.validate_for(&context, 10000).is_err());
    let mut replacement = context.clone();
    replacement.receipt.selection_generation += 1;
    assert!(installed.validate_for(&replacement, 1).is_err());
    let mut replacement = context.clone();
    replacement.consumer_incarnation.0[0] ^= 1;
    assert!(installed.validate_for(&replacement, 1).is_err());
    let mut replacement = context.clone();
    replacement.provider_incarnation.0[0] ^= 1;
    assert!(installed.validate_for(&replacement, 1).is_err());
    let mut replacement = context.clone();
    replacement.nsd_incarnation[0] ^= 1;
    assert!(installed.validate_for(&replacement, 1).is_err());
    let mut replacement = context.clone();
    replacement.grant.expires_at_unix_ms += 1;
    assert!(installed.validate_for(&replacement, 1).is_err());
    installed.validate_successor(&installed).unwrap();
    let mut negative = installed.clone();
    negative.status = ExitInstallStatus::NotInstalled;
    assert!(negative.validate_successor(&installed).is_err());
    negative.generation += 1;
    negative.validate_successor(&installed).unwrap();
    assert!(installed.validate_successor(&negative).is_err());
    negative.challenge_id[0] ^= 1;
    assert!(negative.validate_successor(&installed).is_err());
}

#[test]
fn proof_requires_exact_peer_binding_and_adopted_deadline() {
    let context = context();
    for field in 0..7 {
        let mut report = observation();
        let ExitInstallStatus::Installed { peer, binding } = &mut report.status else {
            panic!()
        };
        match field {
            0 => peer.local_wg[0] ^= 1,
            1 => peer.consumer_wg[0] ^= 1,
            2 => peer.return_hosts[0] = "fd00::1".parse().unwrap(),
            3 => binding.generation = 0,
            4 => binding.adopted_until_unix_ms -= 1,
            5 => binding.resource.service_id[0] ^= 1,
            _ => binding.real.length += 1,
        }
        assert!(report.validate_for(&context, 1).is_err(), "field {field}");
    }
    let report = observation();
    let proof = ExitProviderConfirmation {
        context: context.clone(),
        observation: report,
        valid_until_unix_ms: 10000,
    };
    proof.validate_for(&context, 1).unwrap();
    let mut other = context;
    other.receipt.selection_generation += 1;
    assert!(proof.validate_for(&other, 1).is_err());
}

#[test]
fn gateway_health_receipt_is_not_an_exit_acceptance() {
    use nsshared_control::account::control::{
        FencedGatewayReportRequest, FencedGatewayReportResponse,
    };
    let vectors = nsshared_testkit::vectors!("account/control/fenced-gateway");
    let mut request = FencedGatewayReportRequest::decode(
        &vectors
            .iter()
            .find(|v| v.name() == "full")
            .unwrap()
            .hex("bytes"),
    )
    .unwrap();
    let mut response = FencedGatewayReportResponse::decode(
        &vectors
            .iter()
            .find(|v| v.name() == "receipt")
            .unwrap()
            .hex("bytes"),
    )
    .unwrap();
    response.response.exit_challenge = Some(context());
    response.validate_for(&request).unwrap();
    assert!(response.response.accepted_exit_installation.is_none());
    response.response.accepted_exit_installation = Some(observation().digest().unwrap());
    assert!(response.validate_for(&request).is_err());
    request.report.exit_installation = Some(observation());
    response.validate_for(&request).unwrap();
    assert_eq!(
        FencedGatewayReportResponse::decode(&response.canonical().unwrap()).unwrap(),
        response
    );
    request
        .report
        .exit_installation
        .as_mut()
        .unwrap()
        .generation += 1;
    assert!(response.validate_for(&request).is_err());
    response.response.accepted_exit_installation = None;
    response.validate_for(&request).unwrap();
    response.fence.runtime_generation += 1;
    assert!(response.validate_for(&request).is_err());
}

#[test]
fn installation_subscription_slot_is_mandatory_and_nonzero_when_present() {
    let vectors = nsshared_testkit::vectors!("account/publication/subscription");
    let raw = vectors
        .iter()
        .find(|v| v.name() == "populated")
        .unwrap()
        .hex("bytes");
    let mut value = PublicationSubscriptionRequest::decode(&raw).unwrap();
    value.exit_installation = Some(ExitInstallationIncarnation([3; 16]));
    let encoded = value.canonical().unwrap();
    assert_eq!(
        PublicationSubscriptionRequest::decode(&encoded).unwrap(),
        value
    );
    value.exit_installation = Some(ExitInstallationIncarnation([0; 16]));
    assert!(value.canonical().is_err());
    let mut old = raw;
    old[0] = 0x88;
    old.pop();
    assert!(PublicationSubscriptionRequest::decode(&old).is_err());
}

#[test]
fn context_rejects_inconsistent_authority_and_return_identity() {
    for field in 0..11 {
        let mut context = context();
        match field {
            0 => context.provider_source.nsd = context.consumer_node.identity,
            1 => context.provider_source.scope = "egress".into(),
            2 => context.provider_source.source_node = context.consumer_node.identity,
            3 => context.provider_node.generation.0 = 0,
            4 => context.provider_node.wg_key = [0; 32],
            5 => context.consumer_node.identity = context.provider_node.identity,
            6 => context.grant.incarnation.0 = [0; 16],
            7 => context.return_hosts[0] = "fd00::1".parse().unwrap(),
            8 => context.consumer_incarnation.0 = [0; 16],
            9 => {
                context.provider_source.served_realm =
                    nsshared_identity::realm::RealmId::from_bytes([99; 16])
            }
            _ => context.grant.resource.network_id[0] ^= 1,
        }
        assert!(context.canonical().is_err(), "field {field}");
    }
    let valid = context();
    let mut changed = valid.clone();
    changed.grant.expires_at_unix_ms += 1;
    assert_ne!(
        valid.grant.digest().unwrap(),
        changed.grant.digest().unwrap()
    );
    assert_ne!(valid.digest().unwrap(), changed.digest().unwrap());
    let mut changed = valid.clone();
    changed.receipt.selection_generation += 1;
    assert_eq!(
        valid.grant.digest().unwrap(),
        changed.grant.digest().unwrap()
    );
    assert_ne!(valid.digest().unwrap(), changed.digest().unwrap());
}

#[test]
fn prior_gateway_wire_forms_cannot_supply_readiness() {
    use nsshared_codec::cbor::CborWriter;
    use nsshared_control::account::control::{GatewayReport, GatewayReportResponse};
    let mut legacy = CborWriter::default();
    legacy.array(2).uint(1).bytes(&[8; 16]);
    assert!(GatewayReportResponse::decode(&legacy.into_bytes()).is_err());
    let mut legacy = CborWriter::default();
    legacy
        .array(12)
        .uint(1)
        .bytes(&[8; 16])
        .null()
        .null()
        .null()
        .null()
        .null()
        .null()
        .boolean(false)
        .array(0)
        .array(0)
        .array(0);
    assert!(GatewayReport::decode(&legacy.into_bytes()).is_err());
}
