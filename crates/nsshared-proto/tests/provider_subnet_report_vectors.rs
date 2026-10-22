#![allow(clippy::unwrap_used, clippy::panic)]
mod support;

use nsshared_proto::{
    IdentityKey,
    account::{
        BootstrapEnvelope, EnvelopeDirection, EnvelopeExpectation, EnvelopePins, MAX_BYTES,
        SubnetPrefix, SubnetSelection,
        provider_subnet_report::{
            NODE_SUBNET_REPORT, NodeSubnetRouteReport, NodeSubnetRouteReportResponse,
            RetainedSubnetReport, SubnetAllocationHistory, SubnetMappingAuthority,
            SubnetReportAuthority, SubnetReportDecision, SubnetReportError, decide_subnet_report,
        },
        source_binding::SignedSourceBinding,
    },
};
use support::vectors::Vector;

fn bytes(vectors: &[Vector], name: &str) -> Vec<u8> {
    vectors
        .iter()
        .find(|v| v.name() == name)
        .unwrap()
        .hex("bytes")
}
fn report(vectors: &[Vector], name: &str) -> NodeSubnetRouteReport {
    let raw = bytes(vectors, name);
    let value = NodeSubnetRouteReport::decode(&raw).unwrap();
    assert_eq!(value.canonical().unwrap(), raw, "{name}");
    value
}
fn response(vectors: &[Vector], name: &str) -> NodeSubnetRouteReportResponse {
    let raw = bytes(vectors, &format!("{name}-response"));
    let value = NodeSubnetRouteReportResponse::decode(&raw).unwrap();
    assert_eq!(value.canonical().unwrap(), raw, "{name}");
    value
}
fn authority(binding: &SignedSourceBinding) -> SubnetReportAuthority<'_> {
    SubnetReportAuthority {
        nsd: binding.binding.nsd,
        nsd_id: [21; 16],
        network_id: [3; 16],
        caller: binding.binding.recipient,
        current: binding,
    }
}
fn mappings(binding: &SignedSourceBinding) -> Vec<SubnetMappingAuthority> {
    [(7, "10.0.0.0", 8), (9, "0.0.0.0", 0)]
        .into_iter()
        .map(|(id, address, length)| SubnetMappingAuthority {
            subnet_id: id,
            network_id: [3; 16],
            provider: binding.binding.source_node,
            real: SubnetPrefix {
                address: address.parse().unwrap(),
                length,
            },
            active: true,
        })
        .collect()
}
fn pins(identity: IdentityKey) -> EnvelopePins {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use sha2::{Digest as _, Sha256};
    let x = URL_SAFE_NO_PAD.encode(identity.as_bytes());
    let jwk = format!("{{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"{x}\"}}");
    EnvelopePins::intersect(
        &[URL_SAFE_NO_PAD.encode(Sha256::digest(jwk.as_bytes()))],
        &[],
    )
    .unwrap()
}

#[test]
fn provider_subnet_report() {
    let vectors = support::vectors::load("provider-subnet-report");
    let initial = report(&vectors, "initial");
    let a = initial.binding.clone();
    let authority_a = authority(&a);
    let mapping = mappings(&a);
    assert!(matches!(
        initial.offers[0].selection,
        SubnetSelection::Explicit(_)
    ));
    assert_eq!(initial.offers[1].selection, SubnetSelection::Default);
    let mut state: Option<RetainedSubnetReport> = None;
    for name in [
        "initial",
        "retry",
        "update",
        "withdraw-one",
        "withdraw-all",
        "reoffer",
    ] {
        if name == "reoffer" {
            // Reconstruct the accepted empty report/result and allocation history independently.
            let saved = state.as_ref().unwrap();
            state = Some(RetainedSubnetReport {
                report: NodeSubnetRouteReport::decode(&saved.report.canonical().unwrap()).unwrap(),
                response: NodeSubnetRouteReportResponse::decode(
                    &saved.response.canonical().unwrap(),
                )
                .unwrap(),
                allocations: SubnetAllocationHistory {
                    binding: SignedSourceBinding::decode(
                        &saved.allocations.binding.canonical().unwrap(),
                    )
                    .unwrap(),
                    allocations: response(&vectors, "initial").allocations,
                },
            });
            let before = state.clone();
            assert!(matches!(
                decide_subnet_report(
                    &report(&vectors, "stale-restoration"),
                    &authority_a,
                    &mapping,
                    state.as_ref()
                ),
                Err(SubnetReportError::Stale)
            ));
            assert_eq!(state, before);
        }
        let pending = report(&vectors, name);
        let result = response(&vectors, name);
        let before = state.clone();
        let decision =
            decide_subnet_report(&pending, &authority_a, &mapping, state.as_ref()).unwrap();
        assert_eq!(state, before);
        assert_eq!(
            decision,
            if name == "retry" {
                SubnetReportDecision::Retry
            } else {
                SubnetReportDecision::Replace
            }
        );
        result
            .compare(&pending, &authority_a, state.as_ref())
            .unwrap();
        if name == "retry" {
            assert_eq!(state.as_ref().unwrap().response, result);
            let conflict = report(&vectors, "equal-conflict");
            assert!(matches!(
                decide_subnet_report(&conflict, &authority_a, &mapping, state.as_ref()),
                Err(SubnetReportError::Conflict)
            ));
            assert_eq!(state, before);
            continue;
        }
        let mut history = state.as_ref().map_or_else(
            || SubnetAllocationHistory {
                binding: a.clone(),
                allocations: Vec::new(),
            },
            |s| s.allocations.clone(),
        );
        for allocated in &result.allocations {
            if !history
                .allocations
                .iter()
                .any(|old| old.subnet_id == allocated.subnet_id)
            {
                history.allocations.push(allocated.clone());
            }
        }
        history.allocations.sort_by_key(|entry| entry.subnet_id);
        state = Some(RetainedSubnetReport {
            report: pending,
            response: result,
            allocations: history,
        });
        assert_eq!(state.as_ref().unwrap().allocations.allocations.len(), 2);
    }
    let before = state.clone();
    for name in [
        "egress",
        "wrong-node",
        "wrong-record",
        "unknown-mapping",
        "outside-real",
        "default-nonzero-real",
        "wrong-family",
    ] {
        let pending = report(&vectors, name);
        assert!(
            decide_subnet_report(&pending, &authority_a, &mapping, state.as_ref()).is_err(),
            "{name}"
        );
        assert_eq!(state, before);
    }
    assert!(NodeSubnetRouteReport::decode(&bytes(&vectors, "wrong-profile")).is_err());
    let pending_b = report(&vectors, "replacement");
    let b = pending_b.binding.clone();
    let authority_b = authority(&b);
    let delayed = report(&vectors, "delayed-retired");
    assert!(matches!(
        decide_subnet_report(&delayed, &authority_b, &mapping, state.as_ref()),
        Err(SubnetReportError::Authority)
    ));
    assert!(
        response(&vectors, "initial")
            .compare(&initial, &authority_b, state.as_ref())
            .is_err()
    );
    assert_eq!(state, before);
    assert_eq!(
        decide_subnet_report(&pending_b, &authority_b, &mapping, None).unwrap(),
        SubnetReportDecision::Replace
    );
    let result_b = response(&vectors, "replacement");
    result_b.compare(&pending_b, &authority_b, None).unwrap();
    assert_ne!(
        result_b.allocations,
        response(&vectors, "initial").allocations
    );
    assert!(
        result_b
            .compare(&pending_b, &authority_b, state.as_ref())
            .is_err()
    );
    // B remains usable independently after every refused A operation.
    assert_eq!(
        decide_subnet_report(&pending_b, &authority_b, &mapping, None).unwrap(),
        SubnetReportDecision::Replace
    );
}

#[test]
fn provider_subnet_report_wire_and_allocation_refusals() {
    let vectors = support::vectors::load("provider-subnet-report");
    let pending = report(&vectors, "initial");
    let current = pending.binding.clone();
    let expected = authority(&current);
    let history = RetainedSubnetReport {
        report: pending.clone(),
        response: response(&vectors, "initial"),
        allocations: SubnetAllocationHistory {
            binding: current.clone(),
            allocations: response(&vectors, "initial").allocations,
        },
    };
    for vector in &vectors {
        let raw = vector.hex("bytes");
        match vector.get("mode") {
            "malformed-report" => assert!(
                NodeSubnetRouteReport::decode(&raw).is_err(),
                "{}",
                vector.name()
            ),
            "malformed-response" => assert!(
                NodeSubnetRouteReportResponse::decode(&raw).is_err(),
                "{}",
                vector.name()
            ),
            "invalid-response" => {
                let value = NodeSubnetRouteReportResponse::decode(&raw).unwrap();
                assert!(
                    value.compare(&pending, &expected, Some(&history)).is_err(),
                    "{}",
                    vector.name()
                );
            }
            "boundary" => assert_eq!(
                NodeSubnetRouteReport::decode(&raw)
                    .unwrap()
                    .canonical()
                    .unwrap(),
                raw
            ),
            _ => {}
        }
    }
    assert!(NodeSubnetRouteReport::decode(&vec![0; MAX_BYTES + 1]).is_err());
    assert!(NodeSubnetRouteReportResponse::decode(&vec![0; MAX_BYTES + 1]).is_err());
    let mut wrong = response(&vectors, "initial");
    wrong.report_generation += 1;
    assert!(wrong.compare(&pending, &expected, Some(&history)).is_err());
    wrong = response(&vectors, "initial");
    wrong.binding = report(&vectors, "replacement").binding;
    assert!(wrong.compare(&pending, &expected, Some(&history)).is_err());
    // Association remains stable after all live offers were withdrawn.
    let reoffer = report(&vectors, "reoffer");
    wrong = response(&vectors, "reoffer");
    wrong.allocations[0].resource.service_id = [99; 16];
    assert!(wrong.compare(&reoffer, &expected, Some(&history)).is_err());
}

#[test]
fn provider_subnet_report_carrier_comparisons() {
    let vectors = support::vectors::load("provider-subnet-report");
    let pending = report(&vectors, "initial");
    let current = pending.binding.clone();
    let authority = authority(&current);
    let history = RetainedSubnetReport {
        report: pending.clone(),
        response: response(&vectors, "initial"),
        allocations: SubnetAllocationHistory {
            binding: current.clone(),
            allocations: response(&vectors, "initial").allocations,
        },
    };
    for vector in &vectors {
        let mode = vector.get("mode");
        if !matches!(mode, "request-carrier" | "response-carrier") {
            continue;
        }
        let envelope = BootstrapEnvelope::decode(&vector.hex("bytes")).unwrap();
        let response = mode == "response-carrier";
        let issuer = if response {
            authority.nsd
        } else {
            authority.caller
        };
        let pins = pins(issuer);
        let expected = EnvelopeExpectation {
            pins: &pins,
            direction: if response {
                EnvelopeDirection::Response
            } else {
                EnvelopeDirection::Request
            },
            recipient: if response {
                authority.caller
            } else {
                authority.nsd
            },
            kind: NODE_SUBNET_REPORT,
            now_seconds: 100,
            previous_acceptance_seconds: None,
        };
        let accepted = if response {
            NodeSubnetRouteReportResponse::from_envelope(
                &envelope,
                &expected,
                &pending,
                vector.hex_array("pending_nonce"),
                &authority,
                Some(&history),
            )
            .is_ok()
        } else {
            NodeSubnetRouteReport::from_envelope(&envelope, &expected, &authority).is_ok()
        };
        assert_eq!(
            accepted,
            vector.get("decision") == "accept",
            "{}",
            vector.name()
        );
        if response && accepted {
            assert!(
                NodeSubnetRouteReportResponse::from_envelope(
                    &envelope,
                    &expected,
                    &pending,
                    [99; 16],
                    &authority,
                    Some(&history)
                )
                .is_err()
            );
            let b = report(&vectors, "replacement").binding;
            let replacement = self::authority(&b);
            assert!(
                NodeSubnetRouteReportResponse::from_envelope(
                    &envelope,
                    &expected,
                    &pending,
                    vector.hex_array("pending_nonce"),
                    &replacement,
                    Some(&history)
                )
                .is_err()
            );
        }
    }
}

#[test]
fn provider_subnet_report_mapping_and_retained_state_qualification() {
    let vectors = support::vectors::load("provider-subnet-report");
    let pending = report(&vectors, "initial");
    let a = pending.binding.clone();
    let authority = authority(&a);
    let valid = mappings(&a);
    for variant in 0..6 {
        let mut mappings = valid.clone();
        match variant {
            0 => mappings[0].active = false,
            1 => mappings[0].network_id = [4; 16],
            2 => mappings[0].provider = authority.nsd,
            3 => mappings.push(mappings[0].clone()),
            4 => mappings[0].real.length = 33,
            _ => mappings[0].real.address = "10.0.0.1".parse().unwrap(),
        }
        assert!(decide_subnet_report(&pending, &authority, &mappings, None).is_err());
    }
    let state = RetainedSubnetReport {
        report: pending.clone(),
        response: response(&vectors, "initial"),
        allocations: SubnetAllocationHistory {
            binding: a.clone(),
            allocations: response(&vectors, "initial").allocations,
        },
    };
    for variant in 0..4 {
        let mut broken = state.clone();
        match variant {
            0 => broken.allocations.allocations.clear(),
            1 => broken.response.report_generation += 1,
            2 => broken.allocations.allocations.reverse(),
            _ => broken.allocations.binding = report(&vectors, "replacement").binding,
        }
        assert!(decide_subnet_report(&pending, &authority, &valid, Some(&broken)).is_err());
    }
    let mut wrong = authority.clone();
    wrong.caller = wrong.nsd;
    assert!(decide_subnet_report(&pending, &wrong, &valid, None).is_err());
    wrong = authority.clone();
    wrong.network_id = [4; 16];
    assert!(decide_subnet_report(&pending, &wrong, &valid, None).is_err());
}

#[test]
fn provider_subnet_report_delayed_response_after_withdrawal() {
    let vectors = support::vectors::load("provider-subnet-report");
    let pending = report(&vectors, "initial");
    let binding = pending.binding.clone();
    let authority = authority(&binding);
    let withdrawn = RetainedSubnetReport {
        report: report(&vectors, "withdraw-all"),
        response: response(&vectors, "withdraw-all"),
        allocations: SubnetAllocationHistory {
            binding: binding.clone(),
            allocations: response(&vectors, "initial").allocations,
        },
    };
    assert!(
        response(&vectors, "initial")
            .compare(&pending, &authority, Some(&withdrawn))
            .is_err(),
        "a delayed response must not restore withdrawn offers"
    );
}

#[test]
fn provider_subnet_report_constructed_payload_limits_and_source_signature() {
    use nsshared_proto::account::provider_subnet_report::SubnetRouteOffer;
    let vectors = support::vectors::load("provider-subnet-report");
    let mut pending = report(&vectors, "initial");
    let source = pending.binding.clone();
    let authority = authority(&source);
    pending.binding.signature[0] ^= 1;
    assert!(decide_subnet_report(&pending, &authority, &mappings(&source), None).is_err());
    pending = report(&vectors, "initial");
    let prefixes: Vec<_> = (0u128..256)
        .map(|address| SubnetPrefix {
            address: std::net::IpAddr::V6(std::net::Ipv6Addr::from(address)),
            length: 128,
        })
        .collect();
    pending.offers = (1..=256)
        .map(|subnet_id| SubnetRouteOffer {
            subnet_id,
            selection: SubnetSelection::Explicit(prefixes.clone()),
        })
        .collect();
    assert!(matches!(
        pending.canonical(),
        Err(SubnetReportError::Bounds)
    ));
    pending.offers[0].subnet_id = 0;
    assert!(pending.canonical().is_err());
    let mut result = response(&vectors, "initial");
    result.report_generation = 0;
    assert!(result.canonical().is_err());
    result = response(&vectors, "initial");
    result.allocations = vec![result.allocations[0].clone(); 257];
    assert!(matches!(result.canonical(), Err(SubnetReportError::Bounds)));
}
