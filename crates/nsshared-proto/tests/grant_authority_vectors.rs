#![allow(clippy::unwrap_used, clippy::panic)]

use nsshared_proto::account::{
    GrantDetails, GrantDiscriminator, GrantError, GrantPublication, NodeL3Authority, PayerBindings,
    ResourceAuthority, SubnetPrefix, SubnetSelection, TransportProtocol,
};
use serde_json::{Value, json};

fn vectors() -> Vec<std::collections::BTreeMap<&'static str, &'static str>> {
    include_str!("fixtures/vectors/grant-authority.vec")
        .split("\n\n")
        .filter_map(|block| {
            let fields: std::collections::BTreeMap<_, _> = block
                .lines()
                .filter_map(|line| line.split_once(" = "))
                .collect();
            fields.contains_key("bytes").then_some(fields)
        })
        .collect()
}

fn unhex(encoded: &str) -> Vec<u8> {
    encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn sample(name: &str) -> Vec<u8> {
    unhex(vectors().iter().find(|v| v["name"] == name).unwrap()["bytes"])
}

fn refusal(error: GrantError) -> &'static str {
    match error {
        GrantError::MissingPayer => "missing-payer",
        GrantError::AmbiguousPayer => "ambiguous-payer",
        GrantError::Encoding(_) => "encoding",
        GrantError::Policy(_) => "policy",
        GrantError::Subnet(_) => "subnet",
        GrantError::Reference => "reference",
        GrantError::Scope => "scope",
        GrantError::Field => "field",
        GrantError::Bounds => "bounds",
        GrantError::Ordering => "ordering",
        GrantError::RetiredIncarnation => "retired-incarnation",
        GrantError::Binding => "binding",
        other => panic!("unexpected refusal: {other:?}"),
    }
}

fn prefix(value: &SubnetPrefix) -> Value {
    match value.address {
        std::net::IpAddr::V4(ip) => json!([4, hex(&ip.octets()), value.length]),
        std::net::IpAddr::V6(ip) => json!([6, hex(&ip.octets()), value.length]),
    }
}

// Fixture consumer interpretation of explicit rules; no packet policy runtime is exported.
fn allows(
    value: &NodeL3Authority,
    namespace: [u8; 16],
    source: nsshared_proto::IdentityKey,
    destination: nsshared_proto::IdentityKey,
    protocol: TransportProtocol,
    port: u16,
) -> Result<bool, GrantError> {
    value.canonical()?;
    Ok(value.policy.rules.iter().any(|r| {
        r.namespace == namespace
            && r.source == source
            && r.destination == destination
            && r.protocol == protocol
            && r.first_port <= port
            && port <= r.last_port
    }))
}

#[test]
fn grant_l3_consumer_vectors() {
    let input = include_str!("fixtures/vectors/grant-authority.vec");
    let mut count = 0;
    for block in input.split("\n\n") {
        let fields: std::collections::BTreeMap<_, _> = block
            .lines()
            .filter_map(|line| line.split_once(" = "))
            .collect();
        let Some(encoded) = fields.get("bytes") else {
            continue;
        };
        let bytes: Vec<_> = encoded
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        let result = match fields["kind"] {
            "grants" => GrantPublication::decode(&bytes).and_then(|v| v.canonical()),
            "payer" => PayerBindings::decode(&bytes).and_then(|v| v.canonical()),
            "withdrawal" => ResourceAuthority::decode(&bytes).and_then(|v| v.canonical()),
            "l3-authority" => NodeL3Authority::decode(&bytes).and_then(|v| v.canonical()),
            _ => unreachable!(),
        };
        assert_eq!(
            result.is_ok(),
            fields["decision"] == "accept",
            "{}: {result:?}",
            fields["name"]
        );
        if let Ok(canonical) = result {
            assert_eq!(canonical, bytes);
        } else {
            assert_eq!(
                refusal(result.unwrap_err()),
                fields["decision"],
                "{}",
                fields["name"]
            );
        }
        count += 1;
    }
    assert!(count > 20);
}

#[test]
fn grant_fields_and_subnet_selection() {
    for vector in vectors().iter().filter(|v| v.contains_key("context")) {
        let publication = GrantPublication::decode(&unhex(vector["bytes"])).unwrap();
        assert_eq!(publication.revision, 1);
        assert_eq!(publication.issuer, publication.recipient);
        let grant = &publication.grants[0];
        let payer = grant.payer().unwrap();
        let context = json!({
            "resource": [hex(&grant.resource.nsd_id), hex(&grant.resource.network_id), hex(&grant.resource.service_id)],
            "client": hex(grant.client.as_bytes()), "provider": hex(grant.provider.as_bytes()),
            "payer_realm": hex(payer.realm.as_bytes()), "payer_subject": hex(&payer.subject),
            "incarnation": hex(&grant.incarnation.0), "expiry": grant.expires_at_unix_ms,
        });
        assert_eq!(
            context,
            serde_json::from_str::<Value>(vector["context"]).unwrap()
        );
        match &grant.details {
            GrantDetails::Egress {
                floor,
                name,
                protocol,
                virtual_port,
                alias_generation,
            } => {
                assert_eq!(
                    json!([
                        floor,
                        name,
                        *protocol as u64,
                        virtual_port,
                        alias_generation.map(|v| vec![v])
                    ]),
                    serde_json::from_str::<Value>(vector["details"]).unwrap()
                );
            }
            GrantDetails::Exit(subnet) => {
                let route = &subnet.routes[0];
                let selection = match &route.selection {
                    SubnetSelection::Default => json!([0, []]),
                    SubnetSelection::Explicit(values) => {
                        json!([1, values.iter().map(prefix).collect::<Vec<_>>()])
                    }
                };
                let route_json = json!({"resource":context["resource"], "real":prefix(&route.real), "mapped":prefix(&route.mapped),
                    "client":hex(&route.client), "provider":hex(&route.provider),
                    "exclusions":route.exclusions.iter().map(prefix).collect::<Vec<_>>(),
                    "bypasses":route.bypasses.iter().map(prefix).collect::<Vec<_>>(), "selection":selection});
                assert_eq!(
                    route_json,
                    serde_json::from_str::<Value>(vector["route"]).unwrap()
                );
                let output = &subnet.selected_routes().unwrap()[0];
                assert_eq!(
                    json!({"selected":output.selected.iter().map(prefix).collect::<Vec<_>>(),
                    "coverage":{"tcp":output.coverage.tcp,"udp":output.coverage.udp,"echo":output.coverage.echo}}),
                    serde_json::from_str::<Value>(vector["output"]).unwrap()
                );
            }
        }
        let bindings = PayerBindings::decode(&sample(if publication.family == 4 {
            "payer-exit"
        } else {
            "payer"
        }))
        .unwrap();
        bindings.validate_grants(&publication).unwrap();
        let binding = &bindings.bindings[0];
        assert_eq!(binding.resource, grant.resource);
        assert_eq!(binding.client, grant.client);
        assert_eq!(binding.incarnation, grant.incarnation);
        assert_eq!(binding.payers, grant.payers);
        assert_eq!(binding.discriminator, grant.details.discriminator());
    }
}

#[test]
fn grant_denial_vectors() {
    let initial = ResourceAuthority::decode(&sample("initial-authority")).unwrap();
    let withdrawn = ResourceAuthority::decode(&sample("selective-withdrawal")).unwrap();
    let regrant = ResourceAuthority::decode(&sample("fresh-regrant")).unwrap();
    withdrawn.validate_successor(&initial).unwrap();
    regrant.validate_successor(&withdrawn).unwrap();
    assert_eq!(withdrawn.active, initial.active[1..]);
    assert_eq!(regrant.active[1], initial.active[1]);
    assert_eq!(regrant.active[0].resource, initial.active[0].resource);
    assert_ne!(regrant.active[0].incarnation, initial.active[0].incarnation);
    assert!(matches!(
        ResourceAuthority::decode(&sample("retired-regrant")),
        Err(GrantError::RetiredIncarnation)
    ));
    let mut missing_history = withdrawn.clone();
    missing_history.retired.clear();
    assert!(matches!(
        missing_history.validate_successor(&initial),
        Err(GrantError::History)
    ));
    let mut forgotten = regrant.clone();
    forgotten.retired.clear();
    assert!(matches!(
        forgotten.validate_successor(&withdrawn),
        Err(GrantError::History)
    ));

    for name in ["egress", "exit"] {
        let before = GrantPublication::decode(&sample(name)).unwrap();
        let initial = ResourceAuthority::decode(&sample(if name == "exit" {
            "initial-exit-authority"
        } else {
            "initial-authority"
        }))
        .unwrap();
        let regrant = ResourceAuthority::decode(&sample(if name == "exit" {
            "fresh-exit-authority"
        } else {
            "fresh-regrant"
        }))
        .unwrap();
        initial.validate_grants(&before).unwrap();
        assert!(matches!(
            withdrawn.validate_grants(&before),
            Err(GrantError::Scope)
        ));
        let renewed = GrantPublication::decode(&sample(&format!("{name}-fresh-regrant"))).unwrap();
        regrant.validate_grants(&renewed).unwrap();
        let mut expected = before.clone();
        expected.revision = 3;
        expected.grants[0].incarnation.0 = regrant.active[0].incarnation;
        assert_eq!(renewed, expected);
        let mut empty = before.clone();
        empty.revision = 2;
        empty.grants.clear();
        renewed
            .validate_successor(&empty, &withdrawn.retired)
            .unwrap();
        let mut after = before.clone();
        after.revision += 1;
        after.validate_successor(&before, &[]).unwrap();
        assert!(matches!(
            after.validate_successor(&before, &withdrawn.retired),
            Err(GrantError::RetiredIncarnation)
        ));
        let mut realm = after.grants[0].payers[0].realm.to_bytes();
        realm[0] ^= 1;
        after.grants[0].payers[0].realm = realm.into();
        assert!(matches!(
            after.validate_successor(&before, &[]),
            Err(GrantError::ReusedIncarnation)
        ));
        after.grants[0].incarnation.0[0] ^= 1;
        after
            .validate_successor(&before, &withdrawn.retired)
            .unwrap();
        after.grants[0].payers.clear();
        assert!(matches!(after.canonical(), Err(GrantError::MissingPayer)));
    }
}

#[test]
fn constructed_authority_refusals() {
    use nsshared_proto::account::{MAX_BYTES, MAX_IDENTITIES};
    let mut publication = GrantPublication::decode(&sample("egress")).unwrap();
    let duplicate = publication.grants[0].payers[0].clone();
    publication.grants[0].payers.push(duplicate);
    assert!(matches!(
        publication.canonical(),
        Err(GrantError::AmbiguousPayer)
    ));
    let mut publication = GrantPublication::decode(&sample("egress")).unwrap();
    publication.grants = vec![publication.grants[0].clone(); MAX_IDENTITIES + 1];
    assert!(matches!(publication.canonical(), Err(GrantError::Bounds)));
    let mut bindings = PayerBindings::decode(&sample("payer")).unwrap();
    bindings.bindings[0].payers.clear();
    assert!(matches!(
        bindings.canonical(),
        Err(GrantError::MissingPayer)
    ));
    let mut authority = NodeL3Authority::decode(&sample("node-authority")).unwrap();
    authority.bindings.clear();
    assert!(matches!(authority.canonical(), Err(GrantError::Binding)));
    let mut authority = ResourceAuthority::decode(&sample("initial-authority")).unwrap();
    authority.active.reverse();
    assert!(matches!(authority.canonical(), Err(GrantError::Ordering)));
    let oversized = vec![0; MAX_BYTES + 1];
    assert!(GrantPublication::decode(&oversized).is_err());
    assert!(PayerBindings::decode(&oversized).is_err());
    assert!(NodeL3Authority::decode(&oversized).is_err());
    assert!(ResourceAuthority::decode(&oversized).is_err());
}

#[test]
fn node_l3_exact_authority_boundaries() {
    let full = NodeL3Authority::decode(&sample("two-namespaces")).unwrap();
    let after = NodeL3Authority::decode(&sample("selective-namespace-withdrawal")).unwrap();
    assert_eq!(after.bindings, full.bindings);
    assert_eq!(after.policy.scopes, full.policy.scopes[1..]);
    assert_eq!(after.policy.rules, full.policy.rules[1..]);
    assert!(after.policy.revision > full.policy.revision);
    for (i, rule) in full.policy.rules.iter().enumerate() {
        assert_eq!(
            rule.protocol,
            if i == 0 {
                TransportProtocol::Tcp
            } else {
                TransportProtocol::Udp
            }
        );
        assert_eq!(rule.first_port, if i == 0 { 443 } else { 53 });
        assert_eq!(rule.first_port, rule.last_port);
        assert!(
            allows(
                &full,
                rule.namespace,
                rule.source,
                rule.destination,
                rule.protocol,
                rule.first_port
            )
            .unwrap()
        );
        assert_eq!(
            allows(
                &after,
                rule.namespace,
                rule.source,
                rule.destination,
                rule.protocol,
                rule.first_port
            )
            .unwrap(),
            i == 1
        );
        assert!(
            !allows(
                &full,
                rule.namespace,
                rule.destination,
                rule.source,
                rule.protocol,
                rule.first_port
            )
            .unwrap()
        );
        assert!(
            !allows(
                &full,
                rule.namespace,
                rule.source,
                rule.destination,
                rule.protocol,
                rule.first_port + 1
            )
            .unwrap()
        );
        assert!(
            !allows(
                &full,
                [0; 16],
                rule.source,
                rule.destination,
                rule.protocol,
                rule.first_port
            )
            .unwrap()
        );
        let without_policy = NodeL3Authority::decode(&sample("missing-policy-denies")).unwrap();
        assert!(
            !allows(
                &without_policy,
                rule.namespace,
                rule.source,
                rule.destination,
                rule.protocol,
                rule.first_port
            )
            .unwrap()
        );
        let mut wrong_membership = full.clone();
        wrong_membership.policy.scopes[i].identities.clear();
        assert!(wrong_membership.canonical().is_err());
        let mut keys: Vec<_> = full
            .bindings
            .iter()
            .map(|b| (b.identity, b.wg_key))
            .collect();
        keys.sort_by_key(|entry| entry.1);
        assert_eq!(keys[0], (rule.source, [41; 32]));
        assert_eq!(keys[1], (rule.destination, [42; 32]));
    }
}

#[test]
fn protocol_grant_renewal() {
    let initial = GrantPublication::decode(&sample("protocol-initial")).unwrap();
    let renewed = GrantPublication::decode(&sample("protocol-renewed")).unwrap();
    assert_eq!(initial.grants.len(), 2);
    renewed.validate_successor(&initial, &[]).unwrap();
    for (before, after) in initial.grants.iter().zip(&renewed.grants) {
        assert_eq!(before.incarnation, after.incarnation);
        assert_eq!(before.payers, after.payers);
        assert_eq!(before.details, after.details);
        assert_eq!(after.expires_at_unix_ms, 20000);
    }
    for name in ["earlier-deadline", "changed-payer", "changed-details"] {
        let changed = GrantPublication::decode(&sample(&format!("protocol-{name}"))).unwrap();
        assert!(matches!(
            changed.validate_successor(&initial, &[]),
            Err(GrantError::ReusedIncarnation)
        ));
    }
    let payers = PayerBindings::decode(&sample("protocol-payers")).unwrap();
    payers.validate_grants(&initial).unwrap();
    payers.validate_grants(&renewed).unwrap();
    for index in 0..2 {
        let mut wrong = payers.clone();
        wrong.bindings[index].incarnation.0[0] ^= 1;
        assert!(matches!(
            wrong.validate_grants(&initial),
            Err(GrantError::Scope)
        ));
        let mut wrong = payers.clone();
        wrong.bindings[index].payers[0].subject[0] ^= 1;
        assert!(matches!(
            wrong.validate_grants(&initial),
            Err(GrantError::Scope)
        ));
    }
    let mut wrong_protocol = payers.clone();
    wrong_protocol.bindings.truncate(1);
    let mut udp_only = initial.clone();
    udp_only.grants.remove(0);
    wrong_protocol.bindings[0].incarnation = udp_only.grants[0].incarnation;
    assert!(matches!(
        wrong_protocol.validate_grants(&udp_only),
        Err(GrantError::Scope)
    ));
    let authority = ResourceAuthority::decode(&sample("protocol-authority")).unwrap();
    authority.validate_grants(&initial).unwrap();
    authority.validate_grants(&renewed).unwrap();
    let withdrawn = GrantPublication::decode(&sample("protocol-withdrawn")).unwrap();
    let withdrawn_authority =
        ResourceAuthority::decode(&sample("protocol-withdrawn-authority")).unwrap();
    withdrawn_authority.validate_successor(&authority).unwrap();
    withdrawn_authority.validate_grants(&withdrawn).unwrap();
    withdrawn
        .validate_successor(&renewed, &withdrawn_authority.retired)
        .unwrap();
    let mut retired = renewed.clone();
    retired.revision = 4;
    assert!(matches!(
        retired.validate_successor(&withdrawn, &withdrawn_authority.retired),
        Err(GrantError::RetiredIncarnation)
    ));
    let regrant = GrantPublication::decode(&sample("protocol-regrant")).unwrap();
    let regrant_authority =
        ResourceAuthority::decode(&sample("protocol-regrant-authority")).unwrap();
    regrant_authority
        .validate_successor(&withdrawn_authority)
        .unwrap();
    regrant_authority.validate_grants(&regrant).unwrap();
    let regrant_payers = PayerBindings::decode(&sample("protocol-regrant-payers")).unwrap();
    regrant_payers.validate_grants(&regrant).unwrap();
    assert!(matches!(
        payers.validate_grants(&regrant),
        Err(GrantError::Scope)
    ));
    regrant
        .validate_successor(&withdrawn, &withdrawn_authority.retired)
        .unwrap();
    assert_eq!(regrant.grants[1], renewed.grants[1]);
    let exit = GrantPublication::decode(&sample("exit")).unwrap();
    let exit_renewed = GrantPublication::decode(&sample("protocol-exit-renewed")).unwrap();
    exit_renewed.validate_successor(&exit, &[]).unwrap();
    assert_eq!(exit.grants[0].details, exit_renewed.grants[0].details);
}

#[test]
fn protocol_identity_and_token_ownership_refusals() {
    let initial = GrantPublication::decode(&sample("protocol-initial")).unwrap();
    let authority = ResourceAuthority::decode(&sample("protocol-authority")).unwrap();
    let payers = PayerBindings::decode(&sample("protocol-payers")).unwrap();
    let mut duplicate = initial.clone();
    duplicate.grants[1] = duplicate.grants[0].clone();
    assert!(matches!(duplicate.canonical(), Err(GrantError::Ordering)));
    let mut reversed = initial.clone();
    reversed.grants.reverse();
    assert!(matches!(reversed.canonical(), Err(GrantError::Ordering)));
    let mut reused = initial.clone();
    reused.grants[1].incarnation = reused.grants[0].incarnation;
    assert!(matches!(
        reused.canonical(),
        Err(GrantError::ReusedIncarnation)
    ));
    let mut reused = authority.clone();
    reused.active[1].incarnation = reused.active[0].incarnation;
    assert!(matches!(
        reused.canonical(),
        Err(GrantError::ReusedIncarnation)
    ));
    let mut reused = payers.clone();
    reused.bindings[1].incarnation = reused.bindings[0].incarnation;
    assert!(matches!(
        reused.canonical(),
        Err(GrantError::ReusedIncarnation)
    ));
    let mut reversed = payers.clone();
    reversed.bindings.reverse();
    assert!(matches!(reversed.canonical(), Err(GrantError::Ordering)));
    let mut duplicate = payers.clone();
    duplicate.bindings[1] = duplicate.bindings[0].clone();
    assert!(matches!(duplicate.canonical(), Err(GrantError::Ordering)));
    let mut duplicate = authority.clone();
    duplicate.active[1] = duplicate.active[0].clone();
    assert!(matches!(duplicate.canonical(), Err(GrantError::Ordering)));
    let mut wrong_claim = authority.clone();
    wrong_claim.active.truncate(1);
    wrong_claim.active[0].incarnation = initial.grants[1].incarnation.0;
    let mut udp_only = initial.clone();
    udp_only.grants.remove(0);
    assert!(matches!(
        wrong_claim.validate_grants(&udp_only),
        Err(GrantError::Scope)
    ));
    let mut moved = authority.clone();
    moved.revision += 1;
    moved.active.truncate(1);
    moved.active[0].discriminator = GrantDiscriminator::Exit;
    assert!(matches!(
        moved.validate_successor(&authority),
        Err(GrantError::ReusedIncarnation)
    ));
    let mut moved = initial.clone();
    moved.revision += 1;
    moved.grants.remove(0);
    moved.grants[0].incarnation = initial.grants[0].incarnation;
    assert!(matches!(
        moved.validate_successor(&initial, &[]),
        Err(GrantError::ReusedIncarnation)
    ));
    let mut exact = initial.clone();
    exact.revision += 1;
    exact.validate_successor(&initial, &[]).unwrap();
    assert!(matches!(
        initial.validate_successor(&initial, &[]),
        Err(GrantError::Scope)
    ));
    let exit = GrantPublication::decode(&sample("exit")).unwrap();
    let mut changed = GrantPublication::decode(&sample("protocol-exit-renewed")).unwrap();
    if let GrantDetails::Exit(subnet) = &mut changed.grants[0].details {
        subnet.revision += 1;
    }
    assert!(matches!(
        changed.validate_successor(&exit, &[]),
        Err(GrantError::ReusedIncarnation)
    ));
}

#[test]
fn exit_deadline_and_payer_renewal_boundaries() {
    let before = GrantPublication::decode(&sample("exit")).unwrap();
    let renewed = GrantPublication::decode(&sample("protocol-exit-renewed")).unwrap();
    let mut earlier = renewed.clone();
    earlier.grants[0].expires_at_unix_ms = before.grants[0].expires_at_unix_ms - 1;
    assert!(matches!(
        earlier.validate_successor(&before, &[]),
        Err(GrantError::ReusedIncarnation)
    ));
    let mut changed = renewed.clone();
    changed.grants[0].payers[0].subject[0] ^= 1;
    assert!(matches!(
        changed.validate_successor(&before, &[]),
        Err(GrantError::ReusedIncarnation)
    ));
    let mut unchanged = before.clone();
    unchanged.revision += 1;
    unchanged.validate_successor(&before, &[]).unwrap();
    let retired = ResourceAuthority::decode(&sample("selective-withdrawal")).unwrap();
    assert!(matches!(
        renewed.validate_successor(&before, &retired.retired),
        Err(GrantError::RetiredIncarnation)
    ));
}
