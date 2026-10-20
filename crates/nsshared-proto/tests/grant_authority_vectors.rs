#![allow(clippy::unwrap_used, clippy::panic)]

use nsshared_proto::account::{
    GrantDetails, GrantError, GrantPublication, NodeL3Authority, PayerBindings, ResourceAuthority,
    SubnetPrefix, SubnetSelection, TransportProtocol,
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
            "payer_realm": hex(&payer.realm), "payer_subject": hex(&payer.subject),
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
        let bindings = PayerBindings::decode(&sample("payer")).unwrap();
        let binding = &bindings.bindings[0];
        assert_eq!(binding.resource, grant.resource);
        assert_eq!(binding.client, grant.client);
        assert_eq!(binding.incarnation, grant.incarnation);
        assert_eq!(binding.payers, grant.payers);
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
        after.grants[0].payers[0].realm[0] ^= 1;
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
