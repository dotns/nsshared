#![allow(clippy::unwrap_used, clippy::panic)]

use nsshared_control::{
    account::node::NodeL3, account::subnet::SubnetPrefix, account::subnet::SubnetPublication,
};
use nsshared_identity::identity::AddressGroup;
use serde_json::json;
use std::net::{IpAddr, Ipv4Addr};

fn contains(prefix: &SubnetPrefix, address: Ipv4Addr) -> bool {
    let IpAddr::V4(network) = prefix.address else {
        return false;
    };
    let mask = u32::MAX
        .checked_shl(u32::from(32 - prefix.length))
        .unwrap_or(0);
    u32::from(address) & mask == u32::from(network)
}

#[test]
fn node_l3_route_admission_vectors() {
    let cases = nsshared_testkit::vectors!("account/control/node-l3-route-admission");
    assert_eq!(cases.len(), 15);
    for case in cases {
        let bytes = case.hex("bytes");
        let publication = SubnetPublication::decode(&bytes).unwrap();
        assert_eq!(publication.canonical().unwrap(), bytes);
        let policy = NodeL3::decode(&case.hex("policy")).unwrap();
        assert_eq!(policy.canonical().unwrap(), case.hex("policy"));
        assert!(policy.rules.is_empty());
        let routes = publication.selected_routes().unwrap();
        let selected = &routes[0];
        let route = &selected.route;
        assert_eq!(route.client, case.hex_array::<32>("client"));
        assert_eq!(route.provider, case.hex_array::<32>("provider"));
        assert_eq!(
            nsshared_codec::cbor::value::encode_canonical(&route.resource.value()).unwrap(),
            case.hex("resource")
        );
        assert_eq!(publication.recipient, route.client);
        assert_eq!(route.bypasses.len(), 1);
        let cover: Vec<_> = selected
            .selected
            .iter()
            .map(|prefix| {
                let IpAddr::V4(address) = prefix.address else {
                    panic!("IPv4 fixture");
                };
                let hex = nsshared_testkit::hex::encode(&address.octets());
                json!([4, hex, prefix.length])
            })
            .collect();
        assert_eq!(
            json!({"selected":cover,"coverage":{"tcp":selected.coverage.tcp,
            "udp":selected.coverage.udp,"echo":selected.coverage.echo}}),
            serde_json::from_str::<serde_json::Value>(case.get("cover")).unwrap()
        );
        let destination: IpAddr = case.get("destination").parse().unwrap();
        let provider_group = AddressGroup::derive(&route.provider);
        if case.name().starts_with("direct-n6") {
            assert_eq!(destination, IpAddr::V6(provider_group.n6()));
        }
        if case.name().starts_with("direct-n4") {
            assert_eq!(destination, IpAddr::V6(provider_group.n4()));
        }
        let mapped = match (destination, route.mapped.address) {
            (IpAddr::V6(address), IpAddr::V6(mapping))
                if address.octets()[..12] == mapping.octets()[..12] =>
            {
                Some(Ipv4Addr::from(
                    <[u8; 4]>::try_from(&address.octets()[12..]).unwrap(),
                ))
            }
            _ => None,
        };
        let covered = match case.u64("protocol") {
            6 => selected.coverage.tcp,
            17 => selected.coverage.udp,
            1 => selected.coverage.echo,
            _ => false,
        };
        let admitted = covered
            && mapped.is_some_and(|address| {
                selected
                    .selected
                    .iter()
                    .any(|prefix| contains(prefix, address))
            });
        assert_eq!(admitted, case.get("selected") == "yes", "{}", case.name());
    }
}

#[test]
fn ordinary_node_echo_route_admission_codec_forms() {
    use nsshared_control::account::node::{L3Protocol, L3Rule, L3Scope};
    use nsshared_identity::keys::IdentityKey;

    for case in nsshared_testkit::vectors!("account/control/node-l3-route-admission") {
        let publication = SubnetPublication::decode(&case.hex("bytes")).unwrap();
        let route = &publication.routes[0];
        let mut policy = NodeL3::decode(&case.hex("policy")).unwrap();
        let source = IdentityKey::from_bytes(&route.client).unwrap();
        let destination = IdentityKey::from_bytes(&route.provider).unwrap();
        let mut identities = vec![source, destination];
        identities.sort();
        identities.dedup();
        policy.scopes = vec![L3Scope {
            namespace: [3; 16],
            identities,
        }];
        policy.rules = [L3Protocol::EchoV4, L3Protocol::EchoV6]
            .into_iter()
            .map(|protocol| L3Rule {
                namespace: [3; 16],
                source,
                destination,
                protocol,
                first_port: 0,
                last_port: 0,
            })
            .collect();
        let bytes = policy.canonical().unwrap();
        assert_eq!(NodeL3::decode(&bytes).unwrap(), policy);
        assert_eq!(policy.rules[0].protocol as u64, 1);
        assert_eq!(policy.rules[1].protocol as u64, 58);
        policy.rules[0].first_port = 8;
        assert!(policy.canonical().is_err());
        policy.rules[0].first_port = 0;
        policy.rules[1].last_port = 129;
        assert!(policy.canonical().is_err());
    }
}
