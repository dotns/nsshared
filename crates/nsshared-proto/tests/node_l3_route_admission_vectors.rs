#![allow(clippy::unwrap_used, clippy::panic)]

#[path = "support/vectors.rs"]
mod vectors;
use nsshared_proto::{
    account::{NodeL3, SubnetPrefix, SubnetPublication},
    identity::AddressGroup,
};
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
    let cases = vectors::parse(include_str!("fixtures/vectors/node-l3-route-admission.vec"));
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
            nsshared_service_control::encode_canonical(&route.resource.value()).unwrap(),
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
                let hex: String = address
                    .octets()
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect();
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
