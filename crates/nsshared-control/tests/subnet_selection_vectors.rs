#![allow(clippy::unwrap_used, clippy::panic)]
use nsshared_control::account::AccountError;

use std::collections::{BTreeMap, BTreeSet};

use nsshared_codec::cbor::CborError;
use nsshared_control::{
    account::subnet::SubnetError, account::subnet::SubnetPrefix,
    account::subnet::SubnetPublication, account::subnet::SubnetRoute,
    account::subnet::SubnetSelection,
};
use serde_json::{Value, json};

type Vector = BTreeMap<&'static str, &'static str>;

fn fixtures() -> Vec<Vector> {
    include_str!("fixtures/vectors/account.vec")
        .split("\n\n")
        .filter_map(|block| {
            let fields: BTreeMap<_, _> =
                block.lines().filter_map(|s| s.split_once(" = ")).collect();
            (fields.get("kind") == Some(&"subnet-selection")).then_some(fields)
        })
        .collect()
}

fn bytes(text: &str) -> Vec<u8> {
    if text == "-" {
        return Vec::new();
    }
    assert_eq!(text.len() % 2, 0);
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn prefix(value: &SubnetPrefix) -> Value {
    let (family, address) = match value.address {
        std::net::IpAddr::V4(address) => (4, address.octets().to_vec()),
        std::net::IpAddr::V6(address) => (6, address.octets().to_vec()),
    };
    json!([family, hex(&address), value.length])
}

fn prefixes(values: &[SubnetPrefix]) -> Vec<Value> {
    values.iter().map(prefix).collect()
}

fn route(value: &SubnetRoute) -> Value {
    let selection = match &value.selection {
        SubnetSelection::Default => json!([0, []]),
        SubnetSelection::Explicit(values) => json!([1, prefixes(values)]),
    };
    json!({
        "resource": [hex(&value.resource.nsd_id), hex(&value.resource.network_id), hex(&value.resource.service_id)],
        "real": prefix(&value.real), "mapped": prefix(&value.mapped),
        "provider": hex(&value.provider), "client": hex(&value.client),
        "exclusions": prefixes(&value.exclusions), "bypasses": prefixes(&value.bypasses),
        "selection": selection,
    })
}

fn refusal(error: SubnetError) -> &'static str {
    match error {
        SubnetError::MappedPrefix => "mapped-prefix",
        SubnetError::OutsideExclusion => "outside-exclusion",
        SubnetError::OutsideBypass => "outside-bypass",
        SubnetError::OutsideSelection => "outside-selection",
        SubnetError::Overlap => "overlap",
        SubnetError::NonCanonicalSet => "noncanonical-set",
        SubnetError::MisalignedPrefix => "misaligned-prefix",
        SubnetError::InvalidPrefix => "invalid-prefix",
        SubnetError::UnknownFamily => "unknown-family",
        SubnetError::UnknownSelection => "unknown-selection",
        SubnetError::MixedSelection => "mixed-selection",
        SubnetError::InvalidDefault => "invalid-default",
        SubnetError::Schema => "schema",
        SubnetError::Bounds => "bounds",
        SubnetError::Identity => "identity",
        SubnetError::Scope => "scope",
        SubnetError::M6Reference(_) => "m6-reference",
        SubnetError::Contract(AccountError::Cbor(CborError::TrailingBytes)) => "trailing-bytes",
        SubnetError::Contract(AccountError::Cbor(CborError::NonShortest)) => "non-shortest",
        SubnetError::Contract(AccountError::Cbor(CborError::Truncated)) => "truncated",
        SubnetError::Contract(AccountError::Cbor(_)) => "invalid-encoding",
        other => panic!("unexpected refusal: {other:?}"),
    }
}

#[test]
fn subnet_selection_vectors() {
    let vectors = fixtures();
    assert!(!vectors.is_empty());
    let mut accepted = BTreeSet::new();
    for vector in &vectors {
        let decoded = SubnetPublication::decode(&bytes(vector["bytes"]));
        if vector["decision"] != "accept" {
            assert_eq!(
                refusal(decoded.unwrap_err()),
                vector["decision"],
                "{}",
                vector["name"]
            );
            assert_eq!(vector["expect"], "reject");
            assert_eq!(vector["reason"], vector["decision"]);
            assert_eq!(
                serde_json::from_str::<Value>(vector["output"]).unwrap(),
                json!([])
            );
            let canonical = bytes(vector["canonical"]);
            let normalized = SubnetPublication::decode(&canonical);
            if matches!(
                vector["decision"],
                "trailing-bytes" | "non-shortest" | "truncated"
            ) {
                assert_eq!(normalized.unwrap().canonical().unwrap(), canonical);
            } else {
                assert_eq!(
                    refusal(normalized.unwrap_err()),
                    vector["decision"],
                    "{}",
                    vector["name"]
                );
            }
            continue;
        }
        assert_eq!(vector["expect"], "accept");
        let publication = decoded.unwrap();
        assert_eq!(
            publication.canonical().unwrap(),
            bytes(vector["canonical"]),
            "{}",
            vector["name"]
        );
        assert_eq!(bytes(vector["bytes"]), bytes(vector["canonical"]));
        let scope = json!({"nsd":hex(&publication.nsd_id), "network":hex(&publication.network_id),
            "recipient":hex(&publication.recipient), "revision":publication.revision});
        assert_eq!(
            scope,
            serde_json::from_str::<Value>(vector["scope"]).unwrap()
        );
        assert_eq!(
            json!(publication.routes.iter().map(route).collect::<Vec<_>>()),
            serde_json::from_str::<Value>(vector["routes"]).unwrap(),
            "{}",
            vector["name"]
        );
        let output = publication.selected_routes().unwrap();
        assert_eq!(output.len(), publication.routes.len());
        for (output, source) in output.iter().zip(&publication.routes) {
            assert_eq!(&output.route, source);
        }
        let actual: Vec<_> = output.iter().map(|item| json!({
            "selected": prefixes(&item.selected),
            "coverage": {"tcp":item.coverage.tcp,"udp":item.coverage.udp,"echo":item.coverage.echo},
        })).collect();
        assert_eq!(
            json!(actual),
            serde_json::from_str::<Value>(vector["output"]).unwrap(),
            "{}",
            vector["name"]
        );
        accepted.insert(vector["name"]);
    }
    for name in [
        "explicit",
        "nested-default-specific",
        "ipv6-no-coverage",
        "exclusions-and-bypasses",
        "empty-selection",
        "empty-withdrawal",
        "fully-excluded",
        "selection-within-exclusion",
        "ipv4-host",
        "ipv6-host",
        "ipv4-default-host-exclusion",
        "ipv6-default-host-exclusion",
        "adjacent-selection",
        "prefix-count-boundary",
        "route-count-boundary",
    ] {
        assert!(
            accepted.contains(format!("subnet-{name}").as_str()),
            "missing vector: {name}"
        );
    }
}

#[test]
fn subnet_selection_refusals() {
    let vectors = fixtures();
    let mut refused = BTreeSet::new();
    for vector in &vectors {
        if vector["decision"] == "accept" {
            continue;
        }
        let error = SubnetPublication::decode(&bytes(vector["bytes"])).unwrap_err();
        assert_eq!(refusal(error), vector["decision"], "{}", vector["name"]);
        refused.insert(vector["name"]);
    }
    for name in [
        "mapped-length",
        "mapped-network",
        "mapped-family",
        "outside-exclusion",
        "outside-bypass",
        "outside-selection",
        "wrong-family-selection",
        "overlapping-exclusions",
        "overlapping-bypasses",
        "overlapping-selection",
        "exclusion-bypass-overlap",
        "duplicate-prefix",
        "unsorted-prefix",
        "misaligned-prefix",
        "invalid-length",
        "unknown-prefix-family",
        "mixed-selection",
        "nondefault-real",
        "unknown-selection",
        "prefix-count-limit",
        "invalid-provider",
        "wrong-client",
        "wrong-resource-scope",
        "ipv6-mapped-mismatch",
        "unknown-family",
        "unknown-schema",
        "zero-revision",
        "route-count-limit",
        "duplicate-route",
        "unsorted-route",
        "trailing",
        "nonminimal-array",
        "nonminimal-schema",
        "missing-publication",
        "missing-routes",
        "truncated",
        "invalid-m6-reference",
    ] {
        assert!(
            refused.contains(format!("subnet-{name}").as_str()),
            "missing refusal: {name}"
        );
    }
}

#[test]
fn subnet_constructed_contracts() {
    let vectors = fixtures();
    let vector = vectors
        .iter()
        .find(|v| v["name"] == "subnet-explicit")
        .unwrap();
    let valid = SubnetPublication::decode(&bytes(vector["bytes"])).unwrap();
    let mut invalid = Vec::new();
    let mut item = valid.clone();
    item.routes[0].real.length = 33;
    invalid.push((item, "invalid-prefix"));
    let mut item = valid.clone();
    item.routes[0].mapped.length = 103;
    invalid.push((item, "mapped-prefix"));
    let mut item = valid.clone();
    item.routes[0].provider = [0; 32];
    item.routes[0].provider[0] = 2;
    invalid.push((item, "identity"));
    let mut item = valid.clone();
    item.routes[0].selection = SubnetSelection::Default;
    invalid.push((item, "invalid-default"));
    let mut item = valid.clone();
    item.routes[0].bypasses = vec![SubnetPrefix {
        address: "11.0.0.0".parse().unwrap(),
        length: 8,
    }];
    invalid.push((item, "outside-bypass"));
    let mut item = valid.clone();
    item.routes[0].exclusions = vec![valid.routes[0].real; 2];
    invalid.push((item, "noncanonical-set"));
    let mut item = valid.clone();
    item.routes[0].resource.nsd_id = [0; 16];
    invalid.push((item, "scope"));
    let mut item = valid.clone();
    item.routes[0].selection = SubnetSelection::Explicit(vec![valid.routes[0].real; 257]);
    invalid.push((item, "bounds"));
    let mut item = valid.clone();
    item.routes = vec![valid.routes[0].clone(); 257];
    invalid.push((item, "bounds"));
    for (item, expected) in invalid {
        assert_eq!(refusal(item.canonical().unwrap_err()), expected);
        assert_eq!(refusal(item.selected_routes().unwrap_err()), expected);
    }
    let oversized = vec![0; nsshared_control::account::MAX_BYTES + 1];
    assert!(matches!(
        SubnetPublication::decode(&oversized),
        Err(SubnetError::Contract(AccountError::Cbor(
            CborError::TooLarge { .. }
        )))
    ));
}
