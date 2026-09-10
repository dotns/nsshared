use control::mesh::{
    DISCOVERY_PATH, DiscoveryCapability, DiscoveryDocument, Error, MAX_DISCOVERY_BYTES,
};

const UDP: &str = include_str!("fixtures/mesh-discovery-v1/udp.json");
const FULL: &str = include_str!("fixtures/mesh-discovery-v1/full.json");

#[test]
fn mesh_discovery_fixed_documents_preserve_keys_ports_and_optional_encoding() {
    assert_eq!(DISCOVERY_PATH, "/.well-known/nsmesh");
    for (raw, full) in [(UDP, false), (FULL, true)] {
        let document = DiscoveryDocument::decode(raw.trim().as_bytes()).unwrap();
        assert_eq!(document.encode().unwrap(), raw.trim().as_bytes());
        assert_eq!(document.udp_port, if full { 65535 } else { 51900 });
        assert_eq!(document.wss_port, full.then_some(443));
        assert_eq!(document.relay_key.next.is_some(), full);
        assert_eq!(
            document.capabilities.contains(&DiscoveryCapability::Wss),
            full
        );
        let value: serde_json::Value = serde_json::from_str(raw).unwrap();
        assert_eq!(
            hex::encode(document.relay_key.current),
            value["relay_key"]["current"]
        );
    }
    let mut nulls: serde_json::Value = serde_json::from_str(UDP).unwrap();
    nulls["wss_port"] = serde_json::Value::Null;
    nulls["relay_key"]["next"] = serde_json::Value::Null;
    let value = DiscoveryDocument::decode(&serde_json::to_vec(&nulls).unwrap()).unwrap();
    assert_eq!(value.encode().unwrap(), UDP.trim().as_bytes());
}

#[test]
fn mesh_discovery_rejects_version_keys_and_unready_or_duplicate_carriers() {
    let base: serde_json::Value = serde_json::from_str(FULL).unwrap();
    for (pointer, value) in [
        ("/version", serde_json::json!("mesh_trust.v2")),
        (
            "/relay_origin",
            serde_json::json!("wss://relay.example/path"),
        ),
        (
            "/relay_origin",
            serde_json::json!("wss://user@relay.example:443"),
        ),
        ("/relay_key/current", serde_json::json!("a".repeat(63))),
        ("/relay_key/current", serde_json::json!("A".repeat(64))),
        (
            "/relay_key/current",
            serde_json::json!("0x".to_owned() + &"a".repeat(64)),
        ),
        ("/relay_key/next", serde_json::json!("z".repeat(64))),
        ("/udp_port", serde_json::json!(0)),
        ("/udp_port", serde_json::json!(65536)),
        ("/udp_port", serde_json::json!(-1)),
        ("/udp_port", serde_json::json!(51900.5)),
        ("/wss_port", serde_json::json!(0)),
        ("/wss_port", serde_json::Value::Null),
        ("/capabilities", serde_json::json!(["udp"])),
        ("/capabilities", serde_json::json!(["wss"])),
        ("/capabilities", serde_json::json!(["udp", "wss", "wss"])),
        ("/capabilities", serde_json::json!(["udp", "wss", "exit"])),
    ] {
        let mut bad = base.clone();
        *bad.pointer_mut(pointer).unwrap() = value;
        assert!(
            DiscoveryDocument::decode(&serde_json::to_vec(&bad).unwrap()).is_err(),
            "{pointer}: {bad}"
        );
    }
    let mut document = DiscoveryDocument::decode(UDP.as_bytes()).unwrap();
    document.wss_port = Some(9443);
    assert!(document.encode().is_err());
    document.capabilities.push(DiscoveryCapability::Wss);
    assert!(document.encode().is_ok());
    document.capabilities.push(DiscoveryCapability::Udp);
    assert!(document.encode().is_err());
}

#[test]
fn mesh_discovery_rejects_ambiguous_json_and_missing_required_fields() {
    for (from, to) in [
        ("\"version\":", "\"version\":\"mesh_trust.v1\",\"version\":"),
        ("\"current\":", "\"current\":null,\"current\":"),
        ("\"wss_port\":", "\"wss_port\":null,\"wss_port\":"),
        ("\"next\":", "\"next\":null,\"next\":"),
        ("\"version\":", "\"unknown\":true,\"version\":"),
        ("\"current\":", "\"unknown\":true,\"current\":"),
    ] {
        assert!(DiscoveryDocument::decode(FULL.replacen(from, to, 1).as_bytes()).is_err());
    }
    let base: serde_json::Value = serde_json::from_str(UDP).unwrap();
    for field in [
        "version",
        "relay_origin",
        "relay_key",
        "udp_port",
        "capabilities",
    ] {
        let mut bad = base.clone();
        bad.as_object_mut().unwrap().remove(field);
        assert!(DiscoveryDocument::decode(&serde_json::to_vec(&bad).unwrap()).is_err());
    }
    assert!(DiscoveryDocument::decode(format!("{UDP}{FULL}").as_bytes()).is_err());
    for end in 0..UDP.trim().len() {
        assert!(DiscoveryDocument::decode(&UDP.as_bytes()[..end]).is_err());
    }
}

#[test]
fn mesh_discovery_bounds_complete_body_before_parsing() {
    let mut boundary = UDP.trim().as_bytes().to_vec();
    boundary.resize(MAX_DISCOVERY_BYTES, b' ');
    DiscoveryDocument::decode(&boundary).unwrap();
    boundary.push(b' ');
    assert!(matches!(
        DiscoveryDocument::decode(&boundary),
        Err(Error::TooLarge)
    ));
    let nested = format!("{}0{}", "[".repeat(129), "]".repeat(129));
    assert!(DiscoveryDocument::decode(nested.as_bytes()).is_err());
    let mut document = DiscoveryDocument::decode(UDP.as_bytes()).unwrap();
    document.relay_origin = format!("udp://{}.example:51900", "a".repeat(255));
    assert!(document.encode().is_err());
}
