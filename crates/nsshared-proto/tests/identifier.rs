//! Relay identifiers: quick-v2 §8.6, authority syntax of quick-protocol §12.5.1.

use nsshared_proto::{RelayId, relay::MAX_RELAY_ID_BYTES, relay::RelayIdError};
use proptest::prelude::*;

#[test]
fn canonical_identifiers_parse_without_rewriting() {
    for text in [
        "hkg-a1.relay.ns.io:51822",
        "relay.example:51822",
        "192.0.2.10:51822",
        "127.0.0.1:1",
        "10.0.0.1:65535",
        "[2001:db8::10]:51822",
        "[::1]:443",
        "xn--bcher-kva.example:443",
        "localhost:80",
        "1234:80",
    ] {
        let relay = RelayId::parse(text).unwrap();
        assert_eq!(relay.as_str(), text);
        assert_eq!(relay.to_string(), text);
        assert_eq!(text.parse::<RelayId>(), Ok(relay));
    }
}

#[test]
fn maximum_length_is_accepted() {
    let label = "a".repeat(63);
    let host = format!("{label}.{label}.{label}.{}", "b".repeat(57));
    let text = format!("{host}:51822");
    assert_eq!(text.len(), MAX_RELAY_ID_BYTES);
    assert!(RelayId::parse(&text).is_ok());
}

fn rejects(text: &str, error: RelayIdError) {
    assert_eq!(RelayId::parse(text), Err(error), "{text:?}");
}

#[test]
fn refutation_relay_id_length() {
    rejects("", RelayIdError::Length);
    let text = format!("{}.{}:1", "a".repeat(63), "b".repeat(250));
    rejects(&text, RelayIdError::Length);
    let label = "a".repeat(63);
    let text = format!("{label}.{label}.{label}.{}:51822", "b".repeat(58));
    assert_eq!(text.len(), MAX_RELAY_ID_BYTES + 1);
    rejects(&text, RelayIdError::Length);
}

#[test]
fn refutation_relay_id_syntax() {
    for text in [
        "wss://relay.example:51822/keynet/v1",
        "relay.example:51822/ns",
        "user@relay.example:51822",
        "relay.example:51822?x",
        "relay.example:51822#x",
        "[fe80::1%eth0]:51822",
        " relay.example:51822",
        "relay.example:51822 ",
        "relay.example",
        "relay-a",
        "rélay.example:51822",
        "relay.example:\t1",
        "2001:db8::10:51822",
        "[2001:db8::10]",
        "[2001:db8::10]51822",
        "[2001:db8::10]:1:2",
        "[[::1]]:1",
        "a]:1",
    ] {
        rejects(text, RelayIdError::Syntax);
    }
}

#[test]
fn refutation_relay_id_port() {
    for text in [
        "relay.example:",
        "relay.example:0",
        "relay.example:051822",
        "relay.example:00",
        "relay.example:65536",
        "relay.example:99999999999999999999",
        "relay.example:+1",
        "relay.example:-1",
        "relay.example:1a",
        "[::1]:0",
    ] {
        rejects(text, RelayIdError::Port);
    }
}

#[test]
fn refutation_relay_id_ipv4() {
    for text in [
        "192.000.2.10:51822",
        "192.0.2.010:51822",
        "256.0.0.1:1",
        "1.2.3:1",
        "1.2.3.4.5:1",
        "1..2.3:1",
        "0.0.0.0:1",
        "224.0.0.1:1",
        "169.254.0.1:1",
    ] {
        rejects(text, RelayIdError::Ipv4);
    }
}

#[test]
fn refutation_relay_id_ipv6() {
    for text in [
        "[2001:DB8::10]:1",
        "[2001:0db8::10]:1",
        "[2001:db8:0:0:0:0:0:10]:1",
        "[2001:db8:0::10]:1",
        "[1:0:0:2:0:0:0:3]:1",
        "[::ffff:1.2.3.4]:1",
        "[::ffff:102:304]:1",
        "[::]:1",
        "[ff02::1]:1",
        "[fe80::1]:1",
        "[fec0::1]:1",
        "[relay.example]:1",
        "[]:1",
    ] {
        rejects(text, RelayIdError::Ipv6);
    }
}

#[test]
fn refutation_relay_id_dns_name() {
    let long_label = format!("{}.example:1", "a".repeat(64));
    for text in [
        "Relay.Example:51822",
        "relay.example.:51822",
        ".relay.example:51822",
        "relay..example:51822",
        "-relay.example:1",
        "relay-.example:1",
        "relay_a.example:1",
        ":1",
        long_label.as_str(),
    ] {
        rejects(text, RelayIdError::DnsName);
    }
}

proptest! {
    #[test]
    fn dns_identifiers_round_trip(
        labels in prop::collection::vec("[a-z]([a-z0-9-]{0,10}[a-z0-9])?", 1..4),
        port in 1_u16..,
    ) {
        let text = format!("{}:{port}", labels.join("."));
        let relay = RelayId::parse(&text).unwrap();
        prop_assert_eq!(relay.as_str(), text.as_str());
    }

    #[test]
    fn parse_never_normalises(text in "\\PC{0,40}") {
        if let Ok(relay) = RelayId::parse(&text) {
            prop_assert_eq!(relay.as_str(), text.as_str());
        }
    }
}
