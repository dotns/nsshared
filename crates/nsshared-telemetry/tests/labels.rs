//! Label keys and values match the NS strings.

use nsshared_telemetry::labels::{
    LABEL_PATH, LABEL_PEER_SOURCE, LABEL_TRANSPORT, Path, PeerSource, Transport,
};

#[test]
fn label_keys() {
    assert_eq!(LABEL_PATH, "path");
    assert_eq!(LABEL_TRANSPORT, "transport");
    assert_eq!(LABEL_PEER_SOURCE, "peer_source");
}

#[test]
fn path_values_match_ns() {
    assert_eq!(Path::Tun.as_str(), "tun");
    assert_eq!(Path::Userspace.as_str(), "userspace");
    assert_eq!(Path::Wss.as_str(), "wss");
}

#[test]
fn transport_values_match_ns() {
    assert_eq!(Transport::Udp.as_str(), "udp");
    assert_eq!(Transport::Wss.as_str(), "wss");
    assert_eq!(Transport::Noise.as_str(), "noise");
    assert_eq!(Transport::Quic.as_str(), "quic");
}

#[test]
fn peer_source_values_match_ns_source_kinds() {
    assert_eq!(PeerSource::Nsd.as_str(), "nsd");
    assert_eq!(PeerSource::Quick.as_str(), "quick");
    assert_eq!(PeerSource::App.as_str(), "app");
}
