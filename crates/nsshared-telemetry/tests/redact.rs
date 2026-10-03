//! `Redacted` never reveals the wrapped value.

use nsshared_telemetry::{REDACTED, SENSITIVE_FIELDS, redacted};

#[test]
fn debug_and_display_print_the_placeholder() {
    let secret = String::from("peer-key-material");
    let wrapped = redacted(&secret);
    assert_eq!(format!("{wrapped}"), REDACTED);
    assert_eq!(format!("{wrapped:?}"), REDACTED);
    assert_eq!(format!("{wrapped:#?}"), REDACTED);
    assert_eq!(format!("{:?}", Some(redacted(42))), "Some([redacted])");
    assert_eq!(REDACTED, "[redacted]");
}

#[test]
fn sensitive_fields_cover_the_ns_forbidden_labels() {
    for field in [
        "remote_ip",
        "src_ip",
        "dst_ip",
        "peer_key",
        "connection_id",
        "flow_id",
        "fqid",
    ] {
        assert!(SENSITIVE_FIELDS.contains(&field), "{field}");
    }
}
