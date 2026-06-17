#![forbid(unsafe_code)]

//! Canonical NSIO internal DNS name helpers.

/// Canonical suffix for service DNS names.
pub const SERVICE_DNS_SUFFIX: &str = "n.ns.io";

/// Canonical suffix for machine DNS names.
pub const MACHINE_DNS_SUFFIX: &str = "m.ns.io";

/// Canonical suffix for gateway DNS names.
pub const GATEWAY_DNS_SUFFIX: &str = "gw.ns.io";

/// Build the canonical service FQDN.
pub fn service_fqdn(service: &str, site: &str) -> String {
    format!("{service}.{site}.{SERVICE_DNS_SUFFIX}")
}

/// Build the canonical machine FQDN.
pub fn machine_fqdn(machine_id: &str) -> String {
    format!("{machine_id}.{MACHINE_DNS_SUFFIX}")
}

/// Build the canonical gateway FQDN.
pub fn gateway_fqdn(gateway_id: &str) -> String {
    format!("{gateway_id}.{GATEWAY_DNS_SUFFIX}")
}

/// Return `true` when `name` has the canonical service FQDN shape.
pub fn is_service_fqdn(name: &str) -> bool {
    strip_canonical_suffix(name, SERVICE_DNS_SUFFIX)
        .is_some_and(|prefix| has_exact_non_empty_label_count(prefix, 2))
}

/// Return `true` when `name` has the canonical machine FQDN shape.
pub fn is_machine_fqdn(name: &str) -> bool {
    strip_canonical_suffix(name, MACHINE_DNS_SUFFIX)
        .is_some_and(|prefix| has_exact_non_empty_label_count(prefix, 1))
}

/// Return `true` when `name` has the canonical gateway FQDN shape.
pub fn is_gateway_fqdn(name: &str) -> bool {
    strip_canonical_suffix(name, GATEWAY_DNS_SUFFIX)
        .is_some_and(|prefix| has_exact_non_empty_label_count(prefix, 1))
}

fn strip_canonical_suffix<'a>(name: &'a str, suffix: &str) -> Option<&'a str> {
    name.strip_suffix(suffix)?
        .strip_suffix('.')
        .filter(|prefix| !prefix.is_empty())
}

fn has_exact_non_empty_label_count(prefix: &str, expected: usize) -> bool {
    let mut count = 0;
    for label in prefix.split('.') {
        if label.is_empty() {
            return false;
        }
        count += 1;
    }
    count == expected
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_suffix_constants_match_spec() {
        assert_eq!(SERVICE_DNS_SUFFIX, "n.ns.io");
        assert_eq!(MACHINE_DNS_SUFFIX, "m.ns.io");
        assert_eq!(GATEWAY_DNS_SUFFIX, "gw.ns.io");
    }

    #[test]
    fn fqdn_helpers_generate_canonical_names() {
        assert_eq!(service_fqdn("web", "site-001"), "web.site-001.n.ns.io");
        assert_eq!(machine_fqdn("mid-001"), "mid-001.m.ns.io");
        assert_eq!(gateway_fqdn("gw-us-east"), "gw-us-east.gw.ns.io");
    }

    #[test]
    fn canonical_suffix_checks_accept_generated_names() {
        assert!(is_service_fqdn(&service_fqdn("web", "site-001")));
        assert!(is_machine_fqdn(&machine_fqdn("mid-001")));
        assert!(is_gateway_fqdn(&gateway_fqdn("gw-us-east")));
    }

    #[test]
    fn canonical_suffix_checks_reject_legacy_and_wrong_shapes() {
        assert!(!is_service_fqdn("web.site.n.ns"));
        assert!(!is_service_fqdn("site.n.ns.io"));
        assert!(!is_service_fqdn("web.site.extra.n.ns.io"));
        assert!(!is_service_fqdn("web..n.ns.io"));

        assert!(!is_machine_fqdn("mid-001.n.ns"));
        assert!(!is_machine_fqdn("zone.mid-001.m.ns.io"));
        assert!(!is_machine_fqdn("m.ns.io"));

        assert!(!is_gateway_fqdn("gw-us-east.n.ns"));
        assert!(!is_gateway_fqdn("zone.gw-us-east.gw.ns.io"));
        assert!(!is_gateway_fqdn("gw.ns.io"));
    }
}
