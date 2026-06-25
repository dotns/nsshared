use std::collections::BTreeMap;
use std::collections::HashMap;
use std::net::IpAddr;

use common::{IpNet, Protocol};

use crate::Error;

// ── Subject matcher ───────────────────────────────────────────────────────────

/// Compiled source matcher over verified subjects.
#[derive(Debug, Clone)]
pub(crate) enum SubjectMatcher {
    AnyVerified,
    Subject(String),
}

impl SubjectMatcher {
    pub(crate) fn matches<'a>(
        &self,
        subjects: impl IntoIterator<Item = &'a str>,
        groups: &BTreeMap<String, Vec<String>>,
    ) -> Option<&'a str> {
        match self {
            SubjectMatcher::AnyVerified => subjects.into_iter().next(),
            SubjectMatcher::Subject(expected) => subjects.into_iter().find(|subject| {
                expected == *subject
                    || groups
                        .get(expected)
                        .is_some_and(|members| members.iter().any(|member| member == *subject))
            }),
        }
    }
}

// ── Destination matcher ───────────────────────────────────────────────────────

/// Compiled destination matcher.
#[derive(Debug, Clone)]
pub(crate) struct DstMatcher {
    pub(crate) host: HostMatcher,
    pub(crate) ports: PortMatcher,
}

#[derive(Debug, Clone)]
pub(crate) enum HostMatcher {
    Any,
    Cidr(IpNet),
}

#[derive(Debug, Clone)]
pub(crate) enum PortMatcher {
    Any,
    Single(u16),
    Range(u16, u16),
    List(Vec<u16>),
}

impl DstMatcher {
    pub(crate) fn matches(&self, ip: IpAddr, port: u16) -> bool {
        let host_ok = match &self.host {
            HostMatcher::Any => true,
            HostMatcher::Cidr(net) => net.contains(&ip),
        };
        if !host_ok {
            return false;
        }
        match &self.ports {
            PortMatcher::Any => true,
            PortMatcher::Single(p) => port == *p,
            PortMatcher::Range(lo, hi) => port >= *lo && port <= *hi,
            PortMatcher::List(ports) => ports.contains(&port),
        }
    }
}

// ── Parser functions ──────────────────────────────────────────────────────────

/// Parse a subject string into a [`SubjectMatcher`].
///
/// Accepted forms:
/// - `*` — any verified subject
/// - canonical subjects such as `user:alice`, `group:eng`, `machine:m-1`
/// - `anonymous` for explicit unauthenticated-public policy, never `Unknown`
pub(crate) fn parse_subject(s: &str) -> Result<SubjectMatcher, Error> {
    if s == "*" {
        return Ok(SubjectMatcher::AnyVerified);
    }
    if is_valid_subject(s) {
        return Ok(SubjectMatcher::Subject(s.to_owned()));
    }
    Err(Error::InvalidPolicy(format!(
        "invalid subject '{s}': expected '*', 'anonymous', or a prefixed subject"
    )))
}

pub(crate) fn is_valid_subject(s: &str) -> bool {
    s == "anonymous"
        || [
            "user:",
            "group:",
            "machine:",
            "tag:",
            "gateway:",
            "external:",
        ]
        .iter()
        .any(|prefix| s.strip_prefix(prefix).is_some_and(|rest| !rest.is_empty()))
}

/// Parse a destination string (`host:ports`) into a `DstMatcher`.
///
/// Accepted forms:
/// - `*:*` — any host, any port
/// - `192.168.0.0/24:80` — CIDR + single port
/// - `alias:5432` — host alias + single port
/// - `alias:80,443` — host alias + port list
/// - `alias:8000-8999` — host alias + port range
/// - `alias:*` — host alias + any port
pub(crate) fn parse_dst(s: &str, hosts: &HashMap<String, IpNet>) -> Result<DstMatcher, Error> {
    let colon = s.rfind(':').ok_or_else(|| Error::InvalidDst {
        dst: s.to_owned(),
        reason: "missing ':' between host and port".to_owned(),
    })?;

    let host_part = &s[..colon];
    let port_part = &s[colon + 1..];

    let host = parse_host(host_part, hosts)?;
    let ports = parse_ports(port_part).map_err(|reason| Error::InvalidDst {
        dst: s.to_owned(),
        reason,
    })?;

    Ok(DstMatcher { host, ports })
}

fn parse_host(s: &str, hosts: &HashMap<String, IpNet>) -> Result<HostMatcher, Error> {
    if s == "*" {
        return Ok(HostMatcher::Any);
    }
    if let Ok(net) = s.parse::<IpNet>() {
        return Ok(HostMatcher::Cidr(net));
    }
    if let Some(net) = hosts.get(s) {
        return Ok(HostMatcher::Cidr(*net));
    }
    Err(Error::UnknownAlias(s.to_owned()))
}

fn parse_ports(s: &str) -> Result<PortMatcher, String> {
    if s == "*" {
        return Ok(PortMatcher::Any);
    }
    // Port list: "80,443,8080"
    if s.contains(',') {
        let ports = s
            .split(',')
            .map(|p| {
                p.trim()
                    .parse::<u16>()
                    .map_err(|_| format!("invalid port '{p}'"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        return Ok(PortMatcher::List(ports));
    }
    // Port range: "8000-8999"
    if let Some((lo_s, hi_s)) = s.split_once('-') {
        let lo = lo_s
            .parse::<u16>()
            .map_err(|_| format!("invalid range start '{lo_s}'"))?;
        let hi = hi_s
            .parse::<u16>()
            .map_err(|_| format!("invalid range end '{hi_s}'"))?;
        if lo > hi {
            return Err(format!("range start {lo} > end {hi}"));
        }
        return Ok(PortMatcher::Range(lo, hi));
    }
    // Single port.
    let p = s
        .parse::<u16>()
        .map_err(|_| format!("invalid port '{s}'"))?;
    Ok(PortMatcher::Single(p))
}

/// Parse a protocol string (`"tcp"` / `"udp"`) into a `Protocol`.
pub(crate) fn parse_protocol(s: &str) -> Result<Protocol, Error> {
    match s.to_lowercase().as_str() {
        "tcp" => Ok(Protocol::Tcp),
        "udp" => Ok(Protocol::Udp),
        other => Err(Error::InvalidPolicy(format!(
            "unknown protocol '{other}': expected 'tcp' or 'udp'"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};

    fn hosts() -> HashMap<String, IpNet> {
        let mut m = HashMap::new();
        m.insert("web".to_owned(), "192.168.1.0/24".parse().unwrap());
        m.insert("db".to_owned(), "192.168.1.10/32".parse().unwrap());
        m
    }

    // ── SubjectMatcher ────────────────────────────────────────────────────

    #[test]
    fn subject_wildcard_matches_any_verified_subject() {
        let m = parse_subject("*").unwrap();
        assert_eq!(
            m.matches(std::iter::once("user:alice"), &BTreeMap::new()),
            Some("user:alice")
        );
    }

    #[test]
    fn subject_group_matches_expanded_member() {
        let m = parse_subject("group:eng").unwrap();
        let groups = BTreeMap::from([("group:eng".to_owned(), vec!["user:alice".to_owned()])]);
        assert_eq!(
            m.matches(std::iter::once("user:alice"), &groups),
            Some("user:alice")
        );
        assert_eq!(m.matches(std::iter::once("user:bob"), &groups), None);
    }

    #[test]
    fn subject_exact_matches_member_of_subject_set() {
        let m = parse_subject("external:logto:realm:org:role:admin").unwrap();
        let subjects = [
            "external:logto:realm:org:user-1",
            "external:logto:realm:org",
            "external:logto:realm:org:role:admin",
        ];

        assert_eq!(
            m.matches(subjects, &BTreeMap::new()),
            Some("external:logto:realm:org:role:admin")
        );
    }

    #[test]
    fn subject_set_matching_preserves_group_membership_map() {
        let m = parse_subject("group:eng").unwrap();
        let groups = BTreeMap::from([("group:eng".to_owned(), vec!["user:alice".to_owned()])]);
        let subjects = ["user:alice", "external:logto:realm:org:role:admin"];

        assert_eq!(m.matches(subjects, &groups), Some("user:alice"));
    }

    #[test]
    fn subject_invalid_returns_error() {
        assert!(parse_subject("10.0.0.0/24").is_err());
    }

    // ── DstMatcher ────────────────────────────────────────────────────────

    #[test]
    fn dst_wildcard_matches_anything() {
        let m = parse_dst("*:*", &HashMap::new()).unwrap();
        assert!(m.matches("1.2.3.4".parse().unwrap(), 9999));
    }

    #[test]
    fn dst_cidr_single_port() {
        let m = parse_dst("192.168.1.0/24:80", &HashMap::new()).unwrap();
        assert!(m.matches(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)), 80));
        assert!(!m.matches(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)), 443));
        assert!(!m.matches(IpAddr::V4(Ipv4Addr::new(192, 168, 2, 5)), 80));
    }

    #[test]
    fn dst_alias_port_list() {
        let m = parse_dst("web:80,443", &hosts()).unwrap();
        assert!(m.matches(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)), 80));
        assert!(m.matches(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)), 443));
        assert!(!m.matches(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)), 8080));
    }

    #[test]
    fn dst_alias_port_range() {
        let m = parse_dst("web:8000-8999", &hosts()).unwrap();
        assert!(m.matches(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8000));
        assert!(m.matches(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8500));
        assert!(m.matches(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8999));
        assert!(!m.matches(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 7999));
        assert!(!m.matches(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 9000));
    }

    #[test]
    fn dst_alias_wildcard_port() {
        let m = parse_dst("db:*", &hosts()).unwrap();
        assert!(m.matches(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 1));
        assert!(m.matches(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 65535));
        assert!(!m.matches(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 11)), 80));
    }

    #[test]
    fn dst_missing_colon_returns_error() {
        assert!(parse_dst("192.168.1.1", &HashMap::new()).is_err());
    }

    #[test]
    fn dst_invalid_port_returns_error() {
        assert!(parse_dst("*:notaport", &HashMap::new()).is_err());
    }

    #[test]
    fn dst_range_inverted_returns_error() {
        assert!(parse_dst("*:9000-8000", &HashMap::new()).is_err());
    }

    // ── parse_protocol ────────────────────────────────────────────────────

    #[test]
    fn parse_protocol_tcp() {
        assert_eq!(parse_protocol("tcp").unwrap(), Protocol::Tcp);
    }

    #[test]
    fn parse_protocol_udp() {
        assert_eq!(parse_protocol("udp").unwrap(), Protocol::Udp);
    }

    #[test]
    fn parse_protocol_unknown_returns_error() {
        assert!(parse_protocol("icmp").is_err());
    }
}
