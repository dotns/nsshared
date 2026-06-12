use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use common::{IpNet, Protocol};
use tracing::{debug, warn};

use crate::{
    Error,
    matcher::{
        DstMatcher, SubjectMatcher, is_valid_subject, parse_dst, parse_protocol, parse_subject,
    },
    policy::{AclBindings, AclPolicy, AclTest, ServiceFloor},
};

// ── Public access context ────────────────────────────────────────────────────

/// Network tuple for routing and destination matching.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkTuple {
    /// Observed packet source address. This is routing metadata only and is
    /// never used as the ACL subject.
    pub source_ip: Option<IpAddr>,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub protocol: Protocol,
}

impl NetworkTuple {
    /// Build a network tuple for ACL evaluation.
    #[must_use]
    pub fn new(
        source_ip: Option<IpAddr>,
        dst_ip: IpAddr,
        dst_port: u16,
        protocol: Protocol,
    ) -> Self {
        Self {
            source_ip,
            dst_ip,
            dst_port,
            protocol,
        }
    }
}

/// Identity of the source side of an access attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceIdentity {
    /// No trusted subject could be established. This always denies.
    Unknown,
    /// Trusted source subject asserted by the transport/auth boundary.
    VerifiedSubject {
        realm: String,
        subject: String,
        asserted_by: SourceAssertion,
    },
}

impl SourceIdentity {
    fn subject(&self) -> Option<&str> {
        match self {
            SourceIdentity::Unknown => None,
            SourceIdentity::VerifiedSubject { subject, .. } => Some(subject.as_str()),
        }
    }
}

/// Evidence used to bind a transport anchor to a source subject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceAssertion {
    /// WireGuard peer public key anchor.
    WgPeerKey { pubkey: [u8; 32] },
    /// Termination/session binding anchor.
    Terminate { binding: TerminateBinding },
    /// External identity provider assertion.
    External { idp: String },
}

/// Termination/session binding anchor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminateBinding {
    pub anchor: String,
}

/// Identity of the target side of an access attempt.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TargetIdentity {
    pub service: Option<String>,
}

/// Transport family that delivered the access attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    Direct,
    WgRelay,
    WssRelay,
    Terminate,
    Https,
}

impl TransportKind {
    /// Stable decision-log label, aligned with the `LinkMode` wire vocabulary
    /// (`direct` | `terminate` | `wg-relay` | `wss-relay`). `https` covers the
    /// non-link HTTPS judge path, which has no `LinkMode` counterpart.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            TransportKind::Direct => "direct",
            TransportKind::WgRelay => "wg-relay",
            TransportKind::WssRelay => "wss-relay",
            TransportKind::Terminate => "terminate",
            TransportKind::Https => "https",
        }
    }
}

/// Complete ACL evaluation input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessContext {
    pub network: NetworkTuple,
    pub source: SourceIdentity,
    pub target: TargetIdentity,
    pub transport: TransportKind,
}

impl AccessContext {
    /// Build a context with unknown source identity. This always denies.
    #[must_use]
    pub fn unknown(network: NetworkTuple, transport: TransportKind) -> Self {
        Self {
            network,
            source: SourceIdentity::Unknown,
            target: TargetIdentity::default(),
            transport,
        }
    }

    /// Build a context with a verified subject.
    #[must_use]
    pub fn verified_subject(
        subject: impl Into<String>,
        network: NetworkTuple,
        asserted_by: SourceAssertion,
        transport: TransportKind,
    ) -> Self {
        Self {
            network,
            source: SourceIdentity::VerifiedSubject {
                realm: "default".to_owned(),
                subject: subject.into(),
                asserted_by,
            },
            target: TargetIdentity::default(),
            transport,
        }
    }

    /// Structured source-anchor string for ACL decision logs. For zero-trust
    /// flows this is the verified end-to-end WireGuard peer public key (base64,
    /// same encoding as `bindings.wg_peer`), proving the subject decision was
    /// made from the client WG key.
    #[must_use]
    pub fn source_anchor(&self) -> String {
        match &self.source {
            SourceIdentity::Unknown => "none".to_owned(),
            SourceIdentity::VerifiedSubject { asserted_by, .. } => match asserted_by {
                SourceAssertion::WgPeerKey { pubkey } => wg_peer_anchor(pubkey),
                SourceAssertion::Terminate { binding } => binding.anchor.clone(),
                SourceAssertion::External { idp } => format!("idp:{idp}"),
            },
        }
    }

    /// Coarse classification of how the source subject was asserted, for ACL
    /// decision logs. `client-wg-key` means an end-to-end client WireGuard key
    /// (zero-trust, judged at NSN), distinct from a gateway-terminated or
    /// external-IdP assertion.
    #[must_use]
    pub const fn source_class(&self) -> &'static str {
        match &self.source {
            SourceIdentity::Unknown => "unknown",
            SourceIdentity::VerifiedSubject { asserted_by, .. } => match asserted_by {
                SourceAssertion::WgPeerKey { .. } => "client-wg-key",
                SourceAssertion::Terminate { .. } => "terminate-binding",
                SourceAssertion::External { .. } => "external-idp",
            },
        }
    }
}

/// Result of an ACL evaluation.
#[derive(Debug, Clone)]
pub struct AclDecision {
    /// `true` if an accept rule matched; `false` means default deny.
    pub allowed: bool,
    /// Index of the matched rule within the compiled rule list (if any).
    pub matched_rule_index: Option<usize>,
    /// Human-readable explanation.
    pub reason: String,
}

/// A failed built-in policy test.
#[derive(Debug, Clone)]
pub struct AclTestFailure {
    pub test: AclTest,
    pub reason: String,
}

// ── Internal compiled rule ────────────────────────────────────────────────────

#[derive(Debug)]
struct CompiledRule {
    subject: Vec<SubjectMatcher>,
    dst: Vec<DstMatcher>,
    /// `None` means match both TCP and UDP.
    proto: Option<Protocol>,
}

impl CompiledRule {
    fn matches(
        &self,
        subject: &str,
        groups: &BTreeMap<String, Vec<String>>,
        network: &NetworkTuple,
    ) -> bool {
        if !self.subject.iter().any(|m| m.matches(subject, groups)) {
            return false;
        }
        if !self
            .dst
            .iter()
            .any(|m| m.matches(network.dst_ip, network.dst_port))
        {
            return false;
        }
        match self.proto {
            None => true,
            Some(Protocol::Both) => true,
            Some(proto) => proto == network.protocol,
        }
    }
}

// ── AclEngine ─────────────────────────────────────────────────────────────────

/// ACL engine: load a policy, evaluate access contexts.
///
/// Default policy is **deny**. Traffic is allowed only when a verified source
/// subject matches an explicit `accept` rule.
#[derive(Debug)]
pub struct AclEngine {
    compiled_rules: Vec<CompiledRule>,
    tests: Vec<AclTest>,
    groups: BTreeMap<String, Vec<String>>,
    bindings: AclBindings,
    gateway_roster: Vec<String>,
    service_floor: ServiceFloor,
}

impl AclEngine {
    /// Load, resolve, and compile an [`AclPolicy`].
    ///
    /// Runs the built-in tests and returns [`Error::TestsFailed`] if any fail.
    pub fn load(policy: AclPolicy) -> Result<Self, Error> {
        validate_subjects(&policy)?;
        let hosts = resolve_hosts(&policy.hosts)?;

        let mut compiled_rules = Vec::with_capacity(policy.rules.len());
        for (i, rule) in policy.rules.iter().enumerate() {
            if rule.subject.is_empty() {
                return Err(Error::InvalidPolicy(format!("rule {i} subject is empty")));
            }
            let subject = rule
                .subject
                .iter()
                .map(|s| parse_subject(s))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| Error::InvalidPolicy(format!("rule {i} subject: {e}")))?;

            let dst = rule
                .dst
                .iter()
                .map(|s| parse_dst(s, &hosts))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| Error::InvalidPolicy(format!("rule {i} dst: {e}")))?;

            let proto = rule
                .proto
                .as_deref()
                .map(parse_protocol)
                .transpose()
                .map_err(|e| Error::InvalidPolicy(format!("rule {i} proto: {e}")))?;

            compiled_rules.push(CompiledRule {
                subject,
                dst,
                proto,
            });
        }

        let engine = Self {
            compiled_rules,
            tests: policy.tests.clone(),
            groups: policy.groups.clone(),
            bindings: policy.bindings.clone(),
            gateway_roster: policy.gateway_roster.clone(),
            service_floor: policy.service_floor.clone(),
        };

        let failures = engine.validate_tests();
        if !failures.is_empty() {
            for f in &failures {
                warn!(
                    subject = %f.test.subject,
                    dst = %f.test.dst,
                    expected = f.test.allow,
                    reason = %f.reason,
                    "ACL policy test failed"
                );
            }
            return Err(Error::TestsFailed {
                count: failures.len(),
            });
        }

        Ok(engine)
    }

    /// Number of compiled accept rules.
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.compiled_rules.len()
    }

    /// Resolve a WireGuard public-key anchor to a subject.
    #[must_use]
    pub fn subject_for_wg_peer(&self, anchor: &str) -> Option<&str> {
        self.bindings.wg_peer.get(anchor).map(String::as_str)
    }

    /// Resolve a raw WireGuard public key to a subject using the base64 wire
    /// anchor format.
    #[must_use]
    pub fn subject_for_wg_peer_key(&self, pubkey: &[u8; 32]) -> Option<&str> {
        self.subject_for_wg_peer(&wg_peer_anchor(pubkey))
    }

    /// Resolve a machine/session anchor to a subject.
    #[must_use]
    pub fn subject_for_machine(&self, anchor: &str) -> Option<&str> {
        self.bindings.machine.get(anchor).map(String::as_str)
    }

    /// Gateway roster anchors carried by the policy.
    #[must_use]
    pub fn gateway_roster(&self) -> &[String] {
        &self.gateway_roster
    }

    /// Service-floor data carried by the policy.
    #[must_use]
    pub fn service_floor(&self) -> &ServiceFloor {
        &self.service_floor
    }

    /// Evaluate whether `context` is allowed by the policy.
    ///
    /// Returns `allowed = true` only when an explicit accept rule matches a
    /// verified source subject. Unknown source identity fails closed before
    /// any wildcard rule is considered.
    pub fn is_allowed(&self, context: &AccessContext) -> AclDecision {
        let start = std::time::Instant::now();
        let proto = protocol_label(context.network.protocol);
        let _span = tracing::trace_span!("acl.eval", protocol = proto).entered();

        let Some(subject) = context.source.subject() else {
            warn!(
                dst = %context.network.dst_ip,
                port = context.network.dst_port,
                proto = ?context.network.protocol,
                transport = context.transport.label(),
                source_wg_peer = %context.source_anchor(),
                source_class = context.source_class(),
                "ACL deny: unknown source subject"
            );
            telemetry::acl_otel::record_eval_duration(
                proto,
                telemetry::labels::Outcome::Denied,
                start.elapsed().as_secs_f64(),
            );
            return AclDecision {
                allowed: false,
                matched_rule_index: None,
                reason: "denied: unknown source subject".to_owned(),
            };
        };

        for (idx, rule) in self.compiled_rules.iter().enumerate() {
            if rule.matches(subject, &self.groups, &context.network) {
                debug!(
                    subject = %subject,
                    dst = %context.network.dst_ip,
                    port = context.network.dst_port,
                    proto = ?context.network.protocol,
                    transport = context.transport.label(),
                    source_wg_peer = %context.source_anchor(),
                    source_class = context.source_class(),
                    rule = idx,
                    "ACL accept"
                );
                telemetry::acl_otel::record_eval_duration(
                    proto,
                    telemetry::labels::Outcome::Ok,
                    start.elapsed().as_secs_f64(),
                );
                return AclDecision {
                    allowed: true,
                    matched_rule_index: Some(idx),
                    reason: format!("accepted by rule {idx}"),
                };
            }
        }

        warn!(
            subject = %subject,
            dst = %context.network.dst_ip,
            port = context.network.dst_port,
            proto = ?context.network.protocol,
            transport = context.transport.label(),
            source_wg_peer = %context.source_anchor(),
            source_class = context.source_class(),
            "ACL deny: no matching rule"
        );
        telemetry::acl_otel::record_eval_duration(
            proto,
            telemetry::labels::Outcome::Denied,
            start.elapsed().as_secs_f64(),
        );
        AclDecision {
            allowed: false,
            matched_rule_index: None,
            reason: "denied: no matching accept rule".to_owned(),
        }
    }

    /// Run the built-in policy tests and return a list of failures.
    pub fn validate_tests(&self) -> Vec<AclTestFailure> {
        let mut failures = Vec::new();

        for test in &self.tests {
            if !is_valid_subject(&test.subject) {
                failures.push(AclTestFailure {
                    test: test.clone(),
                    reason: format!("invalid test subject '{}'", test.subject),
                });
                continue;
            }

            let (dst_ip, dst_port) = match parse_test_dst(&test.dst) {
                Ok(pair) => pair,
                Err(reason) => {
                    failures.push(AclTestFailure {
                        test: test.clone(),
                        reason,
                    });
                    continue;
                }
            };

            let protocol = match test.proto.as_deref() {
                Some(raw) => match parse_protocol(raw) {
                    Ok(proto) => proto,
                    Err(reason) => {
                        failures.push(AclTestFailure {
                            test: test.clone(),
                            reason: format!("cannot parse test proto '{raw}': {reason}"),
                        });
                        continue;
                    }
                },
                None => Protocol::Tcp,
            };

            let network = NetworkTuple::new(None, dst_ip, dst_port, protocol);
            let context = AccessContext::verified_subject(
                test.subject.clone(),
                network,
                SourceAssertion::External {
                    idp: "policy-test".to_owned(),
                },
                TransportKind::Direct,
            );
            let decision = self.is_allowed(&context);

            if decision.allowed != test.allow {
                failures.push(AclTestFailure {
                    test: test.clone(),
                    reason: format!(
                        "expected {}, got {} ({})",
                        if test.allow { "allow" } else { "deny" },
                        if decision.allowed { "allow" } else { "deny" },
                        decision.reason,
                    ),
                });
            }
        }

        failures
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Encode a WireGuard public key anchor for policy bindings.
#[must_use]
pub fn wg_peer_anchor(pubkey: &[u8; 32]) -> String {
    STANDARD.encode(pubkey)
}

/// Validate a canonical subject string accepted by ACL rules and bindings.
#[must_use]
pub fn valid_subject(subject: &str) -> bool {
    is_valid_subject(subject)
}

/// Map a [`Protocol`] to a bounded, `'static` label for spans / metrics.
fn protocol_label(proto: Protocol) -> &'static str {
    match proto {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
        Protocol::Both => "both",
        Protocol::Http => "http",
        Protocol::Https => "https",
    }
}

fn validate_subjects(policy: &AclPolicy) -> Result<(), Error> {
    for (group, members) in &policy.groups {
        if !is_valid_subject(group) {
            return Err(Error::InvalidPolicy(format!(
                "invalid group subject '{group}'"
            )));
        }
        for member in members {
            if !is_valid_subject(member) {
                return Err(Error::InvalidPolicy(format!(
                    "invalid member subject '{member}' in group '{group}'"
                )));
            }
        }
    }

    for (anchor, subject) in &policy.bindings.wg_peer {
        if anchor.is_empty() {
            return Err(Error::InvalidPolicy(
                "empty wg_peer binding anchor".to_owned(),
            ));
        }
        if !is_valid_subject(subject) {
            return Err(Error::InvalidPolicy(format!(
                "invalid wg_peer binding subject '{subject}'"
            )));
        }
    }

    for (anchor, subject) in &policy.bindings.machine {
        if anchor.is_empty() {
            return Err(Error::InvalidPolicy(
                "empty machine binding anchor".to_owned(),
            ));
        }
        if !is_valid_subject(subject) {
            return Err(Error::InvalidPolicy(format!(
                "invalid machine binding subject '{subject}'"
            )));
        }
    }

    Ok(())
}

fn resolve_hosts(raw: &HashMap<String, String>) -> Result<HashMap<String, IpNet>, Error> {
    raw.iter()
        .map(|(alias, cidr)| {
            let net = cidr.parse::<IpNet>().map_err(|e| Error::InvalidCidr {
                addr: cidr.clone(),
                reason: e.to_string(),
            })?;
            Ok((alias.clone(), net))
        })
        .collect()
}

/// Parse a test destination string like `"192.168.1.10:5432"`.
fn parse_test_dst(s: &str) -> Result<(IpAddr, u16), String> {
    let colon = s
        .rfind(':')
        .ok_or_else(|| format!("missing ':' in test dst '{s}'"))?;
    let ip_str = &s[..colon];
    let port_str = &s[colon + 1..];
    let ip = ip_str
        .parse::<IpAddr>()
        .map_err(|_| format!("invalid IP '{ip_str}' in test dst '{s}'"))?;
    let port = port_str
        .parse::<u16>()
        .map_err(|_| format!("invalid port '{port_str}' in test dst '{s}'"))?;
    Ok((ip, port))
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{AclAction, AclRule, AclTest};

    fn make_policy(rules: Vec<AclRule>, tests: Vec<AclTest>) -> AclPolicy {
        AclPolicy {
            rules,
            tests,
            ..Default::default()
        }
    }

    fn accept_rule(subject: &[&str], dst: &[&str], proto: Option<&str>) -> AclRule {
        AclRule {
            action: AclAction::Accept,
            subject: subject.iter().map(|s| s.to_string()).collect(),
            dst: dst.iter().map(|s| s.to_string()).collect(),
            proto: proto.map(str::to_owned),
        }
    }

    fn ctx(subject: Option<&str>, dst: &str, port: u16, proto: Protocol) -> AccessContext {
        let network = NetworkTuple::new(None, dst.parse().unwrap(), port, proto);
        match subject {
            Some(subject) => AccessContext::verified_subject(
                subject.to_owned(),
                network,
                SourceAssertion::External {
                    idp: "test".to_owned(),
                },
                TransportKind::Direct,
            ),
            None => AccessContext::unknown(network, TransportKind::Direct),
        }
    }

    // ── decision-log source anchoring ─────────────────────────────────────

    #[test]
    fn source_anchor_and_class_expose_client_wg_key() {
        let network = NetworkTuple::new(None, "10.0.1.5".parse().unwrap(), 443, Protocol::Tcp);
        let pubkey = [7u8; 32];
        let ctx = AccessContext::verified_subject(
            "machine:m-client".to_owned(),
            network.clone(),
            SourceAssertion::WgPeerKey { pubkey },
            TransportKind::WgRelay,
        );
        // The logged anchor must equal the bindings.wg_peer key encoding so an
        // operator can tie the decision back to the projected client binding.
        assert_eq!(ctx.source_anchor(), wg_peer_anchor(&pubkey));
        assert_eq!(ctx.source_class(), "client-wg-key");

        let terminate = AccessContext::verified_subject(
            "machine:m-client".to_owned(),
            network.clone(),
            SourceAssertion::Terminate {
                binding: TerminateBinding {
                    anchor: "sess-1".to_owned(),
                },
            },
            TransportKind::Terminate,
        );
        assert_eq!(terminate.source_anchor(), "sess-1");
        assert_eq!(terminate.source_class(), "terminate-binding");

        let unknown = AccessContext::unknown(network, TransportKind::Direct);
        assert_eq!(unknown.source_anchor(), "none");
        assert_eq!(unknown.source_class(), "unknown");
    }

    /// Decision-log transport labels must use the `LinkMode` wire vocabulary
    /// (`direct` | `terminate` | `wg-relay` | `wss-relay`) so an operator can
    /// correlate ACL decisions with link-mode configuration and signaling.
    #[test]
    fn transport_label_matches_link_mode_wire_names() {
        assert_eq!(TransportKind::Direct.label(), "direct");
        assert_eq!(TransportKind::Terminate.label(), "terminate");
        assert_eq!(TransportKind::WgRelay.label(), "wg-relay");
        assert_eq!(TransportKind::WssRelay.label(), "wss-relay");
        assert_eq!(TransportKind::Https.label(), "https");
    }

    // ── default deny ──────────────────────────────────────────────────────

    #[test]
    fn empty_policy_denies_everything() {
        let engine = AclEngine::load(make_policy(vec![], vec![])).unwrap();
        let d = engine.is_allowed(&ctx(Some("user:alice"), "192.168.1.1", 80, Protocol::Tcp));
        assert!(!d.allowed);
        assert!(d.matched_rule_index.is_none());
    }

    #[test]
    fn unknown_source_denies_even_wildcard_rule() {
        let engine = AclEngine::load(make_policy(
            vec![accept_rule(&["*"], &["*:*"], None)],
            vec![],
        ))
        .unwrap();
        assert!(
            !engine
                .is_allowed(&ctx(None, "5.6.7.8", 9999, Protocol::Udp))
                .allowed
        );
    }

    // ── subject and group matching ────────────────────────────────────────

    #[test]
    fn wildcard_rule_allows_any_verified_subject() {
        let engine = AclEngine::load(make_policy(
            vec![accept_rule(&["*"], &["*:*"], None)],
            vec![],
        ))
        .unwrap();
        assert!(
            engine
                .is_allowed(&ctx(Some("machine:peer"), "5.6.7.8", 9999, Protocol::Udp))
                .allowed
        );
    }

    #[test]
    fn group_rule_allows_expanded_member() {
        let mut policy = make_policy(
            vec![accept_rule(&["group:eng"], &["192.168.1.0/24:80"], None)],
            vec![],
        );
        policy
            .groups
            .insert("group:eng".to_owned(), vec!["user:alice".to_owned()]);
        let engine = AclEngine::load(policy).unwrap();

        assert!(
            engine
                .is_allowed(&ctx(Some("user:alice"), "192.168.1.5", 80, Protocol::Tcp))
                .allowed
        );
        assert!(
            !engine
                .is_allowed(&ctx(Some("user:bob"), "192.168.1.5", 80, Protocol::Tcp))
                .allowed
        );
    }

    // ── destination/protocol matching ─────────────────────────────────────

    #[test]
    fn cidr_rule_allows_in_range_denies_outside() {
        let engine = AclEngine::load(make_policy(
            vec![accept_rule(&["user:alice"], &["192.168.1.0/24:80"], None)],
            vec![],
        ))
        .unwrap();

        assert!(
            engine
                .is_allowed(&ctx(Some("user:alice"), "192.168.1.5", 80, Protocol::Tcp))
                .allowed
        );
        assert!(
            !engine
                .is_allowed(&ctx(Some("user:alice"), "192.168.2.5", 80, Protocol::Tcp))
                .allowed
        );
        assert!(
            !engine
                .is_allowed(&ctx(Some("user:alice"), "192.168.1.5", 443, Protocol::Tcp))
                .allowed
        );
    }

    #[test]
    fn host_alias_resolves_correctly() {
        let mut policy = make_policy(
            vec![accept_rule(
                &["machine:db-client"],
                &["db:5432"],
                Some("tcp"),
            )],
            vec![],
        );
        policy
            .hosts
            .insert("db".to_owned(), "192.168.1.10/32".to_owned());
        let engine = AclEngine::load(policy).unwrap();

        assert!(
            engine
                .is_allowed(&ctx(
                    Some("machine:db-client"),
                    "192.168.1.10",
                    5432,
                    Protocol::Tcp
                ))
                .allowed
        );
        assert!(
            !engine
                .is_allowed(&ctx(
                    Some("machine:db-client"),
                    "192.168.1.11",
                    5432,
                    Protocol::Tcp
                ))
                .allowed
        );
    }

    #[test]
    fn proto_tcp_rule_rejects_udp() {
        let engine = AclEngine::load(make_policy(
            vec![accept_rule(&["*"], &["*:80"], Some("tcp"))],
            vec![],
        ))
        .unwrap();

        assert!(
            engine
                .is_allowed(&ctx(Some("user:alice"), "5.6.7.8", 80, Protocol::Tcp))
                .allowed
        );
        assert!(
            !engine
                .is_allowed(&ctx(Some("user:alice"), "5.6.7.8", 80, Protocol::Udp))
                .allowed
        );
    }

    #[test]
    fn no_proto_rule_matches_tcp_and_udp() {
        let engine = AclEngine::load(make_policy(
            vec![accept_rule(&["*"], &["*:53"], None)],
            vec![],
        ))
        .unwrap();

        assert!(
            engine
                .is_allowed(&ctx(Some("user:alice"), "8.8.8.8", 53, Protocol::Tcp))
                .allowed
        );
        assert!(
            engine
                .is_allowed(&ctx(Some("user:alice"), "8.8.8.8", 53, Protocol::Udp))
                .allowed
        );
    }

    #[test]
    fn port_range_rule() {
        let engine = AclEngine::load(make_policy(
            vec![accept_rule(&["*"], &["*:8000-8999"], None)],
            vec![],
        ))
        .unwrap();

        assert!(
            engine
                .is_allowed(&ctx(Some("user:alice"), "5.6.7.8", 8080, Protocol::Tcp))
                .allowed
        );
        assert!(
            !engine
                .is_allowed(&ctx(Some("user:alice"), "5.6.7.8", 80, Protocol::Tcp))
                .allowed
        );
    }

    #[test]
    fn port_list_rule() {
        let engine = AclEngine::load(make_policy(
            vec![accept_rule(&["*"], &["*:80,443"], None)],
            vec![],
        ))
        .unwrap();

        assert!(
            engine
                .is_allowed(&ctx(Some("user:alice"), "5.6.7.8", 80, Protocol::Tcp))
                .allowed
        );
        assert!(
            engine
                .is_allowed(&ctx(Some("user:alice"), "5.6.7.8", 443, Protocol::Tcp))
                .allowed
        );
        assert!(
            !engine
                .is_allowed(&ctx(Some("user:alice"), "5.6.7.8", 8080, Protocol::Tcp))
                .allowed
        );
    }

    // ── priority ordering ─────────────────────────────────────────────────

    #[test]
    fn first_matching_rule_wins() {
        let engine = AclEngine::load(make_policy(
            vec![
                accept_rule(&["user:alice"], &["*:80"], None),
                accept_rule(&["*"], &["*:*"], None),
            ],
            vec![],
        ))
        .unwrap();

        let d = engine.is_allowed(&ctx(Some("user:alice"), "1.2.3.4", 80, Protocol::Tcp));
        assert!(d.allowed);
        assert_eq!(d.matched_rule_index, Some(0));

        let d2 = engine.is_allowed(&ctx(Some("user:bob"), "1.2.3.4", 9090, Protocol::Tcp));
        assert!(d2.allowed);
        assert_eq!(d2.matched_rule_index, Some(1));
    }

    // ── bindings and tests ────────────────────────────────────────────────

    #[test]
    fn bindings_resolve_subjects() {
        let mut policy = make_policy(vec![], vec![]);
        let pubkey = [7_u8; 32];
        policy
            .bindings
            .wg_peer
            .insert(wg_peer_anchor(&pubkey), "machine:peer".to_owned());
        policy
            .bindings
            .machine
            .insert("machine-1".to_owned(), "user:alice".to_owned());
        let engine = AclEngine::load(policy).unwrap();

        assert_eq!(
            engine.subject_for_wg_peer_key(&pubkey),
            Some("machine:peer")
        );
        assert_eq!(engine.subject_for_machine("machine-1"), Some("user:alice"));
    }

    #[test]
    fn builtin_tests_pass_on_valid_policy() {
        let policy = make_policy(
            vec![accept_rule(&["user:alice"], &["192.168.1.0/24:80"], None)],
            vec![
                AclTest {
                    subject: "user:alice".to_owned(),
                    dst: "192.168.1.5:80".to_owned(),
                    proto: None,
                    allow: true,
                },
                AclTest {
                    subject: "user:alice".to_owned(),
                    dst: "192.168.1.5:443".to_owned(),
                    proto: None,
                    allow: false,
                },
            ],
        );
        assert!(AclEngine::load(policy).is_ok());
    }

    #[test]
    fn builtin_tests_can_validate_udp_policy() {
        let policy = make_policy(
            vec![accept_rule(
                &["machine:peer"],
                &["192.168.1.0/24:53"],
                Some("udp"),
            )],
            vec![
                AclTest {
                    subject: "machine:peer".to_owned(),
                    dst: "192.168.1.5:53".to_owned(),
                    proto: Some("udp".to_owned()),
                    allow: true,
                },
                AclTest {
                    subject: "machine:peer".to_owned(),
                    dst: "192.168.1.5:53".to_owned(),
                    proto: Some("tcp".to_owned()),
                    allow: false,
                },
            ],
        );
        assert!(AclEngine::load(policy).is_ok());
    }

    #[test]
    fn builtin_tests_fail_returns_error() {
        let policy = make_policy(
            vec![],
            vec![AclTest {
                subject: "user:alice".to_owned(),
                dst: "192.168.1.5:80".to_owned(),
                proto: None,
                allow: true,
            }],
        );
        let err = AclEngine::load(policy).unwrap_err();
        assert!(matches!(err, crate::Error::TestsFailed { count: 1 }));
    }

    // ── invalid policy ────────────────────────────────────────────────────

    #[test]
    fn invalid_subject_in_rule_returns_error() {
        let engine = AclEngine::load(make_policy(
            vec![accept_rule(&["10.0.0.0/24"], &["*:80"], None)],
            vec![],
        ));
        assert!(engine.is_err());
    }

    #[test]
    fn invalid_host_alias_in_rule_returns_error() {
        let engine = AclEngine::load(make_policy(
            vec![accept_rule(&["user:alice"], &["does-not-exist:80"], None)],
            vec![],
        ));
        assert!(engine.is_err());
    }

    #[test]
    fn invalid_cidr_in_hosts_returns_error() {
        let mut policy = make_policy(vec![], vec![]);
        policy
            .hosts
            .insert("bad".to_owned(), "not-a-cidr".to_owned());
        assert!(AclEngine::load(policy).is_err());
    }
}
