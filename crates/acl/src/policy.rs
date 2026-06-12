use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};

/// The complete subject ACL policy document.
#[derive(Debug, Clone, Deserialize, Serialize, Default, PartialEq, Eq)]
pub struct AclPolicy {
    /// Named destination host aliases mapping to CIDR strings.
    ///
    /// This remains destination-only shorthand. Source authorization is always
    /// driven by [`AclRule::subject`], never by an IP or host alias.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub hosts: HashMap<String, String>,

    /// Accept-only access control rules evaluated in order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<AclRule>,

    /// Expanded group membership shipped by NSD.
    ///
    /// Keys and values are canonical subjects such as `group:eng` and
    /// `user:alice`. A rule that names a group matches a verified subject when
    /// that subject appears in the expanded group member list.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub groups: BTreeMap<String, Vec<String>>,

    /// Wire-anchor bindings used by data planes before building an
    /// [`crate::AccessContext`].
    #[serde(default, skip_serializing_if = "AclBindings::is_empty")]
    pub bindings: AclBindings,

    /// Gateway WG public keys used by NSN to classify gateway peers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gateway_roster: Vec<String>,

    /// Subject-blind NSN service-floor metadata.
    ///
    /// Runtime enforcement uses the local `services.toml` floor; this wire
    /// field records the NSD-projected view for observability and merge state.
    #[serde(default, skip_serializing_if = "ServiceFloor::is_empty")]
    pub service_floor: ServiceFloor,

    /// Built-in validation tests run when the policy is loaded.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tests: Vec<AclTest>,
}

/// Anchor-to-subject bindings carried in `acl_config`.
#[derive(Debug, Clone, Deserialize, Serialize, Default, PartialEq, Eq)]
pub struct AclBindings {
    /// Base64 or hex WireGuard peer public key to canonical subject.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub wg_peer: BTreeMap<String, String>,

    /// Machine/session identifier to canonical subject.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub machine: BTreeMap<String, String>,
}

impl AclBindings {
    /// `true` when no binding is present.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.wg_peer.is_empty() && self.machine.is_empty()
    }
}

/// Service-floor data carried in `acl_config`.
#[derive(Debug, Clone, Deserialize, Serialize, Default, PartialEq, Eq)]
pub struct ServiceFloor {
    /// Enabled service names from the NSD-projected floor view.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub enabled: Vec<String>,

    /// Reserved floor deny entries from the NSD-projected floor view.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny_scope: Vec<String>,
}

impl ServiceFloor {
    /// `true` when the floor has no wire data.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.enabled.is_empty() && self.deny_scope.is_empty()
    }
}

/// A single subject ACL rule. Action is always `accept`; there are no deny
/// rules.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct AclRule {
    /// Must be `accept`; deny rules are not supported.
    pub action: AclAction,

    /// Source subjects: `*` for any verified subject, or canonical subject
    /// identifiers such as `user:alice`, `group:eng`, and `machine:m-1`.
    pub subject: Vec<String>,

    /// Destination matchers in `host:ports` format, e.g.
    /// `*:*`, `db:5432`, `web:80,443`, `web:8000-8999`.
    pub dst: Vec<String>,

    /// Optional protocol filter: `"tcp"` or `"udp"`.
    /// When absent the rule matches both protocols.
    #[serde(default)]
    pub proto: Option<String>,
}

/// The only valid rule action.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AclAction {
    Accept,
}

/// A built-in policy test assertion.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct AclTest {
    /// Verified source subject to evaluate.
    pub subject: String,

    /// Destination in `"ip:port"` format.
    pub dst: String,

    /// Protocol to evaluate for this assertion: `"tcp"` or `"udp"`.
    /// Defaults to TCP for backwards compatibility with existing test rows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proto: Option<String>,

    /// Expected result: `true` means the connection should be allowed.
    pub allow: bool,
}

/// A lint finding about a policy issue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyLint {
    /// Zero-based index into [`AclPolicy::rules`] identifying the rule.
    pub rule_index: usize,
    /// Machine-readable identifier.
    pub code: &'static str,
    /// Human-readable description of the issue and mitigation.
    pub message: String,
}

impl AclPolicy {
    /// Subject ACLs no longer depend on WSS source-IP metadata. Kept as a
    /// no-op for callers that still surface the old lint while they migrate.
    #[must_use]
    pub fn lint_wss_src_ignored(&self) -> Vec<PolicyLint> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_deserializes_with_defaults() {
        let json = r#"{"rules": []}"#;
        let policy: AclPolicy = serde_json::from_str(json).unwrap();
        assert!(policy.hosts.is_empty());
        assert!(policy.rules.is_empty());
        assert!(policy.groups.is_empty());
        assert!(policy.bindings.is_empty());
        assert!(policy.gateway_roster.is_empty());
        assert!(policy.service_floor.is_empty());
        assert!(policy.tests.is_empty());
    }

    #[test]
    fn policy_round_trips_full_example() {
        let json = r#"{
            "hosts": { "db": "192.168.1.10/32" },
            "rules": [
                {
                    "action": "accept",
                    "subject": ["group:eng"],
                    "dst": ["db:5432"],
                    "proto": "tcp"
                }
            ],
            "groups": { "group:eng": ["user:alice"] },
            "bindings": {
                "wg_peer": { "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=": "user:alice" },
                "machine": { "m-alice": "user:alice" }
            },
            "gateway_roster": ["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb="],
            "service_floor": { "enabled": ["db"], "deny_scope": [] },
            "tests": [
                { "subject": "user:alice", "dst": "192.168.1.10:5432", "proto": "tcp", "allow": true }
            ]
        }"#;
        let policy: AclPolicy = serde_json::from_str(json).unwrap();
        assert_eq!(policy.hosts.len(), 1);
        assert_eq!(policy.rules.len(), 1);
        assert_eq!(policy.rules[0].action, AclAction::Accept);
        assert_eq!(policy.groups["group:eng"], vec!["user:alice"]);
        assert_eq!(policy.tests.len(), 1);
        assert!(policy.tests[0].allow);

        let re: AclPolicy = serde_json::from_str(&serde_json::to_string(&policy).unwrap()).unwrap();
        assert_eq!(re.rules[0].proto, Some("tcp".to_owned()));
        assert_eq!(re.tests[0].proto, Some("tcp".to_owned()));
    }

    #[test]
    fn acl_action_rejects_unknown_variant() {
        let json = r#"{"action":"deny","subject":["*"],"dst":["*:*"]}"#;
        assert!(serde_json::from_str::<AclRule>(json).is_err());
    }
}
