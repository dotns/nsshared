//! Local deny-scope: a narrow post-filter applied after policy union-merge.
//!
//! The matching engine stays accept-only (see PLAN-018). Deny-scope instead
//! edits the text-form [`AclPolicy`] before it is handed to `AclEngine::load`,
//! removing destination CIDRs that the operator forbids, regardless of what
//! any NSD ships.
//!
//! Scope narrowing semantics:
//! - A rule whose destination CIDR is *fully covered* by a deny-scope entry is
//!   dropped entirely.
//! - A rule whose destination CIDR is disjoint from every deny-scope entry is
//!   untouched.
//! - A rule whose destination CIDR *partially overlaps* a deny-scope entry is
//!   rejected conservatively: it is dropped and surfaced in
//!   [`DenyScopeOutcome::dropped`] with reason `PartialOverlap`. We refuse to
//!   produce a subtly-wider-than-intended compiled rule by splitting the CIDR.
//! - Wildcard hosts (`*`) are always considered to overlap any deny-scope
//!   entry → dropped. If you want to allow `*:22`, encode it as an explicit
//!   CIDR instead.
//! - Host-alias destinations whose resolved CIDR overlaps a deny-scope entry
//!   are dropped with reason `HostAliasOverlap`.
//!
//! The protocol constraint narrows the filter: if a deny-scope entry sets
//! `proto = Some("tcp")`, it only affects rules whose effective proto is
//! `Some(Tcp)` or `None` (unspecified = both, which is narrowed by dropping
//! TCP — we keep the rule with an explicit `"udp"` proto if present).

use std::collections::HashMap;

use common::IpNet;
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::Error;
use crate::policy::{AclPolicy, AclRule};

/// Operator-authored deny-scope layer.
///
/// All fields are optional; an empty scope is a no-op.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct DenyScope {
    /// Destination CIDRs that rules must not accept traffic *to*.
    #[serde(default)]
    pub dst_cidr: Vec<String>,

    /// Optional protocol constraint; when `Some`, the scope only affects
    /// rules whose effective protocol overlaps this value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proto: Option<String>,
}

/// A rule that was stripped by the deny-scope post-filter.
#[derive(Debug, Clone)]
pub struct DroppedRule {
    /// Index into the *pre-filter* rule list.
    pub rule_index: usize,
    /// Copy of the dropped rule.
    pub rule: AclRule,
    /// Why the rule was dropped.
    pub reason: DropReason,
}

/// Why a rule was dropped by deny-scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DropReason {
    /// Rule's destination CIDR is fully covered by a deny-scope CIDR.
    DstFullyCovered { scope_cidr: String },
    /// Rule would match more than the deny-scope strips; we refuse to split.
    PartialOverlap { scope_cidr: String },
    /// Rule targets a wildcard host; treated as overlap with every scope entry.
    WildcardShadowed { scope_cidr: String },
    /// Rule references a host alias that resolves into the deny-scope CIDR.
    HostAliasOverlap { alias: String, scope_cidr: String },
}

/// Outcome of applying a [`DenyScope`] to an [`AclPolicy`].
#[derive(Debug, Clone, Default)]
pub struct DenyScopeOutcome {
    /// Rules removed by the filter.
    pub dropped: Vec<DroppedRule>,
}

/// Apply `scope` to `policy` in place. Returns a [`DenyScopeOutcome`] listing
/// every rule that was removed and why.
///
/// Returns `Error::InvalidCidr` if any of the scope CIDRs fail to parse — the
/// caller (merger) should surface this as a startup misconfiguration.
pub fn apply_deny_scope(
    policy: &mut AclPolicy,
    scope: &DenyScope,
) -> Result<DenyScopeOutcome, Error> {
    if scope.dst_cidr.is_empty() {
        return Ok(DenyScopeOutcome::default());
    }

    let dst_scope = parse_cidr_list(&scope.dst_cidr)?;
    let host_map = resolve_hosts(&policy.hosts)?;
    let proto_filter = scope.proto.clone();

    let mut dropped = Vec::new();
    let mut kept = Vec::with_capacity(policy.rules.len());

    for (idx, rule) in policy.rules.iter().enumerate() {
        if !proto_matches(proto_filter.as_deref(), rule.proto.as_deref()) {
            kept.push(rule.clone());
            continue;
        }

        if let Some(reason) = evaluate_rule_dst(rule, &dst_scope, &host_map) {
            warn!(
                rule_index = idx,
                ?reason,
                "deny-scope dropped rule by dst CIDR"
            );
            dropped.push(DroppedRule {
                rule_index: idx,
                rule: rule.clone(),
                reason,
            });
            continue;
        }

        kept.push(rule.clone());
    }

    policy.rules = kept;
    Ok(DenyScopeOutcome { dropped })
}

fn parse_cidr_list(list: &[String]) -> Result<Vec<(String, IpNet)>, Error> {
    list.iter()
        .map(|s| {
            let net = s.parse::<IpNet>().map_err(|e| Error::InvalidCidr {
                addr: s.clone(),
                reason: e.to_string(),
            })?;
            Ok((s.clone(), net))
        })
        .collect()
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

fn proto_matches(scope: Option<&str>, rule: Option<&str>) -> bool {
    match (scope, rule) {
        (None, _) => true,       // scope covers all protocols
        (Some(_), None) => true, // rule is proto-agnostic → overlaps
        (Some(s), Some(r)) => s.eq_ignore_ascii_case(r),
    }
}

/// Check a rule's destination list against the deny-scope dst cidrs.
fn evaluate_rule_dst(
    rule: &AclRule,
    scope: &[(String, IpNet)],
    host_map: &HashMap<String, IpNet>,
) -> Option<DropReason> {
    if scope.is_empty() {
        return None;
    }
    for dst in &rule.dst {
        let host_part = dst.rsplit_once(':').map(|(h, _)| h).unwrap_or(dst.as_str());
        if host_part == "*"
            && let Some((cidr, _)) = scope.first()
        {
            return Some(DropReason::WildcardShadowed {
                scope_cidr: cidr.clone(),
            });
        }
        if let Ok(net) = host_part.parse::<IpNet>() {
            if let Some(r) = classify(net, scope, DropSide::Dst) {
                return Some(r);
            }
            continue;
        }
        if let Some(alias_net) = host_map.get(host_part)
            && let Some((cidr, scope_net)) = scope.iter().find(|(_, s)| overlaps(*alias_net, *s))
        {
            if contains(*scope_net, *alias_net) {
                return Some(DropReason::HostAliasOverlap {
                    alias: host_part.to_owned(),
                    scope_cidr: cidr.clone(),
                });
            }
            return Some(DropReason::PartialOverlap {
                scope_cidr: cidr.clone(),
            });
        }
    }
    None
}

enum DropSide {
    Dst,
}

fn classify(rule_net: IpNet, scope: &[(String, IpNet)], side: DropSide) -> Option<DropReason> {
    for (cidr, scope_net) in scope {
        if !overlaps(rule_net, *scope_net) {
            continue;
        }
        if contains(*scope_net, rule_net) {
            return Some(match side {
                DropSide::Dst => DropReason::DstFullyCovered {
                    scope_cidr: cidr.clone(),
                },
            });
        }
        return Some(DropReason::PartialOverlap {
            scope_cidr: cidr.clone(),
        });
    }
    None
}

/// Does `outer` contain `inner` (every address of `inner` is in `outer`)?
fn contains(outer: IpNet, inner: IpNet) -> bool {
    match (outer, inner) {
        (IpNet::V4(o), IpNet::V4(i)) => {
            o.prefix_len() <= i.prefix_len() && o.contains(&i.network())
        }
        (IpNet::V6(o), IpNet::V6(i)) => {
            o.prefix_len() <= i.prefix_len() && o.contains(&i.network())
        }
        _ => false,
    }
}

fn overlaps(a: IpNet, b: IpNet) -> bool {
    contains(a, b) || contains(b, a)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{AclAction, AclRule};

    fn rule(subject: &[&str], dst: &[&str], proto: Option<&str>) -> AclRule {
        AclRule {
            action: AclAction::Accept,
            subject: subject.iter().map(|s| s.to_string()).collect(),
            dst: dst.iter().map(|s| s.to_string()).collect(),
            proto: proto.map(str::to_owned),
        }
    }

    fn policy_of(rules: Vec<AclRule>) -> AclPolicy {
        AclPolicy {
            hosts: HashMap::new(),
            rules,
            ..Default::default()
        }
    }

    #[test]
    fn empty_scope_is_noop() {
        let mut p = policy_of(vec![rule(&["*"], &["*:*"], None)]);
        let out = apply_deny_scope(&mut p, &DenyScope::default()).unwrap();
        assert!(out.dropped.is_empty());
        assert_eq!(p.rules.len(), 1);
    }

    #[test]
    fn wildcard_dst_is_dropped() {
        let mut p = policy_of(vec![rule(&["*"], &["*:80"], None)]);
        let scope = DenyScope {
            dst_cidr: vec!["10.255.0.0/16".to_owned()],
            ..Default::default()
        };
        let out = apply_deny_scope(&mut p, &scope).unwrap();
        assert_eq!(out.dropped.len(), 1);
        assert!(p.rules.is_empty());
        assert!(matches!(
            out.dropped[0].reason,
            DropReason::WildcardShadowed { .. }
        ));
    }

    #[test]
    fn cidr_contained_by_scope_is_dropped() {
        let mut p = policy_of(vec![rule(&["*"], &["10.255.1.0/24:80"], None)]);
        let scope = DenyScope {
            dst_cidr: vec!["10.255.0.0/16".to_owned()],
            ..Default::default()
        };
        let out = apply_deny_scope(&mut p, &scope).unwrap();
        assert_eq!(out.dropped.len(), 1);
        assert!(matches!(
            out.dropped[0].reason,
            DropReason::DstFullyCovered { .. }
        ));
        assert!(p.rules.is_empty());
    }

    #[test]
    fn disjoint_cidr_is_kept() {
        let mut p = policy_of(vec![rule(&["*"], &["10.0.0.0/24:80"], None)]);
        let scope = DenyScope {
            dst_cidr: vec!["10.255.0.0/16".to_owned()],
            ..Default::default()
        };
        let out = apply_deny_scope(&mut p, &scope).unwrap();
        assert!(out.dropped.is_empty());
        assert_eq!(p.rules.len(), 1);
    }

    #[test]
    fn partial_overlap_is_dropped_not_split() {
        let mut p = policy_of(vec![rule(&["*"], &["10.0.0.0/8:80"], None)]);
        let scope = DenyScope {
            dst_cidr: vec!["10.255.0.0/16".to_owned()],
            ..Default::default()
        };
        let out = apply_deny_scope(&mut p, &scope).unwrap();
        assert_eq!(out.dropped.len(), 1);
        assert!(matches!(
            out.dropped[0].reason,
            DropReason::PartialOverlap { .. }
        ));
        assert!(p.rules.is_empty());
    }

    #[test]
    fn host_alias_overlap_is_dropped() {
        let mut p = policy_of(vec![rule(&["*"], &["mgmt:22"], Some("tcp"))]);
        p.hosts
            .insert("mgmt".to_owned(), "10.255.5.0/24".to_owned());
        let scope = DenyScope {
            dst_cidr: vec!["10.255.0.0/16".to_owned()],
            ..Default::default()
        };
        let out = apply_deny_scope(&mut p, &scope).unwrap();
        assert_eq!(out.dropped.len(), 1);
        assert!(matches!(
            out.dropped[0].reason,
            DropReason::HostAliasOverlap { .. }
        ));
    }

    #[test]
    fn proto_filter_narrows_scope() {
        // scope only affects tcp rules; udp rule survives.
        let mut p = policy_of(vec![
            rule(&["*"], &["10.255.0.0/24:53"], Some("udp")),
            rule(&["*"], &["10.255.0.0/24:80"], Some("tcp")),
        ]);
        let scope = DenyScope {
            dst_cidr: vec!["10.255.0.0/16".to_owned()],
            proto: Some("tcp".to_owned()),
        };
        let out = apply_deny_scope(&mut p, &scope).unwrap();
        assert_eq!(out.dropped.len(), 1);
        assert_eq!(p.rules.len(), 1);
        assert_eq!(p.rules[0].proto.as_deref(), Some("udp"));
    }

    #[test]
    fn invalid_scope_cidr_is_error() {
        let mut p = policy_of(vec![rule(&["*"], &["*:*"], None)]);
        let scope = DenyScope {
            dst_cidr: vec!["not-a-cidr".to_owned()],
            ..Default::default()
        };
        assert!(apply_deny_scope(&mut p, &scope).is_err());
    }
}
