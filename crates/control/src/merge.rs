#![forbid(unsafe_code)]

//! Policy merge helpers for multi-NSD operation.
//!
//! When NSN connects to multiple control centers (NSDs), each may deliver its
//! own `WgConfig`, `ProxyConfig`, and `AclConfig`. These helpers merge them
//! into a single effective configuration.
//!
//! **AclConfig merge (PLAN-020).** The merge is now a **layered union**:
//! - Every NSD's effective policy contributes rules/hosts/tests to the output.
//! - Per-NSD state is tracked as [`AclPayload`]; `ExplicitEmpty` skips the NSD
//!   but does not narrow the merge; `FetchFailed` falls back to the last-good
//!   cache, or, if no cache exists, marks the merge `degraded`.
//! - A local policy contributes at the front of the accept list and may carry
//!   a `deny_scope` that narrows the merged output.
//! - The heavy lifting (dedup, provenance, post-filter) lives in
//!   [`acl::merge::merge_layered`]; this module is the control-plane adaptor
//!   that translates per-NSD envelopes into that API.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::Instant;

use acl::{DenyScope, MergedPolicy, PolicyLayers, RemotePolicy};
use serde::Serialize;

use common::Protocol;

use crate::messages::{AclPayload, PeerConfig, PortMapping, ProxyConfig, SubnetRule, WgConfig};

// ── WgConfig merge ────────────────────────────────────────────────────────────

/// Merge multiple `WgConfig` values into one.
///
/// Uses the `ip_address` and `listen_port` from the first config.
/// Collects all peers across all configs and deduplicates by `public_key`.
///
/// Returns `None` if `configs` is empty.
pub fn merge_wg_configs(configs: &[WgConfig]) -> Option<WgConfig> {
    let base = configs.first()?;
    let mut seen_keys: HashSet<[u8; 32]> = HashSet::new();
    let mut peers: Vec<PeerConfig> = Vec::new();

    for cfg in configs {
        for peer in &cfg.peers {
            if seen_keys.insert(peer.public_key) {
                peers.push(peer.clone());
            }
        }
    }

    Some(WgConfig {
        ip_address: base.ip_address,
        listen_port: base.listen_port,
        peers,
    })
}

// ── ProxyConfig merge ─────────────────────────────────────────────────────────

/// Merge multiple `ProxyConfig` values into one.
pub fn merge_proxy_configs(configs: &[ProxyConfig]) -> Option<ProxyConfig> {
    let base = configs.first()?;
    let mut seen_ids: HashSet<String> = HashSet::new();
    let mut rules: Vec<SubnetRule> = Vec::new();
    let mut seen_listen: HashSet<(u16, Protocol)> = HashSet::new();
    let mut port_mappings: Vec<PortMapping> = Vec::new();

    for cfg in configs {
        for rule in &cfg.rules {
            if seen_ids.insert(rule.resource_id.clone()) {
                rules.push(rule.clone());
            }
        }
        for mapping in &cfg.port_mappings {
            // Deduplicate by (listen_port, protocol) — the listener is the
            // collision key, mirroring the `resource_id` dedup policy used
            // for rules so first-config-wins under multi-NSD overlap.
            if seen_listen.insert((mapping.listen_port, mapping.protocol)) {
                port_mappings.push(mapping.clone());
            }
        }
    }

    Some(ProxyConfig {
        chain_id: base.chain_id.clone(),
        rules,
        port_mappings,
    })
}

// ── Per-NSD ACL slot (PLAN-020) ───────────────────────────────────────────────

/// Per-NSD ACL entry: latest payload plus last-good cache.
///
/// `latest` is whatever NSN last received (may be `FetchFailed`).
/// `last_good` retains the last successfully-loaded or explicit-empty payload
/// so transient failures do not collapse the merged policy.
#[derive(Debug, Clone)]
pub struct NsdAclSlot {
    pub latest: AclPayload,
    pub last_good: Option<AclPayload>,
    pub last_good_at: Option<Instant>,
    pub updated_at: Instant,
}

impl NsdAclSlot {
    /// Initialise a slot with a fresh payload.
    pub fn new(payload: AclPayload) -> Self {
        let now = Instant::now();
        let (last_good, last_good_at) = match &payload {
            AclPayload::Loaded { .. } | AclPayload::ExplicitEmpty => {
                (Some(payload.clone()), Some(now))
            }
            AclPayload::FetchFailed { .. } => (None, None),
        };
        Self {
            latest: payload,
            last_good,
            last_good_at,
            updated_at: now,
        }
    }

    /// Apply a new payload, rotating last-good as appropriate.
    pub fn update(&mut self, payload: AclPayload) {
        self.updated_at = Instant::now();
        match &payload {
            AclPayload::Loaded { .. } | AclPayload::ExplicitEmpty => {
                self.last_good = Some(payload.clone());
                self.last_good_at = Some(self.updated_at);
            }
            AclPayload::FetchFailed { .. } => {}
        }
        self.latest = payload;
    }

    /// Returns the policy NSN should use for this slot under the merge
    /// policy, plus whether it was pulled from `last_good` cache.
    ///
    /// - `Loaded(p)` → `(Some(p), cached=false)`
    /// - `ExplicitEmpty` → `(None, cached=false)` (contributes nothing)
    /// - `FetchFailed`  with fresh cache → use cached policy; `cached=true`
    /// - `FetchFailed`  with stale / no cache → `(None, cached=false)`;
    ///   caller must set `degraded = true`.
    pub fn effective(&self, max_age: Option<std::time::Duration>) -> EffectiveAcl<'_> {
        match &self.latest {
            AclPayload::Loaded { policy } => EffectiveAcl::Live(policy.as_ref()),
            AclPayload::ExplicitEmpty => EffectiveAcl::EmptyExplicit,
            AclPayload::FetchFailed { .. } => {
                if let (Some(AclPayload::Loaded { policy }), Some(at)) =
                    (self.last_good.as_ref(), self.last_good_at)
                    && max_age.is_none_or(|m| at.elapsed() <= m)
                {
                    return EffectiveAcl::Cached(policy.as_ref());
                }
                if let (Some(AclPayload::ExplicitEmpty), Some(at)) =
                    (self.last_good.as_ref(), self.last_good_at)
                    && max_age.is_none_or(|m| at.elapsed() <= m)
                {
                    return EffectiveAcl::EmptyExplicit;
                }
                EffectiveAcl::Degraded
            }
        }
    }
}

/// Per-NSD effective payload after applying last-good cache rules.
#[derive(Debug)]
pub enum EffectiveAcl<'a> {
    /// NSD is healthy; this is the live policy.
    Live(&'a acl::AclPolicy),
    /// NSD is failed but the last-good cache still applies.
    Cached(&'a acl::AclPolicy),
    /// NSD explicitly published an empty policy (live or cached).
    EmptyExplicit,
    /// NSD failed and no usable cache is available.
    Degraded,
}

// ── NsdConfigStore ────────────────────────────────────────────────────────────

/// Tracks the latest config received from each NSD plus the local ACL layer.
#[derive(Default)]
pub struct NsdConfigStore {
    pub wg: HashMap<String, WgConfig>,
    pub proxy: HashMap<String, ProxyConfig>,
    /// Per-NSD ACL state with last-good cache.
    pub acl: HashMap<String, NsdAclSlot>,
    /// Operator-authored local ACL layer (from `acls.toml`).
    pub local_acl: Option<acl::AclPolicy>,
    /// Operator-authored deny-scope filter.
    pub deny_scope: Option<DenyScope>,
    /// Maximum age of a `last_good` cache before it is treated as degraded.
    pub last_good_max_age: Option<std::time::Duration>,
}

impl NsdConfigStore {
    /// Install or replace the local ACL layer.
    pub fn set_local_acl(&mut self, policy: Option<acl::AclPolicy>) {
        self.local_acl = policy;
    }

    /// Install or replace the deny-scope filter.
    pub fn set_deny_scope(&mut self, scope: Option<DenyScope>) {
        self.deny_scope = scope;
    }

    /// Ingest a new per-NSD ACL payload, rotating last-good automatically.
    pub fn upsert_acl(&mut self, nsd_id: impl Into<String>, payload: AclPayload) {
        let id = nsd_id.into();
        match self.acl.get_mut(&id) {
            Some(slot) => slot.update(payload),
            None => {
                self.acl.insert(id, NsdAclSlot::new(payload));
            }
        }
    }

    /// Merge all stored WgConfigs.
    pub fn merged_wg(&self) -> Option<WgConfig> {
        let configs: Vec<_> = self.wg.values().cloned().collect();
        merge_wg_configs(&configs)
    }

    /// Merge all stored ProxyConfigs.
    pub fn merged_proxy(&self) -> Option<ProxyConfig> {
        let configs: Vec<_> = self.proxy.values().cloned().collect();
        merge_proxy_configs(&configs)
    }

    /// Merge all stored ACL payloads plus the local layer into a single
    /// [`MergedPolicy`]. Returns `None` only when the store has absolutely no
    /// ACL input at all (no local layer, no NSD slots) — i.e. startup before
    /// the first SSE frame arrives.
    pub fn merged_acl(&self) -> Option<MergedPolicy> {
        if self.acl.is_empty() && self.local_acl.is_none() {
            return None;
        }

        let mut remote: Vec<RemotePolicy<'_>> = Vec::new();
        let mut degraded = false;

        // Gather per-NSD effective payloads in id order so the merge output
        // is deterministic.
        let mut ordered: Vec<(&String, &NsdAclSlot)> = self.acl.iter().collect();
        ordered.sort_by(|a, b| a.0.cmp(b.0));

        for (id, slot) in ordered {
            match slot.effective(self.last_good_max_age) {
                EffectiveAcl::Live(policy) => remote.push(RemotePolicy {
                    nsd_id: id.as_str(),
                    policy,
                    cached: false,
                }),
                EffectiveAcl::Cached(policy) => {
                    remote.push(RemotePolicy {
                        nsd_id: id.as_str(),
                        policy,
                        cached: true,
                    });
                    degraded = true;
                }
                EffectiveAcl::EmptyExplicit => {
                    // contributes nothing; does not narrow or degrade
                }
                EffectiveAcl::Degraded => {
                    degraded = true;
                }
            }
        }

        let layers = PolicyLayers {
            local: self.local_acl.as_ref(),
            remote,
            deny_scope: self.deny_scope.as_ref(),
            degraded,
        };
        Some(acl::merge_layered(layers))
    }

    /// Compute the observability snapshot for the current merge state.
    pub fn acl_source_snapshot(&self) -> AclSourceSnapshot {
        let mut snapshot = AclSourceSnapshot::default();
        if let Some(local) = &self.local_acl {
            snapshot.rule_count_local = local.rules.len();
        }
        if let Some(merged) = self.merged_acl() {
            snapshot.degraded = merged.degraded;
            snapshot.dropped_by_deny_scope = merged.dropped_by_deny_scope.len();
            for (nsd, count) in merged.stats.remote {
                snapshot.rule_count_remote.insert(nsd, count);
            }
        }
        // `rule_count_cached` reports each NSD's *retained* last-known-good
        // policy size, read straight from the slot rather than from the merged
        // dedup stats. When a remote is `FetchFailed` and serving from cache,
        // operators must be able to see that the NSD still has a usable
        // last-good layer (and how large it is) even when those rules overlap a
        // still-live peer NSD and would otherwise dedup away in the union merge.
        // This is observability readback only; it does not change which policy
        // is served.
        for (id, slot) in &self.acl {
            if let EffectiveAcl::Cached(policy) = slot.effective(self.last_good_max_age) {
                snapshot
                    .rule_count_cached
                    .insert(id.clone(), policy.rules.len());
            }
            snapshot
                .per_nsd_state
                .insert(id.clone(), slot.latest.label());
        }
        snapshot
    }
}

// ── legacy AclMergeConflict (deprecated; superseded by AclSourceSnapshot) ────

/// **Deprecated** — under PLAN-020 union merge there is no intersection drift
/// to report. The struct is kept for one release so existing dashboards and
/// `/healthz` handlers continue to compile; the merger now always publishes
/// an all-zero summary here.
#[derive(Debug, Clone, Default, Serialize)]
pub struct AclMergeConflict {
    pub nsd_count: usize,
    pub dropped_hosts: usize,
    pub dropped_rules: usize,
    pub dropped_tests: usize,
    pub per_nsd: BTreeMap<String, PerNsdContribution>,
}

impl AclMergeConflict {
    pub fn has_conflict(&self) -> bool {
        self.dropped_hosts + self.dropped_rules + self.dropped_tests > 0
    }
}

/// **Deprecated** — see [`AclMergeConflict`].
#[derive(Debug, Clone, Default, Serialize)]
pub struct PerNsdContribution {
    pub hosts_total: usize,
    pub rules_total: usize,
    pub tests_total: usize,
    pub hosts_dropped: usize,
    pub rules_dropped: usize,
    pub tests_dropped: usize,
}

impl NsdConfigStore {
    /// **Deprecated** — under union merge there is no intersection drift.
    /// Always returns an all-zero summary sized by the current NSD count.
    pub fn acl_merge_conflict(&self) -> AclMergeConflict {
        AclMergeConflict {
            nsd_count: self.acl.len(),
            ..Default::default()
        }
    }
}

// ── AclSourceSnapshot ────────────────────────────────────────────────────────

/// Observability snapshot for the current merge state (PLAN-020 §8).
#[derive(Debug, Clone, Default, Serialize)]
pub struct AclSourceSnapshot {
    pub degraded: bool,
    pub rule_count_local: usize,
    pub rule_count_remote: BTreeMap<String, usize>,
    pub rule_count_cached: BTreeMap<String, usize>,
    pub dropped_by_deny_scope: usize,
    pub per_nsd_state: BTreeMap<String, &'static str>,
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use acl::{AclPolicy, policy::AclAction, policy::AclRule};

    use crate::messages::{
        AclConfig, PeerConfig, ProxyConfig, RewriteTarget, SubnetRule, WgConfig,
    };
    use common::Protocol;

    use super::*;

    fn peer(key_byte: u8, port: u16) -> PeerConfig {
        PeerConfig {
            public_key: [key_byte; 32],
            endpoint: Some(SocketAddr::from(([127, 0, 0, 1], port))),
            allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
            persistent_keepalive: 25,
            wss_relay: None,
            wss_relay_fallback: None,
        }
    }

    fn base_wg(ip_last: u8, peers: Vec<PeerConfig>) -> WgConfig {
        WgConfig {
            ip_address: Ipv4Addr::new(10, 0, 0, ip_last),
            listen_port: 51820,
            peers,
        }
    }

    fn proxy_rule(resource_id: &str) -> SubnetRule {
        SubnetRule {
            resource_id: resource_id.to_string(),
            source_prefix: "10.0.0.0/24".parse().unwrap(),
            dest_prefix: "192.168.1.0/24".parse().unwrap(),
            rewrite_to: RewriteTarget::Ip("192.168.1.10".parse().unwrap()),
            port_range: Some((80, 80)),
            protocol: Protocol::Tcp,
        }
    }

    fn proxy_cfg(chain_id: &str, rules: Vec<SubnetRule>) -> ProxyConfig {
        ProxyConfig {
            chain_id: chain_id.to_string(),
            rules,
            port_mappings: vec![],
        }
    }

    fn acl_rule(subject: &str, dst: &str) -> AclRule {
        AclRule {
            action: AclAction::Accept,
            subject: vec![subject.to_string()],
            dst: vec![dst.to_string()],
            proto: None,
        }
    }

    fn policy_with(rules: Vec<AclRule>) -> AclPolicy {
        AclPolicy {
            hosts: Default::default(),
            rules,
            ..Default::default()
        }
    }

    // ── merge_wg_configs ──────────────────────────────────────────────────────

    #[test]
    fn wg_merge_empty_returns_none() {
        assert!(merge_wg_configs(&[]).is_none());
    }

    #[test]
    fn wg_merge_union_of_peers() {
        let c1 = base_wg(1, vec![peer(1, 51820), peer(2, 51821)]);
        let c2 = base_wg(1, vec![peer(3, 51822)]);
        let merged = merge_wg_configs(&[c1, c2]).unwrap();
        assert_eq!(merged.peers.len(), 3);
    }

    #[test]
    fn wg_merge_deduplicates_by_public_key() {
        let c1 = base_wg(1, vec![peer(1, 51820)]);
        let c2 = base_wg(1, vec![peer(1, 51821)]);
        let merged = merge_wg_configs(&[c1, c2]).unwrap();
        assert_eq!(merged.peers.len(), 1);
        assert_eq!(merged.peers[0].endpoint.unwrap().port(), 51820);
    }

    // ── merge_proxy_configs ───────────────────────────────────────────────────

    #[test]
    fn proxy_merge_union_of_rules() {
        let c1 = proxy_cfg("chain-1", vec![proxy_rule("r1"), proxy_rule("r2")]);
        let c2 = proxy_cfg("chain-2", vec![proxy_rule("r3")]);
        let merged = merge_proxy_configs(&[c1, c2]).unwrap();
        assert_eq!(merged.chain_id, "chain-1");
        assert_eq!(merged.rules.len(), 3);
    }

    // ── NsdAclSlot ────────────────────────────────────────────────────────────

    #[test]
    fn slot_new_from_loaded_records_last_good() {
        let slot = NsdAclSlot::new(AclPayload::loaded(policy_with(vec![acl_rule(
            "user:alice",
            "*:80",
        )])));
        assert!(slot.last_good.is_some());
        assert!(slot.last_good_at.is_some());
    }

    #[test]
    fn slot_new_from_failed_has_no_cache() {
        let slot = NsdAclSlot::new(AclPayload::FetchFailed {
            error: "down".into(),
        });
        assert!(slot.last_good.is_none());
    }

    #[test]
    fn slot_transition_to_failed_preserves_last_good() {
        let mut slot = NsdAclSlot::new(AclPayload::loaded(policy_with(vec![acl_rule(
            "user:alice",
            "*:80",
        )])));
        slot.update(AclPayload::FetchFailed {
            error: "boom".into(),
        });
        assert!(matches!(slot.latest, AclPayload::FetchFailed { .. }));
        assert!(slot.last_good.is_some());
    }

    #[test]
    fn slot_effective_uses_cache_under_failure() {
        let mut slot = NsdAclSlot::new(AclPayload::loaded(policy_with(vec![acl_rule(
            "user:alice",
            "*:80",
        )])));
        slot.update(AclPayload::FetchFailed {
            error: "boom".into(),
        });
        let eff = slot.effective(None);
        assert!(matches!(eff, EffectiveAcl::Cached(_)));
    }

    #[test]
    fn slot_effective_degraded_without_cache() {
        let slot = NsdAclSlot::new(AclPayload::FetchFailed {
            error: "boom".into(),
        });
        let eff = slot.effective(None);
        assert!(matches!(eff, EffectiveAcl::Degraded));
    }

    #[test]
    fn slot_effective_cache_expires_with_max_age() {
        use std::time::Duration;
        let mut slot = NsdAclSlot::new(AclPayload::loaded(policy_with(vec![acl_rule(
            "user:alice",
            "*:80",
        )])));
        slot.update(AclPayload::FetchFailed {
            error: "boom".into(),
        });
        // Force last_good_at to be in the past.
        slot.last_good_at = Some(std::time::Instant::now() - Duration::from_secs(3600));
        let eff = slot.effective(Some(Duration::from_secs(60)));
        assert!(matches!(eff, EffectiveAcl::Degraded));
    }

    // ── merged_acl (store) ────────────────────────────────────────────────────

    #[test]
    fn store_merged_acl_none_when_empty_and_no_local() {
        let store = NsdConfigStore::default();
        assert!(store.merged_acl().is_none());
    }

    #[test]
    fn store_merged_acl_unions_across_nsds() {
        let mut store = NsdConfigStore::default();
        store.upsert_acl(
            "nsd-1",
            AclPayload::loaded(policy_with(vec![acl_rule("user:alice", "*:80")])),
        );
        store.upsert_acl(
            "nsd-2",
            AclPayload::loaded(policy_with(vec![acl_rule("user:bob", "*:443")])),
        );
        let merged = store.merged_acl().unwrap();
        assert_eq!(merged.policy.rules.len(), 2);
        assert!(!merged.degraded);
    }

    #[test]
    fn store_merged_acl_honours_explicit_empty() {
        let mut store = NsdConfigStore::default();
        store.upsert_acl(
            "nsd-1",
            AclPayload::loaded(policy_with(vec![acl_rule("user:alice", "*:80")])),
        );
        store.upsert_acl("nsd-2", AclPayload::ExplicitEmpty);
        let merged = store.merged_acl().unwrap();
        assert_eq!(merged.policy.rules.len(), 1);
        assert!(!merged.degraded);
    }

    #[test]
    fn store_merged_acl_fetch_failed_uses_cache() {
        let mut store = NsdConfigStore::default();
        store.upsert_acl(
            "nsd-1",
            AclPayload::loaded(policy_with(vec![acl_rule("user:alice", "*:80")])),
        );
        store.upsert_acl(
            "nsd-1",
            AclPayload::FetchFailed {
                error: "boom".into(),
            },
        );
        let merged = store.merged_acl().unwrap();
        assert_eq!(merged.policy.rules.len(), 1);
        assert!(merged.degraded);
        assert_eq!(merged.stats.cached.get("nsd-1"), Some(&1));
    }

    #[test]
    fn store_merged_acl_fetch_failed_no_cache_degrades() {
        let mut store = NsdConfigStore::default();
        store.upsert_acl(
            "nsd-1",
            AclPayload::FetchFailed {
                error: "boom".into(),
            },
        );
        let merged = store.merged_acl().unwrap();
        assert!(merged.policy.rules.is_empty());
        assert!(merged.degraded);
    }

    #[test]
    fn store_merged_acl_local_layer_first_without_remotes() {
        let mut store = NsdConfigStore::default();
        store.set_local_acl(Some(policy_with(vec![acl_rule("machine:local", "*:80")])));
        let merged = store.merged_acl().unwrap();
        assert_eq!(merged.policy.rules.len(), 1);
        assert!(!merged.degraded);
    }

    #[test]
    fn store_merged_acl_deny_scope_drops_matching_rule() {
        let mut store = NsdConfigStore::default();
        store.upsert_acl(
            "nsd-1",
            AclPayload::loaded(policy_with(vec![acl_rule(
                "user:alice",
                "10.255.0.0/24:22",
            )])),
        );
        store.set_deny_scope(Some(DenyScope {
            dst_cidr: vec!["10.255.0.0/16".into()],
            ..Default::default()
        }));
        let merged = store.merged_acl().unwrap();
        assert!(merged.policy.rules.is_empty());
        assert_eq!(merged.dropped_by_deny_scope.len(), 1);
    }

    // ── sanity: legacy compatibility helper on AclConfig ──────────────────────

    #[test]
    fn acl_config_loaded_helper_matches_legacy_shape() {
        let cfg = AclConfig::loaded("c", AclPolicy::default());
        assert!(matches!(cfg.payload, AclPayload::Loaded { .. }));
    }

    // ── snapshot ──────────────────────────────────────────────────────────────

    #[test]
    fn snapshot_summarises_sources() {
        let mut store = NsdConfigStore::default();
        store.set_local_acl(Some(policy_with(vec![acl_rule("machine:local", "*:80")])));
        store.upsert_acl(
            "nsd-1",
            AclPayload::loaded(policy_with(vec![acl_rule("user:alice", "*:443")])),
        );
        store.upsert_acl("nsd-2", AclPayload::ExplicitEmpty);
        let snap = store.acl_source_snapshot();
        assert_eq!(snap.rule_count_local, 1);
        assert_eq!(snap.rule_count_remote.get("nsd-1"), Some(&1));
        assert_eq!(snap.per_nsd_state.get("nsd-1"), Some(&"loaded"));
        assert_eq!(snap.per_nsd_state.get("nsd-2"), Some(&"empty"));
        assert!(!snap.degraded);
    }

    #[test]
    fn snapshot_cached_count_reflects_last_good_after_fetch_failed() {
        let mut store = NsdConfigStore::default();
        // nsd-2 first loads a 2-rule policy → recorded as its last-known-good.
        store.upsert_acl(
            "nsd-2",
            AclPayload::loaded(policy_with(vec![
                acl_rule("user:alice", "*:80"),
                acl_rule("user:alice", "*:443"),
            ])),
        );
        // A still-live peer serves an identical rule, so cross-NSD dedup in the
        // union merge would otherwise hide nsd-2's cached contribution.
        store.upsert_acl(
            "nsd-1",
            AclPayload::loaded(policy_with(vec![acl_rule("user:alice", "*:80")])),
        );
        // nsd-2 then fails to fetch; NSN keeps serving its last-good cache.
        store.upsert_acl(
            "nsd-2",
            AclPayload::FetchFailed {
                error: "boom".into(),
            },
        );

        let snap = store.acl_source_snapshot();
        assert!(snap.degraded);
        // The cached count equals nsd-2's retained last-good rule count (N=2),
        // independent of the overlapping live rule on nsd-1.
        assert_eq!(snap.rule_count_cached.get("nsd-2"), Some(&2));
    }

    // ── fail-closed synthesis (PLAN-020 SECURITY-CRITICAL) ────────────────────

    use acl::{AccessContext, AclEngine, NetworkTuple, SourceAssertion, TransportKind};

    /// Compile the merged policy and ask the real engine whether a sample
    /// request is allowed — the strongest expression of "fail-closed".
    fn merged_allows(store: &NsdConfigStore, subject: &str, dst: &str, port: u16) -> bool {
        let merged = store.merged_acl().expect("merged policy");
        let engine = AclEngine::load(merged.policy).expect("compile merged policy");
        let network = NetworkTuple::new(None, dst.parse().unwrap(), port, Protocol::Tcp);
        let context = AccessContext::verified_subject(
            subject.to_owned(),
            network,
            SourceAssertion::External {
                idp: "test".to_owned(),
            },
            TransportKind::Direct,
        );
        let decision = engine.is_allowed(&context);
        decision.allowed
    }

    /// When the control plane drops *after* delivering a policy, the synthesized
    /// `FetchFailed` payload must serve the last-good cache (traffic still
    /// flows) while the merge is flagged `degraded`.
    #[test]
    fn fail_closed_drop_after_loaded_serves_last_good_cache() {
        let mut store = NsdConfigStore::default();
        store.upsert_acl(
            "nsd-1",
            AclPayload::loaded(policy_with(vec![acl_rule(
                "user:alice",
                "192.168.1.0/24:80",
            )])),
        );
        assert!(merged_allows(&store, "user:alice", "192.168.1.10", 80));

        // Production synthesis on transport drop: upsert a FetchFailed payload.
        store.upsert_acl(
            "nsd-1",
            AclPayload::FetchFailed {
                error: "control-plane transport dropped".into(),
            },
        );
        let merged = store.merged_acl().unwrap();
        assert!(merged.degraded, "drop must flag the merge degraded");
        assert!(
            merged_allows(&store, "user:alice", "192.168.1.10", 80),
            "last-good cache must keep the steady-state policy alive"
        );
    }

    /// Cold-start fail-closed: every NSD is `FetchFailed` with no cache and
    /// there is no local layer — the compiled engine must DENY everything
    /// (default-deny), and the merge must be `degraded`.
    #[test]
    fn fail_closed_all_nsds_failed_no_cache_denies_everything() {
        let mut store = NsdConfigStore::default();
        store.upsert_acl(
            "nsd-1",
            AclPayload::FetchFailed {
                error: "down".into(),
            },
        );
        store.upsert_acl(
            "nsd-2",
            AclPayload::FetchFailed {
                error: "down".into(),
            },
        );
        let merged = store.merged_acl().unwrap();
        assert!(
            merged.policy.rules.is_empty(),
            "no rules survive total failure"
        );
        assert!(merged.degraded);
        assert!(
            !merged_allows(&store, "user:alice", "192.168.1.10", 80),
            "fail-closed: default-deny when all NSDs failed and no cache exists"
        );
    }

    /// Local backstop: when every NSD has failed with no cache, the on-disk
    /// local accept rule must still be served (and only that rule), so the
    /// site keeps its operator-guaranteed subset alive while degraded.
    #[test]
    fn fail_closed_local_backstop_survives_total_nsd_failure() {
        let mut store = NsdConfigStore::default();
        store.set_local_acl(Some(policy_with(vec![acl_rule(
            "machine:local",
            "192.168.1.0/24:80",
        )])));
        store.upsert_acl(
            "nsd-1",
            AclPayload::FetchFailed {
                error: "down".into(),
            },
        );
        let merged = store.merged_acl().unwrap();
        assert!(merged.degraded);
        assert_eq!(merged.policy.rules.len(), 1, "only the local backstop rule");
        assert!(
            merged_allows(&store, "machine:local", "192.168.1.10", 80),
            "local backstop rule must keep flowing under total NSD failure"
        );
        assert!(
            !merged_allows(&store, "user:alice", "192.168.1.10", 80),
            "traffic outside the local backstop is still denied"
        );
    }

    /// A stale last-good cache past `last_good_max_age` must downgrade to
    /// fail-closed rather than serving an attacker-pinned permissive rule.
    #[test]
    fn fail_closed_stale_cache_past_max_age_denies() {
        use std::time::Duration;
        let mut store = NsdConfigStore {
            last_good_max_age: Some(Duration::from_secs(60)),
            ..Default::default()
        };
        store.upsert_acl(
            "nsd-1",
            AclPayload::loaded(policy_with(vec![acl_rule(
                "user:alice",
                "192.168.1.0/24:80",
            )])),
        );
        store.upsert_acl(
            "nsd-1",
            AclPayload::FetchFailed {
                error: "down".into(),
            },
        );
        // Age the cache past the max.
        if let Some(slot) = store.acl.get_mut("nsd-1") {
            slot.last_good_at = Some(std::time::Instant::now() - Duration::from_secs(3600));
        }
        let merged = store.merged_acl().unwrap();
        assert!(merged.degraded);
        assert!(
            !merged_allows(&store, "user:alice", "192.168.1.10", 80),
            "stale cache must fail closed once past last_good_max_age"
        );
    }
}
