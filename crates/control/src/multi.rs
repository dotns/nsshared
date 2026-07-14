#![forbid(unsafe_code)]

//! Multi-NSD control plane manager.
//!
//! `MultiControlPlane` connects to all configured NSD (control center)
//! endpoints concurrently, merges the configs they push, and re-publishes
//! merged config updates on the same channel interface as a single
//! `ControlPlane`.

use std::sync::Arc;

use arc_swap::ArcSwapOption;
use common::{ConnectorConfig, ControlCenterConfig};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::auth::AuthClient;
use crate::merge::{AclMergeConflict, AclSourceSnapshot, NsdConfigStore};
use crate::messages::{
    AclConfig, AclPayload, DnsConfig, PeerCandidatesUpdate, ProxyConfig, RoutingConfig,
    ServiceReport, WgConfig,
};
use crate::{
    ControlPlane, ControlPlaneStatus, Error, MachineRecoveryConfig, NsdScope, ScopedGatewayConfig,
    ScopedToken, control_mode_from_url,
};

/// **Deprecated** — kept for one release; see
/// [`AclSourceSnapshotSink`] for the PLAN-020 replacement.
///
/// `MultiControlPlane` still writes an all-zero summary here so existing
/// dashboards continue to compile.
pub type AclMergeConflictSink = Arc<ArcSwapOption<AclMergeConflict>>;

/// Shared sink for the latest [`AclSourceSnapshot`] (PLAN-020).
///
/// Published after every ACL update so consumers (e.g. `/api/status`) can read
/// `degraded`, per-NSD state, per-layer rule counts without holding on to
/// merger-internal state.
pub type AclSourceSnapshotSink = Arc<ArcSwapOption<AclSourceSnapshot>>;

// ── NSD update events ─────────────────────────────────────────────────────────

enum NsdUpdate {
    Wg(String, WgConfig),
    Proxy(String, ProxyConfig),
    Acl(String, AclConfig),
    Gateway(ScopedGatewayConfig),
    Routing(String, RoutingConfig),
    Dns(String, DnsConfig),
    PeerCandidates(PeerCandidatesUpdate),
    TokenRefresh(ScopedToken),
}

// ── ControlPlaneInfo ──────────────────────────────────────────────────────────

/// Snapshot of a single NSD connection's status.
#[derive(Debug, Clone)]
pub struct ControlPlaneInfo {
    pub id: String,
    pub url: String,
    pub connected: bool,
}

/// Status update emitted when a control-plane connection comes up or drops.
#[derive(Debug, Clone)]
pub struct ControlPlaneStatusEvent {
    /// Retained compatibility alias for `scope.nsd_id`.
    pub id: String,
    pub scope: NsdScope,
    pub connected: bool,
    /// Exact logical attempt affected by this status.
    /// `None` is legacy or otherwise unproven.
    pub stream_session: Option<crate::ControlStreamSession>,
}

/// Build a child connector that can reach only its selected fixed scope.
fn fixed_scope_connector_config(
    base: &ConnectorConfig,
    selected: &ControlCenterConfig,
) -> ConnectorConfig {
    let mut config = base.clone();
    config.server_url = selected.url.clone();
    config.control_centers.clear();
    config.control_mode = control_mode_from_url(&selected.url).to_string();
    config.nsd_default_mode = None;
    config.realm = selected.realm.clone();
    config.noise_bootstrap_pubkey = selected.noise_bootstrap_pubkey.clone();
    config.quic_bootstrap_cert_sha256 = selected.quic_bootstrap_cert_sha256.clone();
    config.nsd_envelope_key_pins = selected.nsd_envelope_key_pins.clone();
    config
}

// ── MultiControlPlane ─────────────────────────────────────────────────────────

/// Manages connections to one or more NSD endpoints.
///
/// Exposes merged config channels plus a control-plane status channel.
/// The status channel emits an NSD id when that NSD starts delivering config.
pub struct MultiControlPlane {
    /// One entry per NSD.
    entries: Vec<ControlPlaneEntry>,
    /// Base connector config — cloned per NSD with `server_url` overridden.
    base_config: Arc<ConnectorConfig>,
    // Output channels.
    wg_tx: mpsc::Sender<WgConfig>,
    proxy_tx: mpsc::Sender<ProxyConfig>,
    acl_tx: mpsc::Sender<AclConfig>,
    gateway_tx: mpsc::Sender<ScopedGatewayConfig>,
    routing_tx: mpsc::Sender<RoutingConfig>,
    dns_tx: mpsc::Sender<DnsConfig>,
    peer_candidates_tx: mpsc::Sender<PeerCandidatesUpdate>,
    status_tx: mpsc::Sender<ControlPlaneStatusEvent>,
    token_refresh_tx: mpsc::Sender<ScopedToken>,
    /// **Deprecated** legacy sink; always receives an all-zero summary under
    /// union merge. Kept for dashboards that have not migrated to
    /// `acl_source_sink` yet.
    acl_conflict_sink: Option<AclMergeConflictSink>,
    /// Observability sink for the per-layer policy-source snapshot
    /// (PLAN-020).
    acl_source_sink: Option<AclSourceSnapshotSink>,
    /// Optional local ACL layer (operator-authored `acls.toml`).
    local_acl: Option<acl::AclPolicy>,
    /// Optional deny-scope layer that narrows the merged policy.
    deny_scope: Option<acl::DenyScope>,
    /// Maximum age of the last-good cache before it is treated as degraded.
    last_good_max_age: Option<std::time::Duration>,
    heartbeat_start_time: Option<std::time::Instant>,
}

pub struct ControlPlaneEntry {
    pub config: ControlCenterConfig,
    pub auth_client: AuthClient,
    pub services_report: ServiceReport,
    pub machine_recovery: Option<MachineRecoveryConfig>,
}

impl ControlPlaneEntry {
    pub fn new(
        config: ControlCenterConfig,
        auth_client: AuthClient,
        services_report: ServiceReport,
    ) -> Self {
        Self {
            config,
            auth_client,
            services_report,
            machine_recovery: None,
        }
    }

    pub fn with_machine_recovery(mut self, recovery: Option<MachineRecoveryConfig>) -> Self {
        self.machine_recovery = recovery;
        self
    }
}

pub type MultiControlPlaneInit = (
    MultiControlPlane,
    mpsc::Receiver<WgConfig>,
    mpsc::Receiver<ProxyConfig>,
    mpsc::Receiver<AclConfig>,
    mpsc::Receiver<ScopedGatewayConfig>,
    mpsc::Receiver<RoutingConfig>,
    mpsc::Receiver<DnsConfig>,
    mpsc::Receiver<PeerCandidatesUpdate>,
    mpsc::Receiver<ControlPlaneStatusEvent>,
    mpsc::Receiver<ScopedToken>,
);

impl MultiControlPlane {
    /// Create a new `MultiControlPlane`.
    ///
    /// `entries` is a list of `(ControlCenterConfig, AuthClient, ServiceReport)`
    /// — one per NSD to connect to.  `base_config` is the global connector
    /// config; each entry's `server_url` is overridden per NSD.
    ///
    /// Returns the manager and three channel receivers for downstream modules.
    pub fn new(
        entries: Vec<(ControlCenterConfig, AuthClient, ServiceReport)>,
        base_config: Arc<ConnectorConfig>,
    ) -> MultiControlPlaneInit {
        let entries = entries
            .into_iter()
            .map(|(config, auth_client, services_report)| {
                ControlPlaneEntry::new(config, auth_client, services_report)
            })
            .collect();
        Self::new_with_recovery(entries, base_config)
    }

    pub fn new_with_recovery(
        entries: Vec<ControlPlaneEntry>,
        base_config: Arc<ConnectorConfig>,
    ) -> MultiControlPlaneInit {
        let (wg_tx, wg_rx) = mpsc::channel(8);
        let (proxy_tx, proxy_rx) = mpsc::channel(8);
        let (acl_tx, acl_rx) = mpsc::channel(8);
        let (gateway_tx, gateway_rx) = mpsc::channel(8);
        let (routing_tx, routing_rx) = mpsc::channel(8);
        let (dns_tx, dns_rx) = mpsc::channel(8);
        let (peer_candidates_tx, peer_candidates_rx) = mpsc::channel(32);
        let (status_tx, status_rx) = mpsc::channel(8);
        let (token_refresh_tx, token_refresh_rx) = mpsc::channel(8);
        let this = Self {
            entries,
            base_config,
            wg_tx,
            proxy_tx,
            acl_tx,
            gateway_tx,
            routing_tx,
            dns_tx,
            peer_candidates_tx,
            status_tx,
            token_refresh_tx,
            acl_conflict_sink: None,
            acl_source_sink: None,
            local_acl: None,
            deny_scope: None,
            last_good_max_age: None,
            heartbeat_start_time: None,
        };
        (
            this,
            wg_rx,
            proxy_rx,
            acl_rx,
            gateway_rx,
            routing_rx,
            dns_rx,
            peer_candidates_rx,
            status_rx,
            token_refresh_rx,
        )
    }

    /// Attach the legacy ACL merge-conflict sink.
    ///
    /// Under union merge the summary is always all-zero; kept for one release
    /// so `/healthz` dashboards continue to parse the field. Prefer
    /// [`Self::with_acl_source_sink`] for the PLAN-020 surface.
    pub fn with_acl_conflict_sink(mut self, sink: AclMergeConflictSink) -> Self {
        self.acl_conflict_sink = Some(sink);
        self
    }

    /// Attach the PLAN-020 ACL source-snapshot sink.
    ///
    /// After every ACL update the merger publishes a fresh
    /// [`crate::merge::AclSourceSnapshot`] into this slot, including the
    /// `degraded` flag and per-NSD/per-layer rule counts.
    pub fn with_acl_source_sink(mut self, sink: AclSourceSnapshotSink) -> Self {
        self.acl_source_sink = Some(sink);
        self
    }

    /// Install the operator-authored local ACL layer. Contributes to the
    /// union merge at priority 0 (evaluated first).
    pub fn with_local_acl(mut self, policy: acl::AclPolicy) -> Self {
        self.local_acl = Some(policy);
        self
    }

    /// Install the operator-authored deny-scope filter.
    pub fn with_deny_scope(mut self, scope: acl::DenyScope) -> Self {
        self.deny_scope = Some(scope);
        self
    }

    /// Set the maximum age for last-good cache entries before they are
    /// treated as degraded. Default: unlimited.
    pub fn with_last_good_max_age(mut self, age: std::time::Duration) -> Self {
        self.last_good_max_age = Some(age);
        self
    }

    pub fn with_heartbeat_start_time(mut self, start_time: std::time::Instant) -> Self {
        self.heartbeat_start_time = Some(start_time);
        self
    }

    /// Run the multi-NSD control plane loop.
    ///
    /// Spawns one `ControlPlane` task per NSD.  Each sends config updates into
    /// a shared channel tagged with the NSD id.  A merger loop re-merges all
    /// stored configs on every update and publishes to the output channels.
    ///
    /// This method runs until all output channel receivers are dropped.
    pub async fn run(self) -> Result<(), Error> {
        let nsd_count = self.entries.len();
        info!(nsd_count, "MultiControlPlane starting");

        let (update_tx, mut update_rx) = mpsc::channel::<NsdUpdate>(64);
        let status_tx = self.status_tx.clone();
        let acl_conflict_sink = self.acl_conflict_sink.clone();
        let acl_source_sink = self.acl_source_sink.clone();
        let local_acl = self.local_acl.clone();
        let deny_scope = self.deny_scope.clone();
        let last_good_max_age = self.last_good_max_age;

        for entry in self.entries {
            let ControlPlaneEntry {
                config: cc,
                auth_client,
                services_report,
                machine_recovery,
            } = entry;
            let nsd_config = Arc::new(fixed_scope_connector_config(&self.base_config, &cc));
            let id = cc.id.clone();
            let scope = NsdScope::new(id.clone(), auth_client.state.realm.clone());

            let (
                mut plane,
                wg_rx,
                proxy_rx,
                acl_rx,
                gateway_rx,
                routing_rx,
                dns_rx,
                peer_candidates_rx,
                token_refresh_rx,
            ) = ControlPlane::new(nsd_config, services_report, auth_client)?;
            plane.set_nsd_id(id.clone());
            if let Some(start_time) = self.heartbeat_start_time {
                plane.set_heartbeat_start_time(start_time);
            }
            if let Some(recovery) = machine_recovery {
                plane.set_machine_recovery(recovery);
            }

            // Wire the exact scope/session transport status through to the
            // supervisor. Config arrival is not a connection signal.
            let (plane_status_tx, mut plane_status_rx) = mpsc::channel::<ControlPlaneStatus>(8);
            plane.set_status_tx(plane_status_tx);
            {
                let status_tx = status_tx.clone();
                let update_tx = update_tx.clone();
                tokio::spawn(async move {
                    while let Some(status) = plane_status_rx.recv().await {
                        let nsd_id = status.scope.nsd_id.clone();
                        // Control-plane drop → synthesize a `FetchFailed` ACL
                        // payload for this NSD so the merger falls back to the
                        // last-good cache, or degrades fail-closed when no
                        // cache exists. Without this the slot would keep its
                        // stale `Loaded` policy forever after the SSE stream
                        // errored (PLAN-020 fail-closed synthesis).
                        if !status.connected
                            && update_tx
                                .send(NsdUpdate::Acl(
                                    nsd_id.clone(),
                                    AclConfig::fetch_failed(
                                        format!("fetch-failed:{nsd_id}"),
                                        "control-plane transport dropped",
                                    ),
                                ))
                                .await
                                .is_err()
                        {
                            break;
                        }
                        if status_tx
                            .send(ControlPlaneStatusEvent {
                                id: nsd_id,
                                scope: status.scope,
                                connected: status.connected,
                                stream_session: status.stream_session,
                            })
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                });
            }

            // Forward wg_config updates.
            {
                let tx = update_tx.clone();
                let nsd_id = id.clone();
                tokio::spawn(async move {
                    let mut rx = wg_rx;
                    while let Some(cfg) = rx.recv().await {
                        if tx.send(NsdUpdate::Wg(nsd_id.clone(), cfg)).await.is_err() {
                            break;
                        }
                    }
                });
            }

            // Forward proxy_config updates.
            {
                let tx = update_tx.clone();
                let nsd_id = id.clone();
                tokio::spawn(async move {
                    let mut rx = proxy_rx;
                    while let Some(cfg) = rx.recv().await {
                        if tx
                            .send(NsdUpdate::Proxy(nsd_id.clone(), cfg))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                });
            }

            // Forward acl_config updates.
            {
                let tx = update_tx.clone();
                let nsd_id = id.clone();
                tokio::spawn(async move {
                    let mut rx = acl_rx;
                    while let Some(cfg) = rx.recv().await {
                        if tx.send(NsdUpdate::Acl(nsd_id.clone(), cfg)).await.is_err() {
                            break;
                        }
                    }
                });
            }

            // Forward gateway_config updates.
            {
                let tx = update_tx.clone();
                let scope = scope.clone();
                tokio::spawn(async move {
                    let mut rx = gateway_rx;
                    while let Some(cfg) = rx.recv().await {
                        if tx
                            .send(NsdUpdate::Gateway(ScopedGatewayConfig::from_verified(
                                scope.clone(),
                                cfg,
                            )))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                });
            }

            // Forward routing_config updates.
            {
                let tx = update_tx.clone();
                let nsd_id = id.clone();
                tokio::spawn(async move {
                    let mut rx = routing_rx;
                    while let Some(cfg) = rx.recv().await {
                        if tx
                            .send(NsdUpdate::Routing(nsd_id.clone(), cfg))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                });
            }

            // Forward dns_config updates.
            {
                let tx = update_tx.clone();
                let nsd_id = id.clone();
                tokio::spawn(async move {
                    let mut rx = dns_rx;
                    while let Some(cfg) = rx.recv().await {
                        if tx.send(NsdUpdate::Dns(nsd_id.clone(), cfg)).await.is_err() {
                            break;
                        }
                    }
                });
            }

            // Forward peer_candidates updates.
            {
                let tx = update_tx.clone();
                tokio::spawn(async move {
                    let mut rx = peer_candidates_rx;
                    while let Some(update) = rx.recv().await {
                        if tx.send(NsdUpdate::PeerCandidates(update)).await.is_err() {
                            break;
                        }
                    }
                });
            }

            // Forward token_refresh events.
            {
                let tx = update_tx.clone();
                let scope = scope.clone();
                tokio::spawn(async move {
                    let mut rx = token_refresh_rx;
                    while let Some(token) = rx.recv().await {
                        if tx
                            .send(NsdUpdate::TokenRefresh(ScopedToken::from_scope(
                                scope.clone(),
                                token,
                            )))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                });
            }

            // Run the ControlPlane.
            let nsd_id = id.clone();
            let plane_update_tx = update_tx.clone();
            tokio::spawn(async move {
                if let Err(e) = plane.run().await {
                    match e {
                        Error::Auth(ref msg) => {
                            error!(nsd_id, error = %msg, "NSD auth failed");
                        }
                        _ => {
                            warn!(nsd_id, error = %e, "NSD control plane error");
                        }
                    }
                    // Terminal plane failure (auth exhausted, downstream
                    // closed, etc.) → mark this NSD's ACL as fetch-failed so
                    // the merger degrades fail-closed instead of pinning the
                    // last `Loaded` policy indefinitely.
                    let _ = plane_update_tx
                        .send(NsdUpdate::Acl(
                            nsd_id.clone(),
                            AclConfig::fetch_failed(
                                format!("fetch-failed:{nsd_id}"),
                                e.to_string(),
                            ),
                        ))
                        .await;
                }
            });
        }

        // Drop the sender we hold so that if all NSD tasks exit, the receiver
        // can detect it.
        drop(update_tx);
        drop(status_tx);

        // Merger loop — maintains per-NSD state and re-publishes on each update.
        let mut store = NsdConfigStore {
            local_acl,
            deny_scope,
            last_good_max_age,
            ..Default::default()
        };

        // Local backstop (PLAN-020): if an operator local ACL layer is
        // present, publish a merged policy immediately — before any NSD
        // delivers config — so the data plane has a compiled accept set at
        // startup even when every control plane is unreachable.
        if store.local_acl.is_some()
            && let Some(merged) = store.merged_acl()
        {
            if let Some(sink) = &acl_source_sink {
                sink.store(Some(Arc::new(store.acl_source_snapshot())));
            }
            let out = AclConfig {
                chain_id: "local-acl-bootstrap".to_string(),
                payload: AclPayload::loaded(merged.policy),
            };
            if self.acl_tx.send(out).await.is_err() {
                info!("acl_config downstream receiver dropped before local bootstrap");
                return Ok(());
            }
        }

        // Last merged wg_config published downstream; identical re-merges
        // (e.g. an NSD re-sending its config on SSE reconnect) are skipped so
        // consumers never see a redundant redelivery.
        let mut last_sent_wg: Option<WgConfig> = None;

        while let Some(update) = update_rx.recv().await {
            match update {
                NsdUpdate::Wg(nsd_id, cfg) => {
                    store.wg.insert(nsd_id, cfg);
                    let Some(merged) = store.merged_wg() else {
                        continue;
                    };
                    if last_sent_wg.as_ref() == Some(&merged) {
                        debug!("merged wg_config unchanged, skipping redelivery");
                        continue;
                    }
                    if self.wg_tx.send(merged.clone()).await.is_err() {
                        info!("wg_config downstream receiver dropped, stopping merger");
                        return Ok(());
                    }
                    last_sent_wg = Some(merged);
                }
                NsdUpdate::Proxy(nsd_id, cfg) => {
                    store.proxy.insert(nsd_id, cfg);
                    let Some(merged) = store.merged_proxy() else {
                        continue;
                    };
                    if self.proxy_tx.send(merged).await.is_err() {
                        info!("proxy_config downstream receiver dropped, stopping merger");
                        return Ok(());
                    }
                }
                NsdUpdate::Acl(nsd_id, cfg) => {
                    let chain_id = cfg.chain_id.clone();
                    store.upsert_acl(nsd_id.clone(), cfg.payload);
                    let Some(merged) = store.merged_acl() else {
                        continue;
                    };

                    if merged.degraded {
                        warn!(
                            nsd_id,
                            dropped_by_deny_scope = merged.dropped_by_deny_scope.len(),
                            "ACL merge is degraded: at least one NSD is in FetchFailed state"
                        );
                    }
                    if !merged.dropped_by_deny_scope.is_empty() {
                        warn!(
                            dropped = merged.dropped_by_deny_scope.len(),
                            "deny-scope filter stripped rules from merged ACL policy"
                        );
                    }

                    // Publish observability snapshot if a sink is attached.
                    if let Some(sink) = &acl_source_sink {
                        sink.store(Some(Arc::new(store.acl_source_snapshot())));
                    }
                    // Keep the legacy sink populated (all zeros under union)
                    // so existing dashboards continue to render.
                    if let Some(sink) = &acl_conflict_sink {
                        sink.store(Some(Arc::new(store.acl_merge_conflict())));
                    }

                    let out = AclConfig {
                        chain_id,
                        payload: AclPayload::loaded(merged.policy),
                    };
                    if self.acl_tx.send(out).await.is_err() {
                        info!("acl_config downstream receiver dropped, stopping merger");
                        return Ok(());
                    }
                }
                NsdUpdate::Gateway(cfg) => {
                    if self.gateway_tx.send(cfg).await.is_err() {
                        info!("gateway_config downstream receiver dropped, stopping merger");
                        return Ok(());
                    }
                }
                NsdUpdate::Routing(_nsd_id, cfg) => {
                    if self.routing_tx.send(cfg).await.is_err() {
                        info!("routing_config downstream receiver dropped, stopping merger");
                        return Ok(());
                    }
                }
                NsdUpdate::Dns(_nsd_id, cfg) => {
                    if self.dns_tx.send(cfg).await.is_err() {
                        info!("dns_config downstream receiver dropped, stopping merger");
                        return Ok(());
                    }
                }
                NsdUpdate::PeerCandidates(update) => {
                    if self.peer_candidates_tx.send(update).await.is_err() {
                        info!("peer_candidates downstream receiver dropped, stopping merger");
                        return Ok(());
                    }
                }
                NsdUpdate::TokenRefresh(token) => {
                    if self.token_refresh_tx.send(token).await.is_err() {
                        info!("token_refresh downstream receiver dropped, stopping merger");
                        return Ok(());
                    }
                }
            }
        }

        info!("MultiControlPlane: all NSD connections closed");
        Ok(())
    }

    /// Number of configured NSD entries.
    pub fn nsd_count(&self) -> usize {
        self.entries.len()
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use common::MachineState;
    use common::envelope_pins::ed25519_pubkey_to_okp_thumbprint;
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::OsRng;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    fn make_config(server_url: &str) -> Arc<ConnectorConfig> {
        Arc::new(ConnectorConfig {
            server_url: server_url.to_string(),
            log_level: "info".to_string(),
            services_file: "services.toml".to_string(),
            state_dir: "/tmp".to_string(),
            auth_key: None,
            machine_id: None,
            dns_timeout_secs: 5,
            nsd_endpoint_attempt_timeout_secs: 8,
            dns_cache_ttl_secs: 60,
            ws_max_messages_per_sec: 100,
            ws_max_message_size: 1_048_576,
            transport_mode: "auto".to_string(),
            control_centers: vec![],
            gateways: vec![],
            log_dir: None,
            snat_addr: None,
            control_mode: "sse".to_string(),
            nsd_default_mode: None,
            realm: None,
            noise_bootstrap_pubkey: None,
            quic_bootstrap_cert_sha256: None,
            nsd_jwt_key_pins: vec![],
            nsd_envelope_key_pins: vec![],
            conntrack: common::ConntrackConfig::default(),
            local_acl: common::LocalAclConfig::default(),
            extra_ca_certs: None,
            wg_relay_registration_endpoint: None,
        })
    }

    #[test]
    fn nsd_count_matches_entries() {
        let base = make_config("http://localhost");
        let (mcp, _, _, _, _, _, _, _, _, _) = MultiControlPlane::new(vec![], base);
        assert_eq!(mcp.nsd_count(), 0);
    }

    #[tokio::test]
    async fn fixed_scope_connector_config_cannot_fall_back_to_a_sibling() {
        let listener_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listener_b = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url_a = format!("http://{}", listener_a.local_addr().unwrap());
        let url_b = format!("http://{}", listener_b.local_addr().unwrap());
        let signer = SigningKey::generate(&mut OsRng);
        let pin = ed25519_pubkey_to_okp_thumbprint(&signer.verifying_key().to_bytes()).unwrap();

        let mut base = (*make_config("http://legacy.example")).clone();
        base.control_centers = vec![
            ControlCenterConfig {
                id: "nsd-a".to_string(),
                url: url_a,
                realm: Some("realm-a".to_string()),
                noise_bootstrap_pubkey: None,
                quic_bootstrap_cert_sha256: None,
                nsd_envelope_key_pins: vec!["pin-a".to_string()],
                priority: 1,
            },
            ControlCenterConfig {
                id: "nsd-b".to_string(),
                url: url_b.clone(),
                realm: Some("realm-b".to_string()),
                noise_bootstrap_pubkey: None,
                quic_bootstrap_cert_sha256: None,
                nsd_envelope_key_pins: vec![pin.clone()],
                priority: 2,
            },
        ];
        base.nsd_default_mode = Some("sse".to_string());
        base.realm = Some("shared-realm".to_string());
        base.noise_bootstrap_pubkey = Some("aa".repeat(32));
        base.quic_bootstrap_cert_sha256 = Some("cc".repeat(32));
        base.nsd_envelope_key_pins = vec!["shared-pin".to_string()];

        let selected = base.control_centers[1].clone();
        let confined = fixed_scope_connector_config(&base, &selected);

        assert_eq!(confined.server_url, selected.url);
        assert_eq!(confined.control_mode, "sse");
        assert!(confined.control_centers.is_empty());
        assert_eq!(confined.nsd_default_mode, None);
        assert_eq!(confined.realm, Some("realm-b".to_string()));
        assert_eq!(confined.quic_bootstrap_cert_sha256, None);
        assert_eq!(confined.noise_bootstrap_pubkey, None);
        assert_eq!(confined.nsd_envelope_key_pins, vec![pin.clone()]);
        assert_eq!(confined.effective_control_centers().len(), 1);

        let state_dir = tempfile::tempdir().unwrap();
        let mut state = MachineState::load_or_create_for_realm(state_dir.path(), "realm-b")
            .await
            .unwrap();
        state
            .set_registered(
                "machine-b".to_string(),
                &"aa".repeat(32),
                "127.0.0.1:51820",
                None,
            )
            .unwrap();
        let auth = AuthClient::new(&url_b, state).with_envelope_trust(
            "nsd-b",
            "realm-b",
            state_dir.path(),
            vec![pin],
            None,
        );
        let services_report = crate::messages::ServiceReport {
            services: HashMap::new(),
            strict_mode: false,
            system_info: None,
        };
        let (
            mut plane,
            _wg_rx,
            _proxy_rx,
            _acl_rx,
            mut gateway_rx,
            _routing_rx,
            _dns_rx,
            _peer_rx,
            _token_rx,
        ) = ControlPlane::new(Arc::new(confined), services_report, auth).unwrap();
        plane.set_nsd_id("nsd-b".to_string());
        let session = plane.begin_stream_attempt().unwrap();
        let endpoints = plane.control_endpoint_sequence();
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].id(), "nsd-b");
        assert_eq!(endpoints[0].url(), url_b);

        let event_payload = crate::api::to_cbor(&crate::api::ConfigStreamEventPayloadV1 {
            v: 1,
            message: crate::messages::ControlMessage::GatewayConfig(
                crate::messages::GatewayConfig {
                    gateways: vec![crate::messages::GatewayInfo {
                        id: "gateway-b".to_string(),
                        wg_endpoint: "192.0.2.10:51820".to_string(),
                        wss_endpoint: "ws://192.0.2.10:9443".to_string(),
                        tunnel_ip: None,
                        wg_relay_endpoint: Some("192.0.2.10:51821".to_string()),
                    }],
                    wg_relay_roster: None,
                },
            ),
        })
        .unwrap();
        let event_envelope = crate::envelope::ControlEnvelope::sign_response(
            crate::envelope::api::CONFIG_STREAM,
            Some("machine-b".to_string()),
            signer.verifying_key().to_bytes(),
            event_payload,
            |message| signer.sign(message).to_bytes(),
        )
        .unwrap();
        let signed_at_unix_secs = event_envelope.ts;
        let event = format!(
            "event: config-envelope.v1\ndata: {}\n\n",
            URL_SAFE_NO_PAD.encode(event_envelope.to_cbor().unwrap())
        );
        let server_b = tokio::spawn(async move {
            let (mut socket, _) = listener_b.accept().await.unwrap();
            let mut request = Vec::new();
            let mut byte = [0_u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                socket.read_exact(&mut byte).await.unwrap();
                request.push(byte[0]);
            }
            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
            socket.write_all(event.as_bytes()).await.unwrap();
            socket.shutdown().await.unwrap();

            String::from_utf8(request).unwrap()
        });

        let transport = Arc::clone(&plane.transport);
        let mut stream = plane.make_control_stream(transport, &endpoints[0]);
        stream.set_token("scope-b-control-token".to_string());
        stream
            .connect(plane.config_stream_envelope().unwrap())
            .await
            .unwrap();
        let verified_message = stream.next_message().await.unwrap();
        let received_at = verified_message.received_at;
        let mut token = "scope-b-control-token".to_string();
        plane
            .dispatch_message(verified_message, &mut token)
            .await
            .unwrap();
        let verified_config = gateway_rx.recv().await.unwrap();
        let published =
            ScopedGatewayConfig::from_verified(NsdScope::new("nsd-b", "realm-b"), verified_config);

        assert_eq!(published.scope.nsd_id, "nsd-b");
        assert_eq!(published.scope.realm, "realm-b");
        assert_eq!(published.config.gateways[0].id, "gateway-b");
        assert_eq!(published.signed_at_unix_secs, signed_at_unix_secs);
        assert_eq!(published.received_at, received_at);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), listener_a.accept())
                .await
                .is_err(),
            "the B-scoped child must never connect to sibling A"
        );

        let request = server_b.await.unwrap();
        let request_line = request.lines().next().unwrap();
        let path = request_line.split_whitespace().nth(1).unwrap();
        let encoded = path
            .strip_prefix("/api/v1/config/stream?request=")
            .expect("session-bearing fixed-scope request");
        let request_envelope =
            crate::envelope::ControlEnvelope::from_cbor(&URL_SAFE_NO_PAD.decode(encoded).unwrap())
                .unwrap();
        request_envelope
            .verify_request(request_envelope.ts)
            .unwrap();
        let request: crate::api::ConfigStreamRequest =
            crate::api::from_cbor(request_envelope.payload.as_ref()).unwrap();
        assert_eq!(request.stream_session, Some(session));
    }
}
