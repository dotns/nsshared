#![forbid(unsafe_code)]
#![allow(missing_docs)]

//! Control-plane client for NSN.
//!
//! Manages authentication, SSE (Server-Sent Events) connection to NSD, and
//! message dispatch to downstream crates.
//!
//! Key exports:
//! - [`ControlPlane`] — main control-plane actor; call [`ControlPlane::run`]
//!   in a background task.
//! - [`auth::AuthClient`] — Ed25519 signature-based machine registration and
//!   authentication.
//! - [`messages`] — all control-plane message types (`WgConfig`, `ProxyConfig`,
//!   `AclConfig`, `GatewayConfig`, `RoutingConfig`, `DnsConfig`, etc.).
//! - [`merge`] — multi-NSD config merge helpers.
//! - [`multi`] — [`MultiControlPlane`] for connecting to multiple NSDs.

pub mod api;
pub mod auth;
pub mod bootstrap;
pub mod device_flow;
pub mod envelope;
pub mod merge;
pub mod messages;
pub mod multi;
pub mod retry;
pub mod sse;
pub mod transport;
pub mod types;

pub use types::ConnectorType;

use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::ConnectorConfig;
use secrecy::{ExposeSecret, SecretString};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use auth::AuthClient;
use envelope::ControlEnvelope;
use envelope::api as envelope_api;
use messages::{
    AclConfig, ControlMessage, DnsConfig, GatewayConfig, PeerCandidatesUpdate, ProxyConfig,
    RoutingConfig, ServiceReport, WgConfig,
};
use sse::{ControlStream, NoiseControl, SseControl};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("authentication failed: {0}")]
    Auth(String),
    /// Server returned HTTP 401 on an authenticated endpoint and a single
    /// in-flight credential refresh did not recover. The `String` carries
    /// the NSD base URL for caller-side log context.
    #[error("unauthorized at {0}")]
    Unauthorized(String),
    /// Server explicitly reported that this machine id is no longer present in
    /// its machine table. This is distinct from a generic 401 because callers can
    /// safely re-register the existing per-realm identity with that NSD only.
    #[error("machine unknown at {0}")]
    MachineUnknown(String),
    #[error("connect error: {0}")]
    Connect(String),
    #[error("{mode} control transport build failed: {reason}")]
    ControlTransportBuild { mode: &'static str, reason: String },
    #[error("sse error: {0}")]
    Sse(String),
    #[error("message decode error: {0}")]
    Decode(#[from] serde_json::Error),
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("noise error: {0}")]
    Noise(String),
    #[error("quic error: {0}")]
    Quic(String),
    #[error("envelope error: {0}")]
    Envelope(#[from] envelope::Error),
    #[error("not implemented for transport {0}")]
    NotImplemented(&'static str),
    #[error("server error: {0}")]
    ServerError(String),
    #[error("replay rejected")]
    Replay,
    /// Server rejected registration because the submitted machine identity or
    /// peer key collides with an existing namespace entry.
    #[error("key namespace overlap")]
    KeyNamespaceOverlap,
    /// Server rejected an epoch/version-gated write with HTTP 409 and a
    /// `version_conflict` body. `current_epoch` carries the server's stored
    /// high-water mark when the response body surfaces it (additive field),
    /// so callers can fast-forward past it instead of staying wedged.
    #[error("version conflict (server epoch {current_epoch:?})")]
    VersionConflict { current_epoch: Option<u64> },
    #[error("timeout")]
    Timeout,
    /// Cold-boot retry harness exhausted its attempt budget without success.
    /// Carries `op` for log correlation and the rendered `last_error` so
    /// callers can surface the operator-visible failure without re-deriving it.
    #[error("retry of {op} exhausted {attempts} attempts; last error: {last_error}")]
    RetryExhausted {
        op: String,
        attempts: u32,
        last_error: String,
    },
    /// Shutdown signal fired while the retry harness was sleeping between
    /// attempts or driving the operation; the helper returned promptly.
    #[error("cancelled")]
    Cancelled,
}

pub(crate) fn conflict_error_from_body(body: &[u8]) -> Error {
    recognized_conflict_error_from_body(body).unwrap_or(Error::Replay)
}

pub(crate) fn recognized_conflict_error_from_body(body: &[u8]) -> Option<Error> {
    #[derive(serde::Deserialize)]
    struct ConflictBody {
        error: String,
        #[serde(default)]
        current_epoch: Option<u64>,
    }

    let parsed = serde_json::from_slice::<ConflictBody>(body).ok()?;
    match parsed.error.as_str() {
        "version_conflict" => Some(Error::VersionConflict {
            current_epoch: parsed.current_epoch,
        }),
        "key_namespace_overlap" => Some(Error::KeyNamespaceOverlap),
        "replay" => Some(Error::Replay),
        _ => None,
    }
}

#[derive(Clone, Copy, Debug)]
pub struct MachineRecoveryPolicy {
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
    pub max_failures: u32,
}

impl Default for MachineRecoveryPolicy {
    fn default() -> Self {
        Self {
            initial_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(60),
            max_failures: 5,
        }
    }
}

#[derive(Clone)]
pub struct MachineRecoveryConfig {
    auth_key: SecretString,
    state_dir: PathBuf,
    persist_state: bool,
    policy: MachineRecoveryPolicy,
}

impl MachineRecoveryConfig {
    pub fn with_auth_key(
        auth_key: impl Into<String>,
        state_dir: impl Into<PathBuf>,
        persist_state: bool,
    ) -> Self {
        Self {
            auth_key: auth_key.into().into(),
            state_dir: state_dir.into(),
            persist_state,
            policy: MachineRecoveryPolicy::default(),
        }
    }

    pub fn with_policy(mut self, policy: MachineRecoveryPolicy) -> Self {
        self.policy = policy;
        self
    }

    fn policy(&self) -> MachineRecoveryPolicy {
        self.policy
    }
}

impl fmt::Debug for MachineRecoveryConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MachineRecoveryConfig")
            .field("auth_key", &"[REDACTED]")
            .field("state_dir", &self.state_dir)
            .field("persist_state", &self.persist_state)
            .field("policy", &self.policy)
            .finish()
    }
}

#[derive(Debug)]
struct MachineRecoveryCircuit {
    failures: u32,
    next_backoff: Duration,
    next_allowed_at: Option<tokio::time::Instant>,
}

impl MachineRecoveryCircuit {
    fn new(policy: MachineRecoveryPolicy) -> Self {
        Self {
            failures: 0,
            next_backoff: policy.initial_backoff,
            next_allowed_at: None,
        }
    }

    fn can_attempt(&self, policy: MachineRecoveryPolicy, now: tokio::time::Instant) -> bool {
        if self.failures >= policy.max_failures {
            return false;
        }
        self.next_allowed_at.is_none_or(|deadline| now >= deadline)
    }

    fn record_success(&mut self, policy: MachineRecoveryPolicy) {
        self.failures = 0;
        self.next_backoff = policy.initial_backoff;
        self.next_allowed_at = None;
    }

    fn record_failure(&mut self, policy: MachineRecoveryPolicy, now: tokio::time::Instant) {
        self.failures = self.failures.saturating_add(1);
        self.next_allowed_at = Some(now + self.next_backoff);
        self.next_backoff = (self.next_backoff * 2).min(policy.max_backoff);
    }

    fn is_open(&self, policy: MachineRecoveryPolicy) -> bool {
        self.failures >= policy.max_failures
    }
}

/// Issuing NSD identity for data-plane credentials and endpoints.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct NsdScope {
    pub nsd_id: String,
    pub realm: String,
}

impl NsdScope {
    pub fn new(nsd_id: impl Into<String>, realm: impl Into<String>) -> Self {
        Self {
            nsd_id: nsd_id.into(),
            realm: realm.into(),
        }
    }
}

/// WSS relay bearer token scoped to the NSD that issued it.
#[derive(Clone)]
pub struct ScopedToken {
    pub scope: NsdScope,
    token: SecretString,
}

impl ScopedToken {
    pub fn new(
        nsd_id: impl Into<String>,
        realm: impl Into<String>,
        token: impl Into<String>,
    ) -> Self {
        Self::from_scope(NsdScope::new(nsd_id, realm), token)
    }

    pub fn from_scope(scope: NsdScope, token: impl Into<String>) -> Self {
        Self {
            scope,
            token: token.into().into(),
        }
    }

    pub fn into_token(self) -> SecretString {
        self.token
    }
}

impl fmt::Debug for ScopedToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScopedToken")
            .field("scope", &self.scope)
            .field("token", &"[REDACTED]")
            .finish()
    }
}

/// Gateway config scoped to the NSD that supplied the WSS relay endpoints.
#[derive(Clone, Debug)]
pub struct ScopedGatewayConfig {
    pub scope: NsdScope,
    pub config: GatewayConfig,
}

impl ScopedGatewayConfig {
    pub fn new(scope: NsdScope, config: GatewayConfig) -> Self {
        Self { scope, config }
    }
}

/// Control plane: manages auth, SSE connection, and message dispatch.
pub struct ControlPlane {
    config: Arc<ConnectorConfig>,
    auth_client: AuthClient,
    /// Snapshot of the local service whitelist, sent to the server on connect.
    services_report: ServiceReport,
    wg_config_tx: mpsc::Sender<WgConfig>,
    proxy_config_tx: mpsc::Sender<ProxyConfig>,
    acl_config_tx: mpsc::Sender<AclConfig>,
    gateway_config_tx: mpsc::Sender<GatewayConfig>,
    routing_config_tx: mpsc::Sender<RoutingConfig>,
    dns_config_tx: mpsc::Sender<DnsConfig>,
    peer_candidates_tx: mpsc::Sender<PeerCandidatesUpdate>,
    token_refresh_tx: mpsc::Sender<String>,
    config_stream_request: api::ConfigStreamRequest,
    /// Pluggable signed-envelope transport for control calls and streams.
    transport: Arc<dyn transport::ControlTransport>,
    /// Periodic heartbeat client for this single NSD. Owned by the same task
    /// that owns `auth_client`, so recovery can update registration state
    /// without a second consumer or shared mutable manager.
    heartbeat_client: Option<auth::HeartbeatClient>,
    heartbeat_interval: Duration,
    heartbeat_start_time: Instant,
    machine_recovery: Option<MachineRecoveryConfig>,
    recovery_circuit: MachineRecoveryCircuit,
    nsd_id: Option<String>,
    /// Optional connection-status sender. Emits `true` on successful SSE
    /// connect and `false` when the SSE loop breaks out due to an error.
    /// Lets the supervisor (e.g. `MultiControlPlane`) detect transport drops
    /// instead of only knowing about message arrivals.
    status_tx: Option<mpsc::Sender<bool>>,
}

impl ControlPlane {
    /// Create a new `ControlPlane`.
    ///
    /// `auth_client` must already have a registered machine state.
    /// `services_report` is POSTed to the server before each SSE connection.
    ///
    /// Returns the plane and channel receivers for downstream modules.
    #[allow(clippy::type_complexity)]
    pub fn new(
        config: Arc<ConnectorConfig>,
        services_report: ServiceReport,
        auth_client: AuthClient,
    ) -> Result<ControlPlaneInit, Error> {
        let (wg_tx, wg_rx) = mpsc::channel(8);
        let (proxy_tx, proxy_rx) = mpsc::channel(8);
        let (acl_tx, acl_rx) = mpsc::channel(8);
        let (gw_tx, gw_rx) = mpsc::channel(8);
        let (routing_tx, routing_rx) = mpsc::channel(8);
        let (dns_tx, dns_rx) = mpsc::channel(8);
        let (peer_candidates_tx, peer_candidates_rx) = mpsc::channel(32);
        let (token_refresh_tx, token_refresh_rx) = mpsc::channel(8);

        let transport = build_control_transport(&config, &auth_client)?;
        let heartbeat_client = auth_client.heartbeat_client();
        let recovery_circuit = MachineRecoveryCircuit::new(MachineRecoveryPolicy::default());

        let plane = Self {
            config,
            auth_client,
            services_report,
            wg_config_tx: wg_tx,
            proxy_config_tx: proxy_tx,
            acl_config_tx: acl_tx,
            gateway_config_tx: gw_tx,
            routing_config_tx: routing_tx,
            dns_config_tx: dns_tx,
            peer_candidates_tx,
            token_refresh_tx,
            config_stream_request: api::ConfigStreamRequest::default(),
            transport,
            heartbeat_client,
            heartbeat_interval: Duration::from_secs(60),
            heartbeat_start_time: Instant::now(),
            machine_recovery: None,
            recovery_circuit,
            nsd_id: None,
            status_tx: None,
        };
        Ok((
            plane,
            wg_rx,
            proxy_rx,
            acl_rx,
            gw_rx,
            routing_rx,
            dns_rx,
            peer_candidates_rx,
            token_refresh_rx,
        ))
    }

    /// Attach a connection-status sender. The plane will emit `true` when the
    /// SSE/Noise transport is (re-)connected and `false` when it drops.
    /// Callers use this to reflect liveness without waiting for a config push.
    pub fn set_status_tx(&mut self, tx: mpsc::Sender<bool>) {
        self.status_tx = Some(tx);
    }

    pub fn set_config_stream_capabilities(&mut self, capabilities: Vec<String>) {
        self.config_stream_request.capabilities = capabilities;
        self.config_stream_request.capabilities.sort();
        self.config_stream_request.capabilities.dedup();
    }

    pub fn set_nsd_id(&mut self, id: String) {
        self.nsd_id = Some(id);
    }

    pub fn set_heartbeat_start_time(&mut self, start_time: Instant) {
        self.heartbeat_start_time = start_time;
    }

    pub fn set_heartbeat_interval(&mut self, interval: Duration) {
        self.heartbeat_interval = interval;
    }

    pub fn set_machine_recovery(&mut self, recovery: MachineRecoveryConfig) {
        self.recovery_circuit = MachineRecoveryCircuit::new(recovery.policy());
        self.machine_recovery = Some(recovery);
    }

    /// Run the control plane loop.
    ///
    /// Authenticates, POSTs the local service report, connects the SSE stream,
    /// dispatches messages to downstream channels, and reconnects with
    /// exponential backoff on failure.  Runs until all downstream receivers
    /// are dropped.
    pub async fn run(mut self) -> Result<(), Error> {
        let token = self
            .authenticate_control_with_recovery("initial authenticate")
            .await?;

        info!("authenticated with control plane");

        // Whether the operator chose Noise / QUIC is already reflected in
        // `self.transport`. Build the matching `ControlStream` factory and
        // hand off to the unified loop.
        let transport_arc = self.transport.clone();
        let endpoint = url_to_tcp_endpoint(&self.config.server_url);
        let max_rate = self.config.ws_max_messages_per_sec;
        let max_size = self.config.ws_max_message_size;
        let envelope_trust = self.auth_client.envelope_trust();

        let make_stream = move || -> Box<dyn ControlStream> {
            let transport = transport_arc.clone();
            let trust = envelope_trust.clone();
            if transport.name() == "sse" {
                Box::new(SseControl::new(
                    transport,
                    endpoint.clone(),
                    max_rate,
                    max_size,
                    trust,
                ))
            } else {
                Box::new(NoiseControl::new(
                    transport,
                    endpoint.clone(),
                    max_rate,
                    max_size,
                    trust,
                ))
            }
        };

        self.run_loop(token, make_stream).await
    }

    /// Shared SSE/Noise loop. `make_stream` opens a fresh stream on each
    /// reconnect; the auth token is rotated on `ControlMessage::TokenRefresh`.
    async fn run_loop<F>(&mut self, mut token: String, make_stream: F) -> Result<(), Error>
    where
        F: Fn() -> Box<dyn ControlStream>,
    {
        let mut backoff_secs: u64 = 1;
        let mut heartbeat = tokio::time::interval_at(
            tokio::time::Instant::now() + self.heartbeat_interval,
            self.heartbeat_interval,
        );

        loop {
            let mut stream = make_stream();
            stream.set_token(token.clone());

            let services_report = self.services_report_envelope()?;
            match stream.post_services_report(services_report).await {
                Ok(()) => {
                    info!(
                        services = self.services_report.services.len(),
                        strict_mode = self.services_report.strict_mode,
                        "sent services_report to server"
                    );
                    // After services_report lands on NSD, the server-side
                    // `services_count` for this machine flips from 0 to >0
                    // and `resolve_role` upgrades NSN from `client` to
                    // `relay`. Re-mint now so the control stream receives a
                    // fresh control-purpose bearer while WSS consumers receive
                    // a separate WSS-purpose, role-aware bearer for the next
                    // relay dial.
                    if let Some(refreshed) = self.re_auth_after_services_report().await {
                        token = refreshed.clone();
                        stream.set_token(refreshed);
                    }
                }
                Err(Error::MachineUnknown(url)) => {
                    if self
                        .recover_machine_unknown("services.report", &url)
                        .await
                        .unwrap_or(false)
                    {
                        backoff_secs = 1;
                        continue;
                    }
                    warn!(
                        nsd = %url,
                        backoff = backoff_secs,
                        "services_report found unknown machine; recovery deferred"
                    );
                    tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
                    backoff_secs = (backoff_secs * 2).min(60);
                    continue;
                }
                Err(e) => {
                    warn!(error = %e, backoff = backoff_secs, "failed to POST services_report, retrying");
                    tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
                    backoff_secs = (backoff_secs * 2).min(60);
                    continue;
                }
            }

            let config_stream = self.config_stream_envelope()?;
            match stream.connect(config_stream).await {
                Ok(()) => {
                    info!("connected to SSE config stream");
                    backoff_secs = 1;
                    if let Some(ref tx) = self.status_tx {
                        let _ = tx.send(true).await;
                    }
                }
                Err(e) => {
                    warn!(error = %e, backoff = backoff_secs, "SSE connect failed, retrying");
                    if let Some(ref tx) = self.status_tx {
                        let _ = tx.send(false).await;
                    }
                    tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
                    backoff_secs = (backoff_secs * 2).min(60);
                    continue;
                }
            }

            loop {
                tokio::select! {
                    msg = stream.next_message() => {
                        match msg {
                            Ok(msg) => {
                                backoff_secs = 1;
                                let old_token = token.clone();
                                // Measure receive→dispatch latency per control message,
                                // labeled by bounded event_type. Low-rate event stream,
                                // so this is well off any hot path.
                                let event_type = msg.event_type();
                                let dispatch_start = std::time::Instant::now();
                                let shutdown = self.dispatch_message(msg, &mut token).await;
                                let outcome = match &shutdown {
                                    Ok(_) => telemetry::labels::Outcome::Ok,
                                    Err(_) => telemetry::labels::Outcome::Error,
                                };
                                telemetry::control_otel::record_sse_delivery_duration(
                                    event_type,
                                    outcome,
                                    dispatch_start.elapsed().as_secs_f64(),
                                );
                                if shutdown? {
                                    return Ok(());
                                }
                                if token != old_token {
                                    stream.set_token(token.clone());
                                }
                            }
                            Err(e) => {
                                warn!(
                                    error = %e,
                                    backoff = backoff_secs,
                                    "SSE error, reconnecting"
                                );
                                if let Some(ref tx) = self.status_tx {
                                    let _ = tx.send(false).await;
                                }
                                break;
                            }
                        }
                    }
                    _ = heartbeat.tick(), if self.heartbeat_client.is_some() => {
                        let uptime_secs = self.heartbeat_start_time.elapsed().as_secs();
                        let local_ips = common::SystemInfo::collect_local_ips();
                        match self.send_heartbeat(uptime_secs, local_ips).await {
                            Ok(()) => {}
                            Err(Error::MachineUnknown(url)) => {
                                match self.recover_machine_unknown("heartbeat", &url).await {
                                    Ok(true) => {
                                        if let Some(ref tx) = self.status_tx {
                                            let _ = tx.send(false).await;
                                        }
                                        break;
                                    }
                                    Ok(false) => {
                                        warn!(
                                            nsd = %url,
                                            "heartbeat found unknown machine; recovery deferred"
                                        );
                                    }
                                    Err(e) => {
                                        warn!(
                                            nsd = %url,
                                            error = %e,
                                            "heartbeat machine recovery failed"
                                        );
                                    }
                                }
                            }
                            Err(Error::Unauthorized(url)) => {
                                warn!(
                                    nsd = %url,
                                    "heartbeat unauthorized after bearer refresh; will retry next cycle"
                                );
                            }
                            Err(e) => {
                                warn!(error = %e, "heartbeat failed");
                            }
                        }
                    }
                }
            }

            tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
            backoff_secs = (backoff_secs * 2).min(60);

            match self
                .authenticate_control_with_recovery("stream reconnect authenticate")
                .await
            {
                Ok(t) => token = t,
                Err(e) => {
                    error!(error = %e, "re-authentication failed");
                }
            }
        }
    }

    /// Re-authenticate after a successful services_report.
    ///
    /// Returns the fresh control-purpose bearer for the active control stream
    /// and separately broadcasts a WSS-purpose bearer through
    /// [`Self::token_refresh_tx`]. Best-effort: on failure we log a warn and
    /// let the caller or downstream WSS connector keep its existing token; we
    /// never broadcast the control-purpose bearer to WSS consumers.
    async fn re_auth_after_services_report(&mut self) -> Option<String> {
        match self
            .authenticate_control_with_recovery("post-services authenticate")
            .await
        {
            Ok(control_token) => {
                info!("re-authenticated control stream after services_report");
                match self.auth_client.authenticate_wss().await {
                    Ok(wss_token) => {
                        info!("minted post-services WSS bearer for downstream consumers");
                        if self.token_refresh_tx.send(wss_token).await.is_err() {
                            warn!(
                                "token_refresh receiver dropped before post-services WSS token could be broadcast"
                            );
                        }
                    }
                    Err(e) => {
                        warn!(
                            error = %e,
                            "post-services WSS re-authentication failed; keeping existing downstream WSS token",
                        );
                    }
                }
                Some(control_token)
            }
            Err(e) => {
                warn!(
                    error = %e,
                    "post-services re-authentication failed; continuing with original token",
                );
                None
            }
        }
    }

    async fn authenticate_control_with_recovery(
        &mut self,
        reason: &'static str,
    ) -> Result<String, Error> {
        match self.auth_client.authenticate().await {
            Ok(token) => Ok(token),
            Err(Error::MachineUnknown(url)) => {
                if self.recover_machine_unknown(reason, &url).await? {
                    self.auth_client.authenticate().await
                } else {
                    Err(Error::MachineUnknown(url))
                }
            }
            Err(e) => Err(e),
        }
    }

    async fn send_heartbeat(&self, uptime_secs: u64, local_ips: Vec<String>) -> Result<(), Error> {
        let Some(client) = self.heartbeat_client.as_ref() else {
            return Ok(());
        };
        client.heartbeat(uptime_secs, local_ips).await
    }

    async fn recover_machine_unknown(
        &mut self,
        reason: &'static str,
        url: &str,
    ) -> Result<bool, Error> {
        let Some(recovery) = self.machine_recovery.clone() else {
            warn!(
                nsd_id = self.nsd_id.as_deref().unwrap_or("unknown"),
                nsd = %url,
                reason,
                "machine is unknown but no auth-key recovery is configured"
            );
            return Ok(false);
        };

        let policy = recovery.policy();
        let now = tokio::time::Instant::now();
        if !self.recovery_circuit.can_attempt(policy, now) {
            if self.recovery_circuit.is_open(policy) {
                error!(
                    nsd_id = self.nsd_id.as_deref().unwrap_or("unknown"),
                    nsd = %url,
                    reason,
                    failures = self.recovery_circuit.failures,
                    "machine recovery circuit open; re-registration attempts stopped"
                );
            } else {
                warn!(
                    nsd_id = self.nsd_id.as_deref().unwrap_or("unknown"),
                    nsd = %url,
                    reason,
                    failures = self.recovery_circuit.failures,
                    "machine recovery backoff active"
                );
            }
            return Ok(false);
        }

        info!(
            nsd_id = self.nsd_id.as_deref().unwrap_or("unknown"),
            nsd = %url,
            reason,
            "machine unknown; re-registering with this NSD"
        );

        match self.reregister_machine(&recovery).await {
            Ok(()) => {
                self.recovery_circuit.record_success(policy);
                info!(
                    nsd_id = self.nsd_id.as_deref().unwrap_or("unknown"),
                    nsd = %url,
                    reason,
                    "machine recovery succeeded; signed stream will reconnect"
                );
                Ok(true)
            }
            Err(e) => {
                self.recovery_circuit.record_failure(policy, now);
                if self.recovery_circuit.is_open(policy) {
                    error!(
                        nsd_id = self.nsd_id.as_deref().unwrap_or("unknown"),
                        nsd = %url,
                        reason,
                        failures = self.recovery_circuit.failures,
                        error = %e,
                        "machine recovery exhausted; circuit opened"
                    );
                } else {
                    warn!(
                        nsd_id = self.nsd_id.as_deref().unwrap_or("unknown"),
                        nsd = %url,
                        reason,
                        failures = self.recovery_circuit.failures,
                        error = %e,
                        "machine recovery attempt failed"
                    );
                }
                Err(e)
            }
        }
    }

    async fn reregister_machine(&mut self, recovery: &MachineRecoveryConfig) -> Result<(), Error> {
        self.auth_client
            .register(recovery.auth_key.expose_secret())
            .await?;
        if recovery.persist_state {
            self.auth_client
                .state
                .save(&recovery.state_dir)
                .await
                .map_err(|e| Error::Auth(format!("save recovered machine state: {e}")))?;
        }
        self.heartbeat_client = self.auth_client.heartbeat_client();
        self.auth_client.authenticate().await?;
        let token = self.auth_client.authenticate_wss().await?;
        if self.token_refresh_tx.send(token).await.is_err() {
            warn!("token_refresh receiver dropped before recovered WSS token could be broadcast");
        }
        Ok(())
    }

    fn services_report_envelope(&self) -> Result<ControlEnvelope, Error> {
        self.sign_control_envelope(envelope_api::SERVICES_REPORT, &self.services_report)
    }

    fn config_stream_envelope(&self) -> Result<ControlEnvelope, Error> {
        self.sign_control_envelope(envelope_api::CONFIG_STREAM, &self.config_stream_request)
    }

    fn sign_control_envelope<T: serde::Serialize>(
        &self,
        api_id: &'static str,
        payload: &T,
    ) -> Result<ControlEnvelope, Error> {
        let machine_id = self
            .auth_client
            .state
            .machine_id
            .clone()
            .ok_or_else(|| Error::Auth("not registered".to_string()))?;
        let payload_cbor = api::to_cbor(payload)
            .map_err(|e| Error::Envelope(envelope::Error::CborEncode(format!("{e}"))))?;
        ControlEnvelope::sign_request(
            api_id,
            Some(machine_id),
            self.auth_client.state.machine_key_pub,
            payload_cbor,
            |message| self.auth_client.state.sign(message),
        )
        .map_err(Error::from)
    }

    /// Dispatch a single control message to downstream channels.
    ///
    /// Returns `Ok(true)` when the control plane should shut down (receiver
    /// dropped). Token refreshes update `token`; the caller is responsible
    /// for forwarding the new value to the active [`ControlStream`].
    async fn dispatch_message(
        &self,
        msg: ControlMessage,
        token: &mut String,
    ) -> Result<bool, Error> {
        match msg {
            ControlMessage::WgConfig(cfg) => {
                info!("received wg_config");
                if self.wg_config_tx.send(cfg).await.is_err() {
                    info!("wg_config receiver dropped, shutting down");
                    return Ok(true);
                }
            }
            ControlMessage::ProxyConfig(cfg) => {
                info!("received proxy_config");
                if self.proxy_config_tx.send(cfg).await.is_err() {
                    info!("proxy_config receiver dropped, shutting down");
                    return Ok(true);
                }
            }
            ControlMessage::TokenRefresh { token: new_token } => {
                info!("refreshing auth token");
                *token = new_token.clone();
                let _ = self.token_refresh_tx.send(new_token).await;
            }
            ControlMessage::Ping => {
                // SSE is unidirectional; no pong needed.
            }
            ControlMessage::AclConfig(cfg) => {
                info!("received acl_config");
                if self.acl_config_tx.send(cfg).await.is_err() {
                    info!("acl_config receiver dropped, shutting down");
                    return Ok(true);
                }
            }
            ControlMessage::Pong => {
                // Unexpected direction on SSE stream -- ignore.
            }
            ControlMessage::ServicesAck(ack) => {
                if !ack.matched.is_empty() {
                    info!(
                        services = %ack.matched.join(", "),
                        "server: services matched to proxy rules"
                    );
                }
                if !ack.unmatched.is_empty() {
                    warn!(
                        services = %ack.unmatched.join(", "),
                        "server: services have no proxy rules"
                    );
                }
                if !ack.rejected.is_empty() {
                    warn!(
                        rules = %ack.rejected.join(", "),
                        "server: proxy rules target unknown services"
                    );
                }
            }
            ControlMessage::ServicesReport(_) => {
                warn!("received unexpected services_report from server");
            }
            ControlMessage::GatewayServicesReport(_) => {
                warn!("received unexpected gateway.services_report from server");
            }
            ControlMessage::GatewayServicesAck(ack) => {
                if !ack.accepted_services.is_empty() {
                    info!(
                        services = %ack.accepted_services.join(", "),
                        "server: gateway services accepted"
                    );
                }
                if !ack.accepted_exit_profiles.is_empty() {
                    info!(
                        exit_profiles = %ack.accepted_exit_profiles.join(", "),
                        "server: gateway exit profiles accepted"
                    );
                }
                if !ack.rejected.is_empty() {
                    warn!(
                        declarations = %ack.rejected.join(", "),
                        "server: gateway service declarations rejected"
                    );
                }
            }
            ControlMessage::GatewayConfig(cfg) => {
                info!(gateways = cfg.gateways.len(), "received gateway_config");
                if self.gateway_config_tx.send(cfg).await.is_err() {
                    info!("gateway_config receiver dropped, shutting down");
                    return Ok(true);
                }
            }
            ControlMessage::GatewayWgRelay(cfg) => {
                info!(
                    relay_pairs = cfg.relay_pairs.len(),
                    "ignored gateway_wg_relay on non-gateway control plane"
                );
            }
            ControlMessage::GatewayWssRelay(cfg) => {
                info!(
                    relay_pairs = cfg.relay_pairs.len(),
                    "ignored gateway_wss_relay on non-gateway control plane"
                );
            }
            ControlMessage::GatewayExitNftConfig(cfg) => {
                info!(
                    profiles = cfg.profiles.len(),
                    "ignored gateway_exit_config.v1 on non-gateway control plane"
                );
            }
            ControlMessage::RoutingConfig(cfg) => {
                info!(routes = cfg.routes.len(), "received routing_config");
                if self.routing_config_tx.send(cfg).await.is_err() {
                    info!("routing_config receiver dropped, shutting down");
                    return Ok(true);
                }
            }
            ControlMessage::DnsConfig(cfg) => {
                info!(records = cfg.records.len(), "received dns_config");
                if self.dns_config_tx.send(cfg).await.is_err() {
                    info!("dns_config receiver dropped, shutting down");
                    return Ok(true);
                }
            }
            ControlMessage::GatewayHttpConfig(cfg) => {
                info!(
                    routes = cfg.routes.len(),
                    "ignored gateway_http_config.v1 on non-gateway control plane"
                );
            }
            ControlMessage::GatewayL4Map(cfg) => {
                info!(
                    routes = cfg.routes.len(),
                    "ignored gateway_l4_map.v1 on non-gateway control plane"
                );
            }
            ControlMessage::GatewayCertificateBundle(bundle) => {
                info!(
                    cert_id = %bundle.cert_id,
                    hostnames = bundle.hostnames.len(),
                    generation = bundle.generation,
                    "ignored gateway_certificate_bundle.v1 on non-gateway control plane"
                );
            }
            ControlMessage::PeerCandidates(update) => {
                info!(
                    machine_id = %update.machine_id,
                    epoch = update.epoch,
                    candidates = update.candidates.len(),
                    "received peer_candidates"
                );
                if self.peer_candidates_tx.send(update).await.is_err() {
                    info!("peer_candidates receiver dropped, shutting down");
                    return Ok(true);
                }
            }
            ControlMessage::Unknown => {
                // Forward-compat decode fallback. The stream layer already
                // skips these before dispatch; ignore defensively here too.
                warn!("ignored unknown control message variant");
            }
        }
        Ok(false)
    }
}

pub type ControlPlaneInit = (
    ControlPlane,
    mpsc::Receiver<WgConfig>,
    mpsc::Receiver<ProxyConfig>,
    mpsc::Receiver<AclConfig>,
    mpsc::Receiver<GatewayConfig>,
    mpsc::Receiver<RoutingConfig>,
    mpsc::Receiver<DnsConfig>,
    mpsc::Receiver<PeerCandidatesUpdate>,
    mpsc::Receiver<String>,
);

// -- Helper functions ---------------------------------------------------------

fn build_control_transport(
    config: &ConnectorConfig,
    auth_client: &AuthClient,
) -> Result<Arc<dyn transport::ControlTransport>, Error> {
    if let Some(transport) = auth_client.transport() {
        return Ok(transport);
    }

    match config.control_mode.as_str() {
        "noise" => {
            let transport = build_noise_transport(config, auth_client).map_err(|e| {
                Error::ControlTransportBuild {
                    mode: "noise",
                    reason: e.to_string(),
                }
            })?;
            return Ok(Arc::new(transport));
        }
        "quic" => {
            let transport =
                build_quic_transport(config).map_err(|e| Error::ControlTransportBuild {
                    mode: "quic",
                    reason: e.to_string(),
                })?;
            return Ok(Arc::new(transport));
        }
        _ => {}
    }

    match transport::sse::SseTransport::from_base_url(&config.server_url) {
        Ok(t) => Ok(Arc::new(t)),
        Err(e)
            if config.server_url.starts_with("noise://")
                || config.server_url.starts_with("quic://") =>
        {
            Err(e)
        }
        Err(e) => {
            warn!(error = %e, "failed to build signed SSE transport; falling back to plaintext");
            Ok(Arc::new(transport::sse::SseTransport::plaintext()))
        }
    }
}

fn build_noise_transport(
    config: &ConnectorConfig,
    auth_client: &AuthClient,
) -> Result<transport::noise::NoiseTransport, Error> {
    let hex_str = config
        .noise_bootstrap_pubkey
        .as_deref()
        .ok_or_else(|| Error::Connect("noise mode requires noise_bootstrap_pubkey".to_string()))?;
    let bytes = hex::decode(hex_str)
        .map_err(|e| Error::Connect(format!("invalid noise_bootstrap_pubkey hex: {e}")))?;
    if bytes.len() != 32 {
        return Err(Error::Connect(format!(
            "noise_bootstrap_pubkey must be 32 bytes (64 hex chars), got {}",
            bytes.len()
        )));
    }
    let mut remote_pub = [0u8; 32];
    remote_pub.copy_from_slice(&bytes);
    let local_priv = auth_client.peer_key_priv_bytes();
    Ok(transport::noise::NoiseTransport::new(
        local_priv, remote_pub,
    ))
}

fn build_quic_transport(config: &ConnectorConfig) -> Result<transport::quic::QuicTransport, Error> {
    let hex_str = config
        .quic_bootstrap_cert_sha256
        .as_deref()
        .or(config.noise_bootstrap_pubkey.as_deref())
        .ok_or_else(|| {
            Error::Connect("quic mode requires quic_bootstrap_cert_sha256".to_string())
        })?;
    let bytes = hex::decode(hex_str)
        .map_err(|e| Error::Connect(format!("invalid quic_bootstrap_cert_sha256 hex: {e}")))?;
    if bytes.len() != 32 {
        return Err(Error::Connect(format!(
            "quic_bootstrap_cert_sha256 must be 32 bytes (64 hex chars), got {}",
            bytes.len()
        )));
    }
    let mut fingerprint = [0u8; 32];
    fingerprint.copy_from_slice(&bytes);
    transport::quic::QuicTransport::new(fingerprint)
}

/// Strip a known URL scheme (`https?://`, `noise://`, `quic://`) from `url`.
fn strip_url_scheme(url: &str) -> &str {
    url.strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .or_else(|| url.strip_prefix("noise://"))
        .or_else(|| url.strip_prefix("quic://"))
        .unwrap_or(url)
}

/// Extract `host:port` from a full URL for use as a TCP endpoint.
fn url_to_tcp_endpoint(url: &str) -> String {
    let without_scheme = strip_url_scheme(url);
    let host_port = without_scheme.split('/').next().unwrap_or(without_scheme);
    if host_port.contains(':') {
        host_port.to_string()
    } else {
        format!("{host_port}:443")
    }
}

#[cfg(test)]
mod url_helper_tests {
    use super::url_to_tcp_endpoint;

    #[test]
    fn tcp_endpoint_handles_noise_scheme() {
        assert_eq!(
            url_to_tcp_endpoint("noise://nsd-1:4001/api/v1/info"),
            "nsd-1:4001"
        );
    }

    #[test]
    fn tcp_endpoint_handles_quic_scheme() {
        assert_eq!(url_to_tcp_endpoint("quic://nsd-2:4002"), "nsd-2:4002");
    }

    #[test]
    fn tcp_endpoint_handles_https_default_port() {
        assert_eq!(
            url_to_tcp_endpoint("https://nsd.example.com/api"),
            "nsd.example.com:443"
        );
    }
}

#[cfg(test)]
mod control_transport_build_tests {
    use std::sync::Arc;

    use common::{ConnectorConfig, MachineState};

    use super::{Error, auth::AuthClient, build_control_transport};

    fn dummy_config(control_mode: &str) -> ConnectorConfig {
        ConnectorConfig {
            server_url: "http://nsd.test:3001".to_string(),
            log_level: "info".to_string(),
            services_file: "services.toml".to_string(),
            state_dir: "/tmp/nsio-test".to_string(),
            auth_key: None,
            machine_id: None,
            dns_timeout_secs: 5,
            dns_cache_ttl_secs: 60,
            ws_max_messages_per_sec: 100,
            ws_max_message_size: 1_048_576,
            transport_mode: "auto".to_string(),
            control_centers: vec![],
            gateways: vec![],
            log_dir: None,
            snat_addr: None,
            control_mode: control_mode.to_string(),
            realm: None,
            noise_bootstrap_pubkey: None,
            quic_bootstrap_cert_sha256: None,
            nsd_jwt_key_pins: vec![],
            nsd_envelope_key_pins: vec![],
            conntrack: Default::default(),
            local_acl: Default::default(),
            extra_ca_certs: None,
            wg_relay_registration_endpoint: None,
        }
    }

    async fn auth_client() -> AuthClient {
        let tmpdir = tempfile::tempdir().unwrap();
        let dir = tmpdir.path().to_path_buf();
        std::mem::forget(tmpdir);
        let state = MachineState::load_or_create(&dir).await.unwrap();
        AuthClient::new("http://nsd.test:3001", state)
    }

    #[tokio::test]
    async fn noise_control_mode_build_failure_fails_closed() {
        let config = dummy_config("noise");
        let auth = auth_client().await;

        let err = match build_control_transport(&config, &auth) {
            Ok(transport) => panic!("expected fail-closed error, got {}", transport.name()),
            Err(err) => err,
        };

        match err {
            Error::ControlTransportBuild { mode, reason } => {
                assert_eq!(mode, "noise");
                assert!(reason.contains("requires noise_bootstrap_pubkey"));
            }
            other => panic!("expected noise transport build error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn quic_control_mode_build_failure_fails_closed() {
        let mut config = dummy_config("quic");
        config.noise_bootstrap_pubkey = Some("aa".repeat(16));
        let auth = auth_client().await;

        let err = match build_control_transport(&config, &auth) {
            Ok(transport) => panic!("expected fail-closed error, got {}", transport.name()),
            Err(err) => err,
        };

        match err {
            Error::ControlTransportBuild { mode, reason } => {
                assert_eq!(mode, "quic");
                assert!(reason.contains("32 bytes"));
            }
            other => panic!("expected quic transport build error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn sse_control_mode_still_builds_sse_transport() {
        let config = dummy_config("sse");
        let auth = auth_client().await;
        let transport = build_control_transport(&config, &auth).unwrap();

        assert_eq!(transport.name(), "sse");
        let _: Arc<dyn super::transport::ControlTransport> = transport;
    }
}

#[cfg(test)]
mod post_services_reauth_tests {
    //! AUTH-003 Part 1 unit tests.
    //!
    //! Pins the contract that `ControlPlane::re_auth_after_services_report`
    //! re-mints a control-purpose bearer for the control stream and a separate
    //! WSS-purpose bearer for the existing `token_refresh_tx` channel that
    //! downstream `connector::ConnectorManager` already listens on.

    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::Mutex;

    use async_trait::async_trait;
    use common::{CAPABILITY_CAPTURE_ROUTES_V1, ConnectorConfig, MachineState};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::auth::AuthClient;
    use super::{ControlPlane, ControlStream, MachineRecoveryCircuit, MachineRecoveryPolicy};
    use crate::Error;
    use crate::envelope::ControlEnvelope;
    use crate::messages::ServiceReport;

    /// Tiny scripted HTTP mock: accepts N connections, replays one canned
    /// response per connection, returns nothing. Mirrors the shape used by
    /// `crates/control/src/auth.rs` heartbeat tests so the dependency
    /// surface stays identical.
    async fn run_mock_nsd(listener: TcpListener, responses: Vec<Vec<u8>>) {
        let _ = run_capturing_mock_nsd(listener, responses).await;
    }

    #[derive(Debug, PartialEq, Eq)]
    struct CapturedRequest {
        path: String,
        purpose: Option<String>,
    }

    async fn run_capturing_mock_nsd(listener: TcpListener, responses: Vec<Vec<u8>>) -> Vec<String> {
        run_capturing_mock_nsd_requests(listener, responses)
            .await
            .into_iter()
            .map(|request| request.path)
            .collect()
    }

    async fn run_capturing_mock_nsd_requests(
        listener: TcpListener,
        responses: Vec<Vec<u8>>,
    ) -> Vec<CapturedRequest> {
        let mut requests = Vec::new();
        for resp in responses {
            let (mut sock, _) = listener.accept().await.expect("accept");
            let mut buf = Vec::with_capacity(1024);
            let mut tmp = [0u8; 1024];
            loop {
                let n = sock.read(&mut tmp).await.unwrap_or(0);
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&tmp[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let header_end = buf
                .windows(4)
                .position(|w| w == b"\r\n\r\n")
                .map(|pos| pos + 4)
                .unwrap_or(buf.len());
            let request_head = String::from_utf8_lossy(&buf[..header_end]);
            let content_len = request_head
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    if name.eq_ignore_ascii_case("content-length") {
                        value.trim().parse::<usize>().ok()
                    } else {
                        None
                    }
                })
                .unwrap_or(0);
            let mut body = buf[header_end..].to_vec();
            while body.len() < content_len {
                let n = sock.read(&mut tmp).await.unwrap_or(0);
                if n == 0 {
                    break;
                }
                body.extend_from_slice(&tmp[..n]);
            }
            body.truncate(content_len);

            let path = if let Some(line) = request_head.lines().next()
                && let Some(path) = line.split_whitespace().nth(1)
            {
                path.to_string()
            } else {
                String::new()
            };
            let purpose = serde_json::from_slice::<serde_json::Value>(&body)
                .ok()
                .and_then(|value| {
                    value
                        .get("purpose")
                        .and_then(|purpose| purpose.as_str())
                        .map(str::to_string)
                });
            requests.push(CapturedRequest { path, purpose });
            sock.write_all(&resp).await.expect("write response");
            let _ = sock.shutdown().await;
        }
        requests
    }

    fn http_response(status: u16, body: &str) -> Vec<u8> {
        let phrase = match status {
            200 => "OK",
            401 => "Unauthorized",
            _ => "Status",
        };
        format!(
            "HTTP/1.1 {status} {phrase}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {len}\r\n\r\n{body}",
            len = body.len(),
        )
        .into_bytes()
    }

    async fn registered_state() -> MachineState {
        registered_state_with_machine("test-machine").await
    }

    async fn registered_state_with_machine(machine_id: &str) -> MachineState {
        let tmpdir = tempfile::tempdir().unwrap();
        let dir = tmpdir.path().to_path_buf();
        std::mem::forget(tmpdir);
        let mut state = MachineState::load_or_create(&dir).await.unwrap();
        // The bearer-token refresher requires `machine_id` to be set; a
        // synthetic registration is enough — we never call NSD's register
        // endpoint in these tests.
        state
            .set_registered(
                machine_id.to_string(),
                &"aa".repeat(32),
                "127.0.0.1:51820",
                None,
            )
            .expect("set_registered");
        state
    }

    fn dummy_config(server_url: String) -> Arc<ConnectorConfig> {
        Arc::new(ConnectorConfig {
            server_url,
            log_level: "info".to_string(),
            services_file: "services.toml".to_string(),
            state_dir: "/tmp/nsio-test".to_string(),
            auth_key: None,
            machine_id: None,
            dns_timeout_secs: 5,
            dns_cache_ttl_secs: 60,
            ws_max_messages_per_sec: 100,
            ws_max_message_size: 1_048_576,
            transport_mode: "auto".to_string(),
            control_centers: vec![],
            gateways: vec![],
            log_dir: None,
            snat_addr: None,
            control_mode: "sse".to_string(),
            realm: None,
            noise_bootstrap_pubkey: None,
            quic_bootstrap_cert_sha256: None,
            nsd_jwt_key_pins: vec![],
            nsd_envelope_key_pins: vec![],
            conntrack: Default::default(),
            local_acl: Default::default(),
            extra_ca_certs: None,
            wg_relay_registration_endpoint: None,
        })
    }

    fn empty_report() -> ServiceReport {
        ServiceReport {
            services: HashMap::new(),
            strict_mode: false,
            system_info: None,
        }
    }

    #[tokio::test]
    async fn config_stream_envelope_carries_configured_capabilities() {
        let state = registered_state().await;
        let auth = AuthClient::new("http://127.0.0.1:3001", state);
        let (mut plane, _wg, _proxy, _acl, _gw, _rt, _dns, _peer, _tok_rx) = ControlPlane::new(
            dummy_config("http://127.0.0.1:3001".to_string()),
            empty_report(),
            auth,
        )
        .expect("control plane");

        plane.set_config_stream_capabilities(vec![
            common::CAPABILITY_NSC_APPLICATION_UDP_V1.to_owned(),
            common::CAPABILITY_NSC_APPLICATION_UDP_V1.to_owned(),
            CAPABILITY_CAPTURE_ROUTES_V1.to_owned(),
        ]);

        let envelope = plane
            .config_stream_envelope()
            .expect("config stream envelope");
        let request: crate::api::ConfigStreamRequest =
            crate::api::from_cbor(envelope.payload.as_ref()).expect("decode request");
        assert_eq!(
            request.capabilities,
            vec![
                CAPABILITY_CAPTURE_ROUTES_V1.to_owned(),
                common::CAPABILITY_NSC_APPLICATION_UDP_V1.to_owned(),
            ]
        );
        assert!(request.public_ingress_scopes.is_empty());
    }

    fn register_response(machine_id: &str) -> String {
        let peer = "bb".repeat(32);
        format!(
            r#"{{"machine_id":"{machine_id}","server_peer_key_pub":"{peer}","server_endpoint":"127.0.0.1:51820","domain_base":null}}"#
        )
    }

    struct ConnectedStream {
        tokens: Arc<Mutex<Vec<String>>>,
    }

    #[async_trait]
    impl ControlStream for ConnectedStream {
        async fn post_services_report(&mut self, _envelope: ControlEnvelope) -> Result<(), Error> {
            Ok(())
        }

        async fn connect(&mut self, _envelope: ControlEnvelope) -> Result<(), Error> {
            Ok(())
        }

        async fn next_message(&mut self) -> Result<crate::messages::ControlMessage, Error> {
            std::future::pending().await
        }

        fn set_token(&mut self, token: String) {
            self.tokens.lock().expect("token log poisoned").push(token);
        }
    }

    #[tokio::test]
    async fn re_mints_jwt_after_services_report_succeeds() {
        // Mock returns one control token for the active stream and one WSS
        // token for downstream consumers.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(run_capturing_mock_nsd_requests(
            listener,
            vec![
                http_response(200, r#"{"token":"token-B"}"#),
                http_response(200, r#"{"token":"token-C"}"#),
            ],
        ));

        let state = registered_state().await;
        let url = format!("http://{addr}");
        let auth = AuthClient::new(&url, state);

        let (mut plane, _wg, _proxy, _acl, _gw, _rt, _dns, _peer, mut tok_rx) =
            ControlPlane::new(dummy_config(url), empty_report(), auth).expect("control plane");

        let refreshed = plane.re_auth_after_services_report().await;
        assert_eq!(refreshed.as_deref(), Some("token-B"));

        let broadcast = tok_rx.recv().await.expect("token broadcast");
        assert_eq!(broadcast, "token-C");

        let requests = server.await.expect("mock task panicked");
        assert_eq!(
            requests,
            vec![
                CapturedRequest {
                    path: "/api/v1/machine/auth".to_string(),
                    purpose: Some("control".to_string()),
                },
                CapturedRequest {
                    path: "/api/v1/machine/auth".to_string(),
                    purpose: Some("wss".to_string()),
                },
            ]
        );
    }

    #[tokio::test]
    async fn keeps_original_token_when_re_auth_fails() {
        // Mock returns a single 401. `re_auth_after_services_report` must
        // log warn (not assertable here) and return `None`; the
        // `token_refresh_tx` channel must remain idle so downstream
        // connectors keep using the bearer that was already in flight.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(run_mock_nsd(listener, vec![http_response(401, "")]));

        let state = registered_state().await;
        let url = format!("http://{addr}");
        let auth = AuthClient::new(&url, state);

        let (mut plane, _wg, _proxy, _acl, _gw, _rt, _dns, _peer, mut tok_rx) =
            ControlPlane::new(dummy_config(url), empty_report(), auth).expect("control plane");

        let refreshed = plane.re_auth_after_services_report().await;
        assert!(refreshed.is_none(), "401 must surface as None");

        // The receiver should be empty. `try_recv` returns `Empty` because
        // the sender is still owned by the plane (not dropped), so the
        // channel is open-but-quiet rather than closed.
        let attempt = tok_rx.try_recv();
        assert!(
            matches!(attempt, Err(tokio::sync::mpsc::error::TryRecvError::Empty)),
            "no token must be broadcast on auth failure (got {attempt:?})"
        );
    }

    #[tokio::test]
    async fn keeps_wss_channel_idle_when_post_services_wss_mint_fails() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(run_capturing_mock_nsd_requests(
            listener,
            vec![
                http_response(200, r#"{"token":"control-token"}"#),
                http_response(401, ""),
            ],
        ));

        let state = registered_state().await;
        let url = format!("http://{addr}");
        let auth = AuthClient::new(&url, state);

        let (mut plane, _wg, _proxy, _acl, _gw, _rt, _dns, _peer, mut tok_rx) =
            ControlPlane::new(dummy_config(url), empty_report(), auth).expect("control plane");

        let refreshed = plane.re_auth_after_services_report().await;
        assert_eq!(refreshed.as_deref(), Some("control-token"));
        assert!(matches!(
            tok_rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));

        let requests = server.await.expect("mock task panicked");
        assert_eq!(
            requests,
            vec![
                CapturedRequest {
                    path: "/api/v1/machine/auth".to_string(),
                    purpose: Some("control".to_string()),
                },
                CapturedRequest {
                    path: "/api/v1/machine/auth".to_string(),
                    purpose: Some("wss".to_string()),
                },
            ]
        );
    }

    #[tokio::test]
    async fn run_loop_marks_connected_and_runs_heartbeat_after_stream_open() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(run_capturing_mock_nsd(
            listener,
            vec![
                http_response(200, r#"{"token":"token-B"}"#),
                http_response(200, r#"{"token":"token-C"}"#),
                http_response(200, r#"{"token":"token-D"}"#),
                http_response(204, ""),
            ],
        ));

        let state = registered_state().await;
        let url = format!("http://{addr}");
        let auth = AuthClient::new(&url, state);

        let (mut plane, _wg, _proxy, _acl, _gw, _rt, _dns, _peer, _tok_rx) =
            ControlPlane::new(dummy_config(url), empty_report(), auth).expect("control plane");
        let (status_tx, mut status_rx) = tokio::sync::mpsc::channel(4);
        plane.set_status_tx(status_tx);
        plane.set_heartbeat_interval(std::time::Duration::from_millis(10));

        let tokens = Arc::new(Mutex::new(Vec::new()));
        let make_stream_tokens = Arc::clone(&tokens);
        let run_task = tokio::spawn(async move {
            plane
                .run_loop("token-A".to_string(), move || {
                    Box::new(ConnectedStream {
                        tokens: Arc::clone(&make_stream_tokens),
                    })
                })
                .await
        });

        let connected = tokio::time::timeout(std::time::Duration::from_secs(1), status_rx.recv())
            .await
            .expect("stream should report connected")
            .expect("status channel should stay open");
        assert!(
            connected,
            "stream open must mark the control plane connected"
        );

        let paths = tokio::time::timeout(std::time::Duration::from_secs(1), server)
            .await
            .expect("heartbeat should reach the mock NSD")
            .expect("mock task should not panic");
        assert_eq!(
            paths,
            vec![
                "/api/v1/machine/auth",
                "/api/v1/machine/auth",
                "/api/v1/machine/auth",
                "/api/v1/machine/heartbeat",
            ]
        );

        let tokens = tokens.lock().expect("token log poisoned").clone();
        assert!(
            tokens.contains(&"token-A".to_string()),
            "initial control bearer must be installed on the stream"
        );
        assert!(
            tokens.contains(&"token-B".to_string()),
            "post-services control bearer must be installed on the stream"
        );

        run_task.abort();
        let _ = run_task.await;
    }

    #[tokio::test]
    async fn machine_recovery_fails_when_post_register_control_auth_fails() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(run_capturing_mock_nsd(
            listener,
            vec![
                http_response(200, &register_response("machine-new")),
                http_response(401, ""),
            ],
        ));

        let url = format!("http://{addr}");
        let auth = AuthClient::new(&url, registered_state_with_machine("machine-old").await);
        let recovery_dir = tempfile::tempdir().unwrap();
        let (mut plane, _wg, _proxy, _acl, _gw, _rt, _dns, _peer, mut tok_rx) =
            ControlPlane::new(dummy_config(url.clone()), empty_report(), auth)
                .expect("control plane");
        plane.set_machine_recovery(super::MachineRecoveryConfig::with_auth_key(
            "auth-key",
            recovery_dir.path().to_path_buf(),
            false,
        ));

        let err = plane
            .recover_machine_unknown("heartbeat", &url)
            .await
            .expect_err("control-auth failure must fail recovery");
        match err {
            Error::Unauthorized(returned_url) => assert_eq!(returned_url, url),
            other => panic!("expected Error::Unauthorized, got {other:?}"),
        }

        assert_eq!(
            plane.recovery_circuit.failures, 1,
            "failed control auth must record recovery failure"
        );
        assert!(
            plane.recovery_circuit.next_allowed_at.is_some(),
            "failed recovery must start backoff instead of recording success"
        );
        assert!(matches!(
            tok_rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));

        let paths = server.await.expect("mock task panicked");
        assert_eq!(
            paths,
            vec!["/api/v1/machine/register", "/api/v1/machine/auth"]
        );
    }

    #[tokio::test]
    async fn machine_recovery_propagates_post_register_machine_unknown() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(run_capturing_mock_nsd(
            listener,
            vec![
                http_response(200, &register_response("machine-new")),
                http_response(
                    401,
                    r#"{"code":"machine_unknown","message":"machine row missing"}"#,
                ),
            ],
        ));

        let url = format!("http://{addr}");
        let auth = AuthClient::new(&url, registered_state_with_machine("machine-old").await);
        let recovery_dir = tempfile::tempdir().unwrap();
        let (mut plane, _wg, _proxy, _acl, _gw, _rt, _dns, _peer, mut tok_rx) =
            ControlPlane::new(dummy_config(url.clone()), empty_report(), auth)
                .expect("control plane");
        plane.set_machine_recovery(super::MachineRecoveryConfig::with_auth_key(
            "auth-key",
            recovery_dir.path().to_path_buf(),
            false,
        ));

        let err = plane
            .recover_machine_unknown("heartbeat", &url)
            .await
            .expect_err("post-register machine_unknown must fail recovery");
        match err {
            Error::MachineUnknown(returned_url) => assert_eq!(returned_url, url),
            other => panic!("expected Error::MachineUnknown, got {other:?}"),
        }

        assert_eq!(
            plane.recovery_circuit.failures, 1,
            "post-register machine_unknown must record recovery failure"
        );
        assert!(matches!(
            tok_rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));

        let paths = server.await.expect("mock task panicked");
        assert_eq!(
            paths,
            vec!["/api/v1/machine/register", "/api/v1/machine/auth"]
        );
    }

    #[tokio::test]
    async fn machine_recovery_records_success_only_after_control_and_wss_auth() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(run_capturing_mock_nsd(
            listener,
            vec![
                http_response(200, &register_response("machine-new")),
                http_response(200, r#"{"token":"control-token-new"}"#),
                http_response(200, r#"{"token":"wss-token-new"}"#),
            ],
        ));

        let url = format!("http://{addr}");
        let auth = AuthClient::new(&url, registered_state_with_machine("machine-old").await);
        let recovery_dir = tempfile::tempdir().unwrap();
        let policy = MachineRecoveryPolicy {
            initial_backoff: std::time::Duration::from_millis(10),
            max_backoff: std::time::Duration::from_millis(40),
            max_failures: 3,
        };
        let (mut plane, _wg, _proxy, _acl, _gw, _rt, _dns, _peer, mut tok_rx) =
            ControlPlane::new(dummy_config(url.clone()), empty_report(), auth)
                .expect("control plane");
        plane.set_machine_recovery(
            super::MachineRecoveryConfig::with_auth_key(
                "auth-key",
                recovery_dir.path().to_path_buf(),
                false,
            )
            .with_policy(policy),
        );
        plane.recovery_circuit.failures = 2;
        plane.recovery_circuit.next_backoff = std::time::Duration::from_millis(40);
        plane.recovery_circuit.next_allowed_at = None;

        let recovered = plane
            .recover_machine_unknown("heartbeat", &url)
            .await
            .expect("full recovery should succeed");

        assert!(recovered, "successful proof path must report recovered");
        assert_eq!(
            plane.recovery_circuit.failures, 0,
            "success must reset prior recovery failures"
        );
        assert_eq!(plane.recovery_circuit.next_backoff, policy.initial_backoff);
        assert!(plane.recovery_circuit.next_allowed_at.is_none());
        let token = tok_rx.recv().await.expect("recovered WSS token");
        assert_eq!(token, "wss-token-new");

        let paths = server.await.expect("mock task panicked");
        assert_eq!(
            paths,
            vec![
                "/api/v1/machine/register",
                "/api/v1/machine/auth",
                "/api/v1/machine/auth"
            ]
        );
    }

    #[tokio::test]
    async fn machine_unknown_recovery_reregisters_only_the_target_nsd() {
        let listener_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr_a = listener_a.local_addr().unwrap();
        let server_a = tokio::spawn(run_capturing_mock_nsd(
            listener_a,
            vec![
                http_response(200, &register_response("machine-a-new")),
                http_response(200, r#"{"token":"control-a-new"}"#),
                http_response(200, r#"{"token":"wss-a-new"}"#),
            ],
        ));

        let listener_b = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr_b = listener_b.local_addr().unwrap();

        let url_a = format!("http://{addr_a}");
        let url_b = format!("http://{addr_b}");
        let auth_a = AuthClient::new(&url_a, registered_state_with_machine("machine-a-old").await);
        let auth_b = AuthClient::new(&url_b, registered_state_with_machine("machine-b-old").await);

        let recovery_dir_a = tempfile::tempdir().unwrap();
        let recovery_dir_b = tempfile::tempdir().unwrap();
        let (mut plane_a, _wg_a, _proxy_a, _acl_a, _gw_a, _rt_a, _dns_a, _peer_a, mut tok_rx_a) =
            ControlPlane::new(dummy_config(url_a.clone()), empty_report(), auth_a)
                .expect("control plane a");
        let (mut plane_b, _wg_b, _proxy_b, _acl_b, _gw_b, _rt_b, _dns_b, _peer_b, mut tok_rx_b) =
            ControlPlane::new(dummy_config(url_b.clone()), empty_report(), auth_b)
                .expect("control plane b");
        plane_a.set_nsd_id("nsd-a".to_string());
        plane_b.set_nsd_id("nsd-b".to_string());
        plane_a.set_machine_recovery(super::MachineRecoveryConfig::with_auth_key(
            "auth-a",
            recovery_dir_a.path().to_path_buf(),
            false,
        ));
        plane_b.set_machine_recovery(super::MachineRecoveryConfig::with_auth_key(
            "auth-b",
            recovery_dir_b.path().to_path_buf(),
            false,
        ));

        let recovered = plane_a
            .recover_machine_unknown("heartbeat", &url_a)
            .await
            .expect("target NSD recovery should succeed");

        assert!(recovered, "target NSD should be recovered");
        assert_eq!(
            plane_a.auth_client.state.machine_id.as_deref(),
            Some("machine-a-new")
        );
        assert_eq!(
            plane_b.auth_client.state.machine_id.as_deref(),
            Some("machine-b-old")
        );

        let token_a = tok_rx_a.recv().await.expect("target token refresh");
        assert_eq!(token_a, "wss-a-new");
        assert!(matches!(
            tok_rx_b.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), listener_b.accept())
                .await
                .is_err(),
            "non-target NSD must not receive a recovery request"
        );

        let paths = server_a.await.expect("target mock task panicked");
        assert_eq!(
            paths,
            vec![
                "/api/v1/machine/register",
                "/api/v1/machine/auth",
                "/api/v1/machine/auth"
            ]
        );
    }

    #[test]
    fn machine_recovery_circuit_is_bounded_and_per_nsd() {
        let policy = MachineRecoveryPolicy {
            initial_backoff: std::time::Duration::from_millis(10),
            max_backoff: std::time::Duration::from_millis(40),
            max_failures: 3,
        };
        let now = tokio::time::Instant::now();
        let mut nsd_a = MachineRecoveryCircuit::new(policy);
        let nsd_b = MachineRecoveryCircuit::new(policy);

        nsd_a.record_failure(policy, now);
        assert!(
            !nsd_a.can_attempt(policy, now + std::time::Duration::from_millis(9)),
            "failed NSD must respect its own backoff"
        );
        assert!(
            nsd_b.can_attempt(policy, now),
            "other NSDs must not inherit the failed NSD's backoff"
        );

        nsd_a.record_failure(policy, now + std::time::Duration::from_millis(10));
        nsd_a.record_failure(policy, now + std::time::Duration::from_millis(30));

        assert!(nsd_a.is_open(policy), "failure cap must open the circuit");
        assert!(
            !nsd_a.can_attempt(policy, now + std::time::Duration::from_secs(60)),
            "open circuit must stop retry attempts"
        );
        assert!(
            nsd_b.can_attempt(policy, now + std::time::Duration::from_secs(60)),
            "unaffected NSD must remain eligible"
        );
    }
}
