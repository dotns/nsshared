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
pub mod signed_url;
pub mod sse;
pub mod subnet_route;
pub mod transport;
pub mod types;

pub use api::ControlStreamSession;
pub use envelope::{
    MAX_CLOCK_SKEW_SECS, MAX_HEALTHY_WG_RELAY_RENEWAL_SECS, MAX_WG_RELAY_LEASE_SECS,
    WG_RELAY_CLOCK_MARGIN_SECS, WG_RELAY_DEADLINE_GUARD_SECS, WgRelayLeaseDeadlineError,
    WgRelayLeaseDeadlines, translate_wg_relay_lease_deadlines,
};
pub use types::ConnectorType;

use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::{ConnectorConfig, ControlCenterConfig};
use futures_util::future::BoxFuture;
use secrecy::{ExposeSecret, SecretString};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use auth::{AuthClient, AuthEndpointTrust, VerifiedEnvelopePayload};
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
    /// Server accepted no write because the per-machine candidate-report floor
    /// is still active. Additive fields are optional for older servers.
    #[error("rate limited (server epoch {current_epoch:?}, retry after {retry_after:?})")]
    RateLimited {
        current_epoch: Option<u64>,
        retry_after: Option<Duration>,
    },
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
    /// The restart-unique control-stream attempt counter reached `u32::MAX`.
    /// Wrapping or minting a replacement boot nonce in-process would allow a
    /// stale response to match, so the session-bound contract fails closed.
    #[error("control stream attempt counter exhausted")]
    ControlStreamAttemptCounterExhausted,
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

pub(crate) fn rate_limit_error_from_body(body: &[u8]) -> Error {
    #[derive(serde::Deserialize)]
    struct RateLimitBody {
        #[serde(default)]
        current_epoch: Option<u64>,
        #[serde(default)]
        retry_after_ms: Option<u64>,
    }

    let parsed = serde_json::from_slice::<RateLimitBody>(body).ok();
    Error::RateLimited {
        current_epoch: parsed.as_ref().and_then(|body| body.current_epoch),
        retry_after: parsed
            .and_then(|body| body.retry_after_ms)
            .map(Duration::from_millis),
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

/// Scope- and session-specific control-stream connection status.
///
/// `None` is reserved for legacy or otherwise unproven producers. New
/// [`ControlPlane`] instances always emit the exact logical attempt session so
/// a delayed prior-attempt close cannot affect the current attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlPlaneStatus {
    pub scope: NsdScope,
    pub connected: bool,
    pub stream_session: Option<ControlStreamSession>,
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
    /// Authenticated signed-envelope wall-clock timestamp.
    pub signed_at_unix_secs: u64,
    /// Monotonic anchor captured when the signed event entered verification.
    /// Queue delay must never replace or advance this value.
    pub received_at: Instant,
}

impl ScopedGatewayConfig {
    pub fn from_verified(
        scope: NsdScope,
        verified: VerifiedEnvelopePayload<GatewayConfig>,
    ) -> Self {
        Self {
            scope,
            config: verified.payload,
            signed_at_unix_secs: verified.signed_at_unix_secs,
            received_at: verified.received_at,
        }
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
    gateway_config_tx: mpsc::Sender<VerifiedEnvelopePayload<GatewayConfig>>,
    routing_config_tx: mpsc::Sender<RoutingConfig>,
    dns_config_tx: mpsc::Sender<DnsConfig>,
    peer_candidates_tx: mpsc::Sender<PeerCandidatesUpdate>,
    token_refresh_tx: mpsc::Sender<String>,
    config_stream_request: api::ConfigStreamRequest,
    /// Restart-unique identity retained across endpoint fallbacks.
    stream_session: ControlStreamSession,
    /// Whether the first logical outer connection attempt has started.
    stream_attempt_started: bool,
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
    /// Optional scope/session-specific connection-status sender.
    status_tx: Option<mpsc::Sender<ControlPlaneStatus>>,
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

        let transport = if config.control_centers.is_empty() {
            build_control_transport(&config, &auth_client)?
        } else if let Some(transport) = auth_client.transport() {
            transport
        } else {
            Arc::new(transport::sse::SseTransport::plaintext())
        };
        let heartbeat_client = auth_client.heartbeat_client();
        let recovery_circuit = MachineRecoveryCircuit::new(MachineRecoveryPolicy::default());
        let stream_session = ControlStreamSession::new();

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
            stream_session,
            stream_attempt_started: false,
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

    /// Attach a scope/session-specific connection-status sender.
    pub fn set_status_tx(&mut self, tx: mpsc::Sender<ControlPlaneStatus>) {
        self.status_tx = Some(tx);
    }

    /// Begin one logical outer connection attempt.
    ///
    /// All transport endpoint fallbacks reuse the returned session. Calling
    /// this again advances the checked counter once for the next reconnect.
    fn begin_stream_attempt(&mut self) -> Result<ControlStreamSession, Error> {
        if self.stream_attempt_started {
            self.stream_session = self
                .stream_session
                .checked_next_attempt()
                .ok_or(Error::ControlStreamAttemptCounterExhausted)?;
        } else {
            self.stream_attempt_started = true;
        }
        self.config_stream_request.stream_session = Some(self.stream_session);
        Ok(self.stream_session)
    }

    fn stream_status(
        &self,
        connected: bool,
        stream_session: Option<ControlStreamSession>,
    ) -> ControlPlaneStatus {
        let nsd_id = self
            .nsd_id
            .clone()
            .or_else(|| {
                self.control_endpoint_sequence()
                    .first()
                    .map(|endpoint| endpoint.id().to_string())
            })
            .unwrap_or_else(|| "unknown".to_string());
        ControlPlaneStatus {
            scope: NsdScope::new(nsd_id, self.auth_client.state.realm.clone()),
            connected,
            stream_session,
        }
    }

    async fn send_stream_status(
        &self,
        connected: bool,
        stream_session: Option<ControlStreamSession>,
    ) {
        if let Some(ref tx) = self.status_tx {
            let _ = tx.send(self.stream_status(connected, stream_session)).await;
        }
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
        let mut backoff_secs: u64 = 1;
        let mut heartbeat = tokio::time::interval_at(
            tokio::time::Instant::now() + self.heartbeat_interval,
            self.heartbeat_interval,
        );

        loop {
            let stream_session = self.begin_stream_attempt()?;
            let mut connected = match self.connect_active_endpoint().await {
                Ok(connected) => {
                    backoff_secs = 1;
                    self.send_stream_status(true, Some(stream_session)).await;
                    connected
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        backoff = backoff_secs,
                        "all control endpoints failed, retrying"
                    );
                    self.send_stream_status(false, Some(stream_session)).await;
                    tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
                    backoff_secs = (backoff_secs * 2).min(60);
                    continue;
                }
            };

            match self
                .drive_connected_stream(&mut connected.token, &mut connected.stream, &mut heartbeat)
                .await
            {
                Ok(LiveStreamExit::Shutdown) => {
                    self.send_stream_status(false, Some(stream_session)).await;
                    return Ok(());
                }
                Ok(LiveStreamExit::Disconnected) => {
                    self.send_stream_status(false, Some(stream_session)).await;
                    tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
                    backoff_secs = (backoff_secs * 2).min(60);
                }
                Err(error) => {
                    self.send_stream_status(false, Some(stream_session)).await;
                    return Err(error);
                }
            }
        }
    }

    async fn connect_active_endpoint(&mut self) -> Result<ConnectedControlStream, Error> {
        self.connect_active_endpoint_with(|plane, endpoint| {
            Box::pin(plane.try_connect_endpoint(endpoint))
        })
        .await
    }

    async fn connect_active_endpoint_with<T, F>(&mut self, mut connect: F) -> Result<T, Error>
    where
        F: for<'a> FnMut(&'a mut Self, ControlEndpoint) -> BoxFuture<'a, Result<T, Error>>,
    {
        let endpoints = self.control_endpoint_sequence();
        if endpoints.is_empty() {
            return Err(Error::Connect(
                "no control endpoints configured".to_string(),
            ));
        }

        let timeout = self.endpoint_attempt_timeout();
        let mut failures = Vec::new();
        for endpoint in endpoints {
            let id = endpoint.id().to_string();
            let url = endpoint.url().to_string();
            match tokio::time::timeout(timeout, connect(self, endpoint)).await {
                Ok(Ok(connected)) => return Ok(connected),
                Ok(Err(e)) => {
                    warn!(
                        nsd_id = %id,
                        nsd = %url,
                        error = %e,
                        "control endpoint attempt failed"
                    );
                    failures.push(format!("{id} ({url}): {e}"));
                }
                Err(_) => {
                    warn!(
                        nsd_id = %id,
                        nsd = %url,
                        timeout_secs = timeout.as_secs(),
                        "control endpoint attempt timed out"
                    );
                    failures.push(format!(
                        "{id} ({url}): timed out after {}s",
                        timeout.as_secs()
                    ));
                }
            }
        }

        Err(Error::Connect(format!(
            "all control endpoints failed: {}",
            failures.join("; ")
        )))
    }

    async fn try_connect_endpoint(
        &mut self,
        endpoint: ControlEndpoint,
    ) -> Result<ConnectedControlStream, Error> {
        let endpoint_config = self.endpoint_connector_config(&endpoint);
        let build_auth = self.auth_client.rebound_for_endpoint(
            endpoint.url(),
            None,
            self.endpoint_trust(&endpoint),
        );
        let transport = build_control_transport(&endpoint_config, &build_auth)?;
        let auth_client = self.auth_client.rebound_for_endpoint(
            endpoint.url(),
            Some(transport.clone()),
            self.endpoint_trust(&endpoint),
        );

        self.transport = transport.clone();
        self.auth_client = auth_client;
        self.heartbeat_client = self.auth_client.heartbeat_client();

        let mut token = self
            .authenticate_control_with_recovery("control endpoint authenticate")
            .await?;
        info!(
            nsd_id = %endpoint.id(),
            nsd = %endpoint.url(),
            transport = %self.transport.name(),
            "authenticated with control endpoint"
        );

        let mut stream = self.make_control_stream(transport, &endpoint);
        stream.set_token(token.clone());

        let services_report = self.services_report_envelope()?;
        match stream.post_services_report(services_report).await {
            Ok(()) => {
                info!(
                    nsd_id = %endpoint.id(),
                    nsd = %endpoint.url(),
                    services = self.services_report.services.len(),
                    strict_mode = self.services_report.strict_mode,
                    "sent services_report to control endpoint"
                );
            }
            Err(Error::MachineUnknown(url)) => {
                if self
                    .recover_machine_unknown("services.report", &url)
                    .await
                    .unwrap_or(false)
                {
                    token = self
                        .authenticate_control_with_recovery("post-recovery authenticate")
                        .await?;
                    stream.set_token(token.clone());
                    let services_report = self.services_report_envelope()?;
                    stream.post_services_report(services_report).await?;
                } else {
                    return Err(Error::MachineUnknown(url));
                }
            }
            Err(e) => return Err(e),
        }

        if let Some(refreshed) = self.re_auth_after_services_report().await {
            token = refreshed.clone();
            stream.set_token(refreshed);
        }

        let config_stream = self.config_stream_envelope()?;
        stream.connect(config_stream).await?;
        info!(
            nsd_id = %endpoint.id(),
            nsd = %endpoint.url(),
            "connected to control config stream"
        );

        Ok(ConnectedControlStream { stream, token })
    }

    async fn drive_connected_stream(
        &mut self,
        token: &mut String,
        stream: &mut Box<dyn ControlStream>,
        heartbeat: &mut tokio::time::Interval,
    ) -> Result<LiveStreamExit, Error> {
        loop {
            tokio::select! {
                msg = stream.next_message() => {
                    match msg {
                        Ok(msg) => {
                            let old_token = token.clone();
                            let event_type = msg.payload.event_type();
                            let dispatch_start = std::time::Instant::now();
                            let shutdown = self.dispatch_message(msg, token).await;
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
                                return Ok(LiveStreamExit::Shutdown);
                            }
                            if *token != old_token {
                                stream.set_token(token.clone());
                            }
                        }
                        Err(e) => {
                            warn!(error = %e, "SSE error, reconnecting");
                            return Ok(LiveStreamExit::Disconnected);
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
                                Ok(true) => return Ok(LiveStreamExit::Disconnected),
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
    }

    fn control_endpoint_sequence(&self) -> Vec<ControlEndpoint> {
        let explicit_centers = !self.config.control_centers.is_empty();
        let mut centers = self.config.effective_control_centers();
        if !explicit_centers
            && centers.len() == 1
            && let Some(nsd_id) = &self.nsd_id
        {
            centers[0].id.clone_from(nsd_id);
        }
        // PLAN-009: an explicit `nsd_default_mode` names the primary endpoint by
        // transport, overriding list / priority order before the per-endpoint
        // fallback loop consumes the sequence.
        order_endpoints_by_default_mode(
            &mut centers,
            self.config.nsd_default_mode.as_deref(),
            |cc| cc.url.as_str(),
        );
        centers
            .into_iter()
            .map(|config| {
                let mode = if explicit_centers {
                    control_mode_from_url(&config.url).to_string()
                } else {
                    self.config.control_mode.clone()
                };
                ControlEndpoint { config, mode }
            })
            .collect()
    }

    fn endpoint_connector_config(&self, endpoint: &ControlEndpoint) -> ConnectorConfig {
        let mut config = (*self.config).clone();
        config.server_url = endpoint.config.url.clone();
        config.control_centers.clear();
        config.control_mode = endpoint.mode.clone();
        config.nsd_default_mode = None;
        config.realm = endpoint.config.realm.clone();
        config.noise_bootstrap_pubkey = endpoint.config.noise_bootstrap_pubkey.clone();
        config.quic_bootstrap_cert_sha256 = endpoint.config.quic_bootstrap_cert_sha256.clone();
        config.nsd_envelope_key_pins = endpoint.config.nsd_envelope_key_pins.clone();
        config
    }

    fn endpoint_trust(&self, endpoint: &ControlEndpoint) -> AuthEndpointTrust {
        AuthEndpointTrust {
            nsd_id: endpoint.config.id.clone(),
            realm: endpoint
                .config
                .realm
                .clone()
                .or_else(|| self.config.realm.clone())
                .unwrap_or_else(|| "default".to_string()),
            state_dir: PathBuf::from(&self.config.state_dir),
            jwt_key_pins: self.config.nsd_jwt_key_pins.clone(),
            envelope_key_pins: endpoint.config.nsd_envelope_key_pins.clone(),
            advertised_envelope_pubkey: None,
        }
    }

    fn make_control_stream(
        &self,
        transport: Arc<dyn transport::ControlTransport>,
        endpoint: &ControlEndpoint,
    ) -> Box<dyn ControlStream> {
        let tcp_endpoint = url_to_tcp_endpoint(endpoint.url());
        let max_rate = self.config.ws_max_messages_per_sec;
        let max_size = self.config.ws_max_message_size;
        let envelope_trust = self.auth_client.envelope_trust();
        if transport.name() == "sse" {
            Box::new(SseControl::new(
                transport,
                tcp_endpoint,
                max_rate,
                max_size,
                envelope_trust,
            ))
        } else {
            Box::new(NoiseControl::new(
                transport,
                tcp_endpoint,
                max_rate,
                max_size,
                envelope_trust,
            ))
        }
    }

    fn endpoint_attempt_timeout(&self) -> Duration {
        Duration::from_secs(self.config.nsd_endpoint_attempt_timeout_secs)
    }

    /// Shared SSE/Noise loop. `make_stream` opens a fresh stream on each
    /// reconnect; the auth token is rotated on `ControlMessage::TokenRefresh`.
    #[cfg(test)]
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
            let stream_session = self.begin_stream_attempt()?;
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
                    self.send_stream_status(true, Some(stream_session)).await;
                }
                Err(e) => {
                    warn!(error = %e, backoff = backoff_secs, "SSE connect failed, retrying");
                    self.send_stream_status(false, Some(stream_session)).await;
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
                                let event_type = msg.payload.event_type();
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
                                match shutdown {
                                    Ok(true) => {
                                        self.send_stream_status(false, Some(stream_session)).await;
                                        return Ok(());
                                    }
                                    Ok(false) => {}
                                    Err(error) => {
                                        self.send_stream_status(false, Some(stream_session)).await;
                                        return Err(error);
                                    }
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
                                self.send_stream_status(false, Some(stream_session)).await;
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
                                        self.send_stream_status(false, Some(stream_session)).await;
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
        verified: VerifiedEnvelopePayload<ControlMessage>,
        token: &mut String,
    ) -> Result<bool, Error> {
        let VerifiedEnvelopePayload {
            payload: msg,
            signed_at_unix_secs,
            received_at,
        } = verified;
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
                if self
                    .gateway_config_tx
                    .send(VerifiedEnvelopePayload {
                        payload: cfg,
                        signed_at_unix_secs,
                        received_at,
                    })
                    .await
                    .is_err()
                {
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
            ControlMessage::GatewayEgressWgConfig(cfg) => {
                info!(
                    pairings = cfg.pairings.len(),
                    source_identities = cfg.source_identities.len(),
                    "ignored gateway_egress_wg_config.v1 on non-gateway control plane"
                );
            }
            ControlMessage::GatewayExitNftConfig(cfg) => {
                info!(
                    pairings = cfg.pairings.len(),
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
            ControlMessage::GatewayAuthConfig(cfg) => {
                info!(
                    realm_id = %cfg.realm_id,
                    generation = cfg.generation,
                    providers = cfg.providers.len(),
                    "ignored gateway_auth_config.v1 on non-gateway control plane"
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
            ControlMessage::GatewayClientCaBundle(bundle) => {
                info!(
                    trust_ref = %bundle.trust_ref,
                    hostnames = bundle.hostnames.len(),
                    generation = bundle.generation,
                    "ignored gateway_client_ca_bundle.v1 on non-gateway control plane"
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
            ControlMessage::SubnetRouteConfig(cfg) => {
                // NODE-001 (PLAN-015) lands the wire contract only. Installing
                // approved subnet routes is node data-plane work tracked in ns
                // PLAN-124, so this arm decodes and ignores: no channel send,
                // no route install, no forwarding state. NSD gates the event on
                // `node.accept-subnet-routes.v1`, so a node that does not
                // advertise the capability never reaches this arm.
                info!(
                    generation = cfg.generation,
                    routes = cfg.routes.len(),
                    "ignored subnet_route_config (consumer not wired on this control plane)"
                );
            }
            ControlMessage::PolicyVersion { version } => {
                // TASK-049 (PLAN-095): pure no-op on this control plane. The
                // policy_version consumer is wired in nsgw only; NSN/NSC consumer
                // wiring is a deferred follow-up. Decode-and-ignore (no channel
                // send, no state change, no NSN behavior). In practice this arm is
                // unreachable until NSN/NSC advertise `policy_version.v1`, which a
                // gated NSD requires before it will emit the event.
                info!(
                    version,
                    "ignored policy_version (consumer not wired on this control plane)"
                );
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
    mpsc::Receiver<VerifiedEnvelopePayload<GatewayConfig>>,
    mpsc::Receiver<RoutingConfig>,
    mpsc::Receiver<DnsConfig>,
    mpsc::Receiver<PeerCandidatesUpdate>,
    mpsc::Receiver<String>,
);

#[derive(Clone)]
struct ControlEndpoint {
    config: ControlCenterConfig,
    mode: String,
}

impl ControlEndpoint {
    fn id(&self) -> &str {
        &self.config.id
    }

    fn url(&self) -> &str {
        &self.config.url
    }
}

struct ConnectedControlStream {
    stream: Box<dyn ControlStream>,
    token: String,
}

enum LiveStreamExit {
    Disconnected,
    Shutdown,
}

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

/// Canonical control-transport mode for a control endpoint URL scheme.
///
/// `noise://` → `"noise"`, `quic://` → `"quic"`, and everything else
/// (`http(s)://` or scheme-less) → `"sse"`. This is the single shared
/// scheme → mode mapping used by the per-endpoint fallback ordering and by
/// [`order_endpoints_by_default_mode`]; nsgw and ns reuse it so all repos
/// classify endpoints identically.
pub fn control_mode_from_url(url: &str) -> &'static str {
    if url.starts_with("noise://") {
        "noise"
    } else if url.starts_with("quic://") {
        "quic"
    } else {
        "sse"
    }
}

/// Reorder `items` in place so the first endpoint whose URL scheme maps to
/// `default_mode` becomes primary, preserving every other entry's relative
/// order.
///
/// Implements the `nsd_default_mode` selector (PLAN-009): an explicit
/// primary-by-transport choice that is independent of list / priority order.
/// The scheme → mode mapping is [`control_mode_from_url`], shared with the
/// per-endpoint fallback so ns-shared, nsgw, and ns all reorder identically.
/// `url_of` extracts the URL from each item, so the helper is reusable across
/// endpoint representations (ns-shared `ControlCenterConfig`, nsgw
/// `BootstrapControlConfig`, plain `String` URL lists, …).
///
/// Behaviour:
/// - `default_mode == None` → no-op (`items[0]` stays primary). This keeps an
///   unset `nsd_default_mode` byte-for-byte backward compatible.
/// - `Some(mode)` with the first scheme-matching entry at index `i` → that
///   entry is rotated to the front: result is
///   `[items[i]] ++ items[..i] ++ items[i+1..]` (stable for the rest). `i == 0`
///   is a no-op.
/// - `Some(mode)` with no scheme match (including an unrecognised `mode`) →
///   no-op.
pub fn order_endpoints_by_default_mode<T>(
    items: &mut [T],
    default_mode: Option<&str>,
    url_of: impl Fn(&T) -> &str,
) {
    let Some(mode) = default_mode else {
        return;
    };
    let Some(idx) = items
        .iter()
        .position(|item| control_mode_from_url(url_of(item)) == mode)
    else {
        return;
    };
    // `i == 0` rotates a single-element prefix → no-op; `i > 0` moves item `i`
    // to the front while keeping the relative order of all other entries.
    items[..=idx].rotate_right(1);
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
mod order_endpoints_tests {
    use common::ControlCenterConfig;

    use super::order_endpoints_by_default_mode;

    fn urls(items: &[String]) -> Vec<&str> {
        items.iter().map(String::as_str).collect()
    }

    #[test]
    fn none_default_mode_is_noop() {
        let mut list = vec![
            "https://sse.example".to_string(),
            "noise://noise.example:4001".to_string(),
            "quic://quic.example:4002".to_string(),
        ];
        order_endpoints_by_default_mode(&mut list, None, |u| u.as_str());
        assert_eq!(
            urls(&list),
            vec![
                "https://sse.example",
                "noise://noise.example:4001",
                "quic://quic.example:4002",
            ]
        );
    }

    #[test]
    fn picks_first_scheme_match_as_primary() {
        // [sse, noise] + default_mode="noise" -> noise becomes primary.
        let mut list = vec![
            "https://sse.example".to_string(),
            "noise://noise.example:4001".to_string(),
        ];
        order_endpoints_by_default_mode(&mut list, Some("noise"), |u| u.as_str());
        assert_eq!(
            urls(&list),
            vec!["noise://noise.example:4001", "https://sse.example"]
        );
    }

    #[test]
    fn remaining_entries_keep_relative_order() {
        // The first quic moves to front; every other entry keeps its order.
        let mut list = vec![
            "https://sse-1.example".to_string(),
            "noise://noise.example:4001".to_string(),
            "quic://quic.example:4002".to_string(),
            "https://sse-2.example".to_string(),
        ];
        order_endpoints_by_default_mode(&mut list, Some("quic"), |u| u.as_str());
        assert_eq!(
            urls(&list),
            vec![
                "quic://quic.example:4002",
                "https://sse-1.example",
                "noise://noise.example:4001",
                "https://sse-2.example",
            ]
        );
    }

    #[test]
    fn picks_first_of_duplicate_scheme_matches_stably() {
        let mut list = vec![
            "https://sse.example".to_string(),
            "noise://noise-1.example:4001".to_string(),
            "noise://noise-2.example:4001".to_string(),
        ];
        order_endpoints_by_default_mode(&mut list, Some("noise"), |u| u.as_str());
        assert_eq!(
            urls(&list),
            vec![
                "noise://noise-1.example:4001",
                "https://sse.example",
                "noise://noise-2.example:4001",
            ]
        );
    }

    #[test]
    fn no_scheme_match_is_noop() {
        let mut list = vec![
            "https://sse.example".to_string(),
            "noise://noise.example:4001".to_string(),
        ];
        order_endpoints_by_default_mode(&mut list, Some("quic"), |u| u.as_str());
        assert_eq!(
            urls(&list),
            vec!["https://sse.example", "noise://noise.example:4001"]
        );
    }

    #[test]
    fn unrecognised_mode_is_noop() {
        let mut list = vec![
            "https://sse.example".to_string(),
            "noise://noise.example:4001".to_string(),
        ];
        order_endpoints_by_default_mode(&mut list, Some("not-a-mode"), |u| u.as_str());
        assert_eq!(
            urls(&list),
            vec!["https://sse.example", "noise://noise.example:4001"]
        );
    }

    #[test]
    fn match_already_primary_is_noop() {
        // First scheme match at index 0 -> unchanged.
        let mut list = vec![
            "noise://noise.example:4001".to_string(),
            "https://sse.example".to_string(),
        ];
        order_endpoints_by_default_mode(&mut list, Some("noise"), |u| u.as_str());
        assert_eq!(
            urls(&list),
            vec!["noise://noise.example:4001", "https://sse.example"]
        );
    }

    #[test]
    fn scheme_less_url_classifies_as_sse() {
        // [noise, scheme-less] + default_mode="sse" -> scheme-less endpoint first.
        let mut list = vec![
            "noise://noise.example:4001".to_string(),
            "nsd.example.com".to_string(),
        ];
        order_endpoints_by_default_mode(&mut list, Some("sse"), |u| u.as_str());
        assert_eq!(
            urls(&list),
            vec!["nsd.example.com", "noise://noise.example:4001"]
        );
    }

    #[test]
    fn works_on_control_center_config_via_url_accessor() {
        // Reusability across endpoint representations: the same helper reorders
        // ns-shared's `ControlCenterConfig` list via the `url` field accessor,
        // exactly as nsgw / ns will reorder their own endpoint structs.
        let cc = |id: &str, url: &str| ControlCenterConfig {
            id: id.to_string(),
            url: url.to_string(),
            realm: None,
            noise_bootstrap_pubkey: None,
            quic_bootstrap_cert_sha256: None,
            nsd_envelope_key_pins: vec![],
            priority: 1,
        };
        let mut centers = vec![
            cc("sse", "https://sse.example"),
            cc("quic", "quic://quic.example:4002"),
            cc("noise", "noise://noise.example:4001"),
        ];
        order_endpoints_by_default_mode(&mut centers, Some("noise"), |c| c.url.as_str());
        let ids: Vec<&str> = centers.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(ids, vec!["noise", "sse", "quic"]);
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
            nsd_endpoint_attempt_timeout_secs: 8,
            dns_cache_ttl_secs: 60,
            ws_max_messages_per_sec: 100,
            ws_max_message_size: 1_048_576,
            transport_mode: "auto".to_string(),
            control_centers: vec![],
            gateways: vec![],
            log_dir: None,
            snat_addr: None,
            control_mode: control_mode.to_string(),
            nsd_default_mode: None,
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
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use async_trait::async_trait;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use common::{
        CAPABILITY_CAPTURE_ROUTES_V1, ConnectorConfig, ControlCenterConfig, MachineState,
    };
    use futures_util::future::BoxFuture;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::auth::AuthClient;
    use super::{ControlPlane, ControlStream, MachineRecoveryCircuit, MachineRecoveryPolicy};
    use crate::Error;
    use crate::envelope::ControlEnvelope;
    use crate::messages::ServiceReport;

    #[derive(Clone)]
    struct RecordedStreamAttempt {
        mode: &'static str,
        endpoint: String,
        envelope: ControlEnvelope,
    }

    struct RecordingFallbackTransport {
        mode: &'static str,
        attempts: Arc<Mutex<Vec<RecordedStreamAttempt>>>,
    }

    impl crate::transport::ControlTransport for RecordingFallbackTransport {
        fn connect<'a>(
            &'a self,
            _endpoint: &'a str,
        ) -> BoxFuture<'a, Result<crate::transport::BoxStream, Error>> {
            Box::pin(async { Err(Error::Connect("scripted endpoint fallback".to_string())) })
        }

        fn connect_stream<'a>(
            &'a self,
            endpoint: &'a str,
            envelope: ControlEnvelope,
            _bearer_token: Option<&'a str>,
        ) -> BoxFuture<'a, Result<crate::transport::BoxStream, Error>> {
            let attempts = Arc::clone(&self.attempts);
            let mode = self.mode;
            let endpoint = endpoint.to_string();
            Box::pin(async move {
                attempts
                    .lock()
                    .expect("attempt log poisoned")
                    .push(RecordedStreamAttempt {
                        mode,
                        endpoint,
                        envelope,
                    });
                Err(Error::Connect("scripted endpoint fallback".to_string()))
            })
        }

        fn name(&self) -> &str {
            self.mode
        }
    }

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
        let session = plane
            .begin_stream_attempt()
            .expect("first stream attempt must have a session");

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
        assert_eq!(request.stream_session, Some(session));
    }

    #[tokio::test]
    async fn logical_reconnect_advances_session_once_and_exhaustion_fails_closed() {
        let mut config = (*dummy_config("http://legacy.test:3001".to_string())).clone();
        config.control_centers = vec![
            control_center("sse", "http://sse.test:3001", 1, None, None, vec![]),
            control_center(
                "noise",
                "noise://noise.test:4001",
                2,
                Some("aa".repeat(32)),
                None,
                vec![],
            ),
            control_center(
                "quic",
                "quic://quic.test:4002",
                3,
                None,
                Some("bb".repeat(32)),
                vec![],
            ),
        ];
        let mut plane = plane_for_config(Arc::new(config)).await;

        let first = plane.begin_stream_attempt().expect("first logical attempt");
        let attempts = Arc::new(Mutex::new(Vec::new()));
        let attempt_log = Arc::clone(&attempts);
        let error = plane
            .connect_active_endpoint_with::<(), _>(move |plane, endpoint| {
                let attempts = Arc::clone(&attempt_log);
                Box::pin(async move {
                    let mode = match endpoint.mode.as_str() {
                        "sse" => "sse",
                        "noise" => "noise",
                        "quic" => "quic",
                        other => panic!("unexpected endpoint mode {other}"),
                    };
                    let transport: Arc<dyn crate::transport::ControlTransport> =
                        Arc::new(RecordingFallbackTransport { mode, attempts });
                    let mut stream = plane.make_control_stream(transport, &endpoint);
                    stream.set_token("control-token".to_string());
                    stream
                        .connect(
                            plane
                                .config_stream_envelope()
                                .expect("fallback request envelope"),
                        )
                        .await?;
                    Ok(())
                })
            })
            .await
            .expect_err("every scripted endpoint must fail after recording its request");
        assert!(error.to_string().contains("all control endpoints failed"));

        let attempts = attempts.lock().expect("attempt log poisoned").clone();
        assert_eq!(attempts.len(), 3);
        assert_eq!(
            attempts
                .iter()
                .map(|attempt| attempt.mode)
                .collect::<Vec<_>>(),
            vec!["sse", "noise", "quic"]
        );
        assert_eq!(
            attempts
                .iter()
                .map(|attempt| attempt.endpoint.as_str())
                .collect::<Vec<_>>(),
            vec!["sse.test:3001", "noise.test:4001", "quic.test:4002"]
        );
        for attempt in attempts {
            let path = crate::transport::sse::config_stream_path(&attempt.envelope)
                .expect("transport request path");
            let encoded = path
                .strip_prefix("/api/v1/config/stream?request=")
                .expect("session-only fallback must carry the signed request");
            let signed_bytes = URL_SAFE_NO_PAD
                .decode(encoded)
                .expect("signed request base64url");
            let signed_envelope =
                ControlEnvelope::from_cbor(&signed_bytes).expect("signed fallback envelope");
            signed_envelope
                .verify_request(signed_envelope.ts)
                .expect("fallback request signature");
            let request: crate::api::ConfigStreamRequest =
                crate::api::from_cbor(signed_envelope.payload.as_ref())
                    .expect("decode fallback request");
            assert_eq!(request.stream_session, Some(first));
        }

        let second = plane
            .begin_stream_attempt()
            .expect("second logical attempt");
        assert_eq!(second.boot_nonce, first.boot_nonce);
        assert_eq!(
            second.attempt_counter.get(),
            first.attempt_counter.get() + 1
        );

        plane.stream_session = crate::api::ControlStreamSession::from_parts(
            [7; 16],
            std::num::NonZeroU32::new(u32::MAX).unwrap(),
        )
        .unwrap();
        plane.stream_attempt_started = true;
        assert!(matches!(
            plane.begin_stream_attempt(),
            Err(Error::ControlStreamAttemptCounterExhausted)
        ));
    }

    #[tokio::test]
    async fn queued_gateway_config_deadlines_stay_anchored_at_verification_receipt() {
        let state = registered_state().await;
        let auth = AuthClient::new("http://127.0.0.1:3001", state);
        let (plane, _wg, _proxy, _acl, mut gateway_rx, _rt, _dns, _peer, _tok_rx) =
            ControlPlane::new(
                dummy_config("http://127.0.0.1:3001".to_string()),
                empty_report(),
                auth,
            )
            .expect("control plane");
        let signed_at_unix_secs = 10_000;
        let received_at = std::time::Instant::now();
        let session = crate::ControlStreamSession::new();
        let config = crate::messages::GatewayConfig {
            gateways: Vec::new(),
            wg_relay_roster: Some(crate::messages::WgRelayIdentityRoster {
                session,
                config_version: 7,
                confirm_not_before_unix_secs: signed_at_unix_secs,
                expires_at_unix_secs: signed_at_unix_secs + crate::MAX_WG_RELAY_LEASE_SECS,
                endpoints: Vec::new(),
                fleet_lease_enforced: true,
            }),
        };
        let mut token = "token".to_string();

        plane
            .dispatch_message(
                crate::auth::VerifiedEnvelopePayload {
                    payload: crate::messages::ControlMessage::GatewayConfig(config),
                    signed_at_unix_secs,
                    received_at,
                },
                &mut token,
            )
            .await
            .expect("dispatch verified gateway config");
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        let verified = gateway_rx.recv().await.expect("queued gateway config");
        let scoped = crate::ScopedGatewayConfig::from_verified(
            crate::NsdScope::new("nsd-a", "realm-a"),
            verified,
        );
        let roster = scoped
            .config
            .wg_relay_roster
            .as_ref()
            .expect("verified roster");

        let deadlines = crate::translate_wg_relay_lease_deadlines(
            scoped.signed_at_unix_secs,
            roster.confirm_not_before_unix_secs,
            roster.expires_at_unix_secs,
            scoped.received_at,
        )
        .expect("translate from the retained receipt anchor");
        let simulated_dequeue_at = received_at + std::time::Duration::from_secs(30);
        let wrongly_dequeue_anchored = crate::translate_wg_relay_lease_deadlines(
            scoped.signed_at_unix_secs,
            roster.confirm_not_before_unix_secs,
            roster.expires_at_unix_secs,
            simulated_dequeue_at,
        )
        .expect("comparison translation");

        assert_eq!(scoped.received_at, received_at);
        assert_eq!(
            deadlines.expires_at,
            received_at
                + std::time::Duration::from_secs(
                    crate::MAX_WG_RELAY_LEASE_SECS - crate::WG_RELAY_DEADLINE_GUARD_SECS,
                )
        );
        assert_eq!(
            wrongly_dequeue_anchored
                .expires_at
                .duration_since(deadlines.expires_at),
            std::time::Duration::from_secs(30)
        );
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

        async fn next_message(
            &mut self,
        ) -> Result<crate::auth::VerifiedEnvelopePayload<crate::messages::ControlMessage>, Error>
        {
            std::future::pending().await
        }

        fn set_token(&mut self, token: String) {
            self.tokens.lock().expect("token log poisoned").push(token);
        }
    }

    struct PendingStream {
        polls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl ControlStream for PendingStream {
        async fn post_services_report(&mut self, _envelope: ControlEnvelope) -> Result<(), Error> {
            Ok(())
        }

        async fn connect(&mut self, _envelope: ControlEnvelope) -> Result<(), Error> {
            Ok(())
        }

        async fn next_message(
            &mut self,
        ) -> Result<crate::auth::VerifiedEnvelopePayload<crate::messages::ControlMessage>, Error>
        {
            self.polls.fetch_add(1, Ordering::SeqCst);
            std::future::pending().await
        }

        fn set_token(&mut self, _token: String) {}
    }

    struct DisconnectStream;

    #[async_trait]
    impl ControlStream for DisconnectStream {
        async fn post_services_report(&mut self, _envelope: ControlEnvelope) -> Result<(), Error> {
            Ok(())
        }

        async fn connect(&mut self, _envelope: ControlEnvelope) -> Result<(), Error> {
            Ok(())
        }

        async fn next_message(
            &mut self,
        ) -> Result<crate::auth::VerifiedEnvelopePayload<crate::messages::ControlMessage>, Error>
        {
            Err(Error::Sse("scripted disconnect".to_string()))
        }

        fn set_token(&mut self, _token: String) {}
    }

    fn control_center(
        id: &str,
        url: &str,
        priority: u32,
        noise_key: Option<String>,
        quic_key: Option<String>,
        pins: Vec<String>,
    ) -> ControlCenterConfig {
        ControlCenterConfig {
            id: id.to_string(),
            url: url.to_string(),
            realm: None,
            noise_bootstrap_pubkey: noise_key,
            quic_bootstrap_cert_sha256: quic_key,
            nsd_envelope_key_pins: pins,
            priority,
        }
    }

    async fn plane_for_config(config: Arc<ConnectorConfig>) -> ControlPlane {
        let state = registered_state().await;
        let auth = AuthClient::new("http://bootstrap.test:3001", state);
        let (plane, _wg, _proxy, _acl, _gw, _rt, _dns, _peer, _tok_rx) =
            ControlPlane::new(config, empty_report(), auth).expect("control plane");
        plane
    }

    #[tokio::test]
    async fn explicit_control_centers_are_ordered_by_priority_and_scheme() {
        let mut config = (*dummy_config("http://legacy.test:3001".to_string())).clone();
        config.control_centers = vec![
            control_center("quic", "quic://nsd-quic:4002", 20, None, None, vec![]),
            control_center("noise", "noise://nsd-noise:4001", 10, None, None, vec![]),
            control_center("sse", "https://nsd-sse.example", 30, None, None, vec![]),
        ];
        let plane = plane_for_config(Arc::new(config)).await;

        let endpoints = plane.control_endpoint_sequence();
        let order = endpoints
            .iter()
            .map(|endpoint| (endpoint.id(), endpoint.mode.as_str()))
            .collect::<Vec<_>>();

        assert_eq!(
            order,
            vec![("noise", "noise"), ("quic", "quic"), ("sse", "sse")]
        );
    }

    #[tokio::test]
    async fn nsd_default_mode_reorders_effective_sequence() {
        // Priority order alone would keep the sse endpoint primary; an explicit
        // nsd_default_mode="noise" promotes the noise endpoint to primary in the
        // sequence the per-endpoint fallback loop consumes.
        let mut config = (*dummy_config("http://legacy.test:3001".to_string())).clone();
        config.control_centers = vec![
            control_center("sse", "https://nsd-sse.example", 1, None, None, vec![]),
            control_center("noise", "noise://nsd-noise:4001", 2, None, None, vec![]),
        ];
        config.nsd_default_mode = Some("noise".to_string());
        let plane = plane_for_config(Arc::new(config)).await;

        let order = plane
            .control_endpoint_sequence()
            .iter()
            .map(|endpoint| (endpoint.id().to_string(), endpoint.mode.clone()))
            .collect::<Vec<_>>();

        assert_eq!(
            order,
            vec![
                ("noise".to_string(), "noise".to_string()),
                ("sse".to_string(), "sse".to_string()),
            ]
        );
    }

    #[tokio::test]
    async fn nsd_default_mode_unset_keeps_priority_order() {
        // Back-compat: without nsd_default_mode the priority-sorted order (sse
        // primary) is unchanged.
        let mut config = (*dummy_config("http://legacy.test:3001".to_string())).clone();
        config.control_centers = vec![
            control_center("sse", "https://nsd-sse.example", 1, None, None, vec![]),
            control_center("noise", "noise://nsd-noise:4001", 2, None, None, vec![]),
        ];
        let plane = plane_for_config(Arc::new(config)).await;

        let ids = plane
            .control_endpoint_sequence()
            .iter()
            .map(|endpoint| endpoint.id().to_string())
            .collect::<Vec<_>>();

        assert_eq!(ids, vec!["sse".to_string(), "noise".to_string()]);
    }

    #[tokio::test]
    async fn single_server_url_keeps_control_mode_back_compat() {
        let mut config = (*dummy_config("http://legacy.test:3001".to_string())).clone();
        config.control_mode = "noise".to_string();
        config.noise_bootstrap_pubkey = Some("aa".repeat(32));
        let plane = plane_for_config(Arc::new(config)).await;

        let endpoints = plane.control_endpoint_sequence();

        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].id(), "default");
        assert_eq!(endpoints[0].url(), "http://legacy.test:3001");
        assert_eq!(endpoints[0].mode, "noise");
    }

    #[tokio::test]
    async fn fixed_scope_id_replaces_the_derived_default_endpoint_id() {
        let mut plane = plane_for_config(dummy_config("https://nsd-b.example".to_string())).await;
        plane.set_nsd_id("nsd-b".to_string());

        let endpoints = plane.control_endpoint_sequence();

        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].id(), "nsd-b");
    }

    #[tokio::test]
    async fn endpoint_config_and_trust_are_rebound_per_endpoint() {
        let mut config = (*dummy_config("http://legacy.test:3001".to_string())).clone();
        config.realm = Some("shared-realm".to_string());
        config.nsd_envelope_key_pins = vec!["shared-pin".to_string()];
        config.control_centers = vec![
            control_center(
                "noise",
                "noise://nsd-noise:4001",
                1,
                Some("aa".repeat(32)),
                None,
                vec!["noise-pin".to_string()],
            ),
            control_center(
                "quic",
                "quic://nsd-quic:4002",
                2,
                None,
                Some("bb".repeat(32)),
                vec![],
            ),
        ];
        let plane = plane_for_config(Arc::new(config)).await;
        let endpoints = plane.control_endpoint_sequence();

        let noise_config = plane.endpoint_connector_config(&endpoints[0]);
        let noise_trust = plane.endpoint_trust(&endpoints[0]);
        assert_eq!(noise_config.server_url, "noise://nsd-noise:4001");
        assert_eq!(noise_config.control_mode, "noise");
        assert_eq!(noise_config.noise_bootstrap_pubkey, Some("aa".repeat(32)));
        assert_eq!(noise_config.quic_bootstrap_cert_sha256, None);
        assert_eq!(noise_trust.envelope_key_pins, vec!["noise-pin"]);

        let quic_config = plane.endpoint_connector_config(&endpoints[1]);
        let quic_trust = plane.endpoint_trust(&endpoints[1]);
        assert_eq!(quic_config.server_url, "quic://nsd-quic:4002");
        assert_eq!(quic_config.control_mode, "quic");
        assert_eq!(quic_config.noise_bootstrap_pubkey, None);
        assert_eq!(
            quic_config.quic_bootstrap_cert_sha256,
            Some("bb".repeat(32))
        );
        assert_eq!(quic_trust.envelope_key_pins, vec!["shared-pin"]);
        assert_eq!(quic_trust.realm, "shared-realm");
    }

    #[tokio::test]
    async fn all_endpoint_failures_are_aggregated_without_inner_backoff() {
        let mut config = (*dummy_config("http://legacy.test:3001".to_string())).clone();
        config.nsd_endpoint_attempt_timeout_secs = 1;
        config.control_centers = vec![
            control_center("primary", "noise://nsd-primary:4001", 1, None, None, vec![]),
            control_center(
                "secondary",
                "quic://nsd-secondary:4002",
                2,
                None,
                None,
                vec![],
            ),
        ];
        let mut plane = plane_for_config(Arc::new(config)).await;

        let err = match plane.connect_active_endpoint().await {
            Ok(_) => panic!("all endpoints should fail"),
            Err(err) => err,
        };
        let rendered = err.to_string();
        assert!(rendered.contains("primary"));
        assert!(rendered.contains("secondary"));
        assert!(rendered.contains("all control endpoints failed"));
    }

    #[tokio::test]
    async fn established_stream_outlives_endpoint_attempt_timeout() {
        let mut plane = plane_for_config(dummy_config("http://127.0.0.1:3001".to_string())).await;
        let mut heartbeat = tokio::time::interval_at(
            tokio::time::Instant::now() + std::time::Duration::from_secs(60),
            std::time::Duration::from_secs(60),
        );
        let polls = Arc::new(AtomicUsize::new(0));
        let mut stream: Box<dyn ControlStream> = Box::new(PendingStream {
            polls: Arc::clone(&polls),
        });
        let mut token = "token-A".to_string();

        let result = tokio::time::timeout(
            std::time::Duration::from_millis(1_100),
            plane.drive_connected_stream(&mut token, &mut stream, &mut heartbeat),
        )
        .await;

        assert!(
            result.is_err(),
            "live stream must not be closed by the 1s endpoint attempt timeout"
        );
        assert_eq!(polls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn live_stream_does_not_reselect_when_primary_recovers() {
        let mut config = (*dummy_config("http://legacy.test:3001".to_string())).clone();
        config.control_centers = vec![
            control_center("primary", "https://primary.example", 1, None, None, vec![]),
            control_center(
                "fallback",
                "https://fallback.example",
                2,
                None,
                None,
                vec![],
            ),
        ];
        let mut plane = plane_for_config(Arc::new(config)).await;
        let primary_recovered = Arc::new(AtomicBool::new(false));
        let mut heartbeat = tokio::time::interval_at(
            tokio::time::Instant::now() + std::time::Duration::from_secs(60),
            std::time::Duration::from_secs(60),
        );
        let polls = Arc::new(AtomicUsize::new(0));
        let mut stream: Box<dyn ControlStream> = Box::new(PendingStream {
            polls: Arc::clone(&polls),
        });
        let mut token = "fallback-token".to_string();

        primary_recovered.store(true, Ordering::SeqCst);
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            plane.drive_connected_stream(&mut token, &mut stream, &mut heartbeat),
        )
        .await;

        assert!(primary_recovered.load(Ordering::SeqCst));
        assert!(
            result.is_err(),
            "recovered primary must not interrupt a live fallback stream"
        );
        assert_eq!(polls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn disconnect_restarts_selection_from_primary() {
        let mut config = (*dummy_config("http://legacy.test:3001".to_string())).clone();
        config.control_centers = vec![
            control_center("primary", "https://primary.example", 1, None, None, vec![]),
            control_center(
                "fallback",
                "https://fallback.example",
                2,
                None,
                None,
                vec![],
            ),
        ];
        let mut plane = plane_for_config(Arc::new(config)).await;
        let mut heartbeat = tokio::time::interval_at(
            tokio::time::Instant::now() + std::time::Duration::from_secs(60),
            std::time::Duration::from_secs(60),
        );
        let mut stream: Box<dyn ControlStream> = Box::new(DisconnectStream);
        let mut token = "fallback-token".to_string();

        let exit = plane
            .drive_connected_stream(&mut token, &mut stream, &mut heartbeat)
            .await
            .expect("disconnect should be a reconnect signal");

        assert!(matches!(exit, super::LiveStreamExit::Disconnected));
        let next_sequence = plane.control_endpoint_sequence();
        assert_eq!(next_sequence[0].id(), "primary");
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
            connected.connected,
            "stream open must mark the control plane connected"
        );
        assert_eq!(connected.scope.nsd_id, "default");
        assert!(connected.stream_session.is_some());

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
