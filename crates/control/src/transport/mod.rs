#![forbid(unsafe_code)]

//! Pluggable transport layer for the NSN control plane.
//!
//! The inner SSE protocol is unchanged; the outer transport is pluggable.
//!
//! [`ControlTransport`] is the main trait. Implementors return a [`BoxStream`]
//! -- a boxed bidirectional byte stream (AsyncRead + AsyncWrite) -- that carries
//! raw HTTP/SSE traffic.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use futures_util::future::BoxFuture;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::envelope::ControlEnvelope;

pub mod builder;
pub mod framing;
pub mod noise;
pub mod quic;
pub mod sse;

// -- BoxStream ----------------------------------------------------------------

/// Object-safe supertrait for bidirectional async byte streams.
///
/// Blanket-implemented for all `AsyncRead + AsyncWrite + Send + Unpin` types.
/// Used as the erased inner type of [`BoxStream`].
pub(crate) trait AnyStream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> AnyStream for T {}

/// Boxed bidirectional async stream returned by [`ControlTransport::connect`].
///
/// Implements both [`AsyncRead`] and [`AsyncWrite`].
pub struct BoxStream(Box<dyn AnyStream + Send>);

impl BoxStream {
    /// Wrap any `AsyncRead + AsyncWrite + Send + Unpin + 'static` stream.
    pub fn new<T: AsyncRead + AsyncWrite + Send + Unpin + 'static>(inner: T) -> Self {
        Self(Box::new(inner))
    }
}

impl AsyncRead for BoxStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(self.0.as_mut()).poll_read(cx, buf)
    }
}

impl AsyncWrite for BoxStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(self.0.as_mut()).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(self.0.as_mut()).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(self.0.as_mut()).poll_shutdown(cx)
    }
}

// -- ControlTransport ---------------------------------------------------------

/// Pluggable transport for the NSN control plane connection.
///
/// Implementors produce a [`BoxStream`] -- a bidirectional byte stream that
/// carries raw HTTP/SSE.
///
/// # Provided implementations
///
/// | Transport | Struct | Description |
/// |-----------|--------|-------------|
/// | SSE (default) | [`sse::SseTransport`] | TLS/HTTPS via tokio-rustls |
/// | Noise | [`noise::NoiseTransport`] | Noise_IK over TCP (anti-DPI) |
/// | QUIC | [`quic::QuicTransport`] | Noise_IK over QUIC/UDP (anti-DPI) |
pub trait ControlTransport: Send + Sync {
    /// Open a legacy raw connection to `endpoint` (format: `host:port`) and
    /// return the encrypted byte stream.
    ///
    /// Transitional API used by existing HTTP/SSE call sites. New stream
    /// openings should prefer [`ControlTransport::connect_stream`] so the
    /// transport-specific stream auth is centralized.
    fn connect<'a>(&'a self, endpoint: &'a str) -> BoxFuture<'a, Result<BoxStream, crate::Error>>;

    /// Open a stream from a signed envelope.
    ///
    /// Transports open the deployed `config.stream` HTTP endpoint with the
    /// bearer token minted by the control auth flow. Noise and QUIC carry the
    /// HTTP request inside their encrypted byte stream.
    fn connect_stream<'a>(
        &'a self,
        endpoint: &'a str,
        _envelope: ControlEnvelope,
        _bearer_token: Option<&'a str>,
    ) -> BoxFuture<'a, Result<BoxStream, crate::Error>> {
        self.connect(endpoint)
    }

    /// Unary signed-envelope request/response over the transport.
    ///
    /// `endpoint` is `host:port` (no scheme). `envelope.api` carries the
    /// logical API identifier (`machine.register`, `machine.heartbeat`,
    /// `services.report`, `info.get`, ...). Implementations are free to
    /// multiplex calls over a single connection (Noise/QUIC) or open a
    /// fresh HTTPS request per call (SSE).
    ///
    /// The default implementation returns [`crate::Error::NotImplemented`].
    /// Per-transport implementations land in Phases 3 (SSE), 4 (Noise),
    /// 5 (QUIC) of PLAN-022.
    fn call<'a>(
        &'a self,
        _endpoint: &'a str,
        _envelope: ControlEnvelope,
    ) -> BoxFuture<'a, Result<ControlEnvelope, crate::Error>> {
        let name = self.name();
        // Copy the &'static str out so the future doesn't borrow self.
        let static_name: &'static str = match name {
            "sse" => "sse",
            "noise" => "noise",
            "quic" => "quic",
            _ => "unknown",
        };
        Box::pin(async move { Err(crate::Error::NotImplemented(static_name)) })
    }

    /// Short human-readable name for this transport (e.g. `"sse"`, `"noise"`,
    /// `"quic"`).
    fn name(&self) -> &str;
}

// -- Control-socket TCP keepalive ----------------------------------------------

/// Idle time before the kernel sends the first TCP keepalive probe on a
/// control socket.
///
/// Linux defaults (`tcp_keepalive_time` = 7200s) are useless at control-plane
/// timescales. 30s idle + [`TCP_KEEPALIVE_RETRIES`] probes at
/// [`TCP_KEEPALIVE_INTERVAL`] tears a dead path down after roughly
/// 30 + 3 x 10 = 60s and fails pending writes on half-open sockets. The
/// config-stream idle read deadline (`crate::sse`) remains the primary
/// detector; this is the OS-level backstop that also covers the short-lived
/// unary `call()` sockets.
pub(crate) const TCP_KEEPALIVE_TIME: Duration = Duration::from_secs(30);

/// Interval between keepalive probes once [`TCP_KEEPALIVE_TIME`] expires
/// without traffic.
pub(crate) const TCP_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);

/// Unacknowledged probes before the kernel declares the peer dead and fails
/// the socket. Applied where the platform supports it; the deployment target
/// is Linux.
pub(crate) const TCP_KEEPALIVE_RETRIES: u32 = 3;

/// Enable TCP keepalive on a freshly connected control socket.
///
/// Called by the TCP transports right after `TcpStream::connect` succeeds,
/// before any TLS / Noise handshake. Failure is non-fatal: losing the kernel
/// backstop must not fail an otherwise healthy connect, so call sites log
/// and continue.
pub(crate) fn set_control_tcp_keepalive(tcp: &tokio::net::TcpStream) -> io::Result<()> {
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(TCP_KEEPALIVE_TIME)
        .with_interval(TCP_KEEPALIVE_INTERVAL)
        .with_retries(TCP_KEEPALIVE_RETRIES);
    socket2::SockRef::from(tcp).set_tcp_keepalive(&keepalive)
}

// -- Metric instrumentation (CTRL-002) ----------------------------------------

/// Map a transport name to a bounded `&'static str` metric label.
///
/// Keeps the `transport` label cardinality fixed at {sse, noise, quic, unknown}
/// regardless of what a custom [`ControlTransport::name`] returns.
fn transport_label(name: &str) -> &'static str {
    match name {
        "sse" => "sse",
        "noise" => "noise",
        "quic" => "quic",
        _ => "unknown",
    }
}

/// Map a `ControlEnvelope::api` string to a bounded `&'static str` metric
/// label. Anything outside the known enum collapses to `"unknown"` so the
/// `api` label can never carry an attacker-influenced free-form value.
fn api_label(api: &str) -> &'static str {
    use crate::envelope::api;
    match api {
        api::INFO_GET => "info.get",
        api::MACHINE_REGISTER => "machine.register",
        api::MACHINE_AUTH => "machine.auth",
        api::MACHINE_HEARTBEAT => "machine.heartbeat",
        api::SERVICES_REPORT => "services.report",
        api::GATEWAY_SERVICES_REPORT => "gateway.services_report",
        api::PEER_CANDIDATES_REPORT => "peer_candidates.report",
        api::CONFIG_STREAM => "config.stream",
        api::GATEWAY_REPORT => "gateway.report",
        api::GATEWAY_USAGE_REPORT => "gateway.usage_report",
        api::GATEWAY_REALM_CONFIG_SNAPSHOT => "gateway.realm_config_snapshot",
        _ => "unknown",
    }
}

/// Record `control_call_duration_seconds` (and `control_envelope_replay_rejected_total`
/// on a replay) for one transport call, given its labels and elapsed time.
fn record_call_metrics(
    transport: &'static str,
    api: &'static str,
    result_is_ok: bool,
    is_replay: bool,
    secs: f64,
) {
    let status = if result_is_ok { "ok" } else { "error" };
    telemetry::control_otel::record_control_call_duration(transport, api, status, secs);
    if is_replay {
        telemetry::control_otel::record_control_envelope_replay_rejected(transport, api);
    }
}

/// Run [`ControlTransport::call`] with `control_call_duration_seconds` +
/// replay instrumentation. All control-plane unary calls route through here so
/// the metric is recorded once per logical call regardless of transport.
pub async fn instrumented_call(
    transport: &dyn ControlTransport,
    endpoint: &str,
    envelope: ControlEnvelope,
) -> Result<ControlEnvelope, crate::Error> {
    let t = transport_label(transport.name());
    let api = api_label(&envelope.api);
    let start = std::time::Instant::now();
    let result = transport.call(endpoint, envelope).await;
    let secs = start.elapsed().as_secs_f64();
    record_call_metrics(
        t,
        api,
        result.is_ok(),
        matches!(result, Err(crate::Error::Replay)),
        secs,
    );
    result
}

/// Run [`ControlTransport::connect_stream`] with the same instrumentation as
/// [`instrumented_call`]. Used for the `config.stream` open.
pub async fn instrumented_connect_stream(
    transport: &dyn ControlTransport,
    endpoint: &str,
    envelope: ControlEnvelope,
    bearer_token: Option<&str>,
) -> Result<BoxStream, crate::Error> {
    let t = transport_label(transport.name());
    let api = api_label(&envelope.api);
    let start = std::time::Instant::now();
    let result = transport
        .connect_stream(endpoint, envelope, bearer_token)
        .await;
    let secs = start.elapsed().as_secs_f64();
    record_call_metrics(
        t,
        api,
        result.is_ok(),
        matches!(result, Err(crate::Error::Replay)),
        secs,
    );
    result
}
