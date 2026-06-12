//! Pure WebSocket proxy transport.
//!
//! Multiplexes logical streams over a single WebSocket connection to the
//! NSIO relay endpoint (`wss://{server}/api/v1/nsn/relay`).
//! Entirely bypasses WireGuard — no gotatun, no smoltcp, no NAT engine.

#![forbid(unsafe_code)]
#![allow(missing_docs)]

use std::future::Future;
use std::io::BufReader;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use acl::{AccessContext, AclEngine, NetworkTuple, TransportKind};
use anyhow::Context;
use arc_swap::ArcSwapOption;
use common::tunnel::{TransportType, Tunnel};
use common::{Protocol, ServicesConfig};
use dashmap::DashMap;
use futures_util::{SinkExt, StreamExt};
use rustls::ClientConfig;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use telemetry::labels::{Outcome, Protocol as TelemetryProtocol};
use telemetry::proxy_otel::{self, Direction};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio_tungstenite::{
    Connector, MaybeTlsStream, WebSocketStream, connect_async_tls_with_config,
    tungstenite::{Message, client::IntoClientRequest, http::HeaderValue},
};
use tracing::{debug, info, warn};

// Re-export the tokio-tungstenite TLS connector so downstream crates
// (notably the `connector` crate) can pass a [`Connector`] into
// [`WsTunnel::connect`] without taking a direct dependency on
// `tokio-tungstenite`.
pub use tokio_tungstenite::Connector as TlsConnector;

/// NSGW path for opaque zero-trust WSS relay clients.
pub const OPAQUE_WSS_RELAY_PATH: &str = "/wss-relay";
/// Query value that selects opaque zero-trust WSS relay mode on `/client`.
pub const OPAQUE_WSS_RELAY_MODE: &str = "wss-relay";

/// Client-side opaque WebSocket stream.
pub type OpaqueWsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;

// ── TLS connector helper ──────────────────────────────────────────────────

/// Build a rustls-backed [`Connector`] that trusts the Mozilla WebPKI roots
/// plus the PEM-encoded X.509 certificates in `extra_ca_certs`.
///
/// Use when NSGW serves a TLS certificate signed by a private CA (for
/// example in self-hosted or integration deployments) and the production
/// WebPKI roots alone would reject the handshake. Both NSC's outbound proxy
/// (`crates/nsc/src/proxy.rs`, via the `tunnel_ws::build_rustls_connector`
/// re-export) and NSN's `connector::ConnectorManager` (when
/// `ConnectorConfig.extra_ca_certs` is `Some`) build the connector through
/// this helper so the TLS trust path is identical on both ends.
///
/// Errors loudly when the file is missing, unreadable, or contains zero
/// certificates — operator misconfiguration must surface at startup rather
/// than as a runtime mystery on the first WSS dial. The empty-bundle case
/// is rejected on purpose so that an operator who believed they had pinned
/// a CA does not silently fall through to the system roots.
pub fn build_rustls_connector(extra_ca_certs: &Path) -> anyhow::Result<Connector> {
    // Install ring crypto provider (idempotent — Hard Lock 1, see TLS-001).
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let file = std::fs::File::open(extra_ca_certs)
        .with_context(|| format!("open extra_ca_certs bundle at {}", extra_ca_certs.display()))?;
    let mut reader = BufReader::new(file);
    let mut added: usize = 0;
    for cert in CertificateDer::pem_reader_iter(&mut reader) {
        let cert = cert
            .with_context(|| format!("parse PEM certificate from {}", extra_ca_certs.display()))?;
        root_store
            .add(cert)
            .with_context(|| format!("add CA cert from {}", extra_ca_certs.display()))?;
        added += 1;
    }
    if added == 0 {
        anyhow::bail!(
            "extra_ca_certs bundle at {} contained zero PEM certificates",
            extra_ca_certs.display()
        );
    }

    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    Ok(Connector::Rustls(Arc::new(config)))
}

// ── Resolver trait ─────────────────────────────────────────────────────────

/// Resolves the WSS `Open` frame destination to a real backend `SocketAddr`.
///
/// Implemented by `nat::ServiceRouter` on the NSN side; injected into
/// [`WsTunnel`] through [`WsTunnel::with_resolver`] so that the receive path
/// can translate a wg-tunnel IP plus a service port back to the actual
/// service backend (e.g. `echo:17777`). When no resolver is wired (the NSC
/// client which only originates relay traffic and never accepts `Open`
/// frames), the legacy services-whitelist gate runs against the raw
/// `(target_ip, target_port)` instead.
///
/// Lives in `tunnel-ws` rather than `nat` so the slim NSC dep graph stays
/// free of `nat`/`gotatun`; the concrete impl block lives in `nat`.
#[derive(Debug, Clone)]
pub struct WssResolvedTarget {
    /// Backend socket address the relay should connect to.
    pub target: SocketAddr,
    /// Bounded services.toml service name for proxy telemetry labels.
    pub service_name: Option<String>,
}

pub trait WssTargetResolver: Send + Sync {
    /// Resolve the requested destination. Returns `None` when no service
    /// matches, the ACL denies the connection, or DNS resolution fails —
    /// callers MUST surface that as a `Close` frame.
    fn resolve<'a>(
        &'a self,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        dst_port: u16,
        protocol: Protocol,
    ) -> Pin<Box<dyn Future<Output = Option<SocketAddr>> + Send + 'a>>;

    /// Resolve the requested destination plus optional bounded service
    /// metadata for telemetry labels.
    fn resolve_with_service<'a>(
        &'a self,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        dst_port: u16,
        protocol: Protocol,
    ) -> Pin<Box<dyn Future<Output = Option<WssResolvedTarget>> + Send + 'a>> {
        Box::pin(async move {
            self.resolve(src_ip, dst_ip, dst_port, protocol)
                .await
                .map(|target| WssResolvedTarget {
                    target,
                    service_name: None,
                })
        })
    }
}

/// Errors produced by the WebSocket tunnel.
#[derive(Debug, Error)]
pub enum Error {
    #[error("frame decode error: {0}")]
    FrameDecode(String),
    #[error("unknown protocol byte: 0x{0:02x}")]
    UnknownProto(u8),
    #[error("WebSocket error: {0}")]
    WebSocket(String),
    /// Server returned HTTP 401 on the WSS handshake. Surfaced as a typed
    /// variant so callers can distinguish a bearer-token rejection (which
    /// is recoverable via a refresh) from generic transport failures
    /// without string-matching the rendered error.
    #[error("WSS relay unauthorized: {0}")]
    Unauthorized(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// The local data_tx → downstream mpsc channel to the WebSocket writer
    /// closed unexpectedly during a relay.  Surfaces as a `Close` frame to
    /// the peer rather than a panic.
    #[error("relay write channel closed")]
    RelayWriteClosed,
    #[error("invalid opaque WebSocket mode: {0}")]
    InvalidOpaqueMode(String),
}

/// Returns `true` when `err` is a typed 401 surfaced by [`WsTunnel::connect`].
///
/// Lets callers (`connector::ConnectorManager::try_wss`) drive a one-shot
/// bearer-token refresh without parsing the rendered error message.
pub fn is_unauthorized(err: &Error) -> bool {
    matches!(err, Error::Unauthorized(_))
}

// ── Connection events ──────────────────────────────────────────────────────

/// Connection lifecycle events emitted by [`WsTunnel`].
///
/// Consumers receive these via a channel registered with
/// [`WsTunnel::with_event_sender`] to track which gateway handled each
/// proxied stream.
#[derive(Debug, Clone)]
pub struct WssConnectionEvent {
    /// Unique stream identifier within this WebSocket session.
    pub stream_id: u32,
    /// Gateway ID extracted from the relay URL hostname (e.g. `"nsgw-1"`).
    pub gateway_id: String,
    /// `"tcp"` or `"udp"`.
    pub protocol: String,
    /// Remote target address the relay connected to.
    pub target: SocketAddr,
    /// Whether this event marks the opening or closing of the stream.
    pub kind: WssConnectionEventKind,
}

/// Discriminant for [`WssConnectionEvent`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WssConnectionEventKind {
    /// A new proxied stream was opened and the relay task is running.
    Open,
    /// The proxied stream was closed (relay task exited).
    Close,
}

/// Extract the gateway ID (hostname) from a WebSocket relay URL.
///
/// `ws://nsgw-1:9443/relay` → `"nsgw-1"`
/// `wss://my-gw.example.com:443/relay` → `"my-gw.example.com"`
fn extract_gateway_id(url: &str) -> String {
    let after_scheme = url
        .strip_prefix("wss://")
        .or_else(|| url.strip_prefix("ws://"))
        .unwrap_or(url);
    let host_port = after_scheme.split('/').next().unwrap_or(after_scheme);
    host_port.split(':').next().unwrap_or(host_port).to_string()
}

// ── Opaque carrier helpers ─────────────────────────────────────────────────

/// Build the NSN-side NSGW opaque relay URL.
#[must_use]
pub fn opaque_nsn_relay_url(gateway_base_url: &str) -> String {
    let base = gateway_base_url.trim_end_matches('/');
    format!("{base}{OPAQUE_WSS_RELAY_PATH}")
}

/// Build the NSN-side NSGW opaque relay URL for one authorized client pair.
///
/// The `nsc` query parameter names the pair's NSC machine id so the gateway
/// can pair this leg exactly with that client's opaque dial. An older gateway
/// ignores the parameter and pairs the leg as legacy single-leg. NSNs without
/// per-pair dial info keep using [`opaque_nsn_relay_url`].
#[must_use]
pub fn opaque_nsn_relay_url_for_pair(gateway_base_url: &str, nsc_machine_id: &str) -> String {
    let base = gateway_base_url.trim_end_matches('/');
    format!("{base}{OPAQUE_WSS_RELAY_PATH}?nsc={nsc_machine_id}")
}

/// Build the NSC-side NSGW opaque relay URL.
#[must_use]
pub fn opaque_nsc_client_url(gateway_base_url: &str, nsn_machine_id: &str) -> String {
    let base = gateway_base_url.trim_end_matches('/');
    format!("{base}/client?mode={OPAQUE_WSS_RELAY_MODE}&nsn={nsn_machine_id}")
}

/// Return true when a request target selects opaque zero-trust relay mode on
/// `/client`.
pub fn is_opaque_client_request_target(request_target: &str) -> Result<bool, Error> {
    let (path, query) = request_target
        .split_once('?')
        .map_or((request_target, ""), |(path, query)| (path, query));
    if path != "/client" {
        return Ok(false);
    }
    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        if name != "mode" {
            continue;
        }
        return match value {
            OPAQUE_WSS_RELAY_MODE => Ok(true),
            other => Err(Error::InvalidOpaqueMode(other.to_owned())),
        };
    }
    Ok(false)
}

/// Establish an opaque WebSocket connection without the framed `WsFrame`
/// protocol.
pub async fn connect_opaque(
    url: &str,
    token: Option<&str>,
    connector: Option<Connector>,
) -> Result<OpaqueWsStream, Error> {
    connect_websocket(url, token, connector).await
}

/// Dial an outbound opaque WebSocket and forward each binary WebSocket message
/// as one UDP datagram to the local WireGuard socket.
pub async fn run_wg_over_ws_outbound<F>(
    url: &str,
    token: Option<&str>,
    connector: Option<Connector>,
    wg_udp_endpoint: SocketAddr,
    shutdown: F,
) -> Result<(), Error>
where
    F: Future<Output = ()> + Send,
{
    info!(
        url,
        wg_udp_endpoint = %wg_udp_endpoint,
        "WireGuard-over-WebSocket outbound relay dialing"
    );
    // The dial itself can block for up to 15 s; observe shutdown during it so
    // a closed leg never lingers in a dial it can no longer use.
    tokio::pin!(shutdown);
    let ws = tokio::select! {
        biased;
        () = &mut shutdown => {
            info!(url, "WireGuard-over-WebSocket outbound relay dial cancelled by shutdown");
            return Ok(());
        }
        connected = connect_opaque(url, token, connector) => connected?,
    };
    run_wg_over_ws_websocket(ws, wg_udp_endpoint, shutdown).await
}

async fn connect_websocket(
    url: &str,
    token: Option<&str>,
    connector: Option<Connector>,
) -> Result<OpaqueWsStream, Error> {
    let mut request = url
        .into_client_request()
        .map_err(|e| Error::WebSocket(e.to_string()))?;

    if let Some(token) = token {
        let auth_value = HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|e| Error::WebSocket(e.to_string()))?;
        request.headers_mut().insert("Authorization", auth_value);
    }

    let (ws, _response) = tokio::time::timeout(
        Duration::from_secs(15),
        connect_async_tls_with_config(request, None, false, connector),
    )
    .await
    .map_err(|_| Error::WebSocket("WSS relay connect timed out".to_string()))?
    .map_err(|e| match &e {
        tokio_tungstenite::tungstenite::Error::Http(response)
            if response.status().as_u16() == 401 =>
        {
            Error::Unauthorized(url.to_string())
        }
        _ => Error::WebSocket(e.to_string()),
    })?;
    Ok(ws)
}

async fn run_wg_over_ws_websocket<S, F>(
    ws: WebSocketStream<S>,
    wg_udp_endpoint: SocketAddr,
    shutdown: F,
) -> Result<(), Error>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    F: Future<Output = ()> + Send,
{
    let udp = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;
    udp.connect(wg_udp_endpoint).await?;
    let (mut ws_sink, mut ws_stream) = ws.split();
    let (write_tx, mut write_rx) = mpsc::channel::<Message>(64);
    let writer = tokio::spawn(async move {
        while let Some(message) = write_rx.recv().await {
            if ws_sink.send(message).await.is_err() {
                break;
            }
        }
        let _ = ws_sink.close().await;
    });
    let mut udp_buf = vec![0u8; 65535];
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            () = &mut shutdown => break,
            inbound = ws_stream.next() => {
                match inbound {
                    Some(Ok(Message::Binary(data))) => {
                        udp.send(&data).await?;
                    }
                    Some(Ok(Message::Ping(payload))) => {
                        if write_tx.send(Message::Pong(payload)).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(_)) => {}
                    Some(Err(err)) => return Err(Error::WebSocket(err.to_string())),
                }
            }
            received = udp.recv(&mut udp_buf) => {
                let received = received?;
                if write_tx
                    .send(Message::Binary(udp_buf[..received].to_vec()))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        }
    }
    writer.abort();
    Ok(())
}

/// Bind a stable loopback UDP socket for an NSC opaque WG-over-WS pump.
///
/// The returned socket is reused across WS reconnects so boringtun's peer
/// endpoint (pinned to this local address) stays valid for the life of the
/// session — binding a fresh ephemeral port on every reconnect would silently
/// kill the WG flow because boringtun keeps sending to the original address.
///
/// # Errors
///
/// Returns [`Error`] if the loopback UDP socket cannot be bound.
pub async fn bind_nsc_pump_socket() -> Result<UdpSocket, Error> {
    let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    Ok(udp)
}

/// Dial the opaque NSC client URL (`/client?mode=wss-relay&nsn=...`) and pump WG
/// packets between the local boringtun-facing `udp` socket and the WebSocket for
/// the life of one connection.
///
/// `udp` is owned by the caller and reused across reconnects; boringtun must be
/// configured with this socket's local address as the NSN peer endpoint. The
/// pump learns boringtun's source address from the first datagram it sends and
/// replies there (boringtun is the WG initiator on the NSC side, the mirror of
/// the NSN responder served by [`run_wg_over_ws_outbound`]).
///
/// # Errors
///
/// Returns [`Error`] on connect failure or a transport error during the pump.
pub async fn run_wg_over_ws_nsc_client<F>(
    url: &str,
    token: Option<&str>,
    connector: Option<Connector>,
    udp: &UdpSocket,
    shutdown: F,
) -> Result<(), Error>
where
    F: Future<Output = ()> + Send,
{
    info!(url, "NSC opaque WireGuard-over-WebSocket pump dialing");
    // Mirror of run_wg_over_ws_outbound: the dial phase must observe shutdown
    // so a retired pump never lingers in a stale dial.
    tokio::pin!(shutdown);
    let ws = tokio::select! {
        biased;
        () = &mut shutdown => {
            info!(url, "NSC opaque WireGuard-over-WebSocket pump dial cancelled by shutdown");
            return Ok(());
        }
        connected = connect_opaque(url, token, connector) => connected?,
    };
    run_wg_over_ws_nsc_pump(ws, udp, shutdown).await
}

async fn run_wg_over_ws_nsc_pump<S, F>(
    ws: WebSocketStream<S>,
    udp: &UdpSocket,
    shutdown: F,
) -> Result<(), Error>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    F: Future<Output = ()> + Send,
{
    let (mut ws_sink, mut ws_stream) = ws.split();
    let (write_tx, mut write_rx) = mpsc::channel::<Message>(64);
    let writer = tokio::spawn(async move {
        while let Some(message) = write_rx.recv().await {
            if ws_sink.send(message).await.is_err() {
                break;
            }
        }
        let _ = ws_sink.close().await;
    });
    let mut udp_buf = vec![0u8; 65535];
    // boringtun's source address, learned from its first outbound datagram. WS
    // frames received before the first datagram are dropped; WG retransmits its
    // handshake, so the bridge converges once boringtun has spoken.
    let mut wg_peer: Option<SocketAddr> = None;
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            () = &mut shutdown => break,
            inbound = ws_stream.next() => {
                match inbound {
                    Some(Ok(Message::Binary(data))) => {
                        if let Some(peer) = wg_peer {
                            udp.send_to(&data, peer).await?;
                        }
                    }
                    Some(Ok(Message::Ping(payload))) => {
                        if write_tx.send(Message::Pong(payload)).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(_)) => {}
                    Some(Err(err)) => return Err(Error::WebSocket(err.to_string())),
                }
            }
            received = udp.recv_from(&mut udp_buf) => {
                let (len, src) = received?;
                wg_peer = Some(src);
                if write_tx
                    .send(Message::Binary(udp_buf[..len].to_vec()))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        }
    }
    writer.abort();
    Ok(())
}

// ── Wire-format command discriminants ──────────────────────────────────────

/// Open stream, IPv4 target.  Payload: 4 B ip + 2 B port + 1 B protocol.
const CMD_OPEN_V4: u8 = 0x01;
/// Open stream, IPv6 target.  Payload: 16 B ip + 2 B port + 1 B protocol.
const CMD_OPEN_V6: u8 = 0x02;
/// Data frame.  Payload: raw bytes.
const CMD_DATA: u8 = 0x10;
/// Close stream.  No payload.
const CMD_CLOSE: u8 = 0x20;
/// Close acknowledge.  No payload.
const CMD_CLOSE_ACK: u8 = 0x21;

/// Buffer size for reading from local services.
const READ_BUF: usize = 65536;
/// Max concurrently open logical streams on one WSS relay connection.
const MAX_CONCURRENT_STREAMS: usize = 1024;

// ── Frame types ────────────────────────────────────────────────────────────

/// Command carried in a [`WsFrame`].
#[derive(Debug, Clone)]
pub enum FrameCommand {
    /// Server → Client: open a new proxied stream.
    Open {
        target_ip: IpAddr,
        target_port: u16,
        protocol: Protocol,
    },
    /// Bidirectional: payload bytes for an existing stream.
    Data,
    /// Either direction: close a stream.
    Close,
    /// Acknowledge stream closure.
    CloseAck,
}

/// A multiplexed WebSocket frame.
///
/// Wire format (big-endian):
/// ```text
/// [stream_id: u32][command: u8][payload ...]
/// ```
/// For `Open v4`:  `[CMD_OPEN_V4][ip: 4 B][port: 2 B][protocol: 1 B]`
/// For `Open v6`:  `[CMD_OPEN_V6][ip: 16 B][port: 2 B][protocol: 1 B]`
/// For `Data`:     `[CMD_DATA][payload bytes ...]`
/// For `Close` / `CloseAck`:  `[CMD_CLOSE | CMD_CLOSE_ACK]`
///
/// Open-frame protocol bytes are strict: `0` is TCP and `1` is UDP. Unknown
/// values are rejected instead of falling back to TCP.
#[derive(Debug, Clone)]
pub struct WsFrame {
    /// Unique identifier for the proxied stream.
    pub stream_id: u32,
    /// Command type.
    pub command: FrameCommand,
    /// Payload bytes (populated only for `Data` frames).
    pub payload: Vec<u8>,
}

impl WsFrame {
    /// Encode the frame to a `Vec<u8>` for transmission.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(&self.stream_id.to_be_bytes());

        match &self.command {
            FrameCommand::Open {
                target_ip,
                target_port,
                protocol,
            } => {
                let proto_byte: u8 = match protocol {
                    Protocol::Udp => 1,
                    _ => 0,
                };
                match target_ip {
                    IpAddr::V4(ip) => {
                        buf.push(CMD_OPEN_V4);
                        buf.extend_from_slice(&ip.octets());
                    }
                    IpAddr::V6(ip) => {
                        buf.push(CMD_OPEN_V6);
                        buf.extend_from_slice(&ip.octets());
                    }
                }
                buf.extend_from_slice(&target_port.to_be_bytes());
                buf.push(proto_byte);
            }
            FrameCommand::Data => {
                buf.push(CMD_DATA);
                buf.extend_from_slice(&self.payload);
            }
            FrameCommand::Close => {
                buf.push(CMD_CLOSE);
            }
            FrameCommand::CloseAck => {
                buf.push(CMD_CLOSE_ACK);
            }
        }

        buf
    }

    /// Decode a frame from raw bytes received over the WebSocket.
    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        if data.len() < 5 {
            return Err(Error::FrameDecode(format!(
                "frame too short: {} bytes",
                data.len()
            )));
        }

        let stream_id = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let cmd = data[4];
        let rest = &data[5..];

        let (command, payload) = match cmd {
            CMD_OPEN_V4 => {
                if rest.len() < 7 {
                    return Err(Error::FrameDecode(
                        "Open v4 frame body too short".to_string(),
                    ));
                }
                let ip = std::net::Ipv4Addr::new(rest[0], rest[1], rest[2], rest[3]);
                let port = u16::from_be_bytes([rest[4], rest[5]]);
                let protocol = decode_protocol(rest[6])?;
                (
                    FrameCommand::Open {
                        target_ip: IpAddr::V4(ip),
                        target_port: port,
                        protocol,
                    },
                    vec![],
                )
            }
            CMD_OPEN_V6 => {
                if rest.len() < 19 {
                    return Err(Error::FrameDecode(
                        "Open v6 frame body too short".to_string(),
                    ));
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&rest[..16]);
                let ip = std::net::Ipv6Addr::from(octets);
                let port = u16::from_be_bytes([rest[16], rest[17]]);
                let protocol = decode_protocol(rest[18])?;
                (
                    FrameCommand::Open {
                        target_ip: IpAddr::V6(ip),
                        target_port: port,
                        protocol,
                    },
                    vec![],
                )
            }
            CMD_DATA => (FrameCommand::Data, rest.to_vec()),
            CMD_CLOSE => (FrameCommand::Close, vec![]),
            CMD_CLOSE_ACK => (FrameCommand::CloseAck, vec![]),
            _ => {
                return Err(Error::FrameDecode(format!(
                    "unknown command byte: 0x{cmd:02x}"
                )));
            }
        };

        Ok(Self {
            stream_id,
            command,
            payload,
        })
    }
}

fn decode_protocol(byte: u8) -> Result<Protocol, Error> {
    match byte {
        0 => Ok(Protocol::Tcp),
        1 => Ok(Protocol::Udp),
        other => Err(Error::UnknownProto(other)),
    }
}

// ── Per-stream handle ──────────────────────────────────────────────────────

/// Internal handle kept in the stream registry.
///
/// Dropping the handle closes `data_tx`, which causes the relay task to exit.
struct StreamHandle {
    /// Delivers incoming `Data` frame payloads to the relay task.
    data_tx: mpsc::Sender<Vec<u8>>,
}

// ── WsTunnel ───────────────────────────────────────────────────────────────

type WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// Pure WebSocket proxy that multiplexes logical streams over a single
/// WebSocket connection to the NSIO relay.
///
/// The server opens streams by sending `Open` frames; the client connects to
/// the local service and relays data bidirectionally.
pub struct WsTunnel {
    ws: WsStream,
    services: Arc<ServicesConfig>,
    /// Shared ACL engine.  Written by the control-plane update task; read on
    /// every `Open` frame.  `None` = ACL not yet received -> default deny.
    /// Lock-free via `ArcSwapOption` — cannot be poisoned by a panicking writer.
    acl: Arc<ArcSwapOption<AclEngine>>,
    /// Gateway ID extracted from the relay URL (e.g. `"nsgw-1"`).
    /// Used to attribute connection records to the correct gateway.
    gateway_id: String,
    /// Optional sink for connection lifecycle events.
    /// When set, an [`WssConnectionEvent`] is sent on stream open and close.
    event_tx: Option<mpsc::Sender<WssConnectionEvent>>,
    /// Optional target resolver. When `Some`, the receive path uses it to
    /// translate the `Open`-frame destination to the real backend address
    /// and relies on its service-floor check; when `None`, the legacy
    /// services-whitelist gate runs against the raw destination.
    resolver: Option<Arc<dyn WssTargetResolver>>,
}

impl Tunnel for WsTunnel {
    fn transport_type(&self) -> TransportType {
        TransportType::WebSocket
    }

    fn is_connected(&self) -> bool {
        true
    }
}

impl WsTunnel {
    /// Establish a WebSocket connection to `url` authenticated with `token`.
    ///
    /// The gateway ID is extracted from the URL hostname and stored for
    /// connection event attribution (see [`with_event_sender`]).
    ///
    /// `connector` selects the TLS trust path for `wss://` URLs:
    /// - `None` — defer to `tokio-tungstenite`'s default trust path (the
    ///   workspace feature set yields rustls + WebPKI roots). This is the
    ///   production behaviour for publicly-signed gateways and is what every
    ///   caller used before TLS-003.
    /// - `Some(connector)` — use the supplied rustls connector, typically
    ///   produced by [`build_rustls_connector`] to layer operator-supplied
    ///   private-CA roots on top of the Mozilla WebPKI roots. Wired by NSN's
    ///   `connector::ConnectorManager` from `ConnectorConfig.extra_ca_certs`.
    ///
    /// Plaintext `ws://` URLs ignore `connector` (no TLS handshake takes
    /// place).
    pub async fn connect(
        url: &str,
        token: &str,
        services: Arc<ServicesConfig>,
        acl: Arc<ArcSwapOption<AclEngine>>,
        connector: Option<Connector>,
    ) -> Result<Self, Error> {
        let ws = connect_websocket(url, Some(token), connector).await?;

        let gateway_id = extract_gateway_id(url);
        info!(url, gateway_id, "WSS relay connection established");
        Ok(Self {
            ws,
            services,
            acl,
            gateway_id,
            event_tx: None,
            resolver: None,
        })
    }

    /// Attach a connection-event sender.
    ///
    /// When set, the tunnel emits an [`WssConnectionEvent`] each time a
    /// proxied stream opens or closes, allowing callers to track active
    /// connections and attribute them to a gateway.
    pub fn with_event_sender(mut self, tx: mpsc::Sender<WssConnectionEvent>) -> Self {
        self.event_tx = Some(tx);
        self
    }

    /// Attach a target resolver used to translate `Open`-frame destinations
    /// to real backend addresses and enforce the NSN service floor. When set,
    /// the resolver's check supersedes the legacy
    /// [`check_target_allowed`] gate.
    pub fn with_resolver(mut self, resolver: Arc<dyn WssTargetResolver>) -> Self {
        self.resolver = Some(resolver);
        self
    }

    /// Run the relay loop until the WebSocket closes or an error occurs.
    ///
    /// Splits the connection into a read half and a write half.  Incoming
    /// frames are dispatched to per-stream relay tasks; relay tasks send
    /// outgoing frames through a shared write channel.
    pub async fn run(self) -> Result<(), Error> {
        let (mut ws_sink, mut ws_stream) = self.ws.split();
        let services = Arc::clone(&self.services);
        let acl = Arc::clone(&self.acl);
        let gateway_id = self.gateway_id;
        let event_tx = self.event_tx;
        let resolver = self.resolver;

        // Dedicated write task -- allows relay tasks to send without locking.
        let (write_tx, mut write_rx) = mpsc::channel::<Message>(256);
        let write_task = tokio::spawn(async move {
            while let Some(msg) = write_rx.recv().await {
                if ws_sink.send(msg).await.is_err() {
                    break;
                }
            }
            let _ = ws_sink.close().await;
        });

        let streams: Arc<DashMap<u32, StreamHandle>> = Arc::new(DashMap::new());

        loop {
            match ws_stream.next().await {
                Some(Ok(Message::Binary(data))) => {
                    let frame = match WsFrame::decode(&data) {
                        Ok(f) => f,
                        Err(e) => {
                            warn!("failed to decode WSS frame: {e}");
                            continue;
                        }
                    };
                    dispatch_frame(
                        frame,
                        &streams,
                        &write_tx,
                        &services,
                        &acl,
                        &gateway_id,
                        &event_tx,
                        resolver.as_ref(),
                    )
                    .await;
                }
                Some(Ok(Message::Ping(payload))) => {
                    if write_tx.send(Message::Pong(payload)).await.is_err() {
                        break;
                    }
                }
                Some(Ok(Message::Close(_))) => {
                    info!("WSS relay closed by server");
                    break;
                }
                Some(Ok(_)) => {}
                Some(Err(e)) => {
                    write_task.abort();
                    return Err(Error::WebSocket(e.to_string()));
                }
                None => {
                    info!("WSS relay stream ended");
                    break;
                }
            }
        }

        write_task.abort();
        Ok(())
    }
}

// ── Policy check ──────────────────────────────────────────────────────────

/// Returns `true` if the target is allowed by both the services whitelist
/// and the ACL policy.
///
/// - Services check: skipped when `ServicesConfig` is in permissive mode.
///   When strict, the target IP is matched against services entries; hostname
///   entries are resolved via DNS so that targets configured by name (e.g.
///   `mock-server`) match the IP carried in the `Open` frame.
/// - ACL check: always performed.  `None` (engine not yet received from the
///   control plane) is treated as default deny.
///
/// WSS Open frames carry only the destination in this legacy path. Without a
/// trusted source anchor the ACL source is Unknown, which fails closed even
/// when the policy contains a wildcard subject rule.
async fn check_target_allowed(
    services: &ServicesConfig,
    acl: &Arc<ArcSwapOption<AclEngine>>,
    target_ip: IpAddr,
    target_port: u16,
    protocol: Protocol,
) -> bool {
    if services.is_strict()
        && !services
            .is_allowed_by_ip(target_ip, target_port, protocol)
            .await
    {
        return false;
    }
    // Lock-free snapshot — ArcSwapOption can't be poisoned by a panicking
    // writer.  `load()` hands back a borrowed snapshot (one fewer refcount
    // bump than `load_full()`) which is plenty for the single-use decision.
    let guard = acl.load();
    match &*guard {
        Some(engine) => {
            let network = NetworkTuple::new(
                Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
                target_ip,
                target_port,
                protocol,
            );
            let context = wss_open_access_context(network);
            engine.is_allowed(&context).allowed
        }
        None => {
            warn!(%target_ip, target_port, "WSS Open denied: ACL not yet loaded");
            false
        }
    }
}

/// ACL context for a framed WSS `Open`. This is the gateway-terminated leg of
/// the link taxonomy, so decisions attribute as `terminate` — not `wss-relay`,
/// which names the opaque WG-over-WS pump (judged on the WG path with the
/// client key). Open frames carry no trusted source anchor, so the source
/// stays Unknown and fails closed.
fn wss_open_access_context(network: NetworkTuple) -> AccessContext {
    AccessContext::unknown(network, TransportKind::Terminate)
}

fn telemetry_protocol(protocol: Protocol) -> TelemetryProtocol {
    match protocol {
        Protocol::Udp => TelemetryProtocol::Udp,
        _ => TelemetryProtocol::Tcp,
    }
}

struct RelayTelemetryGuard {
    service_name: String,
    protocol: TelemetryProtocol,
    outcome: Outcome,
}

impl RelayTelemetryGuard {
    fn new(service_name: &str, protocol: TelemetryProtocol) -> Self {
        proxy_otel::inc_active(service_name, protocol);
        Self {
            service_name: service_name.to_string(),
            protocol,
            outcome: Outcome::Error,
        }
    }

    fn succeed(&mut self) {
        self.outcome = Outcome::Ok;
    }
}

impl Drop for RelayTelemetryGuard {
    fn drop(&mut self) {
        proxy_otel::dec_active(&self.service_name, self.protocol);
        proxy_otel::record_result(&self.service_name, self.protocol, self.outcome);
    }
}

// Keep these helpers isolated around the canonical direction mapping.
fn record_tcp_ws_to_local_bytes(service_name: &str, n: u64) {
    proxy_otel::record_bytes(service_name, TelemetryProtocol::Tcp, Direction::Tx, n);
}

fn record_tcp_local_to_ws_bytes(service_name: &str, n: u64) {
    proxy_otel::record_bytes(service_name, TelemetryProtocol::Tcp, Direction::Rx, n);
}

fn record_udp_ws_to_local_bytes(service_name: &str, n: u64) {
    proxy_otel::record_bytes(service_name, TelemetryProtocol::Udp, Direction::Tx, n);
}

fn record_udp_local_to_ws_bytes(service_name: &str, n: u64) {
    proxy_otel::record_bytes(service_name, TelemetryProtocol::Udp, Direction::Rx, n);
}

// ── Frame dispatch ─────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
async fn dispatch_frame(
    frame: WsFrame,
    streams: &Arc<DashMap<u32, StreamHandle>>,
    write_tx: &mpsc::Sender<Message>,
    services: &ServicesConfig,
    acl: &Arc<ArcSwapOption<AclEngine>>,
    gateway_id: &str,
    event_tx: &Option<mpsc::Sender<WssConnectionEvent>>,
    resolver: Option<&Arc<dyn WssTargetResolver>>,
) {
    match frame.command {
        FrameCommand::Open {
            target_ip,
            target_port,
            protocol,
        } => {
            let stream_id = frame.stream_id;
            // Determine the real backend address. With a resolver attached
            // (NSN-side ServiceRouter), the service floor is enforced inside
            // `resolve()` and the returned `SocketAddr` is
            // the actual local backend. Without a resolver (NSC client
            // path), fall back to the legacy services gate against
            // the raw `(target_ip, target_port)`.
            let telemetry_proto = telemetry_protocol(protocol);
            let resolved = match resolver {
                Some(r) => {
                    r.resolve_with_service(
                        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                        target_ip,
                        target_port,
                        protocol,
                    )
                    .await
                }
                None => {
                    if check_target_allowed(services, acl, target_ip, target_port, protocol).await {
                        Some(WssResolvedTarget {
                            target: SocketAddr::new(target_ip, target_port),
                            service_name: None,
                        })
                    } else {
                        None
                    }
                }
            };
            let resolved = match resolved {
                Some(resolved) => resolved,
                None => {
                    warn!(
                        %stream_id,
                        %target_ip,
                        target_port,
                        ?protocol,
                        "WSS Open denied (services/ACL/DNS); sending Close"
                    );
                    proxy_otel::record_result("", telemetry_proto, Outcome::Denied);
                    send_close(write_tx, stream_id).await;
                    return;
                }
            };
            let target = resolved.target;
            let service_name = resolved.service_name.unwrap_or_default();
            let (data_tx, data_rx) = mpsc::channel::<Vec<u8>>(64);
            // Atomic reservation: duplicate detection in a single bucket-locked op.
            match streams.entry(stream_id) {
                dashmap::mapref::entry::Entry::Occupied(_) => {
                    warn!(%stream_id, "WSS duplicate Open stream id; sending Close");
                    proxy_otel::record_result(&service_name, telemetry_proto, Outcome::Error);
                    send_close(write_tx, stream_id).await;
                    return;
                }
                dashmap::mapref::entry::Entry::Vacant(v) => {
                    v.insert(StreamHandle { data_tx });
                }
            }
            // Enforce concurrency cap post-insert; concurrent winners rollback
            // the loser rather than racing through the cap check.
            if streams.len() > MAX_CONCURRENT_STREAMS {
                streams.remove(&stream_id);
                warn!(
                    %stream_id,
                    limit = MAX_CONCURRENT_STREAMS,
                    "WSS stream limit reached; sending Close"
                );
                proxy_otel::record_result(&service_name, telemetry_proto, Outcome::Error);
                send_close(write_tx, stream_id).await;
                return;
            }

            // Emit Open event before spawning the relay task.
            let proto_str = if protocol == Protocol::Udp {
                "udp"
            } else {
                "tcp"
            }
            .to_string();
            if let Some(tx) = event_tx
                && let Err(e) = tx.try_send(WssConnectionEvent {
                    stream_id,
                    gateway_id: gateway_id.to_string(),
                    protocol: proto_str.clone(),
                    target,
                    kind: WssConnectionEventKind::Open,
                })
            {
                warn!(
                    %stream_id,
                    error = %e,
                    "failed to emit WSS Open event; monitoring state may drift"
                );
            }

            let tx = write_tx.clone();
            let registry = Arc::clone(streams);
            let event_tx_close = event_tx.clone();
            let gateway_id_close = gateway_id.to_string();
            tokio::spawn(async move {
                let result = match protocol {
                    Protocol::Udp => {
                        relay_udp(stream_id, target, data_rx, tx.clone(), service_name).await
                    }
                    _ => relay_tcp(stream_id, target, data_rx, tx.clone(), service_name).await,
                };
                if let Err(e) = result {
                    debug!(%stream_id, "relay task exited: {e}");
                    // Notify the relay peer that this stream is closed.
                    let close = WsFrame {
                        stream_id,
                        command: FrameCommand::Close,
                        payload: vec![],
                    };
                    let _ = tx.send(Message::Binary(close.encode())).await;
                }
                registry.remove(&stream_id);
                // Emit Close event after relay task exits.
                if let Some(ref etx) = event_tx_close
                    && let Err(e) = etx.try_send(WssConnectionEvent {
                        stream_id,
                        gateway_id: gateway_id_close,
                        protocol: proto_str,
                        target,
                        kind: WssConnectionEventKind::Close,
                    })
                {
                    warn!(
                        %stream_id,
                        error = %e,
                        "failed to emit WSS Close event; monitoring state may drift"
                    );
                }
            });
        }

        FrameCommand::Data => {
            if let Some(handle) = streams.get(&frame.stream_id) {
                if handle.data_tx.send(frame.payload).await.is_err() {
                    debug!(stream_id = frame.stream_id, "data channel already closed");
                }
            } else {
                debug!(stream_id = frame.stream_id, "Data frame for unknown stream");
            }
        }

        FrameCommand::Close => {
            streams.remove(&frame.stream_id);
            let ack = WsFrame {
                stream_id: frame.stream_id,
                command: FrameCommand::CloseAck,
                payload: vec![],
            };
            if write_tx.send(Message::Binary(ack.encode())).await.is_err() {
                warn!(stream_id = frame.stream_id, "failed to send CloseAck");
            }
        }

        FrameCommand::CloseAck => {
            streams.remove(&frame.stream_id);
        }
    }
}

async fn send_close(write_tx: &mpsc::Sender<Message>, stream_id: u32) {
    let close = WsFrame {
        stream_id,
        command: FrameCommand::Close,
        payload: vec![],
    };
    if write_tx
        .send(Message::Binary(close.encode()))
        .await
        .is_err()
    {
        warn!(%stream_id, "failed to send Close");
    }
}

// ── TCP relay ──────────────────────────────────────────────────────────────

/// Relay a TCP stream between the WebSocket and a local TCP service.
#[tracing::instrument(name = "proxy.tcp", skip_all, fields(service = %service_name, target = %target))]
async fn relay_tcp(
    stream_id: u32,
    target: SocketAddr,
    mut data_rx: mpsc::Receiver<Vec<u8>>,
    write_tx: mpsc::Sender<Message>,
    service_name: String,
) -> Result<(), Error> {
    let mut guard = RelayTelemetryGuard::new(&service_name, TelemetryProtocol::Tcp);
    let connect_start = Instant::now();
    let mut local = match TcpStream::connect(target).await {
        Ok(local) => {
            proxy_otel::record_connect_duration(
                &service_name,
                TelemetryProtocol::Tcp,
                Outcome::Ok,
                connect_start.elapsed().as_secs_f64(),
            );
            local
        }
        Err(e) => {
            proxy_otel::record_connect_duration(
                &service_name,
                TelemetryProtocol::Tcp,
                Outcome::Error,
                connect_start.elapsed().as_secs_f64(),
            );
            return Err(e.into());
        }
    };
    debug!(%stream_id, %target, "TCP relay connected");

    let mut buf = vec![0u8; READ_BUF];

    loop {
        tokio::select! {
            // Server -> local service.
            incoming = data_rx.recv() => {
                match incoming {
                    Some(data) => {
                        local.write_all(&data).await?;
                        record_tcp_ws_to_local_bytes(&service_name, data.len() as u64);
                    }
                    None => break, // Stream closed server-side.
                }
            }
            // Local service -> server.
            n = local.read(&mut buf) => {
                match n? {
                    0 => {
                        // Local service closed the connection.
                        let close = WsFrame {
                            stream_id,
                            command: FrameCommand::Close,
                            payload: vec![],
                        };
                        let _ = write_tx.send(Message::Binary(close.encode())).await;
                        break;
                    }
                    n => {
                        let data = WsFrame {
                            stream_id,
                            command: FrameCommand::Data,
                            payload: buf[..n].to_vec(),
                        };
                        write_tx
                            .send(Message::Binary(data.encode()))
                            .await
                            .map_err(|_| Error::RelayWriteClosed)?;
                        record_tcp_local_to_ws_bytes(&service_name, n as u64);
                    }
                }
            }
        }
    }

    guard.succeed();
    Ok(())
}

// ── UDP relay ─────────────────────────────────────────────────────────────

/// Relay UDP datagrams between the WebSocket and a local UDP service.
///
/// Each `Data` frame maps 1:1 to one UDP datagram -- no fragmentation needed
/// because WebSocket is already message-oriented.
#[tracing::instrument(name = "proxy.udp", skip_all, fields(service = %service_name, target = %target))]
async fn relay_udp(
    stream_id: u32,
    target: SocketAddr,
    mut data_rx: mpsc::Receiver<Vec<u8>>,
    write_tx: mpsc::Sender<Message>,
    service_name: String,
) -> Result<(), Error> {
    let mut guard = RelayTelemetryGuard::new(&service_name, TelemetryProtocol::Udp);
    let connect_start = Instant::now();
    let socket = match async {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(target).await?;
        Ok::<UdpSocket, std::io::Error>(socket)
    }
    .await
    {
        Ok(socket) => {
            proxy_otel::record_connect_duration(
                &service_name,
                TelemetryProtocol::Udp,
                Outcome::Ok,
                connect_start.elapsed().as_secs_f64(),
            );
            socket
        }
        Err(e) => {
            proxy_otel::record_connect_duration(
                &service_name,
                TelemetryProtocol::Udp,
                Outcome::Error,
                connect_start.elapsed().as_secs_f64(),
            );
            return Err(e.into());
        }
    };
    debug!(%stream_id, %target, "UDP relay bound");

    let mut buf = vec![0u8; READ_BUF];
    let mut clean_exit = true;

    loop {
        tokio::select! {
            // Server -> local service.
            incoming = data_rx.recv() => {
                match incoming {
                    Some(data) => {
                        match socket.send(&data).await {
                            Ok(n) => record_udp_ws_to_local_bytes(&service_name, n as u64),
                            Err(e) => warn!(%stream_id, "UDP send error: {e}"),
                        }
                    }
                    None => break,
                }
            }
            // Local service -> server.
            result = socket.recv(&mut buf) => {
                match result {
                    Ok(n) => {
                        let data = WsFrame {
                            stream_id,
                            command: FrameCommand::Data,
                            payload: buf[..n].to_vec(),
                        };
                        write_tx
                            .send(Message::Binary(data.encode()))
                            .await
                            .map_err(|_| Error::RelayWriteClosed)?;
                        record_udp_local_to_ws_bytes(&service_name, n as u64);
                    }
                    Err(e) => {
                        warn!(%stream_id, "UDP recv error: {e}");
                        clean_exit = false;
                        break;
                    }
                }
            }
        }
    }

    if clean_exit {
        guard.succeed();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::OnceLock;

    use prometheus::TextEncoder;

    // ── Helpers ───────────────────────────────────────────────────────────

    fn shared_test_registry() -> Arc<prometheus::Registry> {
        static REGISTRY: OnceLock<Arc<prometheus::Registry>> = OnceLock::new();
        REGISTRY
            .get_or_init(|| {
                Arc::new(telemetry::init_telemetry().expect("telemetry init should succeed"))
            })
            .clone()
    }

    fn metrics_text() -> String {
        TextEncoder::new()
            .encode_to_string(&shared_test_registry().gather())
            .expect("encode prometheus text")
    }

    fn metric_series_name_matches(series: &str, name: &str) -> bool {
        let aliases: &[&str] = match name {
            "nsn_proxy_bytes_total" => &["nsn_proxy_bytes_total_total"],
            "nsn_proxy_connections_total" => &["nsn_proxy_connections_total_total"],
            "nsn_proxy_results_total" => &["nsn_proxy_results_total_total"],
            "nsn_proxy_upstream_timeouts_total" => &["nsn_proxy_upstream_timeouts_total_total"],
            "nsn_proxy_connect_duration_seconds_count" => {
                &["nsn_proxy_connect_duration_seconds_seconds_count"]
            }
            _ => &[],
        };

        series == name
            || series.starts_with(&format!("{name}{{"))
            || aliases
                .iter()
                .any(|alias| series == *alias || series.starts_with(&format!("{alias}{{")))
    }

    fn metric_value(text: &str, name: &str, labels: &[(&str, &str)]) -> Option<f64> {
        for line in text.lines() {
            let Some((series, value)) = line.rsplit_once(' ') else {
                continue;
            };
            if !metric_series_name_matches(series, name) {
                continue;
            }
            let matches_labels = labels
                .iter()
                .all(|(key, value)| series.contains(&format!(r#"{key}="{value}""#)));
            if matches_labels {
                return value.parse::<f64>().ok();
            }
        }
        None
    }

    fn metric_value_or_zero(text: &str, name: &str, labels: &[(&str, &str)]) -> f64 {
        metric_value(text, name, labels).unwrap_or(0.0)
    }

    fn assert_metric_value(text: &str, name: &str, labels: &[(&str, &str)], expected: f64) {
        let actual = metric_value_or_zero(text, name, labels);
        assert_eq!(
            actual, expected,
            "expected {name}{labels:?} to equal {expected}, got {actual}:\n{text}"
        );
    }

    fn assert_metric_delta(
        before: &str,
        after: &str,
        name: &str,
        labels: &[(&str, &str)],
        expected_delta: f64,
    ) {
        let before = metric_value_or_zero(before, name, labels);
        let after = metric_value_or_zero(after, name, labels);
        assert_eq!(
            after - before,
            expected_delta,
            "expected {name}{labels:?} delta {expected_delta}, got {before} -> {after}"
        );
    }

    fn assert_metric_delta_at_least(
        before: &str,
        after: &str,
        name: &str,
        labels: &[(&str, &str)],
        min_delta: f64,
    ) {
        let before_value = metric_value_or_zero(before, name, labels);
        let after_value = metric_value_or_zero(after, name, labels);
        assert!(
            after_value - before_value >= min_delta,
            "expected {name}{labels:?} delta at least {min_delta}, got {before_value} -> {after_value}"
        );
    }

    async fn recv_data_frame(write_rx: &mut mpsc::Receiver<Message>) -> WsFrame {
        let msg = tokio::time::timeout(Duration::from_secs(2), write_rx.recv())
            .await
            .expect("expected relay response within 2 s")
            .expect("write_tx still open");
        let bytes = match msg {
            Message::Binary(b) => b,
            other => panic!("expected Binary message, got {other:?}"),
        };
        let decoded = WsFrame::decode(&bytes).expect("valid frame");
        assert!(matches!(decoded.command, FrameCommand::Data));
        decoded
    }

    /// ACL shared handle with no engine loaded (default deny).
    fn no_acl() -> Arc<ArcSwapOption<AclEngine>> {
        Arc::new(ArcSwapOption::from(None))
    }

    /// ACL shared handle pre-loaded with a wildcard accept-all engine.
    fn allow_all_acl() -> Arc<ArcSwapOption<AclEngine>> {
        use acl::policy::{AclAction, AclRule};
        use acl::{AclEngine, AclPolicy};

        let policy = AclPolicy {
            rules: vec![AclRule {
                action: AclAction::Accept,
                subject: vec!["*".to_string()],
                dst: vec!["*:*".to_string()],
                proto: None,
            }],
            ..Default::default()
        };
        Arc::new(ArcSwapOption::from(Some(Arc::new(
            AclEngine::load(policy).unwrap(),
        ))))
    }

    // ── ACL decision-log transport attribution ────────────────────────────

    /// The framed WSS `Open` path is the gateway-terminated leg of the link
    /// taxonomy: decisions must attribute as `terminate`, not `wss-relay`
    /// (the opaque WG pump, which never carries `Open` frames).
    #[test]
    fn wss_open_judges_on_terminate_leg() {
        let network = NetworkTuple::new(
            Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            "10.0.0.1".parse().unwrap(),
            443,
            Protocol::Tcp,
        );
        let context = wss_open_access_context(network);
        assert_eq!(context.transport, TransportKind::Terminate);
        assert_eq!(context.transport.label(), "terminate");
    }

    // ── WsFrame encode/decode roundtrip ───────────────────────────────────

    fn roundtrip(frame: &WsFrame) -> WsFrame {
        let encoded = frame.encode();
        WsFrame::decode(&encoded).unwrap()
    }

    #[test]
    fn data_frame_roundtrips() {
        let frame = WsFrame {
            stream_id: 42,
            command: FrameCommand::Data,
            payload: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        let decoded = roundtrip(&frame);
        assert_eq!(decoded.stream_id, 42);
        assert!(matches!(decoded.command, FrameCommand::Data));
        assert_eq!(decoded.payload, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn close_frame_roundtrips() {
        let frame = WsFrame {
            stream_id: 7,
            command: FrameCommand::Close,
            payload: vec![],
        };
        let decoded = roundtrip(&frame);
        assert_eq!(decoded.stream_id, 7);
        assert!(matches!(decoded.command, FrameCommand::Close));
        assert!(decoded.payload.is_empty());
    }

    #[test]
    fn close_ack_frame_roundtrips() {
        let frame = WsFrame {
            stream_id: 99,
            command: FrameCommand::CloseAck,
            payload: vec![],
        };
        let decoded = roundtrip(&frame);
        assert_eq!(decoded.stream_id, 99);
        assert!(matches!(decoded.command, FrameCommand::CloseAck));
    }

    #[test]
    fn open_v4_tcp_frame_roundtrips() {
        let frame = WsFrame {
            stream_id: 1,
            command: FrameCommand::Open {
                target_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
                target_port: 8080,
                protocol: Protocol::Tcp,
            },
            payload: vec![],
        };
        let decoded = roundtrip(&frame);
        assert_eq!(decoded.stream_id, 1);
        match decoded.command {
            FrameCommand::Open {
                target_ip,
                target_port,
                protocol,
            } => {
                assert_eq!(target_ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)));
                assert_eq!(target_port, 8080);
                assert_eq!(protocol, Protocol::Tcp);
            }
            _ => panic!("expected Open command"),
        }
    }

    #[test]
    fn open_v4_udp_frame_roundtrips() {
        let frame = WsFrame {
            stream_id: 2,
            command: FrameCommand::Open {
                target_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                target_port: 53,
                protocol: Protocol::Udp,
            },
            payload: vec![],
        };
        let decoded = roundtrip(&frame);
        match decoded.command {
            FrameCommand::Open { protocol, .. } => assert_eq!(protocol, Protocol::Udp),
            _ => panic!("expected Open command"),
        }
    }

    #[test]
    fn open_v6_frame_roundtrips() {
        let ip6 = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
        let frame = WsFrame {
            stream_id: 5,
            command: FrameCommand::Open {
                target_ip: IpAddr::V6(ip6),
                target_port: 443,
                protocol: Protocol::Tcp,
            },
            payload: vec![],
        };
        let decoded = roundtrip(&frame);
        match decoded.command {
            FrameCommand::Open {
                target_ip,
                target_port,
                ..
            } => {
                assert_eq!(target_ip, IpAddr::V6(ip6));
                assert_eq!(target_port, 443);
            }
            _ => panic!("expected Open command"),
        }
    }

    #[test]
    fn stream_id_zero_and_max_roundtrip() {
        for id in [0u32, u32::MAX] {
            let frame = WsFrame {
                stream_id: id,
                command: FrameCommand::Close,
                payload: vec![],
            };
            assert_eq!(roundtrip(&frame).stream_id, id);
        }
    }

    // ── decode error cases ────────────────────────────────────────────────

    #[test]
    fn decode_rejects_too_short_frame() {
        assert!(WsFrame::decode(&[0x00, 0x00, 0x00]).is_err());
    }

    #[test]
    fn decode_rejects_unknown_command_byte() {
        let data = [0x00, 0x00, 0x00, 0x01, 0xFF];
        assert!(WsFrame::decode(&data).is_err());
    }

    #[test]
    fn decode_rejects_open_v4_body_too_short() {
        let data = [0x00, 0x00, 0x00, 0x01, 0x01, 0xC0, 0xA8, 0x01];
        assert!(WsFrame::decode(&data).is_err());
    }

    #[test]
    fn decode_rejects_open_v6_body_too_short() {
        let mut data = vec![0x00, 0x00, 0x00, 0x01, 0x02];
        data.extend_from_slice(&[0u8; 10]);
        assert!(WsFrame::decode(&data).is_err());
    }

    #[test]
    fn decode_rejects_open_v4_unknown_proto_byte() {
        let data = [
            0x00, 0x00, 0x00, 0x01, // stream_id
            0x01, // OPEN_V4
            0x7f, 0x00, 0x00, 0x01, // 127.0.0.1
            0x00, 0x16, // port 22
            0x02, // invalid proto
        ];
        match WsFrame::decode(&data) {
            Err(Error::UnknownProto(0x02)) => {}
            other => panic!("expected UnknownProto(0x02), got {other:?}"),
        }
    }

    #[test]
    fn decode_rejects_open_v6_unknown_proto_byte() {
        let mut data = vec![0x00, 0x00, 0x00, 0x01, 0x02];
        data.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        data.extend_from_slice(&53u16.to_be_bytes());
        data.push(0xff);
        match WsFrame::decode(&data) {
            Err(Error::UnknownProto(0xff)) => {}
            other => panic!("expected UnknownProto(0xff), got {other:?}"),
        }
    }

    #[test]
    fn data_frame_with_empty_payload_roundtrips() {
        let frame = WsFrame {
            stream_id: 0,
            command: FrameCommand::Data,
            payload: vec![],
        };
        let decoded = roundtrip(&frame);
        assert!(decoded.payload.is_empty());
    }

    // ── check_target_allowed ──────────────────────────────────────────────

    fn make_strict_services(host: &str, port: u16, protocol: Protocol) -> ServicesConfig {
        ServicesConfig::from_toml_str(&format!(
            r#"
[settings]
strict = true

[services.svc]
protocol = "{proto}"
host = "{host}"
port = {port}
"#,
            proto = match protocol {
                Protocol::Tcp => "tcp",
                Protocol::Udp => "udp",
                Protocol::Both => "both",
                Protocol::Http => "http",
                Protocol::Https => "https",
            },
            host = host,
            port = port,
        ))
        .unwrap()
    }

    fn permissive_services() -> ServicesConfig {
        ServicesConfig::from_toml_str(
            r#"
[settings]
strict = false
"#,
        )
        .unwrap()
    }

    async fn spawn_udp_reply_backend(response: Vec<u8>) -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 64];
            if let Ok((_n, peer)) = socket.recv_from(&mut buf).await {
                let _ = socket.send_to(&response, peer).await;
            }
        });
        addr
    }

    #[tokio::test]
    async fn relay_tcp_emits_proxy_otel_metrics_for_echo() {
        shared_test_registry();
        let service_name = "wss-tcp-otel";
        let target = spawn_tcp_echo_backend().await;
        let (data_tx, data_rx) = mpsc::channel::<Vec<u8>>(4);
        let (write_tx, mut write_rx) = mpsc::channel::<Message>(4);
        let payload = b"tcp-proxy-otel".to_vec();

        let relay = tokio::spawn(relay_tcp(
            3_001,
            target,
            data_rx,
            write_tx,
            service_name.to_string(),
        ));
        data_tx.send(payload.clone()).await.unwrap();

        let decoded = recv_data_frame(&mut write_rx).await;
        assert_eq!(decoded.stream_id, 3_001);
        assert_eq!(decoded.payload, payload);

        drop(data_tx);
        tokio::time::timeout(Duration::from_secs(2), relay)
            .await
            .expect("relay task should finish")
            .expect("relay task should not panic")
            .expect("relay should exit cleanly");

        let text = metrics_text();
        assert_metric_value(
            &text,
            "nsn_proxy_bytes_total",
            &[
                ("service", service_name),
                ("protocol", "tcp"),
                ("direction", "tx"),
            ],
            14.0,
        );
        assert_metric_value(
            &text,
            "nsn_proxy_bytes_total",
            &[
                ("service", service_name),
                ("protocol", "tcp"),
                ("direction", "rx"),
            ],
            14.0,
        );
        assert_metric_value(
            &text,
            "nsn_proxy_active_connections",
            &[("service", service_name), ("protocol", "tcp")],
            0.0,
        );
        assert_metric_value(
            &text,
            "nsn_proxy_connections_total",
            &[("service", service_name), ("protocol", "tcp")],
            1.0,
        );
        assert_metric_value(
            &text,
            "nsn_proxy_results_total",
            &[
                ("service", service_name),
                ("protocol", "tcp"),
                ("result", "ok"),
            ],
            1.0,
        );
        assert_metric_value(
            &text,
            "nsn_proxy_connect_duration_seconds_count",
            &[
                ("service", service_name),
                ("protocol", "tcp"),
                ("result", "ok"),
            ],
            1.0,
        );
    }

    #[tokio::test]
    async fn relay_tcp_records_error_on_connect_failure() {
        shared_test_registry();
        let service_name = "wss-tcp-connect-fail";
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap();
        drop(listener);
        let (_data_tx, data_rx) = mpsc::channel::<Vec<u8>>(1);
        let (write_tx, _write_rx) = mpsc::channel::<Message>(1);

        let result = relay_tcp(3_002, target, data_rx, write_tx, service_name.to_string()).await;
        assert!(result.is_err(), "connect failure should propagate");

        let text = metrics_text();
        assert_metric_value(
            &text,
            "nsn_proxy_active_connections",
            &[("service", service_name), ("protocol", "tcp")],
            0.0,
        );
        assert_metric_value(
            &text,
            "nsn_proxy_connections_total",
            &[("service", service_name), ("protocol", "tcp")],
            1.0,
        );
        assert_metric_value(
            &text,
            "nsn_proxy_results_total",
            &[
                ("service", service_name),
                ("protocol", "tcp"),
                ("result", "error"),
            ],
            1.0,
        );
        assert_metric_value(
            &text,
            "nsn_proxy_connect_duration_seconds_count",
            &[
                ("service", service_name),
                ("protocol", "tcp"),
                ("result", "error"),
            ],
            1.0,
        );
    }

    #[tokio::test]
    async fn relay_udp_emits_proxy_otel_metrics_for_echo() {
        shared_test_registry();
        let service_name = "wss-udp-otel";
        let response = b"udp-rx-reply".to_vec();
        let target = spawn_udp_reply_backend(response.clone()).await;
        let (data_tx, data_rx) = mpsc::channel::<Vec<u8>>(4);
        let (write_tx, mut write_rx) = mpsc::channel::<Message>(4);
        let payload = b"udp-tx".to_vec();

        let relay = tokio::spawn(relay_udp(
            3_003,
            target,
            data_rx,
            write_tx,
            service_name.to_string(),
        ));
        data_tx.send(payload.clone()).await.unwrap();

        let decoded = recv_data_frame(&mut write_rx).await;
        assert_eq!(decoded.stream_id, 3_003);
        assert_eq!(decoded.payload, response);

        drop(data_tx);
        tokio::time::timeout(Duration::from_secs(2), relay)
            .await
            .expect("relay task should finish")
            .expect("relay task should not panic")
            .expect("relay should exit cleanly");

        let text = metrics_text();
        assert_metric_value(
            &text,
            "nsn_proxy_bytes_total",
            &[
                ("service", service_name),
                ("protocol", "udp"),
                ("direction", "tx"),
            ],
            6.0,
        );
        assert_metric_value(
            &text,
            "nsn_proxy_bytes_total",
            &[
                ("service", service_name),
                ("protocol", "udp"),
                ("direction", "rx"),
            ],
            12.0,
        );
        assert_metric_value(
            &text,
            "nsn_proxy_active_connections",
            &[("service", service_name), ("protocol", "udp")],
            0.0,
        );
        assert_metric_value(
            &text,
            "nsn_proxy_connections_total",
            &[("service", service_name), ("protocol", "udp")],
            1.0,
        );
        assert_metric_value(
            &text,
            "nsn_proxy_results_total",
            &[
                ("service", service_name),
                ("protocol", "udp"),
                ("result", "ok"),
            ],
            1.0,
        );
        assert_metric_value(
            &text,
            "nsn_proxy_connect_duration_seconds_count",
            &[
                ("service", service_name),
                ("protocol", "udp"),
                ("result", "ok"),
            ],
            1.0,
        );
    }

    #[tokio::test]
    async fn open_denial_records_proxy_otel_denied_without_active_or_total() {
        shared_test_registry();
        let before = metrics_text();
        let (write_tx, mut write_rx) = mpsc::channel::<Message>(8);
        let streams = Arc::new(DashMap::new());
        let services = Arc::new(make_strict_services("192.168.1.10", 80, Protocol::Tcp));

        dispatch_frame(
            WsFrame {
                stream_id: 3_004,
                command: FrameCommand::Open {
                    target_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                    target_port: 22,
                    protocol: Protocol::Tcp,
                },
                payload: vec![],
            },
            &streams,
            &write_tx,
            &services,
            &allow_all_acl(),
            "test-gw",
            &None,
            None,
        )
        .await;

        let msg = write_rx.try_recv().expect("expected Close frame");
        let bytes = match msg {
            Message::Binary(b) => b,
            other => panic!("expected Binary message, got {other:?}"),
        };
        let decoded = WsFrame::decode(&bytes).expect("valid frame");
        assert_eq!(decoded.stream_id, 3_004);
        assert!(matches!(decoded.command, FrameCommand::Close));

        let after = metrics_text();
        assert_metric_delta_at_least(
            &before,
            &after,
            "nsn_proxy_results_total",
            &[("service", ""), ("protocol", "tcp"), ("result", "denied")],
            1.0,
        );
        assert_metric_delta(
            &before,
            &after,
            "nsn_proxy_active_connections",
            &[("service", ""), ("protocol", "tcp")],
            0.0,
        );
        assert_metric_delta(
            &before,
            &after,
            "nsn_proxy_connections_total",
            &[("service", ""), ("protocol", "tcp")],
            0.0,
        );
    }

    #[tokio::test]
    async fn duplicate_open_records_proxy_otel_error_without_active_or_total() {
        shared_test_registry();
        let service_name = "stub-duplicate";
        let before = metrics_text();
        let (write_tx, mut write_rx) = mpsc::channel::<Message>(8);
        let streams = Arc::new(DashMap::new());
        let (data_tx, _data_rx) = mpsc::channel::<Vec<u8>>(8);
        streams.insert(3_005, StreamHandle { data_tx });
        let resolver: Arc<dyn WssTargetResolver> = Arc::new(StubResolver {
            port: 80,
            backend: "127.0.0.1:80".parse().unwrap(),
            service_name,
        });

        dispatch_frame(
            WsFrame {
                stream_id: 3_005,
                command: FrameCommand::Open {
                    target_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
                    target_port: 80,
                    protocol: Protocol::Tcp,
                },
                payload: vec![],
            },
            &streams,
            &write_tx,
            &permissive_services(),
            &allow_all_acl(),
            "test-gw",
            &None,
            Some(&resolver),
        )
        .await;

        let msg = write_rx.try_recv().expect("expected Close frame");
        let bytes = match msg {
            Message::Binary(b) => b,
            other => panic!("expected Binary message, got {other:?}"),
        };
        let decoded = WsFrame::decode(&bytes).expect("valid frame");
        assert_eq!(decoded.stream_id, 3_005);
        assert!(matches!(decoded.command, FrameCommand::Close));

        let after = metrics_text();
        assert_metric_delta_at_least(
            &before,
            &after,
            "nsn_proxy_results_total",
            &[
                ("service", service_name),
                ("protocol", "tcp"),
                ("result", "error"),
            ],
            1.0,
        );
        assert_metric_delta(
            &before,
            &after,
            "nsn_proxy_active_connections",
            &[("service", service_name), ("protocol", "tcp")],
            0.0,
        );
        assert_metric_delta(
            &before,
            &after,
            "nsn_proxy_connections_total",
            &[("service", service_name), ("protocol", "tcp")],
            0.0,
        );
    }

    #[tokio::test]
    async fn legacy_wss_open_denies_without_source_subject() {
        let services = make_strict_services("192.168.1.10", 80, Protocol::Tcp);
        assert!(
            !check_target_allowed(
                &services,
                &allow_all_acl(),
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
                80,
                Protocol::Tcp,
            )
            .await
        );
    }

    #[tokio::test]
    async fn denied_target_fails_strict_services() {
        let services = make_strict_services("192.168.1.10", 80, Protocol::Tcp);
        let acl = allow_all_acl();
        // Wrong host
        assert!(
            !check_target_allowed(
                &services,
                &acl,
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                80,
                Protocol::Tcp,
            )
            .await
        );
        // Wrong port
        assert!(
            !check_target_allowed(
                &services,
                &acl,
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
                443,
                Protocol::Tcp,
            )
            .await
        );
    }

    #[tokio::test]
    async fn no_acl_loaded_denies_all_targets() {
        // When the ACL engine has not yet been received from the control
        // plane, all WSS Open frames must be denied regardless of services.
        let services = permissive_services();
        assert!(
            !check_target_allowed(
                &services,
                &no_acl(),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                9999,
                Protocol::Udp,
            )
            .await
        );
    }

    #[tokio::test]
    async fn matching_acl_still_denies_without_source_subject() {
        use acl::policy::{AclAction, AclRule};
        use acl::{AclEngine, AclPolicy};

        let policy = AclPolicy {
            rules: vec![AclRule {
                action: AclAction::Accept,
                subject: vec!["*".to_string()],
                dst: vec!["192.168.1.0/24:80".to_string()],
                proto: None,
            }],
            ..Default::default()
        };
        let engine = Arc::new(AclEngine::load(policy).unwrap());
        let acl = Arc::new(ArcSwapOption::from(Some(engine)));
        let services = permissive_services();

        assert!(
            !check_target_allowed(
                &services,
                &acl,
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
                80,
                Protocol::Tcp,
            )
            .await
        );
    }

    #[tokio::test]
    async fn wss_unknown_source_does_not_match_wildcard_subject() {
        use acl::policy::{AclAction, AclRule};
        use acl::{AclEngine, AclPolicy};

        let policy = AclPolicy {
            rules: vec![AclRule {
                action: AclAction::Accept,
                subject: vec!["*".to_string()],
                dst: vec!["192.168.1.0/24:80".to_string()],
                proto: None,
            }],
            ..Default::default()
        };
        let engine = Arc::new(AclEngine::load(policy).unwrap());
        let acl = Arc::new(ArcSwapOption::from(Some(engine)));
        let services = permissive_services();

        assert!(
            !check_target_allowed(
                &services,
                &acl,
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
                80,
                Protocol::Tcp,
            )
            .await,
            "Unknown source must not match wildcard subject"
        );
    }

    #[tokio::test]
    async fn denied_target_fails_acl_check() {
        use acl::policy::{AclAction, AclRule};
        use acl::{AclEngine, AclPolicy};

        let policy = AclPolicy {
            rules: vec![AclRule {
                action: AclAction::Accept,
                subject: vec!["*".to_string()],
                dst: vec!["192.168.1.0/24:80".to_string()],
                proto: None,
            }],
            ..Default::default()
        };
        let engine = Arc::new(AclEngine::load(policy).unwrap());
        let acl = Arc::new(ArcSwapOption::from(Some(engine)));
        let services = permissive_services();

        // Port 22 not in ACL
        assert!(
            !check_target_allowed(
                &services,
                &acl,
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
                22,
                Protocol::Tcp,
            )
            .await
        );
    }

    #[tokio::test]
    async fn open_denied_by_services_sends_close_frame() {
        shared_test_registry();
        use tokio_tungstenite::tungstenite::Message;
        let (write_tx, mut write_rx) = tokio::sync::mpsc::channel::<Message>(8);
        let streams = Arc::new(DashMap::new());

        // Strict services that only allow 192.168.1.10:80/tcp; ACL is allow-all
        // so services is the sole gating factor for this test.
        let services = Arc::new(make_strict_services("192.168.1.10", 80, Protocol::Tcp));

        let open_frame = WsFrame {
            stream_id: 42,
            command: FrameCommand::Open {
                target_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), // not allowed
                target_port: 22,
                protocol: Protocol::Tcp,
            },
            payload: vec![],
        };

        dispatch_frame(
            open_frame,
            &streams,
            &write_tx,
            &services,
            &allow_all_acl(),
            "test-gw",
            &None,
            None,
        )
        .await;

        // A Close frame must have been sent back.
        let msg = write_rx.try_recv().expect("expected Close frame");
        let bytes = match msg {
            Message::Binary(b) => b,
            other => panic!("expected Binary message, got {other:?}"),
        };
        let decoded = WsFrame::decode(&bytes).expect("valid frame");
        assert_eq!(decoded.stream_id, 42);
        assert!(matches!(decoded.command, FrameCommand::Close));

        // Stream must NOT be registered.
        assert!(!streams.contains_key(&42u32));
    }

    #[tokio::test]
    async fn duplicate_open_sends_close_without_replacing_stream() {
        shared_test_registry();
        use tokio_tungstenite::tungstenite::Message;
        let (write_tx, mut write_rx) = tokio::sync::mpsc::channel::<Message>(8);
        let streams = Arc::new(DashMap::new());
        let (data_tx, mut data_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(8);
        streams.insert(9, StreamHandle { data_tx });

        let open_frame = WsFrame {
            stream_id: 9,
            command: FrameCommand::Open {
                target_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
                target_port: 80,
                protocol: Protocol::Tcp,
            },
            payload: vec![],
        };

        dispatch_frame(
            open_frame,
            &streams,
            &write_tx,
            &permissive_services(),
            &allow_all_acl(),
            "test-gw",
            &None,
            None,
        )
        .await;

        let msg = write_rx.try_recv().expect("expected Close frame");
        let bytes = match msg {
            Message::Binary(b) => b,
            other => panic!("expected Binary message, got {other:?}"),
        };
        let decoded = WsFrame::decode(&bytes).expect("valid frame");
        assert_eq!(decoded.stream_id, 9);
        assert!(matches!(decoded.command, FrameCommand::Close));

        dispatch_frame(
            WsFrame {
                stream_id: 9,
                command: FrameCommand::Data,
                payload: b"still-original".to_vec(),
            },
            &streams,
            &write_tx,
            &permissive_services(),
            &allow_all_acl(),
            "test-gw",
            &None,
            None,
        )
        .await;
        assert_eq!(data_rx.recv().await.unwrap(), b"still-original".to_vec());
    }

    #[tokio::test]
    async fn stream_limit_sends_close_without_registering_stream() {
        shared_test_registry();
        use tokio_tungstenite::tungstenite::Message;
        let (write_tx, mut write_rx) = tokio::sync::mpsc::channel::<Message>(8);
        let streams = Arc::new(DashMap::new());
        for id in 0..MAX_CONCURRENT_STREAMS as u32 {
            let (data_tx, _data_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
            streams.insert(id, StreamHandle { data_tx });
        }

        let open_frame = WsFrame {
            stream_id: 50_000,
            command: FrameCommand::Open {
                target_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
                target_port: 80,
                protocol: Protocol::Tcp,
            },
            payload: vec![],
        };

        dispatch_frame(
            open_frame,
            &streams,
            &write_tx,
            &permissive_services(),
            &allow_all_acl(),
            "test-gw",
            &None,
            None,
        )
        .await;

        let msg = write_rx.try_recv().expect("expected Close frame");
        let bytes = match msg {
            Message::Binary(b) => b,
            other => panic!("expected Binary message, got {other:?}"),
        };
        let decoded = WsFrame::decode(&bytes).expect("valid frame");
        assert_eq!(decoded.stream_id, 50_000);
        assert!(matches!(decoded.command, FrameCommand::Close));
        assert!(!streams.contains_key(&50_000));
        assert_eq!(streams.len(), MAX_CONCURRENT_STREAMS);
    }

    #[tokio::test]
    async fn legacy_open_allowed_by_services_still_closes_without_subject() {
        shared_test_registry();
        use tokio_tungstenite::tungstenite::Message;
        let (write_tx, mut write_rx) = tokio::sync::mpsc::channel::<Message>(8);
        let streams = Arc::new(DashMap::new());

        let services = Arc::new(make_strict_services("192.168.1.10", 80, Protocol::Tcp));

        let open_frame = WsFrame {
            stream_id: 7,
            command: FrameCommand::Open {
                target_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
                target_port: 80,
                protocol: Protocol::Tcp,
            },
            payload: vec![],
        };

        dispatch_frame(
            open_frame,
            &streams,
            &write_tx,
            &services,
            &allow_all_acl(),
            "test-gw",
            &None,
            None,
        )
        .await;

        let msg = write_rx.try_recv().expect("expected Close frame");
        let bytes = match msg {
            Message::Binary(b) => b,
            other => panic!("expected Binary message, got {other:?}"),
        };
        let decoded = WsFrame::decode(&bytes).expect("valid frame");
        assert_eq!(decoded.stream_id, 7);
        assert!(matches!(decoded.command, FrameCommand::Close));
        assert!(!streams.contains_key(&7u32));
    }

    // ── WssTargetResolver integration ─────────────────────────────────────

    /// Stub resolver that maps `(port, tcp)` to a fixed backend `SocketAddr`,
    /// modelling the production `(wg_ip, svc_port) -> svc.host` indirection
    /// (the analogue of `integration/fixtures/nsn-services.toml`'s
    /// `host = "echo"`). Uses a literal address so the test doesn't depend
    /// on docker DNS.
    struct StubResolver {
        port: u16,
        backend: SocketAddr,
        service_name: &'static str,
    }

    impl WssTargetResolver for StubResolver {
        fn resolve<'a>(
            &'a self,
            _src_ip: IpAddr,
            _dst_ip: IpAddr,
            dst_port: u16,
            protocol: Protocol,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<SocketAddr>> + Send + 'a>>
        {
            let backend = self.backend;
            let matches_port = dst_port == self.port;
            let matches_proto = protocol == Protocol::Tcp;
            Box::pin(async move {
                if matches_port && matches_proto {
                    Some(backend)
                } else {
                    None
                }
            })
        }

        fn resolve_with_service<'a>(
            &'a self,
            _src_ip: IpAddr,
            _dst_ip: IpAddr,
            dst_port: u16,
            protocol: Protocol,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Option<WssResolvedTarget>> + Send + 'a>,
        > {
            let backend = self.backend;
            let service_name = self.service_name;
            let matches_port = dst_port == self.port;
            let matches_proto = protocol == Protocol::Tcp;
            Box::pin(async move {
                if matches_port && matches_proto {
                    Some(WssResolvedTarget {
                        target: backend,
                        service_name: Some(service_name.to_string()),
                    })
                } else {
                    None
                }
            })
        }
    }

    /// Stub resolver that always denies, modelling a services-config reload
    /// where the destination temporarily resolves to `None`.
    struct DenyAllResolver;

    impl WssTargetResolver for DenyAllResolver {
        fn resolve<'a>(
            &'a self,
            _src_ip: IpAddr,
            _dst_ip: IpAddr,
            _dst_port: u16,
            _protocol: Protocol,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<SocketAddr>> + Send + 'a>>
        {
            Box::pin(async { None })
        }
    }

    /// Spawn a tokio TCP echo loopback on `127.0.0.1:0` and return the bound
    /// `SocketAddr`. The first accepted connection echoes one read back to
    /// the writer half so the resolved-backend assertion can complete a
    /// round-trip.
    async fn spawn_tcp_echo_backend() -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = [0u8; 64];
                if let Ok(n) = stream.read(&mut buf).await {
                    let _ = stream.write_all(&buf[..n]).await;
                }
            }
        });
        addr
    }

    /// With a stub resolver mapping (port=17777, tcp) -> echo backend, an
    /// Open frame carrying `target_ip = 10.0.0.2` (an arbitrary wg-IP that
    /// is NOT the echo backend's address) must connect to the *resolved*
    /// backend, not the raw `target_ip`.
    #[tokio::test]
    async fn resolver_routes_open_to_resolved_backend() {
        shared_test_registry();
        let backend = spawn_tcp_echo_backend().await;
        let resolver: Arc<dyn WssTargetResolver> = Arc::new(StubResolver {
            port: 17777,
            backend,
            service_name: "stub-resolver",
        });

        let (write_tx, mut write_rx) = mpsc::channel::<Message>(16);
        let streams = Arc::new(DashMap::new());

        let open_frame = WsFrame {
            stream_id: 100,
            command: FrameCommand::Open {
                target_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), // a wg IP
                target_port: 17777,
                protocol: Protocol::Tcp,
            },
            payload: vec![],
        };

        dispatch_frame(
            open_frame,
            &streams,
            &write_tx,
            // Strict services + no ACL would deny — proves the resolver
            // path bypasses the legacy gate as designed.
            &permissive_services(),
            &no_acl(),
            "test-gw",
            &None,
            Some(&resolver),
        )
        .await;

        // No synchronous Close frame: dispatch must have spawned the relay
        // task against the *resolved* backend.
        assert!(
            write_rx.try_recv().is_err(),
            "resolver should have steered the Open to the echo backend"
        );
        assert!(streams.contains_key(&100u32), "stream must be registered");

        // Drive one Data round-trip through the registered stream to prove
        // the connection landed on the echo backend.
        dispatch_frame(
            WsFrame {
                stream_id: 100,
                command: FrameCommand::Data,
                payload: b"ping".to_vec(),
            },
            &streams,
            &write_tx,
            &permissive_services(),
            &no_acl(),
            "test-gw",
            &None,
            Some(&resolver),
        )
        .await;

        // The echo backend writes "ping" back; the relay task wraps it in a
        // Data frame addressed to stream 100.
        let msg = tokio::time::timeout(Duration::from_secs(2), write_rx.recv())
            .await
            .expect("expected echo response within 2 s")
            .expect("write_tx still open");
        let bytes = match msg {
            Message::Binary(b) => b,
            other => panic!("expected Binary, got {other:?}"),
        };
        let decoded = WsFrame::decode(&bytes).expect("decode echo frame");
        assert_eq!(decoded.stream_id, 100);
        assert!(matches!(decoded.command, FrameCommand::Data));
        assert_eq!(decoded.payload, b"ping");
    }

    /// When the resolver returns `None` (e.g. mid-reload of services
    /// config), dispatch must emit a Close frame and NOT register a
    /// stream — fail-closed contract.
    #[tokio::test]
    async fn resolver_denial_sends_close_and_skips_registration() {
        shared_test_registry();
        let resolver: Arc<dyn WssTargetResolver> = Arc::new(DenyAllResolver);
        let (write_tx, mut write_rx) = mpsc::channel::<Message>(16);
        let streams = Arc::new(DashMap::new());

        let open_frame = WsFrame {
            stream_id: 200,
            command: FrameCommand::Open {
                target_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                target_port: 17777,
                protocol: Protocol::Tcp,
            },
            payload: vec![],
        };

        dispatch_frame(
            open_frame,
            &streams,
            &write_tx,
            // Strict services with allow-all ACL would normally permit
            // (192.168.x.x); proves the resolver's None vetoes regardless.
            &Arc::new(make_strict_services("192.168.1.10", 80, Protocol::Tcp)),
            &allow_all_acl(),
            "test-gw",
            &None,
            Some(&resolver),
        )
        .await;

        let msg = write_rx.try_recv().expect("expected Close frame");
        let bytes = match msg {
            Message::Binary(b) => b,
            other => panic!("expected Binary, got {other:?}"),
        };
        let decoded = WsFrame::decode(&bytes).expect("decode");
        assert_eq!(decoded.stream_id, 200);
        assert!(matches!(decoded.command, FrameCommand::Close));
        assert!(!streams.contains_key(&200u32));
    }

    // ── build_rustls_connector / WsTunnel::connect TLS plumbing ──────────

    /// Generate a self-signed CA and a server cert signed by it for the
    /// TLS handshake tests below. Returns `(ca_pem, server_cert_pem,
    /// server_key_pem)`.
    fn generate_test_pki() -> (String, String, String) {
        use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};

        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "tunnel-ws-test-ca");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let mut server_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        server_params
            .distinguished_name
            .push(DnType::CommonName, "localhost");
        let server_key = KeyPair::generate().unwrap();
        let server_cert = server_params
            .signed_by(&server_key, &ca_cert, &ca_key)
            .unwrap();

        (ca_cert.pem(), server_cert.pem(), server_key.serialize_pem())
    }

    /// Spawn a TLS-terminating WebSocket server that completes the WSS
    /// handshake then drops the stream. Returns a `wss://localhost:<port>/`
    /// URL the client can dial.
    async fn spawn_tls_wss_server(server_cert_pem: &str, server_key_pem: &str) -> String {
        use rustls::ServerConfig;
        use rustls::pki_types::PrivateKeyDer;
        use tokio_rustls::TlsAcceptor;

        let cert_chain: Vec<CertificateDer<'static>> =
            CertificateDer::pem_slice_iter(server_cert_pem.as_bytes())
                .collect::<std::result::Result<Vec<_>, _>>()
                .unwrap();
        let key = PrivateKeyDer::from_pem_slice(server_key_pem.as_bytes())
            .expect("private key in server PEM");

        let _ = rustls::crypto::ring::default_provider().install_default();
        let cfg = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(cfg));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let Ok(ws) = tokio_tungstenite::accept_async(tls).await else {
                        return;
                    };
                    let (_tx, mut rx) = ws.split();
                    while rx.next().await.is_some() {}
                });
            }
        });

        format!("wss://localhost:{}/relay", addr.port())
    }

    /// Spawn a plaintext WebSocket server that completes the handshake then
    /// drops the stream. Returns a `ws://127.0.0.1:<port>/` URL — used by
    /// the no-connector backwards-compatibility test below.
    async fn spawn_plain_ws_server() -> String {
        use tokio_tungstenite::accept_async;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                tokio::spawn(async move {
                    if let Ok(ws) = accept_async(tcp).await {
                        let (_tx, mut rx) = ws.split();
                        while rx.next().await.is_some() {}
                    }
                });
            }
        });
        format!("ws://{addr}/relay")
    }

    /// `build_rustls_connector` + `WsTunnel::connect(_, _, _, _, Some(conn))`
    /// must complete the TLS handshake against a server presenting a cert
    /// signed by the supplied private CA — the integration shape NSN's WSS
    /// fallback dials when NSGW uses a self-signed cert chain.
    #[tokio::test]
    async fn connect_with_connector_succeeds_against_rustls_signing_ca() {
        let (ca_pem, server_cert_pem, server_key_pem) = generate_test_pki();
        let url = spawn_tls_wss_server(&server_cert_pem, &server_key_pem).await;

        let dir = tempfile::tempdir().unwrap();
        let bundle = dir.path().join("ca.pem");
        std::fs::write(&bundle, ca_pem).unwrap();

        let connector = build_rustls_connector(&bundle).expect("connector builds");

        let result = WsTunnel::connect(
            &url,
            "test-token",
            Arc::new(ServicesConfig::default()),
            no_acl(),
            Some(connector),
        )
        .await;

        assert!(
            result.is_ok(),
            "WSS handshake against the test CA must succeed: {:?}",
            result.err()
        );
    }

    /// Passing `None` for the connector must reach the default
    /// tokio-tungstenite path, which completes a plaintext `ws://`
    /// handshake without any TLS material. Pins backwards compatibility for
    /// every pre-TLS-003 caller that did not pass a `Connector`.
    #[tokio::test]
    async fn connect_without_connector_falls_back_to_default_path() {
        let url = spawn_plain_ws_server().await;

        let result = WsTunnel::connect(
            &url,
            "test-token",
            Arc::new(ServicesConfig::default()),
            no_acl(),
            None,
        )
        .await;

        assert!(
            result.is_ok(),
            "plaintext ws:// handshake with default trust path must succeed: {:?}",
            result.err()
        );
    }

    /// Empty PEM bundle must surface as a loud error so a misconfigured
    /// operator does not silently fall through to the system roots.
    #[test]
    fn build_rustls_connector_errors_on_empty_pem() {
        let dir = tempfile::tempdir().unwrap();
        let empty = dir.path().join("empty.pem");
        std::fs::write(&empty, "").unwrap();

        let err = build_rustls_connector(&empty)
            .err()
            .expect("empty PEM must error");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("zero PEM certificates"),
            "expected zero-certs error, got: {msg}"
        );
    }

    /// Missing file must surface as a loud error at helper time.
    #[test]
    fn build_rustls_connector_errors_on_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does-not-exist.pem");

        let err = build_rustls_connector(&missing)
            .err()
            .expect("missing file must error");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("open extra_ca_certs bundle"),
            "expected open-failure error, got: {msg}"
        );
    }

    #[test]
    fn opaque_relay_urls_use_endpoint_free_paths() {
        assert_eq!(
            opaque_nsn_relay_url("wss://gw.example.test/"),
            "wss://gw.example.test/wss-relay"
        );
        assert_eq!(
            opaque_nsn_relay_url_for_pair("wss://gw.example.test/", "m-nsc"),
            "wss://gw.example.test/wss-relay?nsc=m-nsc"
        );
        assert_eq!(
            opaque_nsc_client_url("wss://gw.example.test/", "m-nsn"),
            "wss://gw.example.test/client?mode=wss-relay&nsn=m-nsn"
        );
        assert!(is_opaque_client_request_target("/client?mode=wss-relay&nsn=m-nsn").unwrap());
        assert!(!is_opaque_client_request_target("/client").unwrap());
        assert!(!is_opaque_client_request_target("/wss-relay").unwrap());
    }

    #[test]
    fn opaque_client_request_rejects_unknown_mode() {
        let err = is_opaque_client_request_target("/client?mode=terminate").unwrap_err();
        assert!(err.to_string().contains("terminate"));
    }

    #[tokio::test]
    async fn wg_over_ws_outbound_bridges_binary_datagrams_to_udp() {
        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let udp_addr = udp.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 64];
            if let Ok((n, peer)) = udp.recv_from(&mut buf).await {
                let _ = udp.send_to(&buf[..n], peer).await;
            }
        });

        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            ws.send(Message::Binary(b"wg-packet".to_vec()))
                .await
                .unwrap();
            match ws.next().await.unwrap().unwrap() {
                Message::Binary(data) => assert_eq!(data, b"wg-packet"),
                other => panic!("expected binary echo, got {other:?}"),
            }
            let _ = done_tx.send(());
            while let Some(next) = ws.next().await {
                if matches!(next, Ok(Message::Close(_)) | Err(_)) {
                    break;
                }
            }
        });

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let url = format!("ws://{listen_addr}{OPAQUE_WSS_RELAY_PATH}");
        let pump = tokio::spawn(async move {
            run_wg_over_ws_outbound(&url, None, None, udp_addr, async {
                let _ = shutdown_rx.await;
            })
            .await
        });

        done_rx.await.unwrap();
        let _ = shutdown_tx.send(());
        pump.await.unwrap().unwrap();
        server.await.unwrap();
    }

    /// Bind a TCP listener that accepts connections but never answers the
    /// WebSocket handshake, holding every accepted socket open so the dial
    /// hangs inside connect until its own 15 s timeout.
    async fn spawn_silent_tcp_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let hold = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((socket, _)) = listener.accept().await {
                held.push(socket);
            }
        });
        (addr, hold)
    }

    #[tokio::test]
    async fn outbound_dial_cancelled_by_shutdown_terminates_promptly() {
        let (addr, hold) = spawn_silent_tcp_server().await;

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let url = format!("ws://{addr}{OPAQUE_WSS_RELAY_PATH}");
        let leg = tokio::spawn(async move {
            run_wg_over_ws_outbound(&url, None, None, "127.0.0.1:1".parse().unwrap(), async {
                let _ = shutdown_rx.await;
            })
            .await
        });

        // Let the leg enter the dial phase, then signal shutdown mid-dial.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!leg.is_finished(), "leg must be parked in the dial phase");
        let _ = shutdown_tx.send(());

        let result = tokio::time::timeout(Duration::from_secs(2), leg)
            .await
            .expect("shutdown must cancel the dial phase promptly")
            .unwrap();
        assert!(
            result.is_ok(),
            "cancelled dial must exit cleanly: {result:?}"
        );
        hold.abort();
    }

    #[tokio::test]
    async fn nsc_pump_dial_cancelled_by_shutdown_terminates_promptly() {
        let (addr, hold) = spawn_silent_tcp_server().await;
        let pump_socket = bind_nsc_pump_socket().await.unwrap();

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let url = format!("ws://{addr}/client?mode=wss-relay&nsn=m-nsn");
        let pump = tokio::spawn(async move {
            run_wg_over_ws_nsc_client(&url, None, None, &pump_socket, async {
                let _ = shutdown_rx.await;
            })
            .await
        });

        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!pump.is_finished(), "pump must be parked in the dial phase");
        let _ = shutdown_tx.send(());

        let result = tokio::time::timeout(Duration::from_secs(2), pump)
            .await
            .expect("shutdown must cancel the dial phase promptly")
            .unwrap();
        assert!(
            result.is_ok(),
            "cancelled dial must exit cleanly: {result:?}"
        );
        hold.abort();
    }

    // ACL-013 — the NSC pump is the WG *initiator* mirror: boringtun (the UDP
    // side) speaks first to the stable pump socket, the pump forwards over the
    // opaque WS and replies to the learned boringtun address.
    #[tokio::test]
    async fn nsc_pump_bridges_udp_initiated_datagrams_over_ws() {
        // The stable pump socket boringtun is configured to send to.
        let pump = bind_nsc_pump_socket().await.unwrap();
        let pump_addr = pump.local_addr().unwrap();
        assert!(pump_addr.ip().is_loopback(), "pump must bind loopback");

        // Fake boringtun: sends one WG packet to the pump, expects the echo back.
        let wg = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        wg.connect(pump_addr).await.unwrap();

        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            // First frame is the boringtun packet the pump forwarded; echo it.
            match ws.next().await.unwrap().unwrap() {
                Message::Binary(data) => {
                    assert_eq!(data, b"wg-handshake");
                    ws.send(Message::Binary(data)).await.unwrap();
                }
                other => panic!("expected binary, got {other:?}"),
            }
            while let Some(next) = ws.next().await {
                if matches!(next, Ok(Message::Close(_)) | Err(_)) {
                    break;
                }
            }
        });

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        // NSC dials the opaque client URL the NSGW bridge recognizes.
        let url = format!("ws://{listen_addr}/client?mode=wss-relay&nsn=m-nsn");
        let pump_task = tokio::spawn(async move {
            run_wg_over_ws_nsc_client(&url, None, None, &pump, async {
                let _ = shutdown_rx.await;
            })
            .await
        });

        // boringtun is the initiator: it speaks first. The datagram is buffered
        // on the bound pump socket until the pump's loop reads it.
        wg.send(b"wg-handshake").await.unwrap();
        let mut buf = [0u8; 64];
        let n = tokio::time::timeout(Duration::from_secs(5), wg.recv(&mut buf))
            .await
            .expect("pump must echo the WS reply back to boringtun")
            .unwrap();
        assert_eq!(&buf[..n], b"wg-handshake");

        let _ = shutdown_tx.send(());
        pump_task.await.unwrap().unwrap();
        server.await.unwrap();
    }

    /// Spawn a TLS-terminating WebSocket server that gates the upgrade on a
    /// bearer token: a matching `Authorization: Bearer <token>` upgrades
    /// (101); anything else is rejected with HTTP 401. Returns a
    /// `wss://localhost:<port>/relay` URL.
    ///
    /// The bearer check runs *after* the TLS handshake, so a 401 from this
    /// server proves TLS trust was not the blocker.
    // The bearer-check closure's `Err` type is tungstenite's `ErrorResponse`
    // (an `http::Response`), whose size is fixed by that external API.
    #[allow(clippy::result_large_err)]
    async fn spawn_tls_wss_server_requiring_bearer(
        server_cert_pem: &str,
        server_key_pem: &str,
        expected_token: &'static str,
    ) -> String {
        use rustls::ServerConfig;
        use rustls::pki_types::PrivateKeyDer;
        use tokio_rustls::TlsAcceptor;
        use tokio_tungstenite::accept_hdr_async;
        use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
        use tokio_tungstenite::tungstenite::http::StatusCode;

        let cert_chain: Vec<CertificateDer<'static>> =
            CertificateDer::pem_slice_iter(server_cert_pem.as_bytes())
                .collect::<std::result::Result<Vec<_>, _>>()
                .unwrap();
        let key = PrivateKeyDer::from_pem_slice(server_key_pem.as_bytes())
            .expect("private key in server PEM");

        let _ = rustls::crypto::ring::default_provider().install_default();
        let cfg = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(cfg));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let callback =
                        |req: &Request,
                         resp: Response|
                         -> std::result::Result<Response, ErrorResponse> {
                            let ok = req
                                .headers()
                                .get("Authorization")
                                .and_then(|v| v.to_str().ok())
                                .map(|v| v == format!("Bearer {expected_token}"))
                                .unwrap_or(false);
                            if ok {
                                Ok(resp)
                            } else {
                                Err(Response::builder()
                                    .status(StatusCode::UNAUTHORIZED)
                                    .body(Some("invalid bearer".to_string()))
                                    .unwrap())
                            }
                        };
                    if let Ok(ws) = accept_hdr_async(tls, callback).await {
                        let (_tx, mut rx) = ws.split();
                        while rx.next().await.is_some() {}
                    }
                });
            }
        });

        format!("wss://localhost:{}/relay", addr.port())
    }

    /// mmpr31ah core property: once the custom CA is trusted, a wrong bearer
    /// must surface as the typed [`Error::Unauthorized`] (HTTP 401) — proving
    /// the failure reached bearer validation rather than being masked by a
    /// TLS `UnknownIssuer` error. Guards [`is_unauthorized`] for the
    /// connector-side refresh path.
    #[tokio::test]
    async fn connect_with_wrong_bearer_reaches_typed_401() {
        let (ca_pem, server_cert_pem, server_key_pem) = generate_test_pki();
        let url =
            spawn_tls_wss_server_requiring_bearer(&server_cert_pem, &server_key_pem, "right").await;

        let dir = tempfile::tempdir().unwrap();
        let bundle = dir.path().join("ca.pem");
        std::fs::write(&bundle, ca_pem).unwrap();
        let connector = build_rustls_connector(&bundle).expect("connector builds");

        let err = WsTunnel::connect(
            &url,
            "wrong",
            Arc::new(ServicesConfig::default()),
            no_acl(),
            Some(connector),
        )
        .await
        .err()
        .expect("wrong bearer must fail the handshake");

        assert!(
            is_unauthorized(&err),
            "wrong bearer must surface as a typed 401, got: {err:?}"
        );
    }

    /// Negative control: dialing the same custom-CA server over `wss://`
    /// *without* trusting that CA (default WebPKI-only path via `None`) must
    /// fail at TLS certificate verification — not reach the bearer. Confirms
    /// the custom CA is what unlocks trust and that verification is genuinely
    /// enforced, never disabled.
    #[tokio::test]
    async fn connect_over_wss_without_trusting_ca_fails_on_certificate() {
        let (_ca_pem, server_cert_pem, server_key_pem) = generate_test_pki();
        let url = spawn_tls_wss_server(&server_cert_pem, &server_key_pem).await;

        let err = WsTunnel::connect(
            &url,
            "test-token",
            Arc::new(ServicesConfig::default()),
            no_acl(),
            None,
        )
        .await
        .err()
        .expect("untrusted custom-CA chain must fail the TLS handshake");

        assert!(
            !is_unauthorized(&err),
            "failure must be a TLS trust error, not a bearer 401: {err:?}"
        );
        let msg = err.to_string().to_lowercase();
        assert!(
            msg.contains("unknownissuer") || msg.contains("certificate") || msg.contains("tls"),
            "expected a TLS certificate verification failure, got: {msg}"
        );
    }
}
