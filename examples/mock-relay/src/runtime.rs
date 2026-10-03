//! The tokio runtime around the sans-IO core: the UDP and WSS carriers, a tick task and
//! the [`MockRelay`] server handle (quick-v2 §8.5, §8.6).
//!
//! ns derives both carriers from the relay identifier `host:port`: UDP datagrams go to
//! `host:port` and WSS connects to `wss://host:port/ns/v2`. The mock therefore binds UDP
//! and TCP on the same port unless told otherwise. WSS is TLS only: the ns WSS carrier
//! always dials `wss://` with a rustls client configuration, so there is no plain `ws://`.
//!
//! A combined server that owns the TLS listener itself sets
//! [`MockRelayConfig::external_wss`] and hands each `/ns/v2` connection to
//! [`MockRelay::handle_stream`] or [`MockRelay::handle_websocket`].

mod tls;
mod udp;
mod wss;

pub use wss::{accept_relay_request, relay_websocket_config};

use crate::{ConfigError, Counters, Limits, Now, Peer, Relay, RelayConfig, SessionInfo, Transmit};
use getrandom::SysRng;
use nsshared_proto::rendezvous::capability::{self, Capabilities, Capability, CapabilityError};
use nsshared_proto::{DEFAULT_PRESENCE_TTL_SECONDS, RelayId, RelayIdError, WSS_CONNECTIONS_PER_IP};
use rand_core::UnwrapErr;
use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::{Arc, Mutex, MutexGuard, PoisonError, atomic::AtomicU64},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, UdpSocket},
    sync::{mpsc, watch},
    task::JoinHandle,
};
use tokio_tungstenite::WebSocketStream;
use tracing::{debug, warn};

/// How often the tick task drives the core's expiry.
const TICK_INTERVAL: Duration = Duration::from_secs(1);

/// How many ephemeral TCP ports are tried before giving up on a free UDP twin.
const SHARED_PORT_ATTEMPTS: usize = 16;

/// Where the WSS server certificate comes from.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TlsSource {
    /// A fresh self-signed certificate from rcgen. Its names always include the relay
    /// identifier host; an empty `names` adds `localhost` and `127.0.0.1`.
    SelfSigned {
        /// Extra subject alternative names; IP literals become IP names.
        names: Vec<String>,
    },
    /// A PEM certificate chain and private key.
    Pem {
        /// The PEM certificate chain file, leaf first.
        cert: PathBuf,
        /// The PEM private key file.
        key: PathBuf,
    },
}

/// The settings of a [`MockRelay`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MockRelayConfig {
    /// The relay identifier `host:port`; `None` uses the bound address, with an
    /// unspecified IP shown as loopback (`127.0.0.1:<port>`).
    pub relay_id: Option<RelayId>,
    /// The shared UDP and WSS listen address; port 0 picks one free port for both.
    pub listen: SocketAddr,
    /// A separate UDP listen address instead of `listen`.
    pub udp_listen: Option<SocketAddr>,
    /// A separate WSS (TCP) listen address instead of `listen`.
    pub wss_listen: Option<SocketAddr>,
    /// Serves the UDP carrier and announces `udp`.
    pub udp: bool,
    /// Serves the WSS carrier and announces `wss`.
    pub wss: bool,
    /// Tokens announced after `udp` and `wss` in the tentative REGISTERED, duplicates
    /// skipped; at most 16 tokens in total (rendezvous §3.1).
    pub extra_capabilities: Vec<Capability>,
    /// With `wss`, binds no TCP listener and generates no certificate: the caller owns
    /// the TLS listener and passes `/ns/v2` connections to [`MockRelay::handle_stream`]
    /// or [`MockRelay::handle_websocket`]. `wss` is still announced and UDP still binds
    /// `udp_listen` or `listen`, which should carry the caller's TCP port because ns uses
    /// the identifier port for both carriers. Ignored without `wss`.
    pub external_wss: bool,
    /// The WSS server certificate.
    pub tls: TlsSource,
    /// The presence TTL in seconds, 30..=3600 (quick-v2 §8.3 rule 5).
    pub presence_ttl_s: u32,
    /// Per-node limits of the core.
    pub limits: Limits,
    /// Concurrent WSS connections per remote IP; more are closed on accept.
    pub wss_connections_per_ip: usize,
}

impl Default for MockRelayConfig {
    /// Both carriers on `127.0.0.1:0`, a self-signed certificate with the default names,
    /// the default presence TTL and limits.
    fn default() -> Self {
        Self {
            relay_id: None,
            listen: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            udp_listen: None,
            wss_listen: None,
            udp: true,
            wss: true,
            extra_capabilities: Vec::new(),
            external_wss: false,
            tls: TlsSource::SelfSigned { names: Vec::new() },
            presence_ttl_s: DEFAULT_TTL_S,
            limits: Limits::default(),
            wss_connections_per_ip: WSS_CONNECTIONS_PER_IP,
        }
    }
}

/// A certificate generated for [`TlsSource::SelfSigned`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneratedCert {
    /// The DER certificate.
    pub der: Vec<u8>,
    /// The same certificate as PEM.
    pub pem: String,
}

/// Why a [`MockRelay`] could not start.
#[derive(Debug, Error)]
pub enum Error {
    /// Both carriers are disabled.
    #[error("at least one of the UDP and WSS carriers must be enabled")]
    NoCarrier,
    /// The core rejected the configuration.
    #[error(transparent)]
    Config(#[from] ConfigError),
    /// The announced capabilities exceed 16 tokens.
    #[error(transparent)]
    Capabilities(#[from] CapabilityError),
    /// The default relay identifier built from the bound address is invalid.
    #[error("relay identifier {text:?}: {source}")]
    RelayId {
        /// The rejected identifier text.
        text: String,
        /// The parse error.
        source: RelayIdError,
    },
    /// A listen socket could not be bound.
    #[error("bind {address}: {source}")]
    Bind {
        /// The address that failed.
        address: SocketAddr,
        /// The bind error.
        source: io::Error,
    },
    /// The self-signed certificate could not be generated.
    #[error("certificate generation: {0}")]
    Certificate(#[from] rcgen::Error),
    /// A PEM file could not be read.
    #[error("PEM {}: {source}", path.display())]
    Pem {
        /// The file that failed.
        path: PathBuf,
        /// The PEM error.
        source: rustls::pki_types::pem::Error,
    },
    /// rustls rejected the TLS configuration.
    #[error("TLS: {0}")]
    Tls(#[from] rustls::Error),
}

/// A running single-instance relay mock serving UDP and WSS.
///
/// Dropping the handle also stops the tasks, but without waiting for them; use
/// [`MockRelay::shutdown`] to know the sockets are released. Share it as
/// `Arc<MockRelay>` to serve external connections from several tasks.
#[derive(Debug)]
pub struct MockRelay {
    relay_id: RelayId,
    udp_addr: Option<SocketAddr>,
    wss_addr: Option<SocketAddr>,
    cert: Option<GeneratedCert>,
    shared: Arc<Shared>,
    stop: watch::Sender<()>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

impl MockRelay {
    /// Binds the enabled carriers and starts the UDP, WSS and tick tasks.
    ///
    /// # Errors
    ///
    /// [`Error`] for an invalid configuration, a failed bind or a bad certificate.
    pub async fn start(config: MockRelayConfig) -> Result<Self, Error> {
        if !config.udp && !config.wss {
            return Err(Error::NoCarrier);
        }
        let (udp_socket, tcp_listener) = bind(&config).await?;
        let udp_addr = local_addr(udp_socket.as_ref().map(UdpSocket::local_addr))?;
        let wss_addr = local_addr(tcp_listener.as_ref().map(TcpListener::local_addr))?;
        let relay_id = match &config.relay_id {
            Some(relay_id) => relay_id.clone(),
            None => default_relay_id(wss_addr.or(udp_addr).unwrap_or(config.listen))?,
        };
        if let (Some(udp), Some(wss)) = (udp_addr, wss_addr)
            && udp.port() != wss.port()
        {
            warn!(%udp, %wss, "UDP and WSS ports differ; ns uses the identifier port for both");
        }

        let mut tokens = Vec::new();
        if config.udp {
            tokens.push(capability::UDP);
        }
        if config.wss {
            tokens.push(capability::WSS);
        }
        for token in &config.extra_capabilities {
            if !tokens.contains(token) {
                tokens.push(token.clone());
            }
        }
        let relay_config = RelayConfig {
            capabilities: Capabilities::new(tokens)?,
            presence_ttl_s: config.presence_ttl_s,
            limits: config.limits,
            ..RelayConfig::new(relay_id.clone())
        };
        let relay = Relay::new(relay_config, UnwrapErr(SysRng))?;

        let (server_tls, cert) = match tcp_listener {
            Some(_) => {
                let (server_tls, cert) = tls::server_config(&config.tls, relay_host(&relay_id))?;
                (Some(server_tls), cert)
            }
            None => (None, None),
        };

        let udp_socket = udp_socket.map(Arc::new);
        let (stop, stopped) = watch::channel(());
        let shared = Arc::new(Shared {
            relay: Mutex::new(relay),
            udp: Mutex::new(udp_socket.clone()),
            wss: Mutex::new(HashMap::new()),
            ip_slots: Arc::new(Mutex::new(HashMap::new())),
            wss_per_ip: config.wss_connections_per_ip,
            next_connection: AtomicU64::new(1),
            stopped: stopped.clone(),
        });
        let mut tasks = vec![tokio::spawn(tick(Arc::clone(&shared), stopped.clone()))];
        if let Some(socket) = udp_socket {
            tasks.push(tokio::spawn(udp::serve(
                socket,
                Arc::clone(&shared),
                stopped,
            )));
        }
        if let (Some(listener), Some(server_tls)) = (tcp_listener, server_tls) {
            tasks.push(tokio::spawn(wss::serve(
                listener,
                server_tls,
                Arc::clone(&shared),
            )));
        }
        Ok(Self {
            relay_id,
            udp_addr,
            wss_addr,
            cert,
            shared,
            stop,
            tasks: Mutex::new(tasks),
        })
    }

    /// Returns the relay identifier nodes sign into REGISTER and list in their records.
    #[must_use]
    pub const fn relay_id(&self) -> &RelayId {
        &self.relay_id
    }

    /// Returns the bound UDP address, `None` when UDP is disabled.
    #[must_use]
    pub const fn udp_addr(&self) -> Option<SocketAddr> {
        self.udp_addr
    }

    /// Returns the bound WSS (TCP) address, `None` when WSS is disabled or external.
    #[must_use]
    pub const fn wss_addr(&self) -> Option<SocketAddr> {
        self.wss_addr
    }

    /// Returns the generated certificate, `None` for PEM files, external WSS or without
    /// WSS.
    #[must_use]
    pub const fn generated_cert(&self) -> Option<&GeneratedCert> {
        self.cert.as_ref()
    }

    /// Returns the core's provisional registrations and confirmed sessions.
    #[must_use]
    pub fn sessions(&self) -> Vec<SessionInfo> {
        self.shared.relay().sessions()
    }

    /// Returns a snapshot of the core's counters.
    #[must_use]
    pub fn counters(&self) -> Counters {
        self.shared.relay().counters().clone()
    }

    /// Serves one TLS-terminated connection from `remote`, handed over by a caller-owned
    /// listener in [`MockRelayConfig::external_wss`] mode: the same WebSocket handshake as
    /// the built-in listener ([`accept_relay_request`], [`relay_websocket_config`]), then
    /// relay packets until the connection closes or [`shutdown`](Self::shutdown) closes it
    /// with code 1001. `remote`'s IP counts toward the per-IP WSS connection limit; a
    /// connection over it is dropped before the handshake.
    ///
    /// The future resolves when the connection ends, so spawn it per connection, e.g.
    /// from an `Arc<MockRelay>`. `S` needs no `Send` or `'static` of its own.
    pub async fn handle_stream<S>(&self, stream: S, remote: SocketAddr)
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        wss::handle_stream(Arc::clone(&self.shared), stream, remote).await;
    }

    /// Serves a WebSocket from `remote` that the caller has already upgraded: it must
    /// have validated the request and selected `ns-relay-v2` with
    /// [`accept_relay_request`] and should apply [`relay_websocket_config`]; under a larger
    /// limit (a router sharing one config with `/rendezvous/v1`) the relay still closes a
    /// message over 2048 bytes with code 1009. A connection over
    /// the per-IP limit is closed with code 1013. Otherwise as
    /// [`handle_stream`](Self::handle_stream).
    pub async fn handle_websocket<S>(&self, ws: WebSocketStream<S>, remote: SocketAddr)
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        wss::handle_websocket(Arc::clone(&self.shared), ws, remote).await;
    }

    /// Stops every task, closes the WSS connections, including those served through
    /// [`handle_stream`](Self::handle_stream) and
    /// [`handle_websocket`](Self::handle_websocket), and releases the sockets.
    /// Later calls return at once.
    pub async fn shutdown(&self) {
        // Every task watches the channel and returns once the value changes.
        self.stop.send_replace(());
        let tasks = std::mem::take(&mut *self.tasks.lock().unwrap_or_else(PoisonError::into_inner));
        for task in tasks {
            if let Err(error) = task.await {
                warn!(%error, "relay task failed");
            }
        }
        wss::drain(&self.shared).await;
        self.shared
            .udp
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
    }
}

/// State shared by the tasks: the core, the UDP socket and the WSS connection state.
#[derive(Debug)]
struct Shared {
    relay: Mutex<Relay<UnwrapErr<SysRng>>>,
    /// Taken on shutdown so the socket is released while external connections linger.
    udp: Mutex<Option<Arc<UdpSocket>>>,
    wss: Mutex<HashMap<u64, mpsc::Sender<Vec<u8>>>>,
    /// Open WSS connections per remote IP, built-in and external alike.
    ip_slots: Arc<Mutex<HashMap<IpAddr, usize>>>,
    wss_per_ip: usize,
    next_connection: AtomicU64,
    /// Changes once on shutdown; WSS connections clone it.
    stopped: watch::Receiver<()>,
}

impl Shared {
    fn relay(&self) -> MutexGuard<'_, Relay<UnwrapErr<SysRng>>> {
        self.relay.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn connections(&self) -> MutexGuard<'_, HashMap<u64, mpsc::Sender<Vec<u8>>>> {
        self.wss.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Feeds one packet to the core and sends its replies.
    async fn handle(&self, from: Peer, packet: &[u8]) {
        let transmits = self.relay().handle(now(), from, packet);
        self.deliver(transmits).await;
    }

    /// Sends each transmit on its carrier; a full or closed WSS queue drops the packet.
    async fn deliver(&self, transmits: Vec<Transmit>) {
        for Transmit { to, packet } in transmits {
            match to {
                Peer::Udp(address) => {
                    let socket = self
                        .udp
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .clone();
                    let Some(socket) = socket else { continue };
                    if let Err(error) = socket.send_to(&packet, address).await {
                        debug!(%address, %error, "relay UDP send failed");
                    }
                }
                Peer::Wss { connection, .. } => {
                    let queue = self.connections().get(&connection).cloned();
                    if let Some(queue) = queue
                        && queue.try_send(packet).is_err()
                    {
                        debug!(connection, "relay WSS queue full or closed; packet dropped");
                    }
                }
            }
        }
    }
}

/// Drives presence, provisional and record expiry about once per second.
async fn tick(shared: Arc<Shared>, mut stopped: watch::Receiver<()>) {
    let mut interval = tokio::time::interval(TICK_INTERVAL);
    loop {
        tokio::select! {
            _ = stopped.changed() => return,
            _ = interval.tick() => shared.relay().tick(now()),
        }
    }
}

/// Returns the current monotonic and Unix time.
fn now() -> Now {
    Now {
        instant: Instant::now(),
        unix: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs()),
    }
}

/// Binds the enabled carriers; UDP and TCP share `listen`'s port unless overridden.
async fn bind(config: &MockRelayConfig) -> Result<(Option<UdpSocket>, Option<TcpListener>), Error> {
    let listen_wss = config.wss && !config.external_wss;
    let shared_port =
        config.udp && listen_wss && config.udp_listen.is_none() && config.wss_listen.is_none();
    if shared_port && config.listen.port() == 0 {
        return bind_shared_ephemeral(config.listen).await;
    }
    let udp = if config.udp {
        Some(bind_udp(config.udp_listen.unwrap_or(config.listen)).await?)
    } else {
        None
    };
    let tcp = if listen_wss {
        Some(bind_tcp(config.wss_listen.unwrap_or(config.listen)).await?)
    } else {
        None
    };
    Ok((udp, tcp))
}

/// Binds TCP on an ephemeral port, then UDP on the same port, retrying on a conflict.
async fn bind_shared_ephemeral(
    listen: SocketAddr,
) -> Result<(Option<UdpSocket>, Option<TcpListener>), Error> {
    let mut last = None;
    for _ in 0..SHARED_PORT_ATTEMPTS {
        let tcp = bind_tcp(listen).await?;
        let address = tcp.local_addr().map_err(|source| Error::Bind {
            address: listen,
            source,
        })?;
        match bind_udp(address).await {
            Ok(udp) => return Ok((Some(udp), Some(tcp))),
            Err(error) => {
                debug!(%address, %error, "UDP twin port taken; retrying");
                last = Some(error);
            }
        }
    }
    Err(last.unwrap_or_else(|| Error::Bind {
        address: listen,
        source: io::Error::from(io::ErrorKind::AddrInUse),
    }))
}

async fn bind_udp(address: SocketAddr) -> Result<UdpSocket, Error> {
    UdpSocket::bind(address)
        .await
        .map_err(|source| Error::Bind { address, source })
}

async fn bind_tcp(address: SocketAddr) -> Result<TcpListener, Error> {
    TcpListener::bind(address)
        .await
        .map_err(|source| Error::Bind { address, source })
}

/// Unwraps an optional `local_addr` result.
fn local_addr(address: Option<io::Result<SocketAddr>>) -> Result<Option<SocketAddr>, Error> {
    address.transpose().map_err(|source| Error::Bind {
        address: SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
        source,
    })
}

/// Returns `ip:port` for a bound address, an unspecified IP shown as loopback.
fn default_relay_id(address: SocketAddr) -> Result<RelayId, Error> {
    let ip = match address.ip() {
        ip if ip.is_unspecified() && ip.is_ipv4() => IpAddr::from(Ipv4Addr::LOCALHOST),
        ip if ip.is_unspecified() => IpAddr::from(std::net::Ipv6Addr::LOCALHOST),
        ip => ip,
    };
    let text = SocketAddr::new(ip, address.port()).to_string();
    RelayId::parse(&text).map_err(|source| Error::RelayId { text, source })
}

/// Returns the host of a relay identifier, IPv6 brackets removed.
fn relay_host(relay_id: &RelayId) -> &str {
    let text = relay_id.as_str();
    let host = text.rsplit_once(':').map_or(text, |(host, _)| host);
    host.strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host)
}

// DEFAULT_PRESENCE_TTL_SECONDS is 90, well inside u32.
const DEFAULT_TTL_S: u32 = DEFAULT_PRESENCE_TTL_SECONDS as u32;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_relay_id_shows_unspecified_as_loopback() {
        let relay = default_relay_id(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 4433))).unwrap();
        assert_eq!(relay.as_str(), "127.0.0.1:4433");
        let relay = default_relay_id("[::]:4433".parse().unwrap()).unwrap();
        assert_eq!(relay.as_str(), "[::1]:4433");
    }

    #[test]
    fn relay_host_strips_the_port_and_brackets() {
        for (text, host) in [
            ("relay.example:443", "relay.example"),
            ("127.0.0.1:9", "127.0.0.1"),
            ("[2001:db8::10]:8443", "2001:db8::10"),
        ] {
            assert_eq!(relay_host(&RelayId::parse(text).unwrap()), host);
        }
    }
}
