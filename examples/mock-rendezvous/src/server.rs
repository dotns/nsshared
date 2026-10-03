//! TLS WebSocket server for `wss://{host:port}/quick/v2` (rendezvous §3, §4, §5.2, §6,
//! §7; quick-v2 §7.2).
//!
//! [`RendezvousServer`] terminates TLS, accepts only path `/quick/v2` with subprotocol
//! `ns-quick-v2`, bounds every incoming message by the §6 message size before parsing,
//! sends the `challenge`, then answers one text message per request, in order. Each
//! request runs against the [`MailboxBroker`] and [`RegistryStore`] behind one mutex;
//! the server adds the `hello` binding, the §6 and quick-v2 §7.4 rate limits, the
//! pending-`recv` count, the `recv` long poll and the 10 s sweep. It is the only part
//! of the crate that reads the clock or OS randomness.
//!
//! Another server can embed it: [`RendezvousServer::handle_tcp`] takes an accepted TCP
//! connection, [`RendezvousServer::handle_stream`] an already decrypted (or plain)
//! stream and [`RendezvousServer::handle_websocket`] an already upgraded socket (a
//! router upgrades with [`accept_quick_request`] and
//! [`RendezvousServer::websocket_config`]); the embedder then runs
//! [`RendezvousServer::run_sweeper`] once.

use crate::{
    config::{Config, Limits, TlsSource},
    mailbox::MailboxBroker,
    rate::RateLimiter,
    registry::{self, RegistryStore},
    tls::{ServerTls, TlsError},
};
use futures_util::{SinkExt, StreamExt};
use getrandom::SysRng;
use nsshared_rendezvous::{
    auth::Challenge,
    capability,
    directory::{Directory, RelayEntry},
    error::ErrorCode,
    limits::SWEEP_INTERVAL_SECONDS,
    message::RecvRequest,
    phase::{Actor, check_pending_recv_within},
    transport::{
        MAX_MESSAGE_BYTES, Operation, PATH, Request, Response, SUBPROTOCOL, decode_request,
        encode_response,
    },
};
use nsshared_wire::{Identity, RelayId};
use rand_core::TryRng;
use std::{
    io,
    net::IpAddr,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
    sync::watch,
    time::timeout,
};
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::{
    WebSocketStream, accept_hdr_async_with_config,
    tungstenite::{
        Message,
        handshake::server::{ErrorResponse, Request as HttpRequest, Response as HttpResponse},
        http::{HeaderValue, StatusCode, header::SEC_WEBSOCKET_PROTOCOL},
        protocol::WebSocketConfig,
    },
};

/// Time allowed for the TLS handshake and for the WebSocket upgrade, each.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Challenge nonce draws before the RNG is considered broken; a working RNG never
/// draws 32 zero bytes.
const MAX_NONCE_ATTEMPTS: usize = 4;

/// Why the server could not start.
#[derive(Debug, Error)]
pub enum ServerError {
    /// The self entry or the served directory breaks a rendezvous §5.4 rule.
    #[error("invalid relay entry or directory: {0}")]
    Config(#[from] ErrorCode),
    /// The TLS configuration could not be built.
    #[error(transparent)]
    Tls(#[from] TlsError),
    /// Binding the listener failed.
    #[error("listener: {0}")]
    Io(#[from] io::Error),
}

/// The rendezvous §6 and quick-v2 §7.4 rate limiters keyed by source IP or global.
#[derive(Debug)]
struct Rates {
    lookup_ip: RateLimiter<IpAddr>,
    lookup: RateLimiter<()>,
    open_ip: RateLimiter<IpAddr>,
    open: RateLimiter<()>,
    publish_ip: RateLimiter<IpAddr>,
    publish: RateLimiter<()>,
    publish_identity: RateLimiter<Identity>,
    lookup_node_ip: RateLimiter<IpAddr>,
    lookup_node: RateLimiter<()>,
}

impl Rates {
    fn new(limits: &Limits, keys: usize) -> Self {
        Self {
            lookup_ip: RateLimiter::per_minute(limits.lookups_per_ip_per_minute, keys),
            lookup: RateLimiter::per_second(limits.lookups_per_second, 1),
            open_ip: RateLimiter::per_minute(limits.opens_per_ip_per_minute, keys),
            open: RateLimiter::per_second(limits.opens_per_second, 1),
            publish_ip: RateLimiter::per_minute(limits.publishes_per_ip_per_minute, keys),
            publish: RateLimiter::per_second(limits.publishes_per_second, 1),
            publish_identity: RateLimiter::min_interval(
                limits
                    .publish_interval_per_identity_seconds
                    .saturating_mul(1000),
                keys,
            ),
            lookup_node_ip: RateLimiter::per_minute(limits.lookup_nodes_per_ip_per_minute, keys),
            lookup_node: RateLimiter::per_second(limits.lookup_nodes_per_second, 1),
        }
    }

    /// The per-source-IP and global limits of `operation`, if it has any.
    fn check(&mut self, operation: Operation, ip: IpAddr, now_ms: u64) -> Result<(), ErrorCode> {
        let (per_ip, global) = match operation {
            Operation::Lookup => (&mut self.lookup_ip, &mut self.lookup),
            Operation::Open => (&mut self.open_ip, &mut self.open),
            Operation::Publish => (&mut self.publish_ip, &mut self.publish),
            Operation::LookupNode => (&mut self.lookup_node_ip, &mut self.lookup_node),
            _ => return Ok(()),
        };
        per_ip.check(ip, now_ms)?;
        global.check((), now_ms)
    }

    fn prune(&mut self, now_ms: u64) {
        self.lookup_ip.prune(now_ms);
        self.lookup.prune(now_ms);
        self.open_ip.prune(now_ms);
        self.open.prune(now_ms);
        self.publish_ip.prune(now_ms);
        self.publish.prune(now_ms);
        self.publish_identity.prune(now_ms);
        self.lookup_node_ip.prune(now_ms);
        self.lookup_node.prune(now_ms);
    }
}

/// Everything behind the state mutex.
#[derive(Debug)]
struct State {
    mailboxes: MailboxBroker,
    registry: RegistryStore,
    rates: Rates,
}

#[derive(Debug)]
struct Shared {
    entry: RelayEntry,
    limits: Limits,
    tls: ServerTls,
    state: Mutex<State>,
    /// Pending `recv` across all connections (rendezvous §6).
    pending_recv: AtomicUsize,
    shutdown: watch::Sender<bool>,
}

/// Per-connection state: the challenge nonce, the `hello` actor and the request rate.
struct Connection {
    peer: IpAddr,
    nonce: [u8; 32],
    actor: Option<Actor>,
    requests: RateLimiter<()>,
}

/// Releases one pending `recv` slot on drop.
struct PendingRecv<'a>(&'a AtomicUsize);

impl Drop for PendingRecv<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// A single-instance `/quick/v2` relay: mailbox broker and registry over TLS
/// WebSocket. Cloning yields another handle to the same server.
#[derive(Clone, Debug)]
pub struct RendezvousServer {
    shared: Arc<Shared>,
}

impl RendezvousServer {
    /// Builds the server for `config`: the self entry is `config.host` at
    /// `config.listen`'s port with [`Config::ips`], announcing `mailbox`, `registry`
    /// and `config.capabilities`. Nothing is bound; see [`bind`](Self::bind).
    ///
    /// # Errors
    ///
    /// [`ServerError::Config`] for an invalid self entry (port 0 included) or a
    /// directory that does not list it, [`ServerError::Tls`] when the certificate
    /// cannot be loaded or generated.
    pub fn new(config: Config) -> Result<Self, ServerError> {
        let ips = config.ips();
        let entry = registry::self_entry(
            config.relay_id,
            config.code.clone(),
            config.host.clone(),
            ips.clone(),
            config.listen.port(),
            &config.capabilities,
        )?;
        let registry = match config.directory {
            Some(directory) => {
                RegistryStore::with_directory(config.limits.clone(), entry.clone(), directory)?
            }
            None => RegistryStore::new(config.limits.clone(), entry.clone())?,
        };
        let tls = match &config.tls {
            TlsSource::SelfSigned => ServerTls::self_signed(&config.host, &ips)?,
            TlsSource::Pem { certificate, key } => ServerTls::from_pem_files(certificate, key)?,
        };
        let state = State {
            mailboxes: MailboxBroker::new(config.limits.clone()),
            registry,
            rates: Rates::new(&config.limits, config.rate_keys),
        };
        let (shutdown, _) = watch::channel(false);
        Ok(Self {
            shared: Arc::new(Shared {
                entry,
                limits: config.limits,
                tls,
                state: Mutex::new(state),
                pending_recv: AtomicUsize::new(0),
                shutdown,
            }),
        })
    }

    /// Binds `config.listen`, then builds the server with the bound address, so port 0
    /// picks a free port that the self entry announces.
    ///
    /// # Errors
    ///
    /// [`ServerError::Io`] when binding fails, otherwise the errors of
    /// [`new`](Self::new).
    pub async fn bind(mut config: Config) -> Result<(Self, TcpListener), ServerError> {
        let listener = TcpListener::bind(config.listen).await?;
        config.listen = listener.local_addr()?;
        Ok((Self::new(config)?, listener))
    }

    /// The mock's own directory entry.
    #[must_use]
    pub fn relay_entry(&self) -> &RelayEntry {
        &self.shared.entry
    }

    /// The `challenge.authority`, `host:port` (rendezvous §3).
    #[must_use]
    pub fn authority(&self) -> RelayId {
        self.shared.entry.relay_id()
    }

    /// The served directory (rendezvous §5.4).
    ///
    /// # Errors
    ///
    /// [`ErrorCode::Storage`] when the state is unavailable.
    pub fn directory(&self) -> Result<Directory, ErrorCode> {
        Ok(self.lock()?.registry.directory().clone())
    }

    /// Replaces the served directory per the rendezvous §5.4 update rule.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::InvalidDirectory`] when the update is rejected,
    /// [`ErrorCode::Storage`] when the state is unavailable.
    pub fn set_directory(&self, directory: Directory) -> Result<(), ErrorCode> {
        self.lock()?.registry.set_directory(directory)
    }

    /// The TLS configuration presented by [`handle_tcp`](Self::handle_tcp).
    #[must_use]
    pub fn tls(&self) -> &ServerTls {
        &self.shared.tls
    }

    /// The presented certificate chain as PEM, for clients to trust.
    #[must_use]
    pub fn certificate_pem(&self) -> &str {
        self.shared.tls.certificate_pem()
    }

    /// The WebSocket limits the server applies: messages and frames of at most
    /// [`MAX_MESSAGE_BYTES`] (rendezvous §3, §6). An embedder that upgrades the socket
    /// itself must use it.
    #[must_use]
    pub fn websocket_config() -> WebSocketConfig {
        WebSocketConfig::default()
            .max_message_size(Some(MAX_MESSAGE_BYTES))
            .max_frame_size(Some(MAX_MESSAGE_BYTES))
    }

    /// Stops accepting, wakes pending `recv` and closes every connection.
    pub fn shutdown(&self) {
        self.shared.shutdown.send_replace(true);
    }

    /// Accepts connections on `listener` and runs the sweeper until
    /// [`shutdown`](Self::shutdown).
    pub async fn serve(&self, listener: TcpListener) {
        let sweeper = tokio::spawn({
            let server = self.clone();
            async move { server.run_sweeper().await }
        });
        loop {
            tokio::select! {
                () = self.stopped() => break,
                accepted = listener.accept() => match accepted {
                    Ok((stream, peer)) => {
                        let server = self.clone();
                        tokio::spawn(async move { server.handle_tcp(stream, peer.ip()).await });
                    }
                    // Transient accept failures such as file descriptor exhaustion.
                    Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
                },
            }
        }
        let _ = sweeper.await;
    }

    /// Every [`SWEEP_INTERVAL_SECONDS`] removes due mailboxes and registry records and
    /// prunes the rate limiters, until [`shutdown`](Self::shutdown) (rendezvous §5.3;
    /// quick-v2 §7.2). [`serve`](Self::serve) runs it; an embedder runs it once.
    pub async fn run_sweeper(&self) {
        let mut interval = tokio::time::interval(Duration::from_secs(SWEEP_INTERVAL_SECONDS));
        loop {
            tokio::select! {
                () = self.stopped() => break,
                _ = interval.tick() => {
                    let now_ms = now_ms();
                    let now = now_ms / 1000;
                    if let Ok(mut state) = self.lock() {
                        state.mailboxes.sweep(now);
                        state.registry.sweep(now);
                        state.rates.prune(now_ms);
                    }
                }
            }
        }
    }

    /// Serves one accepted TCP connection from `peer`: TLS, WebSocket upgrade, then
    /// [`handle_websocket`](Self::handle_websocket).
    pub async fn handle_tcp(&self, stream: TcpStream, peer: IpAddr) {
        let acceptor = TlsAcceptor::from(self.shared.tls.config());
        if let Ok(Ok(stream)) = timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
            self.handle_stream(stream, peer).await;
        }
    }

    /// Serves one decrypted (or plain) stream from `peer`: the WebSocket upgrade, which
    /// answers 404 for a path other than `/quick/v2` and 400 without the `ns-quick-v2`
    /// subprotocol, then [`handle_websocket`](Self::handle_websocket).
    pub async fn handle_stream<S>(&self, stream: S, peer: IpAddr)
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let accepted = timeout(
            HANDSHAKE_TIMEOUT,
            accept_hdr_async_with_config(
                stream,
                accept_quick_request,
                Some(Self::websocket_config()),
            ),
        )
        .await;
        if let Ok(Ok(socket)) = accepted {
            self.handle_websocket(socket, peer).await;
        }
    }

    /// Runs the `/quick/v2` protocol on an upgraded socket from `peer` until it closes,
    /// sends a non-text message or the server shuts down. The upgrade must have checked
    /// the path and subprotocol and applied [`websocket_config`](Self::websocket_config).
    pub async fn handle_websocket<S>(&self, mut socket: WebSocketStream<S>, peer: IpAddr)
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let Some(nonce) = challenge_nonce() else {
            let _ = socket.close(None).await;
            return;
        };
        let challenge = Challenge {
            nonce,
            authority: self.authority(),
            capabilities: self.shared.entry.capabilities().clone(),
        };
        let mut connection = Connection {
            peer,
            nonce,
            actor: None,
            requests: RateLimiter::per_second(
                self.shared.limits.requests_per_connection_per_second,
                1,
            ),
        };
        if send(&mut socket, &Response::Challenge(challenge))
            .await
            .is_ok()
        {
            loop {
                let message = tokio::select! {
                    () = self.stopped() => break,
                    message = socket.next() => message,
                };
                let text = match message {
                    Some(Ok(Message::Text(text))) => text,
                    Some(Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_))) => continue,
                    // Binary, close, transport error or end of stream.
                    _ => break,
                };
                let response = self
                    .respond(&mut connection, text.as_str())
                    .await
                    .unwrap_or_else(Response::Error);
                if send(&mut socket, &response).await.is_err() {
                    break;
                }
            }
        }
        let _ = socket.close(None).await;
    }

    /// Answers one request (rendezvous §4, §5.2, §6; quick-v2 §7.2, §7.4).
    async fn respond(
        &self,
        connection: &mut Connection,
        text: &str,
    ) -> Result<Response, ErrorCode> {
        let now_ms = now_ms();
        let now = now_ms / 1000;
        connection.requests.check((), now_ms)?;
        let request = decode_request(text)?;
        let operation = request.operation();
        match request {
            Request::Directory => Ok(Response::Directory(
                self.lock()?.registry.directory().clone(),
            )),
            Request::Hello(hello) => {
                if connection.actor.is_some() {
                    return Err(ErrorCode::InvalidActor);
                }
                hello.verify(&connection.nonce, &self.authority())?;
                connection.actor = Some(hello.actor);
                Ok(Response::Ok)
            }
            Request::Publish(publish) => {
                self.check_registry()?;
                let mut guard = self.lock()?;
                let state = &mut *guard;
                state.rates.check(operation, connection.peer, now_ms)?;
                let verified = state.registry.verify(&publish, &connection.nonce, now)?;
                state
                    .rates
                    .publish_identity
                    .check(*verified.record().identity(), now_ms)?;
                Ok(Response::Published(state.registry.accept(&verified, now)?))
            }
            Request::LookupNode(lookup) => {
                self.check_registry()?;
                let mut state = self.lock()?;
                state.rates.check(operation, connection.peer, now_ms)?;
                Ok(Response::Record(state.registry.lookup_node(&lookup, now)?))
            }
            Request::Recv(recv) => {
                let actor = connection.actor.ok_or(ErrorCode::InvalidActor)?;
                self.recv(actor, &recv).await
            }
            request => {
                let actor = connection.actor.ok_or(ErrorCode::InvalidActor)?;
                let mut state = self.lock()?;
                state.rates.check(operation, connection.peer, now_ms)?;
                let mailboxes = &mut state.mailboxes;
                match request {
                    Request::Open(open) => Ok(Response::Opened(mailboxes.open(
                        actor,
                        &open,
                        now,
                        &mut SysRng,
                    )?)),
                    Request::Lookup(digits) => Ok(Response::Found(mailboxes.lookup(&digits, now)?)),
                    Request::Join(join) => {
                        mailboxes.join(actor, &join.id, join.intro, now)?;
                        Ok(Response::Ok)
                    }
                    Request::Admit(admit) => {
                        mailboxes.admit(&actor, &admit.id, &admit.actor, now)?;
                        Ok(Response::Ok)
                    }
                    Request::Reject(reject) => {
                        mailboxes.reject(&actor, &reject.id, &reject.actor, now)?;
                        Ok(Response::Ok)
                    }
                    Request::Send(send) => Ok(Response::Sent(
                        mailboxes.send(&actor, &send.id, send.data, now)?,
                    )),
                    Request::Close(close) => {
                        mailboxes.close(&actor, &close.id, now)?;
                        Ok(Response::Ok)
                    }
                    // Handled above.
                    Request::Directory
                    | Request::Hello(_)
                    | Request::Publish(_)
                    | Request::LookupNode(_)
                    | Request::Recv(_) => Err(ErrorCode::InvalidMessage),
                }
            }
        }
    }

    /// `recv` with its long poll: answers at once with messages or when `wait_ms` is 0,
    /// otherwise holds a pending slot and waits for a change of the mailbox, at most
    /// `wait_ms` (rendezvous §5.2, §6).
    async fn recv(&self, actor: Actor, request: &RecvRequest) -> Result<Response, ErrorCode> {
        let mut changes = {
            let mut state = self.lock()?;
            // Subscribe before reading so no change between the two is lost.
            let mut changes = state.mailboxes.subscribe(&request.id)?;
            let view = state
                .mailboxes
                .recv(&actor, &request.id, request.after, now_ms() / 1000)?;
            if request.wait_ms == 0 || !view.messages.is_empty() {
                return Ok(Response::Mailbox(view));
            }
            // Requests on a connection run in order, so it holds no other pending recv.
            check_pending_recv_within(
                0,
                self.shared.pending_recv.load(Ordering::SeqCst),
                self.shared.limits.pending_recv_per_connection,
                self.shared.limits.pending_recv,
            )?;
            self.shared.pending_recv.fetch_add(1, Ordering::SeqCst);
            changes.mark_unchanged();
            changes
        };
        let pending = PendingRecv(&self.shared.pending_recv);
        tokio::select! {
            () = self.stopped() => {}
            _ = timeout(Duration::from_millis(request.wait_ms), changes.changed()) => {}
        }
        drop(pending);
        let mut state = self.lock()?;
        let view = state
            .mailboxes
            .recv(&actor, &request.id, request.after, now_ms() / 1000)?;
        Ok(Response::Mailbox(view))
    }

    /// `publish` and `lookup_node` are served only while the self entry announces
    /// `registry` (rendezvous §5.2).
    fn check_registry(&self) -> Result<(), ErrorCode> {
        if self
            .shared
            .entry
            .capabilities()
            .contains(&capability::REGISTRY)
        {
            Ok(())
        } else {
            Err(ErrorCode::NotPermitted)
        }
    }

    fn lock(&self) -> Result<MutexGuard<'_, State>, ErrorCode> {
        self.shared.state.lock().map_err(|_| ErrorCode::Storage)
    }

    /// Resolves once [`shutdown`](Self::shutdown) is called.
    async fn stopped(&self) {
        let mut shutdown = self.shared.shutdown.subscribe();
        let _ = shutdown.wait_for(|stopped| *stopped).await;
    }
}

/// The `/quick/v2` upgrade check, usable as an `accept_hdr_async` callback by a router
/// that upgrades the socket itself before
/// [`RendezvousServer::handle_websocket`]: 404 for a path other than `/quick/v2`, 400
/// without the `ns-quick-v2` subprotocol, otherwise `response` selecting it
/// (rendezvous §3). [`RendezvousServer::handle_stream`] runs the same check.
///
/// # Errors
///
/// The refusal [`ErrorResponse`] for a wrong path or a missing subprotocol.
// tungstenite's `Callback` fixes the error type.
#[allow(clippy::result_large_err)]
pub fn accept_quick_request(
    request: &HttpRequest,
    mut response: HttpResponse,
) -> Result<HttpResponse, ErrorResponse> {
    if request.uri().path() != PATH {
        return Err(refusal(StatusCode::NOT_FOUND));
    }
    if !offers_subprotocol(request) {
        return Err(refusal(StatusCode::BAD_REQUEST));
    }
    response.headers_mut().insert(
        SEC_WEBSOCKET_PROTOCOL,
        HeaderValue::from_static(SUBPROTOCOL),
    );
    Ok(response)
}

/// Whether the upgrade request offers the `ns-quick-v2` subprotocol (rendezvous §3).
fn offers_subprotocol(request: &HttpRequest) -> bool {
    request
        .headers()
        .get_all(SEC_WEBSOCKET_PROTOCOL)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|protocol| protocol.trim() == SUBPROTOCOL)
}

fn refusal(status: StatusCode) -> ErrorResponse {
    let mut response = ErrorResponse::new(None);
    *response.status_mut() = status;
    response
}

/// Encodes and sends one broker message; a response that does not encode is replaced
/// by its error code.
async fn send<S>(socket: &mut WebSocketStream<S>, response: &Response) -> Result<(), ()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let text = match encode_response(response) {
        Ok(text) => text,
        Err(code) => encode_response(&Response::Error(code)).map_err(|_| ())?,
    };
    socket.send(Message::text(text)).await.map_err(|_| ())
}

/// A nonzero 32-byte challenge nonce from OS randomness (rendezvous §3).
fn challenge_nonce() -> Option<[u8; 32]> {
    for _ in 0..MAX_NONCE_ATTEMPTS {
        let mut nonce = [0; 32];
        SysRng.try_fill_bytes(&mut nonce).ok()?;
        if nonce != [0; 32] {
            return Some(nonce);
        }
    }
    None
}

/// Wall clock in Unix milliseconds.
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

#[cfg(test)]
mod tests {
    use super::accept_quick_request;
    use tokio_tungstenite::tungstenite::{
        handshake::server::{Request, Response},
        http::{StatusCode, header::SEC_WEBSOCKET_PROTOCOL},
    };

    fn request(path: &str, subprotocol: Option<&str>) -> Request {
        let mut builder = Request::builder().uri(format!("wss://localhost:8443{path}"));
        if let Some(subprotocol) = subprotocol {
            builder = builder.header(SEC_WEBSOCKET_PROTOCOL, subprotocol);
        }
        builder.body(()).unwrap()
    }

    fn status(path: &str, subprotocol: Option<&str>) -> StatusCode {
        accept_quick_request(&request(path, subprotocol), Response::default())
            .unwrap_err()
            .status()
    }

    #[test]
    fn accept_quick_request_routes_by_path_and_subprotocol() {
        assert_eq!(status("/ns/v2", Some("ns-quick-v2")), StatusCode::NOT_FOUND);
        assert_eq!(status("/quick/v2", None), StatusCode::BAD_REQUEST);
        assert_eq!(
            status("/quick/v2", Some("ns-relay-v2")),
            StatusCode::BAD_REQUEST
        );
        let accepted = accept_quick_request(
            &request("/quick/v2", Some("other, ns-quick-v2")),
            Response::default(),
        )
        .unwrap();
        assert_eq!(
            accepted.headers().get(SEC_WEBSOCKET_PROTOCOL).unwrap(),
            "ns-quick-v2"
        );
    }
}
