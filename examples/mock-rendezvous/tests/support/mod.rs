//! Shared client for the integration tests: an ns-style `/quick/v2` client over TLS
//! WebSocket (TLS to the entry's IP with SNI = host, subprotocol `ns-quick-v2`) driving
//! a [`RendezvousServer`] bound to a free loopback port.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    dead_code,
    reason = "test fixture helpers; each test binary uses a subset"
)]

use ed25519_dalek::SigningKey;
use futures_util::{SinkExt, StreamExt};
use nsshared_mock_rendezvous::{Config, Limits, RendezvousServer};
use nsshared_rendezvous::{
    auth::{Challenge, Hello},
    error::ErrorCode,
    message::{
        CloseRequest, Digits, Found, JoinRequest, MailboxId, MailboxView, OpenRequest, Opened,
        RecvRequest, SendRequest, Sent,
    },
    transport::{
        MAX_MESSAGE_BYTES, PATH, Request, Response, SUBPROTOCOL, decode_response, encode_request,
    },
};
use nsshared_wire::RelayId;
use rustls::{
    ClientConfig, RootCertStore,
    crypto::aws_lc_rs,
    pki_types::{CertificateDer, pem::PemObject},
};
use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{net::TcpStream, task::JoinHandle, time::timeout};
use tokio_tungstenite::{
    Connector, MaybeTlsStream, WebSocketStream, client_async_tls_with_config,
    tungstenite::{
        self, Message,
        client::IntoClientRequest,
        http::{HeaderValue, StatusCode, header::SEC_WEBSOCKET_PROTOCOL},
        protocol::WebSocketConfig,
    },
};

/// Upper bound for any single wait on the server; a hang fails the test instead.
pub const STEP: Duration = Duration::from_secs(30);

type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// Production limits with the per-connection, per-IP and per-identity rate limits
/// raised, so a test only meets the limit it configures.
pub fn relaxed_limits() -> Limits {
    Limits {
        requests_per_connection_per_second: 10_000,
        lookups_per_ip_per_minute: 10_000,
        opens_per_ip_per_minute: 10_000,
        publishes_per_ip_per_minute: 10_000,
        publish_interval_per_identity_seconds: 0,
        lookup_nodes_per_ip_per_minute: 10_000,
        ..Limits::default()
    }
}

/// Wall clock in Unix seconds, the server's time base.
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A running mock bound to `127.0.0.1:0`.
pub struct Mock {
    pub server: RendezvousServer,
    serving: JoinHandle<()>,
    tls: Arc<ClientConfig>,
}

impl Mock {
    pub async fn start(limits: Limits) -> Self {
        let config = Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            limits,
            ..Config::default()
        };
        let (server, listener) = RendezvousServer::bind(config).await.unwrap();
        let serving = tokio::spawn({
            let server = server.clone();
            async move { server.serve(listener).await }
        });
        let mut roots = RootCertStore::empty();
        for certificate in CertificateDer::pem_slice_iter(server.certificate_pem().as_bytes()) {
            roots.add(certificate.unwrap()).unwrap();
        }
        let tls = ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Self {
            server,
            serving,
            tls: Arc::new(tls),
        }
    }

    pub fn authority(&self) -> RelayId {
        self.server.authority()
    }

    /// Opens a WebSocket to `path`, offering the subprotocol when `subprotocol` is set.
    pub async fn websocket(
        &self,
        path: &str,
        subprotocol: bool,
    ) -> Result<Socket, tungstenite::Error> {
        let entry = self.server.relay_entry();
        let stream = TcpStream::connect(SocketAddr::new(entry.ips()[0], entry.port()))
            .await
            .unwrap();
        let mut request = format!("wss://{}{path}", entry.relay_id().as_str())
            .into_client_request()
            .unwrap();
        if subprotocol {
            request.headers_mut().insert(
                SEC_WEBSOCKET_PROTOCOL,
                HeaderValue::from_static(SUBPROTOCOL),
            );
        }
        // The client accepts as much as the server sends; outgoing size is not bounded
        // so the oversize test can exceed the server limit.
        let websocket = WebSocketConfig::default()
            .max_message_size(Some(MAX_MESSAGE_BYTES))
            .max_frame_size(Some(MAX_MESSAGE_BYTES));
        let (socket, _) = timeout(
            STEP,
            client_async_tls_with_config(
                request,
                stream,
                Some(websocket),
                Some(Connector::Rustls(Arc::clone(&self.tls))),
            ),
        )
        .await
        .unwrap()?;
        Ok(socket)
    }

    /// The HTTP status of a refused WebSocket upgrade.
    pub async fn refused(&self, path: &str, subprotocol: bool) -> StatusCode {
        match self.websocket(path, subprotocol).await {
            Err(tungstenite::Error::Http(response)) => response.status(),
            other => panic!("expected a refused upgrade, got {other:?}"),
        }
    }

    /// A `/quick/v2` client that has read and checked the challenge.
    pub async fn connect(&self) -> Client {
        let mut socket = self.websocket(PATH, true).await.unwrap();
        let Response::Challenge(challenge) = receive(&mut socket).await else {
            panic!("expected a challenge");
        };
        challenge.check_authority(&self.authority()).unwrap();
        Client { socket, challenge }
    }

    /// A client bound to `actor_key` by `hello`.
    pub async fn actor(&self, actor_key: &SigningKey) -> Client {
        let mut client = self.connect().await;
        client.hello(actor_key).await;
        client
    }

    pub async fn stop(self) {
        self.server.shutdown();
        timeout(STEP, self.serving).await.unwrap().unwrap();
    }
}

async fn receive(socket: &mut Socket) -> Response {
    timeout(STEP, async {
        loop {
            match socket.next().await {
                Some(Ok(Message::Text(text))) => return decode_response(&text).unwrap(),
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                other => panic!("unexpected message {other:?}"),
            }
        }
    })
    .await
    .unwrap()
}

/// One `/quick/v2` connection.
pub struct Client {
    pub socket: Socket,
    pub challenge: Challenge,
}

impl Client {
    pub fn nonce(&self) -> [u8; 32] {
        self.challenge.nonce
    }

    pub async fn send_text(&mut self, text: String) {
        self.socket.send(Message::text(text)).await.unwrap();
    }

    pub async fn receive(&mut self) -> Response {
        receive(&mut self.socket).await
    }

    pub async fn request(&mut self, request: &Request) -> Response {
        self.send_text(encode_request(request).unwrap()).await;
        self.receive().await
    }

    /// Sends raw text and returns the response.
    pub async fn raw(&mut self, text: &str) -> Response {
        self.send_text(text.to_owned()).await;
        self.receive().await
    }

    /// The error code of `request`; panics on success.
    pub async fn error(&mut self, request: &Request) -> ErrorCode {
        match self.request(request).await {
            Response::Error(code) => code,
            other => panic!("expected an error, got {other:?}"),
        }
    }

    pub async fn hello(&mut self, actor_key: &SigningKey) {
        let hello = Hello::sign(actor_key, &self.challenge.nonce, &self.challenge.authority);
        assert_eq!(self.request(&Request::Hello(hello)).await, Response::Ok);
    }

    pub async fn open(&mut self, open: OpenRequest) -> Opened {
        match self.request(&Request::Open(open)).await {
            Response::Opened(opened) => opened,
            other => panic!("expected opened, got {other:?}"),
        }
    }

    pub async fn lookup(&mut self, digits: &Digits) -> Result<Found, ErrorCode> {
        match self.request(&Request::Lookup(digits.clone())).await {
            Response::Found(found) => Ok(found),
            Response::Error(code) => Err(code),
            other => panic!("expected found, got {other:?}"),
        }
    }

    pub async fn join(&mut self, id: MailboxId, intro: Vec<u8>) -> Result<(), ErrorCode> {
        ok(self
            .request(&Request::Join(JoinRequest { id, intro }))
            .await)
    }

    pub async fn send(&mut self, id: MailboxId, data: Vec<u8>) -> Result<Sent, ErrorCode> {
        match self.request(&Request::Send(SendRequest { id, data })).await {
            Response::Sent(sent) => Ok(sent),
            Response::Error(code) => Err(code),
            other => panic!("expected sent, got {other:?}"),
        }
    }

    pub async fn recv(
        &mut self,
        id: MailboxId,
        after: u64,
        wait_ms: u64,
    ) -> Result<MailboxView, ErrorCode> {
        mailbox(
            self.request(&Request::Recv(RecvRequest { id, after, wait_ms }))
                .await,
        )
    }

    pub async fn close(&mut self, id: MailboxId) -> Result<(), ErrorCode> {
        ok(self.request(&Request::Close(CloseRequest { id })).await)
    }
}

/// `Ok(())` for `ok`, the code for `error`.
pub fn ok(response: Response) -> Result<(), ErrorCode> {
    match response {
        Response::Ok => Ok(()),
        Response::Error(code) => Err(code),
        other => panic!("expected ok, got {other:?}"),
    }
}

/// The view of a `mailbox` result, the code for `error`.
pub fn mailbox(response: Response) -> Result<MailboxView, ErrorCode> {
    match response {
        Response::Mailbox(view) => Ok(view),
        Response::Error(code) => Err(code),
        other => panic!("expected mailbox, got {other:?}"),
    }
}

/// A deterministic signing key.
pub fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}
