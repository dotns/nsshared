//! External WSS mode: a test-local combined server owns the TCP+TLS listener on the relay
//! identifier port and routes `/ns/v2` to the relay's per-connection entry points.
#![allow(clippy::unwrap_used, clippy::panic, reason = "test fixture helpers")]

#[allow(
    dead_code,
    reason = "each test crate uses a subset of the shared helpers"
)]
mod common;

use common::{Link, WAIT, register, unix_now, ws_connect};
use futures_util::{SinkExt, StreamExt};
use nsshared_mock_relay::{
    Carrier, MockRelay, MockRelayConfig, accept_relay_request, relay_websocket_config,
    testing::TestNode,
};
use nsshared_wire::{RELAY_WSS_PATH, RELAY_WSS_SUBPROTOCOL};
use rustls::{
    ServerConfig,
    crypto::aws_lc_rs,
    pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
};
use std::{
    net::{SocketAddr, TcpListener as StdTcpListener},
    sync::Arc,
};
use tokio::{net::TcpListener, task::JoinHandle, time::timeout};
use tokio_rustls::{TlsAcceptor, server::TlsStream};
use tokio_tungstenite::{
    accept_hdr_async_with_config,
    tungstenite::{
        self, Message,
        handshake::server::{ErrorResponse, Request, Response},
        http::StatusCode,
        protocol::frame::coding::CloseCode,
    },
};

/// The second route of the combined server, standing in for `/quick/v2`.
const DUMMY_PATH: &str = "/quick/v2";

/// How the router hands `/ns/v2` to the relay.
#[derive(Clone, Copy)]
enum Mode {
    /// Every TLS stream goes to [`MockRelay::handle_stream`], which does the upgrade.
    Stream,
    /// The router upgrades itself and routes by path; `/ns/v2` goes to
    /// [`MockRelay::handle_websocket`].
    WebSocket,
}

/// A combined server: one TLS listener, the relay in external mode on the same port.
struct Combined {
    relay: Arc<MockRelay>,
    addr: SocketAddr,
    cert_der: Vec<u8>,
    task: JoinHandle<()>,
}

impl Combined {
    async fn start(mode: Mode, wss_connections_per_ip: usize) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let relay = MockRelay::start(MockRelayConfig {
            listen: addr,
            external_wss: true,
            wss_connections_per_ip,
            ..MockRelayConfig::default()
        });
        let relay = Arc::new(timeout(WAIT, relay).await.unwrap().unwrap());
        assert_eq!(relay.relay_id().as_str(), addr.to_string());
        assert_eq!(relay.udp_addr(), Some(addr));

        let certified = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_owned()]).unwrap();
        let cert_der = certified.cert.der().to_vec();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            certified.signing_key.serialize_der(),
        ));
        let config = ServerConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![certified.cert.der().clone()], key)
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(config));

        let task = tokio::spawn({
            let relay = Arc::clone(&relay);
            async move {
                loop {
                    let (tcp, remote) = listener.accept().await.unwrap();
                    let acceptor = acceptor.clone();
                    let relay = Arc::clone(&relay);
                    tokio::spawn(async move {
                        let Ok(tls) = acceptor.accept(tcp).await else {
                            return;
                        };
                        match mode {
                            Mode::Stream => relay.handle_stream(tls, remote).await,
                            Mode::WebSocket => route(&relay, tls, remote).await,
                        }
                    });
                }
            }
        });
        Self {
            relay,
            addr,
            cert_der,
            task,
        }
    }

    async fn connect(
        &self,
        path: &str,
        subprotocol: Option<&str>,
    ) -> Result<(), tungstenite::Error> {
        self.ws(path, subprotocol).await.map(drop)
    }

    async fn ws(
        &self,
        path: &str,
        subprotocol: Option<&str>,
    ) -> Result<common::Ws, tungstenite::Error> {
        ws_connect(
            self.relay.relay_id().as_str(),
            self.addr,
            &self.cert_der,
            path,
            subprotocol,
        )
        .await
        .map(|(ws, _)| ws)
    }

    async fn stop(self) {
        self.task.abort();
        timeout(WAIT, self.relay.shutdown()).await.unwrap();
    }
}

/// Upgrades `tls` with the relay's WebSocket limits and routes by path: the dummy path
/// echoes one text message, every other path goes through [`accept_relay_request`] (404
/// unless `/ns/v2`) and then to [`MockRelay::handle_websocket`].
async fn route(relay: &MockRelay, tls: TlsStream<tokio::net::TcpStream>, remote: SocketAddr) {
    let mut dummy = false;
    #[expect(
        clippy::result_large_err,
        reason = "the tungstenite callback signature fixes the error type"
    )]
    let callback = |request: &Request, response: Response| -> Result<Response, ErrorResponse> {
        if request.uri().path() == DUMMY_PATH {
            dummy = true;
            return Ok(response);
        }
        accept_relay_request(request, response)
    };
    let Ok(mut ws) =
        accept_hdr_async_with_config(tls, callback, Some(relay_websocket_config())).await
    else {
        return;
    };
    if dummy {
        if let Some(Ok(message)) = ws.next().await {
            ws.send(message).await.unwrap();
        }
        return;
    }
    relay.handle_websocket(ws, remote).await;
}

fn http_status(result: Result<(), tungstenite::Error>) -> StatusCode {
    match result {
        Err(tungstenite::Error::Http(response)) => response.status(),
        other => panic!("handshake not refused with HTTP: {other:?}"),
    }
}

/// Registers one node over WSS through the router and checks the confirmed session.
async fn register_through(combined: &Combined) {
    let relay = &combined.relay;
    let node = TestNode::new([3; 32], relay.relay_id(), unix_now() - 60).unwrap();
    let mut link = Link::wss_via(relay, combined.addr, &combined.cert_der).await;
    let (registered, _) = register(&mut link, relay, &node, [13; 32]).await;
    assert_eq!(registered.capabilities, ["udp", "wss"]);
    assert!(registered.observed_addr.is_none());
    let sessions = relay.sessions();
    assert_eq!(sessions.len(), 1);
    assert!(sessions[0].confirmed);
    assert_eq!(sessions[0].carrier, Carrier::Wss);
}

#[tokio::test]
async fn router_upgrades_and_hands_ns_v2_to_handle_websocket() {
    let combined = Combined::start(Mode::WebSocket, 8).await;
    register_through(&combined).await;

    let mut dummy = combined.ws(DUMMY_PATH, None).await.unwrap();
    dummy.send(Message::text("hello")).await.unwrap();
    assert_eq!(
        timeout(WAIT, dummy.next()).await.unwrap().unwrap().unwrap(),
        Message::text("hello")
    );

    let refused = combined.connect("/other", Some(RELAY_WSS_SUBPROTOCOL));
    assert_eq!(http_status(refused.await), StatusCode::NOT_FOUND);
    let refused = combined.connect(RELAY_WSS_PATH, None);
    assert_eq!(http_status(refused.await), StatusCode::BAD_REQUEST);
    combined.stop().await;
}

#[tokio::test]
async fn handle_stream_runs_the_relay_handshake_and_shutdown_closes_it() {
    let combined = Combined::start(Mode::Stream, 8).await;
    register_through(&combined).await;

    let refused = combined.connect("/other", Some(RELAY_WSS_SUBPROTOCOL));
    assert_eq!(http_status(refused.await), StatusCode::NOT_FOUND);
    let refused = combined.connect(RELAY_WSS_PATH, None);
    assert_eq!(http_status(refused.await), StatusCode::BAD_REQUEST);

    let mut ws = combined
        .ws(RELAY_WSS_PATH, Some(RELAY_WSS_SUBPROTOCOL))
        .await
        .unwrap();
    combined.relay.shutdown().await;
    let code = loop {
        match timeout(WAIT, ws.next()).await.unwrap() {
            Some(Ok(Message::Close(frame))) => break frame.map(|frame| frame.code),
            Some(Ok(_)) => {}
            Some(Err(_)) | None => break None,
        }
    };
    assert_eq!(code, Some(CloseCode::Away));
    combined.stop().await;
}

#[tokio::test]
async fn external_connections_share_the_per_ip_limit() {
    let combined = Combined::start(Mode::Stream, 1).await;
    let _first = combined
        .ws(RELAY_WSS_PATH, Some(RELAY_WSS_SUBPROTOCOL))
        .await
        .unwrap();
    let second = combined
        .connect(RELAY_WSS_PATH, Some(RELAY_WSS_SUBPROTOCOL))
        .await;
    assert!(
        !matches!(second, Ok(()) | Err(tungstenite::Error::Http(_))),
        "{second:?}"
    );
    combined.stop().await;
}

#[tokio::test]
async fn external_mode_announces_wss_without_a_tcp_listener() {
    let relay = MockRelay::start(MockRelayConfig {
        external_wss: true,
        ..MockRelayConfig::default()
    });
    let relay = timeout(WAIT, relay).await.unwrap().unwrap();
    assert!(relay.wss_addr().is_none());
    assert!(relay.generated_cert().is_none());
    let udp = relay.udp_addr().unwrap();
    assert_eq!(relay.relay_id().as_str(), udp.to_string());
    // The caller can bind the TCP side of the identifier port itself.
    drop(StdTcpListener::bind(udp).unwrap());

    let node = TestNode::new([4; 32], relay.relay_id(), unix_now() - 60).unwrap();
    let attempt = node
        .register(relay.relay_id(), 1, unix_now(), [14; 32])
        .unwrap();
    let mut link = Link::udp(&relay).await;
    link.send(attempt.packet()).await;
    let (registered, _) = attempt.accept(&link.recv().await).unwrap();
    assert_eq!(registered.capabilities, ["udp", "wss"]);
    timeout(WAIT, relay.shutdown()).await.unwrap();
}
