//! Shared client plumbing for the integration tests: a UDP or WSS link to a running
//! [`MockRelay`] and the generic register-then-confirm flow of the `testing` helpers.

use futures_util::{SinkExt, StreamExt};
use nsshared_mock_relay::{
    MockRelay, MockRelayConfig,
    testing::{NodeSession, TestNode},
};
use nsshared_wire::{
    MAX_RELAY_PACKET_BYTES, RELAY_WSS_PATH, RELAY_WSS_SUBPROTOCOL, Registered, RelayBody,
};
use rustls::{
    ClientConfig, RootCertStore,
    crypto::aws_lc_rs,
    pki_types::{CertificateDer, ServerName},
};
use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    net::{TcpStream, UdpSocket},
    time::timeout,
};
use tokio_rustls::{TlsConnector, client::TlsStream};
use tokio_tungstenite::{
    WebSocketStream, client_async_with_config,
    tungstenite::{
        Message,
        client::IntoClientRequest,
        http::{HeaderValue, header::SEC_WEBSOCKET_PROTOCOL},
    },
};

/// The bound on every await.
pub const WAIT: Duration = Duration::from_secs(5);

/// Starts a mock on 127.0.0.1:0 with both carriers and a self-signed certificate.
pub async fn start() -> MockRelay {
    timeout(WAIT, MockRelay::start(MockRelayConfig::default()))
        .await
        .unwrap()
        .unwrap()
}

/// Shuts the mock down, bounded by [`WAIT`].
pub async fn stop(relay: MockRelay) {
    timeout(WAIT, relay.shutdown()).await.unwrap();
}

/// The current Unix time in seconds.
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// One carrier connection from a simulated node to the relay.
pub enum Link {
    /// A UDP socket bound to 127.0.0.1:0 sending to the relay UDP address.
    Udp { socket: UdpSocket, to: SocketAddr },
    /// A WSS connection to `wss://{relay_id}/ns/v2` with `ns-relay-v2` selected.
    Wss(Box<WebSocketStream<TlsStream<TcpStream>>>),
}

impl Link {
    /// Binds a UDP socket on 127.0.0.1:0 toward the relay.
    pub async fn udp(relay: &MockRelay) -> Self {
        let socket = timeout(WAIT, UdpSocket::bind("127.0.0.1:0"))
            .await
            .unwrap()
            .unwrap();
        Self::Udp {
            socket,
            to: relay.udp_addr().unwrap(),
        }
    }

    /// Opens TLS trusting only the mock's self-signed certificate (aws-lc-rs provider),
    /// verifying the identifier host, then runs the WebSocket handshake for
    /// `wss://{relay_id}/ns/v2` offering `ns-relay-v2` and asserts it is selected.
    pub async fn wss(relay: &MockRelay) -> Self {
        let mut roots = RootCertStore::empty();
        let der = relay.generated_cert().unwrap().der.clone();
        roots.add(CertificateDer::from(der)).unwrap();
        let config = ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let relay_id = relay.relay_id().as_str();
        let (host, _) = relay_id.rsplit_once(':').unwrap();
        let tcp = timeout(WAIT, TcpStream::connect(relay.wss_addr().unwrap()))
            .await
            .unwrap()
            .unwrap();
        let tls = timeout(
            WAIT,
            TlsConnector::from(Arc::new(config))
                .connect(ServerName::try_from(host.to_owned()).unwrap(), tcp),
        )
        .await
        .unwrap()
        .unwrap();
        let mut request = format!("wss://{relay_id}{RELAY_WSS_PATH}")
            .into_client_request()
            .unwrap();
        request.headers_mut().insert(
            SEC_WEBSOCKET_PROTOCOL,
            HeaderValue::from_static(RELAY_WSS_SUBPROTOCOL),
        );
        let (ws, response) = timeout(WAIT, client_async_with_config(request, tls, None))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            response.headers().get(SEC_WEBSOCKET_PROTOCOL).unwrap(),
            RELAY_WSS_SUBPROTOCOL
        );
        Self::Wss(Box::new(ws))
    }

    /// Returns the local UDP address, `None` on WSS.
    pub fn local_udp_addr(&self) -> Option<SocketAddr> {
        match self {
            Self::Udp { socket, .. } => Some(socket.local_addr().unwrap()),
            Self::Wss(_) => None,
        }
    }

    /// Sends one relay packet: one datagram or one binary message.
    pub async fn send(&mut self, packet: &[u8]) {
        match self {
            Self::Udp { socket, to } => {
                timeout(WAIT, socket.send_to(packet, *to))
                    .await
                    .unwrap()
                    .unwrap();
            }
            Self::Wss(ws) => {
                timeout(WAIT, ws.send(Message::Binary(packet.to_vec().into())))
                    .await
                    .unwrap()
                    .unwrap();
            }
        }
    }

    /// Receives the next relay packet; WSS control frames are skipped.
    pub async fn recv(&mut self) -> Vec<u8> {
        match self {
            Self::Udp { socket, to } => {
                let mut buf = vec![0; MAX_RELAY_PACKET_BYTES];
                let (len, from) = timeout(WAIT, socket.recv_from(&mut buf))
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(from, *to);
                buf.truncate(len);
                buf
            }
            Self::Wss(ws) => loop {
                match timeout(WAIT, ws.next()).await.unwrap() {
                    Some(Ok(Message::Binary(packet))) => return packet.to_vec(),
                    Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                    other => panic!("no relay packet: {other:?}"),
                }
            },
        }
    }
}

/// Registers `node` through `link` with the `testing` helpers: REGISTER, tentative
/// REGISTERED, confirming PRESENCE seq 1 and its acknowledgement (quick-v2 §8.3).
pub async fn register(
    link: &mut Link,
    relay: &MockRelay,
    node: &TestNode,
    ephemeral: [u8; 32],
) -> (Registered, NodeSession) {
    let attempt = node
        .register(relay.relay_id(), 1, unix_now(), ephemeral)
        .unwrap();
    link.send(attempt.packet()).await;
    let (registered, session) = attempt.accept(&link.recv().await).unwrap();

    link.send(&session.presence(1).unwrap()).await;
    match session.open(&link.recv().await).unwrap() {
        RelayBody::Registered(ack) => {
            assert_eq!(ack.ack_seq, 1);
            assert_eq!(ack.incarnation, 1);
        }
        other => panic!("no PRESENCE acknowledgement: {other:?}"),
    }
    (registered, session)
}
