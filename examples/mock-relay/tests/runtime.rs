//! Runtime tests: shared UDP and WSS port, shutdown, the WSS handshake rules and the
//! carrier framing limits (quick-v2 §8.5, §8.6).
#![allow(clippy::unwrap_used, reason = "test fixture helpers")]

use futures_util::{SinkExt, StreamExt};
use nsshared_mock_relay::{MockRelay, MockRelayConfig, testing::TestNode};
use nsshared_proto::rendezvous::capability;
use nsshared_proto::{MAX_RELAY_PACKET_BYTES, RELAY_WSS_PATH, RELAY_WSS_SUBPROTOCOL};
use rustls::{
    ClientConfig, RootCertStore,
    crypto::aws_lc_rs,
    pki_types::{CertificateDer, ServerName},
};
use std::{
    net::{SocketAddr, TcpListener as StdTcpListener, UdpSocket as StdUdpSocket},
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
        self, Message,
        client::IntoClientRequest,
        handshake::client::Response,
        http::{HeaderValue, StatusCode, header::SEC_WEBSOCKET_PROTOCOL},
        protocol::frame::coding::CloseCode,
    },
};

const WAIT: Duration = Duration::from_secs(5);

type Ws = WebSocketStream<TlsStream<TcpStream>>;

async fn start() -> MockRelay {
    MockRelay::start(MockRelayConfig::default()).await.unwrap()
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Opens TLS to the relay trusting only its generated certificate, verifying the
/// identifier host like ns does, then runs the WebSocket handshake.
async fn ws_connect(
    relay: &MockRelay,
    path: &str,
    subprotocol: Option<&str>,
) -> Result<(Ws, Response), tungstenite::Error> {
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
    let tcp = TcpStream::connect(relay.wss_addr().unwrap()).await.unwrap();
    let tls = TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from(host.to_owned()).unwrap(), tcp)
        .await
        .unwrap();
    let mut request = format!("wss://{relay_id}{path}")
        .into_client_request()
        .unwrap();
    if let Some(subprotocol) = subprotocol {
        request.headers_mut().insert(
            SEC_WEBSOCKET_PROTOCOL,
            HeaderValue::from_str(subprotocol).unwrap(),
        );
    }
    client_async_with_config(request, tls, None).await
}

async fn close_code(ws: &mut Ws) -> Option<CloseCode> {
    loop {
        match timeout(WAIT, ws.next()).await.unwrap() {
            Some(Ok(Message::Close(frame))) => return frame.map(|frame| frame.code),
            Some(Ok(_)) => {}
            Some(Err(_)) | None => return None,
        }
    }
}

async fn wait_for(relay: &MockRelay, mut done: impl FnMut(&MockRelay) -> bool) {
    timeout(WAIT, async {
        while !done(relay) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn udp_and_wss_share_one_port_and_shutdown_releases_it() {
    let relay = start().await;
    let udp = relay.udp_addr().unwrap();
    let wss = relay.wss_addr().unwrap();
    assert_eq!(udp, wss);
    assert_eq!(relay.relay_id().as_str(), udp.to_string());
    assert!(StdUdpSocket::bind(udp).is_err());
    assert!(StdTcpListener::bind(wss).is_err());

    relay.shutdown().await;
    StdUdpSocket::bind(udp).unwrap();
    StdTcpListener::bind(wss).unwrap();
}

#[tokio::test]
async fn disabled_carrier_is_not_bound_or_announced() {
    let relay = MockRelay::start(MockRelayConfig {
        wss: false,
        ..MockRelayConfig::default()
    })
    .await
    .unwrap();
    assert!(relay.wss_addr().is_none());
    assert!(relay.generated_cert().is_none());

    let node = TestNode::new([7; 32], relay.relay_id(), unix_now() - 60).unwrap();
    let attempt = node
        .register(relay.relay_id(), 1, unix_now(), [1; 32])
        .unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket
        .send_to(attempt.packet(), relay.udp_addr().unwrap())
        .await
        .unwrap();
    let mut buf = vec![0; MAX_RELAY_PACKET_BYTES];
    let (len, _) = timeout(WAIT, socket.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let (registered, _) = attempt.accept(&buf[..len]).unwrap();
    assert_eq!(registered.capabilities, ["udp"]);
    relay.shutdown().await;
}

#[tokio::test]
async fn extra_capabilities_follow_the_carriers_in_registered() {
    let relay = MockRelay::start(MockRelayConfig {
        extra_capabilities: vec![capability::MAILBOX, capability::WSS, capability::REGISTRY],
        ..MockRelayConfig::default()
    })
    .await
    .unwrap();
    let node = TestNode::new([7; 32], relay.relay_id(), unix_now() - 60).unwrap();
    let attempt = node
        .register(relay.relay_id(), 1, unix_now(), [1; 32])
        .unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket
        .send_to(attempt.packet(), relay.udp_addr().unwrap())
        .await
        .unwrap();
    let mut buf = vec![0; MAX_RELAY_PACKET_BYTES];
    let (len, _) = timeout(WAIT, socket.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let (registered, _) = attempt.accept(&buf[..len]).unwrap();
    assert_eq!(
        registered.capabilities,
        ["udp", "wss", "mailbox", "registry"]
    );
    relay.shutdown().await;
}

#[tokio::test]
async fn udp_register_and_presence_confirm_a_session() {
    let relay = start().await;
    let node = TestNode::new([7; 32], relay.relay_id(), unix_now() - 60).unwrap();
    let attempt = node
        .register(relay.relay_id(), 1, unix_now(), [1; 32])
        .unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let to = relay.udp_addr().unwrap();
    socket.send_to(attempt.packet(), to).await.unwrap();
    let mut buf = vec![0; MAX_RELAY_PACKET_BYTES];
    let (len, _) = timeout(WAIT, socket.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let (registered, session) = attempt.accept(&buf[..len]).unwrap();
    assert_eq!(registered.capabilities, ["udp", "wss"]);
    let observed = registered.observed_addr.unwrap();
    assert_eq!(
        SocketAddr::new(observed.ip, observed.port),
        socket.local_addr().unwrap()
    );

    socket
        .send_to(&session.presence(1).unwrap(), to)
        .await
        .unwrap();
    let (len, _) = timeout(WAIT, socket.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    session.open(&buf[..len]).unwrap();
    let sessions = relay.sessions();
    assert_eq!(sessions.len(), 1);
    assert!(sessions[0].confirmed);
    assert_eq!(sessions[0].node_id, node.node_id());
    relay.shutdown().await;
}

#[tokio::test]
async fn oversize_datagram_is_dropped() {
    let relay = start().await;
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let to = relay.udp_addr().unwrap();
    socket
        .send_to(&[0; MAX_RELAY_PACKET_BYTES + 1], to)
        .await
        .unwrap();
    socket.send_to(&[0; 4], to).await.unwrap();
    wait_for(&relay, |relay| relay.counters().received == 1).await;
    socket
        .send_to(&[0; MAX_RELAY_PACKET_BYTES], to)
        .await
        .unwrap();
    wait_for(&relay, |relay| relay.counters().received == 2).await;
    relay.shutdown().await;
}

#[tokio::test]
async fn wss_handshake_needs_the_path_and_the_subprotocol() {
    let relay = start().await;
    match ws_connect(&relay, "/other", Some(RELAY_WSS_SUBPROTOCOL)).await {
        Err(tungstenite::Error::Http(response)) => {
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        }
        other => panic!("wrong path accepted: {other:?}"),
    }
    match ws_connect(&relay, RELAY_WSS_PATH, None).await {
        Err(tungstenite::Error::Http(response)) => {
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }
        other => panic!("missing subprotocol accepted: {other:?}"),
    }
    let (_ws, response) = ws_connect(&relay, RELAY_WSS_PATH, Some("other, ns-relay-v2"))
        .await
        .unwrap();
    assert_eq!(
        response.headers().get(SEC_WEBSOCKET_PROTOCOL).unwrap(),
        RELAY_WSS_SUBPROTOCOL
    );
    relay.shutdown().await;
}

#[tokio::test]
async fn wss_register_then_close_disconnects_the_session() {
    let relay = start().await;
    let (mut ws, _) = ws_connect(&relay, RELAY_WSS_PATH, Some(RELAY_WSS_SUBPROTOCOL))
        .await
        .unwrap();
    let node = TestNode::new([9; 32], relay.relay_id(), unix_now() - 60).unwrap();
    let attempt = node
        .register(relay.relay_id(), 1, unix_now(), [2; 32])
        .unwrap();
    ws.send(Message::Binary(attempt.packet().to_vec().into()))
        .await
        .unwrap();
    let reply = match timeout(WAIT, ws.next()).await.unwrap() {
        Some(Ok(Message::Binary(reply))) => reply,
        other => panic!("no REGISTERED: {other:?}"),
    };
    let (registered, session) = attempt.accept(&reply).unwrap();
    assert!(registered.observed_addr.is_none());
    ws.send(Message::Binary(session.presence(1).unwrap().into()))
        .await
        .unwrap();
    assert!(matches!(
        timeout(WAIT, ws.next()).await.unwrap(),
        Some(Ok(Message::Binary(_)))
    ));
    assert!(relay.sessions()[0].confirmed);

    ws.close(None).await.unwrap();
    wait_for(&relay, |relay| relay.counters().disconnected == 1).await;
    assert!(relay.sessions().is_empty());
    relay.shutdown().await;
}

#[tokio::test]
async fn wss_text_message_closes_the_connection() {
    let relay = start().await;
    let (mut ws, _) = ws_connect(&relay, RELAY_WSS_PATH, Some(RELAY_WSS_SUBPROTOCOL))
        .await
        .unwrap();
    ws.send(Message::Text("hello".into())).await.unwrap();
    assert_eq!(close_code(&mut ws).await, Some(CloseCode::Unsupported));
    relay.shutdown().await;
}

#[tokio::test]
async fn wss_oversize_message_closes_the_connection() {
    let relay = start().await;
    let (mut ws, _) = ws_connect(&relay, RELAY_WSS_PATH, Some(RELAY_WSS_SUBPROTOCOL))
        .await
        .unwrap();
    ws.send(Message::Binary(vec![0; MAX_RELAY_PACKET_BYTES + 1].into()))
        .await
        .unwrap();
    assert_eq!(close_code(&mut ws).await, Some(CloseCode::Size));
    relay.shutdown().await;
}

#[tokio::test]
async fn wss_ping_is_answered() {
    let relay = start().await;
    let (mut ws, _) = ws_connect(&relay, RELAY_WSS_PATH, Some(RELAY_WSS_SUBPROTOCOL))
        .await
        .unwrap();
    ws.send(Message::Ping(vec![1, 2].into())).await.unwrap();
    assert_eq!(
        timeout(WAIT, ws.next()).await.unwrap().unwrap().unwrap(),
        Message::Pong(vec![1, 2].into())
    );
    relay.shutdown().await;
}

#[tokio::test]
async fn shutdown_closes_open_wss_connections() {
    let relay = start().await;
    let (mut ws, _) = ws_connect(&relay, RELAY_WSS_PATH, Some(RELAY_WSS_SUBPROTOCOL))
        .await
        .unwrap();
    // A handshake-complete connection is registered before shutdown signals it.
    tokio::time::sleep(Duration::from_millis(50)).await;
    relay.shutdown().await;
    assert_eq!(close_code(&mut ws).await, Some(CloseCode::Away));
}
