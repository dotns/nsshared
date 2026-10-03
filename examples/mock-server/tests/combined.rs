//! The combined server on one loopback port: a node registers on `/ns/v2` and over UDP,
//! publishes its record on `/quick/v2`, another connection looks it up, the directory
//! lists the server itself, and other paths are refused (quick-v2 §7.2, §8.3, §8.6;
//! rendezvous §3, §3.1, §5.4).

#![allow(clippy::unwrap_used, clippy::panic, reason = "test fixture helpers")]

use futures_util::{SinkExt, StreamExt};
use nsshared_mock_relay::{Carrier, testing::TestNode};
use nsshared_mock_rendezvous::Config;
use nsshared_mock_server::MockServer;
use nsshared_rendezvous::{
    auth::Challenge,
    message::{LookupNodeRequest, RecordResult},
    registry,
    transport::{PATH, Request, Response, SUBPROTOCOL, decode_response, encode_request},
};
use nsshared_wire::{
    IdentitySecret, MAX_RELAY_PACKET_BYTES, NODE_ID_BYTES, RELAY_WSS_PATH, RELAY_WSS_SUBPROTOCOL,
    RelayBody, RelayId,
};
use rustls::{
    ClientConfig, RootCertStore,
    crypto::aws_lc_rs,
    pki_types::{CertificateDer, ServerName, pem::PemObject},
};
use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    net::{TcpStream, UdpSocket},
    task::JoinHandle,
    time::timeout,
};
use tokio_rustls::{TlsConnector, client::TlsStream};
use tokio_tungstenite::{
    WebSocketStream, client_async_with_config,
    tungstenite::{
        self, Message,
        client::IntoClientRequest,
        http::{HeaderValue, StatusCode, header::SEC_WEBSOCKET_PROTOCOL},
    },
};

/// The bound on every await.
const WAIT: Duration = Duration::from_secs(10);

type Ws = WebSocketStream<TlsStream<TcpStream>>;

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A running combined server on `127.0.0.1:0` with host `localhost` and a self-signed
/// certificate, and an ns-style client configuration trusting only that certificate.
struct Combined {
    server: MockServer,
    serving: JoinHandle<()>,
    addr: SocketAddr,
    tls: Arc<ClientConfig>,
}

impl Combined {
    async fn start() -> Self {
        let config = Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            ..Config::default()
        };
        let (server, listener) = timeout(WAIT, MockServer::bind(config))
            .await
            .unwrap()
            .unwrap();
        let addr = listener.local_addr().unwrap();
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
            addr,
            tls: Arc::new(tls),
        }
    }

    fn authority(&self) -> RelayId {
        self.server.authority()
    }

    /// TLS to the listen address with SNI = the authority host, then the WebSocket
    /// upgrade for `wss://{authority}{path}` offering `subprotocol` if any.
    async fn ws(&self, path: &str, subprotocol: Option<&str>) -> Result<Ws, tungstenite::Error> {
        let authority = self.authority();
        let (host, _) = authority.as_str().rsplit_once(':').unwrap();
        let tcp = timeout(WAIT, TcpStream::connect(self.addr))
            .await
            .unwrap()
            .unwrap();
        let tls = timeout(
            WAIT,
            TlsConnector::from(Arc::clone(&self.tls))
                .connect(ServerName::try_from(host.to_owned()).unwrap(), tcp),
        )
        .await
        .unwrap()
        .unwrap();
        let mut request = format!("wss://{}{path}", authority.as_str())
            .into_client_request()
            .unwrap();
        if let Some(subprotocol) = subprotocol {
            request.headers_mut().insert(
                SEC_WEBSOCKET_PROTOCOL,
                HeaderValue::from_str(subprotocol).unwrap(),
            );
        }
        let (ws, response) = timeout(WAIT, client_async_with_config(request, tls, None))
            .await
            .unwrap()?;
        assert_eq!(
            response.headers().get(SEC_WEBSOCKET_PROTOCOL).unwrap(),
            subprotocol.unwrap()
        );
        Ok(ws)
    }

    async fn refused(&self, path: &str, subprotocol: Option<&str>) -> StatusCode {
        match self.ws(path, subprotocol).await {
            Err(tungstenite::Error::Http(response)) => response.status(),
            other => panic!("expected a refused upgrade, got {other:?}"),
        }
    }

    /// A `/quick/v2` connection that has read the challenge.
    async fn quick(&self) -> Quick {
        let mut ws = self.ws(PATH, Some(SUBPROTOCOL)).await.unwrap();
        let Response::Challenge(challenge) = quick_receive(&mut ws).await else {
            panic!("expected a challenge");
        };
        challenge.check_authority(&self.authority()).unwrap();
        Quick { ws, challenge }
    }

    async fn stop(self) {
        timeout(WAIT, self.server.shutdown()).await.unwrap();
        timeout(WAIT, self.serving).await.unwrap().unwrap();
    }
}

struct Quick {
    ws: Ws,
    challenge: Challenge,
}

impl Quick {
    async fn request(&mut self, request: &Request) -> Response {
        let text = encode_request(request).unwrap();
        timeout(WAIT, self.ws.send(Message::text(text)))
            .await
            .unwrap()
            .unwrap();
        quick_receive(&mut self.ws).await
    }
}

async fn quick_receive(ws: &mut Ws) -> Response {
    loop {
        match timeout(WAIT, ws.next()).await.unwrap() {
            Some(Ok(Message::Text(text))) => return decode_response(&text).unwrap(),
            Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
            other => panic!("unexpected message {other:?}"),
        }
    }
}

async fn relay_receive(ws: &mut Ws) -> Vec<u8> {
    loop {
        match timeout(WAIT, ws.next()).await.unwrap() {
            Some(Ok(Message::Binary(packet))) => return packet.to_vec(),
            Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
            other => panic!("no relay packet: {other:?}"),
        }
    }
}

async fn relay_send(ws: &mut Ws, packet: &[u8]) {
    timeout(WAIT, ws.send(Message::Binary(packet.to_vec().into())))
        .await
        .unwrap()
        .unwrap();
}

fn capability_tokens<'a>(tokens: impl IntoIterator<Item = &'a str>) -> Vec<&'a str> {
    let mut tokens: Vec<_> = tokens.into_iter().collect();
    tokens.sort_unstable();
    tokens
}

#[tokio::test]
async fn one_port_serves_relay_and_rendezvous() {
    let combined = Combined::start().await;
    let authority = combined.authority();
    let port = combined.addr.port();
    assert_eq!(authority.as_str(), format!("localhost:{port}"));
    assert_eq!(combined.server.relay().relay_id(), &authority);
    assert_eq!(
        combined.server.relay().udp_addr(),
        Some(combined.addr),
        "UDP shares the TCP port"
    );

    // (a) A node registers over WSS on /ns/v2: REGISTER, tentative REGISTERED,
    // confirming PRESENCE and its acknowledgement (quick-v2 §8.3).
    let seed = [3; 32];
    let node = TestNode::new(seed, &authority, unix_now() - 60).unwrap();
    let mut relay_ws = combined
        .ws(RELAY_WSS_PATH, Some(RELAY_WSS_SUBPROTOCOL))
        .await
        .unwrap();
    let attempt = node.register(&authority, 1, unix_now(), [13; 32]).unwrap();
    relay_send(&mut relay_ws, attempt.packet()).await;
    let (registered, session) = attempt.accept(&relay_receive(&mut relay_ws).await).unwrap();
    relay_send(&mut relay_ws, &session.presence(1).unwrap()).await;
    match session.open(&relay_receive(&mut relay_ws).await).unwrap() {
        RelayBody::Registered(ack) => assert_eq!(ack.ack_seq, 1),
        other => panic!("no PRESENCE acknowledgement: {other:?}"),
    }
    let sessions = combined.server.relay().sessions();
    assert_eq!(sessions.len(), 1);
    assert!(sessions[0].confirmed);
    assert_eq!(sessions[0].carrier, Carrier::Wss);

    // (b) The same identity publishes its record on /quick/v2; another connection
    // looks it up (hit) and an unknown node ID (miss).
    let identity = IdentitySecret::from_seed(seed);
    assert_eq!(identity.public().node_id(), node.node_id());
    let mut publisher = combined.quick().await;
    let publish = registry::publish_request(
        identity.signing_key(),
        &publisher.challenge.nonce,
        &publisher.challenge.authority,
        node.record(),
        false,
    );
    match publisher.request(&Request::Publish(publish)).await {
        Response::Published(published) => assert_eq!(published.expires, node.record().expires()),
        other => panic!("expected published, got {other:?}"),
    }
    let mut reader = combined.quick().await;
    let hit = Request::LookupNode(LookupNodeRequest {
        node_id: *node.node_id().as_bytes(),
    });
    match reader.request(&hit).await {
        Response::Record(RecordResult {
            record: Some(bytes),
        }) => {
            assert_eq!(bytes, node.record().as_bytes());
        }
        other => panic!("expected a record, got {other:?}"),
    }
    let miss = Request::LookupNode(LookupNodeRequest {
        node_id: [0x5a; NODE_ID_BYTES],
    });
    assert_eq!(
        reader.request(&miss).await,
        Response::Record(RecordResult { record: None })
    );

    // (c) The directory is the server itself with udp, wss, mailbox and registry, and
    // the challenge carries the relay authority and the same capabilities.
    let Response::Directory(directory) = reader.request(&Request::Directory).await else {
        panic!("expected the directory");
    };
    let [entry] = directory.relays() else {
        panic!("expected one entry, got {directory:?}");
    };
    assert_eq!(entry.relay_id(), authority);
    assert_eq!(entry.port(), port);
    let announced = capability_tokens(entry.capabilities().as_slice().iter().map(|c| c.as_str()));
    assert_eq!(announced, ["mailbox", "registry", "udp", "wss"]);
    assert_eq!(
        &reader.challenge.authority,
        combined.server.relay().relay_id()
    );
    assert_eq!(&reader.challenge.capabilities, entry.capabilities());
    // The relay lists its carriers first, so compare the three announcements as sorted
    // token sets (rendezvous §3.1).
    let challenged = capability_tokens(
        reader
            .challenge
            .capabilities
            .as_slice()
            .iter()
            .map(|c| c.as_str()),
    );
    let relayed = capability_tokens(registered.capabilities.iter().map(String::as_str));
    assert_eq!(relayed, announced);
    assert_eq!(challenged, announced);

    // (d) Other paths get 404, a missing subprotocol 400.
    assert_eq!(
        combined.refused("/other", Some(SUBPROTOCOL)).await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(combined.refused(PATH, None).await, StatusCode::BAD_REQUEST);
    assert_eq!(
        combined.refused(RELAY_WSS_PATH, None).await,
        StatusCode::BAD_REQUEST
    );

    // (e) A REGISTER datagram to the same port gets the tentative REGISTERED.
    let udp_node = TestNode::new([4; 32], &authority, unix_now() - 60).unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let attempt = udp_node
        .register(&authority, 1, unix_now(), [14; 32])
        .unwrap();
    timeout(WAIT, socket.send_to(attempt.packet(), combined.addr))
        .await
        .unwrap()
        .unwrap();
    let mut buf = vec![0; MAX_RELAY_PACKET_BYTES];
    let (len, from) = timeout(WAIT, socket.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(from, combined.addr);
    let (registered, _) = attempt.accept(&buf[..len]).unwrap();
    assert_eq!(
        registered.observed_addr.map(SocketAddr::from),
        Some(socket.local_addr().unwrap())
    );

    combined.stop().await;
}
