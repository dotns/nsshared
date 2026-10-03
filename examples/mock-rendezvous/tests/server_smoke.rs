//! Smoke test: a client built like the ns registry connection (TLS to the entry's IP
//! with SNI = host, `wss://{host:port}/rendezvous/v1`, subprotocol `ns-rendezvous-v1`) completes
//! the handshake, reads the `challenge` and gets a `directory`.

#![allow(clippy::unwrap_used, clippy::panic, reason = "test fixture helpers")]

use futures_util::{SinkExt, StreamExt};
use nsshared_mock_rendezvous::{Config, RendezvousServer};
use nsshared_proto::rendezvous::{
    capability,
    transport::{
        MAX_MESSAGE_BYTES, PATH, Request, Response, SUBPROTOCOL, decode_response, encode_request,
    },
};
use rustls::{
    ClientConfig, RootCertStore,
    crypto::aws_lc_rs,
    pki_types::{CertificateDer, pem::PemObject},
};
use std::{net::SocketAddr, sync::Arc};
use tokio::net::TcpStream;
use tokio_tungstenite::{
    Connector, MaybeTlsStream, WebSocketStream, client_async_tls_with_config,
    tungstenite::{
        Message,
        client::IntoClientRequest,
        http::{HeaderValue, header::SEC_WEBSOCKET_PROTOCOL},
        protocol::WebSocketConfig,
    },
};

type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;

async fn receive(socket: &mut Socket) -> Response {
    loop {
        match socket.next().await {
            Some(Ok(Message::Text(text))) => return decode_response(&text).unwrap(),
            Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
            other => panic!("unexpected message {other:?}"),
        }
    }
}

#[tokio::test]
async fn challenge_and_directory() {
    let config = Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        ..Config::default()
    };
    let (server, listener) = RendezvousServer::bind(config).await.unwrap();
    let serving = tokio::spawn({
        let server = server.clone();
        async move { server.serve(listener).await }
    });
    let entry = server.relay_entry().clone();

    let mut roots = RootCertStore::empty();
    for certificate in CertificateDer::pem_slice_iter(server.certificate_pem().as_bytes()) {
        roots.add(certificate.unwrap()).unwrap();
    }
    let tls = ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let relay = entry.relay_id();
    let stream = TcpStream::connect(SocketAddr::new(entry.ips()[0], entry.port()))
        .await
        .unwrap();
    let mut request = format!("wss://{}{PATH}", relay.as_str())
        .into_client_request()
        .unwrap();
    request.headers_mut().insert(
        SEC_WEBSOCKET_PROTOCOL,
        HeaderValue::from_static(SUBPROTOCOL),
    );
    let websocket = WebSocketConfig::default()
        .max_message_size(Some(MAX_MESSAGE_BYTES))
        .max_frame_size(Some(MAX_MESSAGE_BYTES));
    let (mut socket, response) = client_async_tls_with_config(
        request,
        stream,
        Some(websocket),
        Some(Connector::Rustls(Arc::new(tls))),
    )
    .await
    .unwrap();
    assert_eq!(
        response.headers().get(SEC_WEBSOCKET_PROTOCOL).unwrap(),
        SUBPROTOCOL
    );

    let Response::Challenge(challenge) = receive(&mut socket).await else {
        panic!("expected a challenge");
    };
    challenge.check_authority(&relay).unwrap();
    assert_eq!(relay.as_str(), server.authority().as_str());
    assert_ne!(challenge.nonce, [0; 32]);
    assert!(challenge.capabilities.contains(&capability::MAILBOX));
    assert!(challenge.capabilities.contains(&capability::REGISTRY));

    let text = encode_request(&Request::Directory).unwrap();
    socket.send(Message::text(text)).await.unwrap();
    let Response::Directory(directory) = receive(&mut socket).await else {
        panic!("expected a directory");
    };
    assert_eq!(directory.version(), 1);
    assert_eq!(directory.relays(), &[entry]);

    server.shutdown();
    serving.await.unwrap();
}
