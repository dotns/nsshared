#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Combined single-instance mock: relay v2 and rendezvous on one `host:port`
//! (docs ns/quick-v2.md §8.6; ns/rendezvous.md §3, §3.1, §5.4).
//!
//! [`MockServer`] owns one TCP+TLS listener with one certificate and routes each
//! WebSocket upgrade by path: `/ns/v2` to the relay mock
//! ([`MockRelay::handle_websocket`], relay started with
//! [`MockRelayConfig::external_wss`]) and `/rendezvous/v1` to the rendezvous mock
//! ([`RendezvousServer::handle_websocket`]). The relay's UDP carrier binds the same port.
//! Both services keep their own state; this crate adds only the shared listener, the
//! router and the lifecycle. The served directory lists the mock itself announcing
//! `mailbox`, `registry`, `udp` and `wss` (rendezvous §3.1, §5.4).

use nsshared_mock_relay::{MockRelay, MockRelayConfig, accept_relay_request};
use nsshared_mock_rendezvous::{
    Config, RendezvousServer, ServerError, accept_quick_request, server::HANDSHAKE_TIMEOUT,
};
use nsshared_proto::RelayId;
use nsshared_proto::rendezvous::{capability, transport::PATH};
use std::{io, net::SocketAddr, sync::Arc, time::Duration};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
    sync::watch,
    time::timeout,
};
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::{
    accept_hdr_async_with_config,
    tungstenite::handshake::server::{ErrorResponse, Request, Response},
};

/// Free ports tried for port 0 before giving up on one whose UDP twin is also free.
const SHARED_PORT_ATTEMPTS: usize = 16;

/// Why the combined server could not start.
#[derive(Debug, Error)]
pub enum Error {
    /// Binding the TCP listener failed.
    #[error("listener: {0}")]
    Io(#[from] io::Error),
    /// The rendezvous mock rejected the configuration or certificate.
    #[error("rendezvous: {0}")]
    Rendezvous(#[from] ServerError),
    /// The relay mock could not start.
    #[error("relay: {0}")]
    Relay(#[from] nsshared_mock_relay::Error),
}

/// Relay v2 (UDP and `/ns/v2`) and rendezvous (`/rendezvous/v1`) behind one authority.
/// Cloning yields another handle to the same server.
#[derive(Clone, Debug)]
pub struct MockServer {
    rendezvous: RendezvousServer,
    relay: Arc<MockRelay>,
    shutdown: watch::Sender<bool>,
}

impl MockServer {
    /// Binds `config.listen` for TCP and the relay's UDP on the same port, then builds
    /// both services: the rendezvous mock from `config` with `udp` and `wss` added to
    /// its capabilities, the relay with the rendezvous authority as its identifier.
    /// Port 0 picks a port free for both TCP and UDP. TLS comes from `config.tls`.
    ///
    /// # Errors
    ///
    /// [`enum@Error`] when binding, the configuration or the certificate fails.
    pub async fn bind(mut config: Config) -> Result<(Self, TcpListener), Error> {
        for token in [capability::UDP, capability::WSS] {
            if !config.capabilities.contains(&token) {
                config.capabilities.push(token);
            }
        }
        let attempts = if config.listen.port() == 0 {
            SHARED_PORT_ATTEMPTS
        } else {
            1
        };
        let mut attempt = 0;
        loop {
            attempt += 1;
            let listener = TcpListener::bind(config.listen).await?;
            let mut bound = config.clone();
            bound.listen = listener.local_addr()?;
            let rendezvous = RendezvousServer::new(bound.clone())?;
            let relay = MockRelay::start(MockRelayConfig {
                relay_id: Some(rendezvous.authority()),
                listen: bound.listen,
                external_wss: true,
                extra_capabilities: vec![capability::MAILBOX, capability::REGISTRY],
                ..MockRelayConfig::default()
            })
            .await;
            let relay = match relay {
                Ok(relay) => relay,
                Err(nsshared_mock_relay::Error::Bind { .. }) if attempt < attempts => continue,
                Err(error) => return Err(error.into()),
            };
            let (shutdown, _) = watch::channel(false);
            let server = Self {
                rendezvous,
                relay: Arc::new(relay),
                shutdown,
            };
            return Ok((server, listener));
        }
    }

    /// The shared authority `host:port`: the relay identifier and the
    /// `challenge.authority`.
    #[must_use]
    pub fn authority(&self) -> RelayId {
        self.rendezvous.authority()
    }

    /// The rendezvous mock.
    #[must_use]
    pub const fn rendezvous(&self) -> &RendezvousServer {
        &self.rendezvous
    }

    /// The relay mock.
    #[must_use]
    pub fn relay(&self) -> &MockRelay {
        &self.relay
    }

    /// The presented certificate chain as PEM, for clients to trust.
    #[must_use]
    pub fn certificate_pem(&self) -> &str {
        self.rendezvous.certificate_pem()
    }

    /// Accepts connections on `listener` and runs the rendezvous sweeper until
    /// [`shutdown`](Self::shutdown).
    pub async fn serve(&self, listener: TcpListener) {
        let sweeper = tokio::spawn({
            let rendezvous = self.rendezvous.clone();
            async move { rendezvous.run_sweeper().await }
        });
        loop {
            tokio::select! {
                () = self.stopped() => break,
                accepted = listener.accept() => match accepted {
                    Ok((stream, remote)) => {
                        let server = self.clone();
                        tokio::spawn(async move { server.handle_tcp(stream, remote).await });
                    }
                    // Transient accept failures such as file descriptor exhaustion.
                    Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
                },
            }
        }
        let _ = sweeper.await;
    }

    /// Serves one accepted TCP connection: TLS, then [`route`](Self::route).
    pub async fn handle_tcp(&self, stream: TcpStream, remote: SocketAddr) {
        let acceptor = TlsAcceptor::from(self.rendezvous.tls().config());
        if let Ok(Ok(tls)) = timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
            self.route(tls, remote).await;
        }
    }

    /// Upgrades one decrypted stream and routes it by path: `/rendezvous/v1` (400 without
    /// `ns-rendezvous-v1`) to the rendezvous mock, `/ns/v2` (400 without `ns-relay-v2`) to the
    /// relay mock, 404 otherwise. The upgrade applies the larger rendezvous WebSocket
    /// limit; the relay still closes a message over 2048 bytes with 1009.
    pub async fn route<S>(&self, stream: S, remote: SocketAddr)
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut quick = false;
        // tungstenite's `Callback` fixes the error type.
        #[allow(clippy::result_large_err)]
        let callback = |request: &Request, response: Response| -> Result<Response, ErrorResponse> {
            if request.uri().path() == PATH {
                quick = true;
                return accept_quick_request(request, response);
            }
            accept_relay_request(request, response)
        };
        let upgrade = accept_hdr_async_with_config(
            stream,
            callback,
            Some(RendezvousServer::websocket_config()),
        );
        let Ok(Ok(socket)) = timeout(HANDSHAKE_TIMEOUT, upgrade).await else {
            return;
        };
        if quick {
            self.rendezvous.handle_websocket(socket, remote.ip()).await;
        } else {
            self.relay.handle_websocket(socket, remote).await;
        }
    }

    /// Stops accepting, shuts both services down and waits for the relay's tasks and
    /// sockets.
    pub async fn shutdown(&self) {
        self.shutdown.send_replace(true);
        self.rendezvous.shutdown();
        self.relay.shutdown().await;
    }

    /// Resolves once [`shutdown`](Self::shutdown) is called.
    async fn stopped(&self) {
        let mut shutdown = self.shutdown.subscribe();
        let _ = shutdown.wait_for(|stopped| *stopped).await;
    }
}
