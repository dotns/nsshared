//! The relay WSS carrier: `wss://host:port/ns/v2` with subprotocol `ns-relay-v2`, one
//! relay packet per binary WebSocket message, no compression; a text or oversize message
//! closes the connection (quick-v2 §8.5).

use super::Shared;
use crate::Peer;
use futures_util::{SinkExt, StreamExt};
use nsshared_proto::{
    constants::MAX_RELAY_PACKET_BYTES, constants::RELAY_WSS_PATH, constants::RELAY_WSS_SUBPROTOCOL,
};
use rustls::ServerConfig;
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex, PoisonError, atomic::Ordering},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpListener,
    sync::{mpsc, watch},
    task::JoinSet,
};
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::{
    WebSocketStream, accept_hdr_async_with_config,
    tungstenite::{
        self, Message,
        handshake::server::{ErrorResponse, Request, Response},
        http::{HeaderValue, StatusCode, header::SEC_WEBSOCKET_PROTOCOL},
        protocol::{CloseFrame, WebSocketConfig, frame::coding::CloseCode},
    },
};
use tracing::debug;

/// Bound on the TLS and WebSocket handshakes of one connection.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Bound on closing the open connections at shutdown.
const CLOSE_GRACE: Duration = Duration::from_secs(1);

/// How often [`drain`] checks for the last connection to end.
const DRAIN_POLL: Duration = Duration::from_millis(10);

/// Relay packets queued toward one connection before new ones are dropped.
const SEND_QUEUE: usize = 256;

/// Accepts WSS connections until stopped, then closes every open connection.
pub(super) async fn serve(listener: TcpListener, tls: Arc<ServerConfig>, shared: Arc<Shared>) {
    let acceptor = TlsAcceptor::from(tls);
    let mut stopped = shared.stopped.clone();
    let mut connections = JoinSet::new();
    loop {
        while connections.try_join_next().is_some() {}
        let accepted = tokio::select! {
            _ = stopped.changed() => break,
            accepted = listener.accept() => accepted,
        };
        let (stream, remote) = match accepted {
            Ok(accepted) => accepted,
            Err(error) => {
                debug!(%error, "relay WSS accept failed");
                continue;
            }
        };
        let Some(slot) = IpSlot::take(&shared.ip_slots, remote.ip(), shared.wss_per_ip) else {
            debug!(%remote, "relay WSS per-IP connection limit reached");
            continue;
        };
        let acceptor = acceptor.clone();
        let shared = Arc::clone(&shared);
        connections.spawn(async move {
            match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                Ok(Ok(tls)) => upgrade(tls, remote, slot, shared).await,
                Ok(Err(error)) => debug!(%remote, %error, "relay TLS handshake failed"),
                Err(_) => debug!(%remote, "relay TLS handshake timed out"),
            }
        });
    }
    // Open connections send a close frame on the stop signal; give them a moment.
    let drain = async { while connections.join_next().await.is_some() {} };
    if tokio::time::timeout(CLOSE_GRACE, drain).await.is_err() {
        connections.shutdown().await;
    }
}

/// Serves one TLS-terminated stream from a caller-owned listener.
pub(super) async fn handle_stream<S>(shared: Arc<Shared>, stream: S, remote: SocketAddr)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let Some(slot) = IpSlot::take(&shared.ip_slots, remote.ip(), shared.wss_per_ip) else {
        debug!(%remote, "relay WSS per-IP connection limit reached");
        return;
    };
    upgrade(stream, remote, slot, shared).await;
}

/// Serves one WebSocket the caller has already upgraded.
pub(super) async fn handle_websocket<S>(
    shared: Arc<Shared>,
    mut ws: WebSocketStream<S>,
    remote: SocketAddr,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let Some(slot) = IpSlot::take(&shared.ip_slots, remote.ip(), shared.wss_per_ip) else {
        debug!(%remote, "relay WSS per-IP connection limit reached");
        close(&mut ws, CloseCode::Again, "per-IP connection limit").await;
        return;
    };
    run(ws, remote, slot, shared).await;
}

/// Waits briefly until every WSS connection, built-in or external, has ended.
pub(super) async fn drain(shared: &Shared) {
    let idle = async {
        while !shared
            .ip_slots
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_empty()
        {
            tokio::time::sleep(DRAIN_POLL).await;
        }
    };
    if tokio::time::timeout(CLOSE_GRACE, idle).await.is_err() {
        debug!("relay WSS connections still open after shutdown");
    }
}

/// Runs the WebSocket handshake on a TLS-terminated stream, then [`run`].
async fn upgrade<S>(stream: S, remote: SocketAddr, slot: IpSlot, shared: Arc<Shared>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut stopped = shared.stopped.clone();
    let handshake = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        accept_hdr_async_with_config(stream, accept_relay_request, Some(relay_websocket_config())),
    );
    let ws = tokio::select! {
        _ = stopped.changed() => return,
        handshake = handshake => match handshake {
            Ok(Ok(ws)) => ws,
            Ok(Err(error)) => {
                debug!(%remote, %error, "relay WSS handshake failed");
                return;
            }
            Err(_) => {
                debug!(%remote, "relay WSS handshake timed out");
                return;
            }
        },
    };
    run(ws, remote, slot, shared).await;
}

/// Serves one upgraded connection until either side closes, then disconnects it.
async fn run<S>(ws: WebSocketStream<S>, remote: SocketAddr, _slot: IpSlot, shared: Arc<Shared>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let connection = shared.next_connection.fetch_add(1, Ordering::Relaxed);
    let peer = Peer::Wss { connection, remote };
    let (queue, outgoing) = mpsc::channel(SEND_QUEUE);
    shared.connections().insert(connection, queue);
    pump(ws, peer, outgoing, &shared, shared.stopped.clone()).await;
    shared.connections().remove(&connection);
    shared.relay().disconnect(&peer);
}

/// Moves packets between the WebSocket and the core until the connection ends.
async fn pump<S>(
    mut ws: WebSocketStream<S>,
    peer: Peer,
    mut outgoing: mpsc::Receiver<Vec<u8>>,
    shared: &Shared,
    mut stopped: watch::Receiver<()>,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        tokio::select! {
            _ = stopped.changed() => {
                close(&mut ws, CloseCode::Away, "relay shutting down").await;
                return;
            }
            Some(packet) = outgoing.recv() => {
                if let Err(error) = ws.send(Message::Binary(packet.into())).await {
                    debug!(?peer, %error, "relay WSS send failed");
                    return;
                }
            }
            incoming = ws.next() => match incoming {
                Some(Ok(Message::Binary(packet))) if packet.len() <= MAX_RELAY_PACKET_BYTES => {
                    shared.handle(peer, &packet).await;
                }
                Some(Ok(Message::Binary(_)) | Err(tungstenite::Error::Capacity(_))) => {
                    close(&mut ws, CloseCode::Size, "relay message exceeds 2048 bytes").await;
                    return;
                }
                Some(Ok(Message::Text(_))) => {
                    close(&mut ws, CloseCode::Unsupported, "text message").await;
                    return;
                }
                // tungstenite answers pings itself on the next read or write.
                Some(Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_))) => {}
                Some(Ok(Message::Close(_))) | None => return,
                Some(Err(error)) => {
                    debug!(?peer, %error, "relay WSS receive failed");
                    return;
                }
            },
        }
    }
}

/// The WebSocket limits of the relay carrier: messages and frames of at most 2048 bytes
/// (`MAX_RELAY_PACKET_BYTES`, quick-v2 §8.1). A router that upgrades `/ns/v2` itself
/// must apply it before [`MockRelay::handle_websocket`](super::MockRelay::handle_websocket).
#[must_use]
pub fn relay_websocket_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .max_message_size(Some(MAX_RELAY_PACKET_BYTES))
        .max_frame_size(Some(MAX_RELAY_PACKET_BYTES))
}

/// The relay's WebSocket handshake check, usable as or inside a tungstenite
/// `accept_hdr_async` callback: accepts only the path `/ns/v2` (else HTTP 404) offering
/// the `ns-relay-v2` subprotocol (else HTTP 400), and selects that subprotocol in the
/// response.
///
/// # Errors
///
/// The 404 or 400 [`ErrorResponse`] to send instead of upgrading.
#[expect(
    clippy::result_large_err,
    reason = "the tungstenite callback signature fixes the error type"
)]
pub fn accept_relay_request(
    request: &Request,
    mut response: Response,
) -> Result<Response, ErrorResponse> {
    if request.uri().path() != RELAY_WSS_PATH {
        return Err(reject(StatusCode::NOT_FOUND));
    }
    let offered = request
        .headers()
        .get_all(SEC_WEBSOCKET_PROTOCOL)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|protocol| protocol.trim() == RELAY_WSS_SUBPROTOCOL);
    if !offered {
        return Err(reject(StatusCode::BAD_REQUEST));
    }
    response.headers_mut().insert(
        SEC_WEBSOCKET_PROTOCOL,
        HeaderValue::from_static(RELAY_WSS_SUBPROTOCOL),
    );
    Ok(response)
}

fn reject(status: StatusCode) -> ErrorResponse {
    let mut response = ErrorResponse::new(None);
    *response.status_mut() = status;
    response
}

async fn close<S>(ws: &mut WebSocketStream<S>, code: CloseCode, reason: &'static str)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let frame = CloseFrame {
        code,
        reason: reason.into(),
    };
    if let Err(error) = ws.close(Some(frame)).await {
        debug!(%error, "relay WSS close failed");
    }
}

/// One counted connection of a remote IP; dropping it frees the slot.
struct IpSlot {
    counts: Arc<Mutex<HashMap<IpAddr, usize>>>,
    ip: IpAddr,
}

impl IpSlot {
    fn take(counts: &Arc<Mutex<HashMap<IpAddr, usize>>>, ip: IpAddr, limit: usize) -> Option<Self> {
        let ip = ip.to_canonical();
        let mut map = counts.lock().unwrap_or_else(PoisonError::into_inner);
        let count = map.entry(ip).or_default();
        if *count >= limit {
            return None;
        }
        *count += 1;
        Some(Self {
            counts: Arc::clone(counts),
            ip,
        })
    }
}

impl Drop for IpSlot {
    fn drop(&mut self) {
        let mut map = self.counts.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(count) = map.get_mut(&self.ip) {
            *count -= 1;
            if *count == 0 {
                map.remove(&self.ip);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_slots_are_limited_and_released() {
        let counts = Arc::new(Mutex::new(HashMap::new()));
        let ip = IpAddr::from([192, 0, 2, 1]);
        let first = IpSlot::take(&counts, ip, 2).unwrap();
        let _second = IpSlot::take(&counts, ip, 2).unwrap();
        assert!(IpSlot::take(&counts, ip, 2).is_none());
        assert!(IpSlot::take(&counts, IpAddr::from([192, 0, 2, 2]), 2).is_some());
        drop(first);
        assert!(IpSlot::take(&counts, ip, 2).is_some());
    }
}
