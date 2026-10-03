//! The relay WSS carrier: `wss://host:port/ns/v2` with subprotocol `ns-relay-v2`, one
//! relay packet per binary WebSocket message, no compression; a text or oversize message
//! closes the connection (quick-v2 §8.5).

use super::Shared;
use crate::Peer;
use futures_util::{SinkExt, StreamExt};
use nsshared_wire::{MAX_RELAY_PACKET_BYTES, RELAY_WSS_PATH, RELAY_WSS_SUBPROTOCOL};
use rustls::ServerConfig;
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
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

/// Relay packets queued toward one connection before new ones are dropped.
const SEND_QUEUE: usize = 256;

/// Accepts WSS connections until stopped, then closes every open connection.
pub(super) async fn serve(
    listener: TcpListener,
    tls: Arc<ServerConfig>,
    per_ip: usize,
    shared: Arc<Shared>,
    mut stopped: watch::Receiver<()>,
) {
    let acceptor = TlsAcceptor::from(tls);
    let counts = Arc::new(Mutex::new(HashMap::new()));
    let next_id = AtomicU64::new(1);
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
        let Some(slot) = IpSlot::take(&counts, remote.ip(), per_ip) else {
            debug!(%remote, "relay WSS per-IP connection limit reached");
            continue;
        };
        let peer = Peer::Wss {
            connection: next_id.fetch_add(1, Ordering::Relaxed),
            remote,
        };
        connections.spawn(connection(
            stream,
            acceptor.clone(),
            peer,
            slot,
            Arc::clone(&shared),
            stopped.clone(),
        ));
    }
    // Open connections send a close frame on the stop signal; give them a moment.
    let drain = async { while connections.join_next().await.is_some() {} };
    if tokio::time::timeout(CLOSE_GRACE, drain).await.is_err() {
        connections.shutdown().await;
    }
}

/// Runs one connection: handshake, then packets both ways until either side closes.
async fn connection(
    stream: TcpStream,
    acceptor: TlsAcceptor,
    peer: Peer,
    _slot: IpSlot,
    shared: Arc<Shared>,
    stopped: watch::Receiver<()>,
) {
    let handshake = async {
        let tls = acceptor.accept(stream).await?;
        accept_hdr_async_with_config(tls, check_request, Some(websocket_config()))
            .await
            .map_err(std::io::Error::other)
    };
    let ws = match tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake).await {
        Ok(Ok(ws)) => ws,
        Ok(Err(error)) => {
            debug!(?peer, %error, "relay WSS handshake failed");
            return;
        }
        Err(_) => {
            debug!(?peer, "relay WSS handshake timed out");
            return;
        }
    };
    let Peer::Wss { connection, .. } = peer else {
        return;
    };
    let (queue, outgoing) = mpsc::channel(SEND_QUEUE);
    shared.connections().insert(connection, queue);
    pump(ws, peer, outgoing, &shared, stopped).await;
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

/// Bounds incoming messages and frames by the relay packet limit (quick-v2 §8.1).
fn websocket_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .max_message_size(Some(MAX_RELAY_PACKET_BYTES))
        .max_frame_size(Some(MAX_RELAY_PACKET_BYTES))
}

/// Accepts only `RELAY_WSS_PATH` (else 404) offering `ns-relay-v2` (else 400), and
/// selects that subprotocol in the response.
#[expect(
    clippy::result_large_err,
    reason = "the tungstenite callback signature fixes the error type"
)]
fn check_request(request: &Request, mut response: Response) -> Result<Response, ErrorResponse> {
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
