//! The relay UDP carrier: one relay packet per datagram, at most 2048 bytes
//! (quick-v2 §8.1, §8.5).

use super::Shared;
use crate::Peer;
use nsshared_proto::constants::MAX_RELAY_PACKET_BYTES;
use std::sync::Arc;
use tokio::{net::UdpSocket, sync::watch};
use tracing::debug;

/// Receives datagrams until stopped and feeds each one to the core.
pub(super) async fn serve(
    socket: Arc<UdpSocket>,
    shared: Arc<Shared>,
    mut stopped: watch::Receiver<()>,
) {
    // One spare byte detects a datagram over the limit instead of truncating it.
    let mut buf = vec![0; MAX_RELAY_PACKET_BYTES + 1];
    loop {
        let received = tokio::select! {
            _ = stopped.changed() => return,
            received = socket.recv_from(&mut buf) => received,
        };
        match received {
            Ok((len, from)) if len > MAX_RELAY_PACKET_BYTES => {
                debug!(%from, "oversize relay datagram dropped");
            }
            Ok((len, from)) => shared.handle(Peer::Udp(from), &buf[..len]).await,
            // ICMP errors of earlier sends surface here; the socket stays usable.
            Err(error) => debug!(%error, "relay UDP receive failed"),
        }
    }
}
