//! Time, peers and output of the sans-IO core (quick-v2 §8.2, §8.5).

use nsshared_proto::ObservedAddr;
use std::{
    net::{IpAddr, SocketAddr},
    time::Instant,
};

/// The current time as a monotonic instant for timers and Unix seconds for the REGISTER
/// `ts` window and record expiry (quick-v2 §8.3).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Now {
    /// Monotonic time for every timer and token bucket.
    pub instant: Instant,
    /// Wall-clock Unix seconds.
    pub unix: u64,
}

/// The carrier of a peer (quick-v2 §8.5).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Carrier {
    /// One relay packet per UDP datagram.
    Udp,
    /// One relay packet per binary WebSocket message.
    Wss,
}

/// Where a relay packet comes from or goes to (quick-v2 §8.5).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Peer {
    /// A UDP source address.
    Udp(SocketAddr),
    /// One WSS connection, identified by a runtime-assigned id; `remote` is the TCP peer
    /// address, used only for the per-IP provisional limit.
    Wss {
        /// The runtime-assigned connection id.
        connection: u64,
        /// The remote TCP address of the connection.
        remote: SocketAddr,
    },
}

impl Peer {
    /// Returns the carrier of this peer.
    #[must_use]
    pub const fn carrier(&self) -> Carrier {
        match self {
            Self::Udp(_) => Carrier::Udp,
            Self::Wss { .. } => Carrier::Wss,
        }
    }

    /// Returns the source IP address, IPv4-mapped IPv6 folded to IPv4.
    #[must_use]
    pub fn ip(&self) -> IpAddr {
        match self {
            Self::Udp(address)
            | Self::Wss {
                remote: address, ..
            } => address.ip().to_canonical(),
        }
    }

    /// Returns `observed_addr`: the UDP source, `None` on WSS (quick-v2 §8.2). IPv4 is
    /// never reported as mapped IPv6 (quick-protocol §12.5).
    #[must_use]
    pub fn observed_addr(&self) -> Option<ObservedAddr> {
        match self {
            Self::Udp(address) => Some(ObservedAddr {
                ip: address.ip().to_canonical(),
                port: address.port(),
            }),
            Self::Wss { .. } => None,
        }
    }
}

/// One relay packet to send to a peer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Transmit {
    /// The destination peer.
    pub to: Peer,
    /// The whole relay packet.
    pub packet: Vec<u8>,
}
