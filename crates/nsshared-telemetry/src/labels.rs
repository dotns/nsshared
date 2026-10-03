//! Metric label keys and values shared between NS and the mock servers and
//! relay.
//!
//! Every value enum has a small fixed domain; `as_str` returns a
//! `&'static str` so call sites can attach it without allocating. Values that
//! identify a peer, an address or a flow are never labels (see
//! [`crate::redact::SENSITIVE_FIELDS`]).
//!
//! Adopted from NS `telemetry/src/labels.rs`, with the same strings:
//! - `transport` and [`Transport`] (`udp`, `wss`, `noise`, `quic`).
//! - `path` and [`Path`] (`tun`, `userspace`, `wss`).
//!
//! New here: `peer_source` and [`PeerSource`], the kind of an NS overlay
//! `SourceId` (`nsd:<uuid>`, `quick`, `app:<session>` in
//! `overlay/src/source.rs`). Only the kind is a label; the UUID and the
//! session name are unbounded.
//!
//! Left in NS:
//! - `service`: names come from the NS `services.toml`.
//! - `gateway`: identifiers come from the NS connector config.
//! - `task`: names of NS supervised tasks.
//! - `event_type`: NS control-plane and SSE events.
//! - `protocol` and `result`: no other component emits them yet.
//!
//! Metric names: NS `telemetry/src/metrics.rs` names only the
//! `nat_conntrack_*` series, labelled by `result` and `reason` and internal
//! to the NS NAT table. None carries `path`, `transport` or `peer_source`, so
//! no metric name is shared yet.

/// Transport in use for a tunnel or control-plane connection.
pub const LABEL_TRANSPORT: &str = "transport";

/// Data-plane path a packet traversed.
pub const LABEL_PATH: &str = "path";

/// Kind of the peer source a peer came from.
pub const LABEL_PEER_SOURCE: &str = "peer_source";

/// Data-plane path a packet flows through.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Path {
    /// Kernel TUN device.
    Tun,
    /// User-space network stack and proxy.
    Userspace,
    /// WSS fallback relay.
    Wss,
}

impl Path {
    /// Returns the label value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tun => "tun",
            Self::Userspace => "userspace",
            Self::Wss => "wss",
        }
    }
}

/// Transport used for a control-plane or data-plane tunnel.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Transport {
    /// Plain UDP.
    Udp,
    /// WebSocket over TLS.
    Wss,
    /// Noise over UDP.
    Noise,
    /// QUIC.
    Quic,
}

impl Transport {
    /// Returns the label value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Wss => "wss",
            Self::Noise => "noise",
            Self::Quic => "quic",
        }
    }
}

/// Kind of peer source.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PeerSource {
    /// An NSD control plane (`nsd:<uuid>`).
    Nsd,
    /// The local Quick allow list (`quick`).
    Quick,
    /// An app rendezvous session (`app:<session>`).
    App,
}

impl PeerSource {
    /// Returns the label value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Nsd => "nsd",
            Self::Quick => "quick",
            Self::App => "app",
        }
    }
}
