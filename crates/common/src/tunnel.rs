/// Conservative plaintext MTU used by WireGuard-backed interfaces by default.
///
/// A 1360-byte plaintext packet produces an approximately 1420-byte outer
/// UDP/IPv4 packet after WireGuard encapsulation, leaving headroom for common
/// underlay encapsulation below a 1500-byte link MTU.
pub const DEFAULT_WIREGUARD_PLAINTEXT_MTU: u16 = 1360;

/// Transport layer type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportType {
    /// WireGuard over UDP.
    WireGuard,
    /// WebSocket relay (WSS).
    WebSocket,
}

/// Common interface implemented by all tunnel types.
pub trait Tunnel: Send + Sync {
    /// Returns the transport mechanism used by this tunnel.
    fn transport_type(&self) -> TransportType;

    /// Returns `true` while the tunnel is considered active/connected.
    fn is_connected(&self) -> bool;
}
