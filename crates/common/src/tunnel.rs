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
