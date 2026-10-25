//! Protocol constants, derivation labels and signature contexts (quick-v2 §2.2, §12.2-§12.3).

pub use nsshared_identity::constants::*;

/// Relay packet magic (quick-v2 §8).
pub const RELAY_MAGIC: [u8; 4] = *b"NSR2";
/// Relay packet header length in bytes (quick-v2 §12.3).
pub const RELAY_HEADER_BYTES: usize = 29;
/// Maximum relay packet length in bytes (quick-v2 §12.3).
pub const MAX_RELAY_PACKET_BYTES: usize = 2048;
/// Maximum relay control packet length in bytes (quick-v2 §12.3).
pub const MAX_RELAY_CONTROL_BYTES: usize = 1200;
/// Minimum relay DATA body length in bytes (quick-v2 §12.3).
pub const MIN_RELAY_DATA_BODY_BYTES: usize = 1;
/// Maximum relay DATA body length in bytes (quick-v2 §12.3).
pub const MAX_RELAY_DATA_BODY_BYTES: usize = 2019;
/// Accepted REGISTER `ts` skew in seconds, in either direction (quick-v2 §12.3).
pub const REGISTER_TS_WINDOW_SECONDS: u64 = 120;

/// Relay WSS URL path, `wss://host:port/ns/v2` (quick-v2 §8.5).
pub const RELAY_WSS_PATH: &str = "/ns/v2";
/// Relay WSS subprotocol (quick-v2 §8.5).
pub const RELAY_WSS_SUBPROTOCOL: &str = "ns-relay-v2";

/// Minimum presence TTL in seconds (quick-v2 §12.3).
pub const MIN_PRESENCE_TTL_SECONDS: u64 = 30;
/// Maximum presence TTL in seconds (quick-v2 §12.3).
pub const MAX_PRESENCE_TTL_SECONDS: u64 = 3600;
/// Default presence TTL in seconds (quick-v2 §12.3).
pub const DEFAULT_PRESENCE_TTL_SECONDS: u64 = 90;

/// Registry shard replica count (quick-v2 §12.3).
pub const REGISTRY_SHARD_REPLICAS: usize = 2;
/// Maximum registry nodes asked per lookup (quick-v2 §12.3).
pub const REGISTRY_LOOKUP_MAX: usize = 4;

/// Signature context for relay REGISTER, signed by `I` (quick-v2 §12.2).
pub const RELAY_REGISTER_CONTEXT: &[u8] = b"ns/relay-register/v2";
/// HKDF info for the relay session key (quick-v2 §12.2).
pub const RELAY_SESSION_CONTEXT: &[u8] = b"ns/relay-session/v2";
/// MAC context for relay control packets, keyed by `sk` (quick-v2 §12.2).
pub const RELAY_CTL_CONTEXT: &[u8] = b"ns/relay-ctl/v2";
/// MAC context for relay replies, keyed by `sk` (quick-v2 §12.2).
pub const RELAY_REPLY_CONTEXT: &[u8] = b"ns/relay-reply/v2";
