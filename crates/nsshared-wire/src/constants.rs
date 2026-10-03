//! Protocol constants, derivation labels and signature contexts (quick-v2 §2.2, §6.2, §12.2-§12.3).

use std::net::Ipv4Addr;

/// NodeRecord format version (quick-v2 §12.3).
pub const NODE_RECORD_VERSION: u8 = 2;
/// Maximum encoded NodeRecord length in bytes (quick-v2 §12.3).
pub const MAX_NODE_RECORD_BYTES: usize = 600;
/// Maximum record service period `expires - issued_at` in seconds (quick-v2 §12.3).
pub const MAX_RECORD_SERVICE_SECONDS: u64 = 604_800;

/// Raw node ID length in bytes (quick-v2 §2.2, §12.3).
pub const NODE_ID_BYTES: usize = 12;
/// Node ID text length in lowercase unpadded base32 characters (quick-v2 §2.2, §12.3).
pub const NODE_ID_TEXT_LEN: usize = 20;

/// First byte of every node address, `fd` in `fd ‖ g ‖ m` (quick-v2 §2.2, §12.3).
pub const ADDRESS_PREFIX: u8 = 0xfd;
/// Prefix length of a node address group (quick-v2 §2.2, §12.3).
pub const ADDRESS_GROUP_PREFIX_LEN: u8 = 127;

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

/// Maximum encoded region frame array length in bytes, prefix excluded, of types 10
/// RENDEZVOUS_REQUEST and 11 RENDEZVOUS_RESPONSE on the control connection: a whole
/// 16 KiB rendezvous JSON message plus its forwarding fields. Every other frame, and every
/// frame on the data connection, stays at 4096 bytes (quick-v2 §8.5, quick-protocol §12.8).
pub const MAX_REGION_RENDEZVOUS_FRAME_BYTES: usize = 20_480;

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

/// In-tunnel control UDP port (quick-v2 §12.3).
pub const CONTROL_PORT: u16 = 47900;
/// Maximum in-tunnel control message length in bytes (quick-v2 §12.3).
pub const MAX_CONTROL_MESSAGE_BYTES: usize = 1200;
/// Maximum endpoint candidates in ENDPOINTS (quick-v2 §12.3).
pub const MAX_ENDPOINT_CANDIDATES: usize = 8;
/// Maximum relays in ENDPOINTS (quick-v2 §12.3).
pub const MAX_ENDPOINT_RELAYS: usize = 4;

/// Registry shard replica count (quick-v2 §12.3).
pub const REGISTRY_SHARD_REPLICAS: usize = 2;
/// Maximum registry nodes asked per lookup (quick-v2 §12.3).
pub const REGISTRY_LOOKUP_MAX: usize = 4;

/// Default pairing mailbox TTL in seconds (quick-v2 §12.3).
pub const DEFAULT_PAIRING_MAILBOX_TTL_SECONDS: u64 = 600;
/// Maximum pairing mailbox TTL in seconds (quick-v2 §12.3).
pub const MAX_PAIRING_MAILBOX_TTL_SECONDS: u64 = 900;

/// Prepare deadline in seconds (quick-v2 §12.3).
pub const PREPARE_DEADLINE_SECONDS: u64 = 5;
/// Maximum inner MTU for traffic carried through a relay (quick-v2 §12.3).
pub const MAX_RELAYED_INNER_MTU: usize = 1376;

/// Keyed BLAKE2s label for the node ID (quick-v2 §2.2).
pub const NODE_ID_LABEL: &[u8] = b"ns-node-id-v2";
/// Keyed BLAKE2s label for the address group (quick-v2 §2.2).
pub const NODE_ADDR_LABEL: &[u8] = b"ns-node-addr-v2";
/// Keyed BLAKE2s label for IPv4 alias candidates (quick-v2 §2.2, §6.2).
pub const ALIAS4_LABEL: &[u8] = b"ns-alias4-v2";
/// Keyed BLAKE2s label for published LAN prefixes (next §4.1).
pub const LAN_ADDR_LABEL: &[u8] = b"ns-lan-addr-v2";

/// Signature context for NodeRecord, signed by `I` (quick-v2 §12.2).
pub const NODE_RECORD_CONTEXT: &[u8] = b"ns/node-record/v2";
/// Signature context for relay REGISTER, signed by `I` (quick-v2 §12.2).
pub const RELAY_REGISTER_CONTEXT: &[u8] = b"ns/relay-register/v2";
/// HKDF info for the relay session key (quick-v2 §12.2).
pub const RELAY_SESSION_CONTEXT: &[u8] = b"ns/relay-session/v2";
/// MAC context for relay control packets, keyed by `sk` (quick-v2 §12.2).
pub const RELAY_CTL_CONTEXT: &[u8] = b"ns/relay-ctl/v2";
/// MAC context for relay replies, keyed by `sk` (quick-v2 §12.2).
pub const RELAY_REPLY_CONTEXT: &[u8] = b"ns/relay-reply/v2";

/// Number of IPv4 alias candidates tried before reporting a conflict (quick-v2 §6.2).
pub const ALIAS_CANDIDATES: u8 = 16;
/// Alias kind for a native IPv6 service (quick-v2 §6.2).
pub const ALIAS_KIND_IPV6: u8 = 6;
/// Alias kind for an IPv4 service (quick-v2 §6.2).
pub const ALIAS_KIND_IPV4: u8 = 4;
/// Default IPv4 alias pool base, `100.64.0.0` (quick-v2 §6.2).
pub const DEFAULT_ALIAS_POOL_BASE: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 0);
/// Default IPv4 alias pool prefix length, `/10` (quick-v2 §6.2).
pub const DEFAULT_ALIAS_POOL_PREFIX_LEN: u8 = 10;
