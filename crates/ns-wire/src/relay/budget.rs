//! Production relay budget defaults: the quick-protocol §5.2.1 table without the
//! INTRO / INTRO_ACK row, keyed by `I` instead of `(network_id, I)` and with the 29-byte
//! header (quick-v2 §8.5). Values only; rate limiting is the caller's.

const KIB: u64 = 1024;
const MIB: u64 = 1024 * KIB;
const GIB: u64 = 1024 * MIB;

/// A token bucket default: refill per second and burst capacity (quick-protocol §5.2.1).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RateLimit {
    /// Tokens added per second of monotonic time.
    pub per_second: u64,
    /// Bucket capacity.
    pub burst: u64,
}

const fn rate(per_second: u64, burst: u64) -> RateLimit {
    RateLimit { per_second, burst }
}

/// REGISTER verification attempts per source IP, before signature or DH work
/// (quick-protocol §5.2.1).
pub const REGISTER_ATTEMPTS_PER_IP: RateLimit = rate(4, 8);
/// REGISTER verification attempts, global (quick-protocol §5.2.1).
pub const REGISTER_ATTEMPTS_GLOBAL: RateLimit = rate(1000, 2000);

/// Concurrent cryptographic work in flight (quick-protocol §5.2.1).
pub const CRYPTO_IN_FLIGHT: usize = 32;
/// Queued cryptographic work (quick-protocol §5.2.1).
pub const CRYPTO_QUEUED: usize = 128;
/// Maximum cryptographic queueing time in seconds (quick-protocol §5.2.1).
pub const CRYPTO_QUEUE_SECONDS: u64 = 1;

/// Provisional registrations, global (quick-protocol §5.2.1).
pub const PROVISIONAL_GLOBAL: usize = 4096;
/// Provisional registrations per source IP (quick-protocol §5.2.1).
pub const PROVISIONAL_PER_IP: usize = 16;
/// Provisional registrations per identity `I` (quick-protocol §5.2.1, quick-v2 §8.5).
pub const PROVISIONAL_PER_IDENTITY: usize = 2;
/// Provisional registrations per WSS connection (quick-protocol §5.2.1).
pub const PROVISIONAL_PER_WSS: usize = 8;

/// Active slots, global; never evicted to admit a new identity (quick-protocol §5.2.1).
pub const ACTIVE_SLOTS_GLOBAL: usize = 10_000;
/// Active slots per WSS connection (quick-protocol §5.2.1).
pub const ACTIVE_SLOTS_PER_WSS: usize = 8;

/// Retained mark entries, one per distinct `I` (quick-protocol §5.2.1, quick-v2 §8.5).
pub const RETAINED_MARK_ENTRIES: usize = 1_000_000;
/// Maximum encoded logical mark data in bytes (quick-protocol §5.2.1).
pub const RETAINED_MARK_BYTES: u64 = 512 * MIB;
/// Mark store disk budget in bytes, journal and compaction headroom included
/// (quick-protocol §5.2.1).
pub const MARK_STORE_DISK_BYTES: u64 = 4 * GIB;

/// WSS connections, global (quick-protocol §5.2.1).
pub const WSS_CONNECTIONS_GLOBAL: usize = 2048;
/// WSS connections per source IP (quick-protocol §5.2.1).
pub const WSS_CONNECTIONS_PER_IP: usize = 16;
/// Concurrent WSS connections without a confirmed registration (quick-protocol §5.2.1).
pub const WSS_UNCONFIRMED_CONNECTIONS: usize = 256;

/// New TLS / WSS handshakes per source IP (quick-protocol §5.2.1).
pub const WSS_HANDSHAKES_PER_IP: RateLimit = rate(2, 4);
/// New TLS / WSS handshakes, global (quick-protocol §5.2.1).
pub const WSS_HANDSHAKES_GLOBAL: RateLimit = rate(100, 200);

/// Node control packets per sender (quick-protocol §5.2.1).
pub const CONTROL_PACKETS_PER_SENDER: RateLimit = rate(16, 32);
/// Node control bytes per sender (quick-protocol §5.2.1).
pub const CONTROL_BYTES_PER_SENDER: RateLimit = rate(32 * KIB, 64 * KIB);
/// Node control packets, global (quick-protocol §5.2.1).
pub const CONTROL_PACKETS_GLOBAL: RateLimit = rate(20_000, 40_000);
/// Node control bytes, global (quick-protocol §5.2.1).
pub const CONTROL_BYTES_GLOBAL: RateLimit = rate(32 * MIB, 64 * MIB);

/// Forwarded DATA packets, each of sender and destination (quick-protocol §5.2.1).
pub const DATA_PACKETS_PER_NODE: RateLimit = rate(2000, 4000);
/// Forwarded DATA bytes, each of sender and destination (quick-protocol §5.2.1).
pub const DATA_BYTES_PER_NODE: RateLimit = rate(2 * MIB, 4 * MIB);
/// Forwarded DATA packets, global (quick-protocol §5.2.1).
pub const DATA_PACKETS_GLOBAL: RateLimit = rate(100_000, 200_000);
/// Forwarded DATA bytes, global (quick-protocol §5.2.1).
pub const DATA_BYTES_GLOBAL: RateLimit = rate(128 * MIB, 256 * MIB);
/// Handshake-initiation DATA packets per destination, also counted in every DATA bucket
/// (quick-protocol §5.2.1, quick-v2 §8.4).
pub const HANDSHAKE_INITIATIONS_PER_DESTINATION: RateLimit = rate(20, 40);

/// Reply packets (STATUS and REGISTERED included) per source IP (quick-protocol §5.2.1).
pub const REPLY_PACKETS_PER_IP: RateLimit = rate(16, 32);
/// Reply bytes per source IP (quick-protocol §5.2.1).
pub const REPLY_BYTES_PER_IP: RateLimit = rate(32 * KIB, 64 * KIB);
/// Reply packets, global (quick-protocol §5.2.1).
pub const REPLY_PACKETS_GLOBAL: RateLimit = rate(20_000, 40_000);
/// Reply bytes, global (quick-protocol §5.2.1).
pub const REPLY_BYTES_GLOBAL: RateLimit = rate(32 * MIB, 64 * MIB);

/// Queued output packets per committed destination session (quick-protocol §5.2.1).
pub const QUEUED_PACKETS_PER_SESSION: usize = 64;
/// Queued output bytes per committed destination session (quick-protocol §5.2.1).
pub const QUEUED_BYTES_PER_SESSION: u64 = 128 * KIB;
/// Queued output packets, global (quick-protocol §5.2.1).
pub const QUEUED_PACKETS_GLOBAL: usize = 8192;
/// Queued output bytes, global (quick-protocol §5.2.1).
pub const QUEUED_BYTES_GLOBAL: u64 = 16 * MIB;
/// Maximum output queueing time in seconds (quick-protocol §5.2.1).
pub const QUEUED_OUTPUT_SECONDS: u64 = 1;

/// Total WSS inbound framing buffers across connections in bytes; each connection
/// frames one message of at most 2048 bytes, 1200 for known control types
/// (quick-protocol §5.2.1).
pub const WSS_FRAMING_GLOBAL_BYTES: u64 = 4 * MIB;

/// Pre-authentication rate-limit table entries (source IPs); unseen sources are
/// refused when full (quick-protocol §5.2.1).
pub const PREAUTH_TABLE_ENTRIES: usize = 65_536;
/// Idle retention of a pre-authentication table entry in seconds (quick-protocol §5.2.1).
pub const PREAUTH_IDLE_SECONDS: u64 = 120;
