//! Mailbox field ranges and broker limits (rendezvous §5.1-§5.3, §6).
//!
//! Every §6 limit is a relay configuration item; the values here are the production
//! defaults.

/// Minimum mailbox `ttl` in seconds (rendezvous §5.2).
pub const MIN_TTL_SECONDS: u64 = 1;
/// Maximum mailbox `ttl` in seconds; a mailbox never lives longer (rendezvous §5.1-§5.3).
pub const MAX_TTL_SECONDS: u64 = ns_wire::MAX_PAIRING_MAILBOX_TTL_SECONDS;
/// Maximum `recv` `wait_ms` in milliseconds (rendezvous §5.2).
pub const MAX_WAIT_MS: u64 = 20_000;
/// Maximum `intro` length in bytes (rendezvous §5.2, §6).
pub const MAX_INTRO_BYTES: usize = 4096;
/// Maximum `data` length in bytes (rendezvous §5.2, §6).
pub const MAX_DATA_BYTES: usize = 8192;
/// Minimum mailbox `candidates` (rendezvous §5.1).
pub const MIN_CANDIDATES: u8 = 1;
/// Maximum mailbox `candidates`, also the §6 candidates-per-mailbox limit (rendezvous §5.1, §6).
pub const MAX_CANDIDATES: u8 = 4;
/// Number of lookup digits (rendezvous §5.1).
pub const DIGITS_LEN: usize = 8;
/// Mailbox id length in bytes (rendezvous §5.1).
pub const MAILBOX_ID_BYTES: usize = 16;

/// Owner or peer inactivity after which the mailbox is removed, in seconds (rendezvous §5.3).
pub const INACTIVITY_SECONDS: u64 = 180;
/// Interval between expiry and inactivity sweeps, in seconds (rendezvous §5.3).
pub const SWEEP_INTERVAL_SECONDS: u64 = 10;
/// Grace period of the `closing` stage before removal, in seconds (rendezvous §5.3).
pub const CLOSING_GRACE_SECONDS: u64 = 30;

/// Stored mailboxes (rendezvous §6).
pub const MAX_MAILBOXES: usize = 10_000;
/// Live mailboxes per actor (rendezvous §6).
pub const MAX_MAILBOXES_PER_ACTOR: usize = 3;
/// Rejected actors remembered per mailbox (rendezvous §6).
pub const MAX_REJECTED_ACTORS: usize = 16;
/// `reject` of an admitted peer per mailbox; the mailbox closes when reached (rendezvous §5.3, §6).
pub const MAX_PEER_REJECTS: u8 = 3;
/// Unacknowledged messages per direction (rendezvous §6).
pub const MAX_UNACKED_MESSAGES: usize = 16;
/// Unacknowledged message bytes per direction (rendezvous §6).
pub const MAX_UNACKED_BYTES: usize = 64 * 1024;
/// Cumulative messages per mailbox (rendezvous §6).
pub const MAX_MAILBOX_MESSAGES: usize = 256;
/// Cumulative message bytes per mailbox (rendezvous §6).
pub const MAX_MAILBOX_BYTES: usize = 512 * 1024;
/// Queued message bytes across all mailboxes (rendezvous §6).
pub const MAX_QUEUED_BYTES: usize = 64 * 1024 * 1024;
/// Pending `recv` per connection (rendezvous §6).
pub const MAX_PENDING_RECV_PER_CONNECTION: usize = 1;
/// Pending `recv` across all connections (rendezvous §6).
pub const MAX_PENDING_RECV: usize = 4096;
/// JSON message size in bytes, checked before parsing (rendezvous §3, §6).
pub const MAX_MESSAGE_BYTES: usize = 16 * 1024;
/// `lookup` per source IP per minute (rendezvous §6).
pub const LOOKUPS_PER_IP_PER_MINUTE: u32 = 12;
/// `lookup` across all sources per second (rendezvous §6).
pub const LOOKUPS_PER_SECOND: u32 = 100;
/// `open` per source IP per minute (rendezvous §6).
pub const OPENS_PER_IP_PER_MINUTE: u32 = 30;
/// `open` across all sources per second (rendezvous §6).
pub const OPENS_PER_SECOND: u32 = 100;
/// Requests per connection per second; a pending `recv` counts once when sent (rendezvous §6).
pub const REQUESTS_PER_CONNECTION_PER_SECOND: u32 = 10;
