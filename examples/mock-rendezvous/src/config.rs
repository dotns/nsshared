//! Broker limits and mock configuration (rendezvous §6; quick-v2 §7.4).
//!
//! Every §6 and §7.4 limit is a relay configuration item; [`Limits::default`] takes the
//! production defaults from `nsshared_rendezvous::limits` and
//! `nsshared_rendezvous::registry`.
//!
//! The broker owns, and enforces at the configured value: stored mailboxes, mailboxes
//! per actor, global queued bytes, pending `recv`, message bytes, every rate limit and
//! registry records. The per-mailbox limits (candidates, rejected actors, peer rejects,
//! `intro` / `data` bytes, unacknowledged messages and bytes per direction, cumulative
//! messages and bytes per mailbox) are fixed by the `nsshared_rendezvous::phase` rules
//! and the message decoders: those fields only report the library values, and changing
//! them has no effect.

use nsshared_rendezvous::{limits, registry};

/// Every rendezvous §6 and quick-v2 §7.4 limit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Stored mailboxes (rendezvous §6).
    pub mailboxes: usize,
    /// Live mailboxes per actor (rendezvous §6).
    pub mailboxes_per_actor: usize,
    /// Candidates per mailbox; fixed by the library (rendezvous §6).
    pub candidates: u8,
    /// Rejected actors per mailbox; fixed by the library (rendezvous §6).
    pub rejected_actors: usize,
    /// `reject` of an admitted peer per mailbox; fixed by the library (rendezvous §6).
    pub peer_rejects: u8,
    /// `intro` bytes; fixed by the library (rendezvous §6).
    pub intro_bytes: usize,
    /// `data` bytes; fixed by the library (rendezvous §6).
    pub data_bytes: usize,
    /// Unacknowledged messages per direction; fixed by the library (rendezvous §6).
    pub unacked_messages: usize,
    /// Unacknowledged bytes per direction; fixed by the library (rendezvous §6).
    pub unacked_bytes: usize,
    /// Cumulative messages per mailbox; fixed by the library (rendezvous §6).
    pub mailbox_messages: usize,
    /// Cumulative bytes per mailbox; fixed by the library (rendezvous §6).
    pub mailbox_bytes: usize,
    /// Queued message bytes across all mailboxes (rendezvous §6).
    pub queued_bytes: usize,
    /// Pending `recv` per connection (rendezvous §6).
    pub pending_recv_per_connection: usize,
    /// Pending `recv` across all connections (rendezvous §6).
    pub pending_recv: usize,
    /// JSON message bytes, checked before parsing (rendezvous §3, §6).
    pub message_bytes: usize,
    /// `lookup` per source IP per minute (rendezvous §6).
    pub lookups_per_ip_per_minute: u32,
    /// `lookup` across all sources per second (rendezvous §6).
    pub lookups_per_second: u32,
    /// `open` per source IP per minute (rendezvous §6).
    pub opens_per_ip_per_minute: u32,
    /// `open` across all sources per second (rendezvous §6).
    pub opens_per_second: u32,
    /// Requests per connection per second (rendezvous §6).
    pub requests_per_connection_per_second: u32,
    /// Stored registry records (quick-v2 §7.4).
    pub registry_records: usize,
    /// `publish` per source IP per minute (quick-v2 §7.4).
    pub publishes_per_ip_per_minute: u32,
    /// Minimum interval between `publish` of one identity, in seconds (quick-v2 §7.4).
    pub publish_interval_per_identity_seconds: u64,
    /// `publish` across all sources per second (quick-v2 §7.4).
    pub publishes_per_second: u32,
    /// `lookup_node` per source IP per minute (quick-v2 §7.4).
    pub lookup_nodes_per_ip_per_minute: u32,
    /// `lookup_node` across all sources per second (quick-v2 §7.4).
    pub lookup_nodes_per_second: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            mailboxes: limits::MAX_MAILBOXES,
            mailboxes_per_actor: limits::MAX_MAILBOXES_PER_ACTOR,
            candidates: limits::MAX_CANDIDATES,
            rejected_actors: limits::MAX_REJECTED_ACTORS,
            peer_rejects: limits::MAX_PEER_REJECTS,
            intro_bytes: limits::MAX_INTRO_BYTES,
            data_bytes: limits::MAX_DATA_BYTES,
            unacked_messages: limits::MAX_UNACKED_MESSAGES,
            unacked_bytes: limits::MAX_UNACKED_BYTES,
            mailbox_messages: limits::MAX_MAILBOX_MESSAGES,
            mailbox_bytes: limits::MAX_MAILBOX_BYTES,
            queued_bytes: limits::MAX_QUEUED_BYTES,
            pending_recv_per_connection: limits::MAX_PENDING_RECV_PER_CONNECTION,
            pending_recv: limits::MAX_PENDING_RECV,
            message_bytes: limits::MAX_MESSAGE_BYTES,
            lookups_per_ip_per_minute: limits::LOOKUPS_PER_IP_PER_MINUTE,
            lookups_per_second: limits::LOOKUPS_PER_SECOND,
            opens_per_ip_per_minute: limits::OPENS_PER_IP_PER_MINUTE,
            opens_per_second: limits::OPENS_PER_SECOND,
            requests_per_connection_per_second: limits::REQUESTS_PER_CONNECTION_PER_SECOND,
            registry_records: registry::MAX_RECORDS,
            publishes_per_ip_per_minute: registry::PUBLISHES_PER_IP_PER_MINUTE,
            publish_interval_per_identity_seconds: registry::PUBLISH_INTERVAL_PER_IDENTITY_SECONDS,
            publishes_per_second: registry::PUBLISHES_PER_SECOND,
            lookup_nodes_per_ip_per_minute: registry::LOOKUP_NODES_PER_IP_PER_MINUTE,
            lookup_nodes_per_second: registry::LOOKUP_NODES_PER_SECOND,
        }
    }
}

/// Default number of keys one rate limiter tracks before refusing new keys.
pub const DEFAULT_RATE_KEYS: usize = 65_536;

/// Mock configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Config {
    /// Rendezvous and registry limits.
    pub limits: Limits,
    /// Keys (source IPs, identities) one rate limiter tracks at most; bounds its memory.
    pub rate_keys: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            limits: Limits::default(),
            rate_keys: DEFAULT_RATE_KEYS,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Config, Limits};
    use nsshared_rendezvous::{limits, registry};

    #[test]
    fn defaults_are_the_production_values() {
        let limits = Limits::default();
        assert_eq!(limits.mailboxes, 10_000);
        assert_eq!(limits.mailboxes_per_actor, 3);
        assert_eq!(limits.candidates, 4);
        assert_eq!(limits.rejected_actors, 16);
        assert_eq!(limits.peer_rejects, 3);
        assert_eq!((limits.intro_bytes, limits.data_bytes), (4096, 8192));
        assert_eq!(
            (limits.unacked_messages, limits.unacked_bytes),
            (16, 65_536)
        );
        assert_eq!(
            (limits.mailbox_messages, limits.mailbox_bytes),
            (256, 524_288)
        );
        assert_eq!(limits.queued_bytes, 64 * 1024 * 1024);
        assert_eq!(
            (limits.pending_recv_per_connection, limits.pending_recv),
            (1, 4096)
        );
        assert_eq!(limits.message_bytes, limits::MAX_MESSAGE_BYTES);
        assert_eq!(
            (limits.lookups_per_ip_per_minute, limits.lookups_per_second),
            (12, 100)
        );
        assert_eq!(
            (limits.opens_per_ip_per_minute, limits.opens_per_second),
            (30, 100)
        );
        assert_eq!(limits.requests_per_connection_per_second, 10);
        assert_eq!(limits.registry_records, registry::MAX_RECORDS);
        assert_eq!(limits.publishes_per_ip_per_minute, 12);
        assert_eq!(limits.publish_interval_per_identity_seconds, 60);
        assert_eq!(limits.publishes_per_second, 1000);
        assert_eq!(
            (
                limits.lookup_nodes_per_ip_per_minute,
                limits.lookup_nodes_per_second
            ),
            (60, 5000)
        );
        assert_eq!(Config::default().limits, limits);
    }
}
