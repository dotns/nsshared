//! Relay configuration and limits (quick-v2 §8.3 rule 5, §8.5; quick-protocol §5.2.1).

use nsshared_rendezvous::capability::{self, Capabilities};
use nsshared_wire::{
    ACTIVE_SLOTS_GLOBAL, DATA_BYTES_PER_NODE, DATA_PACKETS_PER_NODE, DEFAULT_PRESENCE_TTL_SECONDS,
    HANDSHAKE_INITIATIONS_PER_DESTINATION, MAX_PRESENCE_TTL_SECONDS, MIN_PRESENCE_TTL_SECONDS,
    PROVISIONAL_PER_IP, RateLimit, RelayId,
};
use std::time::Duration;
use thiserror::Error;

/// Maximum lifetime of a provisional registration (quick-v2 §8.3 rule 2).
pub const PROVISIONAL_LIFETIME: Duration = Duration::from_secs(10);

/// Upper bound of the PRESENCE interval (quick-v2 §8.3 rule 5).
const MAX_PRESENCE_INTERVAL: Duration = Duration::from_secs(25);

/// Simple per-node limits; the global production budgets are out of scope
/// (quick-protocol §5.2.1).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Maximum confirmed sessions; a new identity is refused when full, never evicted.
    pub max_sessions: usize,
    /// Maximum provisional registrations per source IP.
    pub provisional_per_ip: usize,
    /// Forwarded DATA packets per sender.
    pub data_packets: RateLimit,
    /// Forwarded DATA bytes per sender, header included.
    pub data_bytes: RateLimit,
    /// Forwarded WireGuard handshake initiations per destination (quick-v2 §8.4).
    pub handshake_initiations: RateLimit,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_sessions: ACTIVE_SLOTS_GLOBAL,
            provisional_per_ip: PROVISIONAL_PER_IP,
            data_packets: DATA_PACKETS_PER_NODE,
            data_bytes: DATA_BYTES_PER_NODE,
            handshake_initiations: HANDSHAKE_INITIATIONS_PER_DESTINATION,
        }
    }
}

/// The relay configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayConfig {
    /// The published `host:port` identifier nodes sign as REGISTER `relay_name`
    /// (quick-v2 §8.6).
    pub relay_id: RelayId,
    /// The capability tokens of the tentative REGISTERED; default `udp`, `wss`
    /// (quick-v2 §8.2, rendezvous §3.1).
    pub capabilities: Capabilities,
    /// The presence TTL in seconds, 30..=3600; default 90 (quick-v2 §8.3 rule 5).
    pub presence_ttl_s: u32,
    /// Per-node limits.
    pub limits: Limits,
}

/// An invalid [`RelayConfig`].
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ConfigError {
    /// `presence_ttl_s` is outside 30..=3600 (quick-v2 §8.3 rule 5).
    #[error(
        "presence_ttl_s {0} is outside {MIN_PRESENCE_TTL_SECONDS}..={MAX_PRESENCE_TTL_SECONDS}"
    )]
    PresenceTtl(u32),
    /// A limit is zero.
    #[error("relay limits must be non-zero")]
    ZeroLimit,
}

impl RelayConfig {
    /// Returns the defaults for `relay_id`: capabilities `udp`, `wss`, the default
    /// presence TTL and [`Limits::default`].
    #[must_use]
    pub fn new(relay_id: RelayId) -> Self {
        Self {
            relay_id,
            capabilities: Capabilities::new(vec![capability::UDP, capability::WSS])
                .unwrap_or_default(),
            presence_ttl_s: DEFAULT_TTL_S,
            limits: Limits::default(),
        }
    }

    /// Checks the TTL range and that every limit is non-zero.
    ///
    /// # Errors
    ///
    /// [`ConfigError`].
    pub fn validate(&self) -> Result<(), ConfigError> {
        let ttl = u64::from(self.presence_ttl_s);
        if !(MIN_PRESENCE_TTL_SECONDS..=MAX_PRESENCE_TTL_SECONDS).contains(&ttl) {
            return Err(ConfigError::PresenceTtl(self.presence_ttl_s));
        }
        let limits = &self.limits;
        let rates = [
            limits.data_packets,
            limits.data_bytes,
            limits.handshake_initiations,
        ];
        if limits.max_sessions == 0
            || limits.provisional_per_ip == 0
            || rates
                .iter()
                .any(|rate| rate.per_second == 0 || rate.burst == 0)
        {
            return Err(ConfigError::ZeroLimit);
        }
        Ok(())
    }

    /// Returns the presence TTL.
    #[must_use]
    pub fn presence_ttl(&self) -> Duration {
        Duration::from_secs(u64::from(self.presence_ttl_s))
    }

    /// Returns the PRESENCE interval `min(TTL / 3, 25 s)`, which also spaces accepted
    /// REFLECTs (quick-v2 §8.3 rules 5 and 7).
    #[must_use]
    pub fn presence_interval(&self) -> Duration {
        (self.presence_ttl() / 3).min(MAX_PRESENCE_INTERVAL)
    }
}

// DEFAULT_PRESENCE_TTL_SECONDS is 90, well inside u32.
const DEFAULT_TTL_S: u32 = DEFAULT_PRESENCE_TTL_SECONDS as u32;
