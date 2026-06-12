use std::sync::atomic::{AtomicI64, AtomicU32, AtomicU64, Ordering};

/// Per-resource proxy metrics.
pub struct ProxyMetrics {
    pub resource_id: String,
    pub bytes_tx: AtomicU64,
    pub bytes_rx: AtomicU64,
    pub active_connections: AtomicU32,
    pub total_connections: AtomicU64,
    /// UDP relay loops where the upstream did not reply within budget.
    /// Incremented in `proxy::udp::handle_udp` after a bounded `recv` timeout.
    pub upstream_timeouts: AtomicU64,
}

impl ProxyMetrics {
    /// Create a new `ProxyMetrics` for the given resource.
    pub fn new(resource_id: impl Into<String>) -> Self {
        Self {
            resource_id: resource_id.into(),
            bytes_tx: AtomicU64::new(0),
            bytes_rx: AtomicU64::new(0),
            active_connections: AtomicU32::new(0),
            total_connections: AtomicU64::new(0),
            upstream_timeouts: AtomicU64::new(0),
        }
    }
}

/// Per-tunnel WireGuard metrics.
pub struct TunnelMetrics {
    pub tunnel_id: String,
    pub wg_handshakes: AtomicU64,
    pub wg_rx_bytes: AtomicU64,
    pub wg_tx_bytes: AtomicU64,
    pub last_handshake: AtomicI64,
}

impl TunnelMetrics {
    /// Create a new `TunnelMetrics` for the given tunnel.
    pub fn new(tunnel_id: impl Into<String>) -> Self {
        Self {
            tunnel_id: tunnel_id.into(),
            wg_handshakes: AtomicU64::new(0),
            wg_rx_bytes: AtomicU64::new(0),
            wg_tx_bytes: AtomicU64::new(0),
            last_handshake: AtomicI64::new(0),
        }
    }
}

/// Counters for the reverse-NAT conntrack table (PLAN-019).
///
/// Owned via `Arc` by a [`ConntrackTable`](../nat/conntrack/struct.ConntrackTable.html)
/// and also retained by the monitoring layer so Prometheus can scrape without
/// cloning the table.  All fields are atomic and use `Relaxed` ordering:
/// approximate counts are acceptable for observability, and the hot path
/// (one store per insert / lookup) must stay lock-free.
///
/// Prometheus export keys:
/// - `nat_conntrack_entries` (gauge) — snapshotted at the end of each GC pass.
/// - `nat_conntrack_insertions_total` (counter)
/// - `nat_conntrack_lookups_total{result="hit|miss"}` (counter)
/// - `nat_conntrack_evictions_total{reason="ttl|lru|cap_overflow"}` (counter)
#[derive(Debug, Default)]
pub struct ConntrackMetrics {
    /// Current entry count as of the last GC pass.
    pub entries: AtomicU64,
    /// Successful inserts (distinct from cap-overflow drops).
    pub insertions: AtomicU64,
    /// Lookups that found a matching entry and refreshed its `last_seen`.
    pub lookups_hit: AtomicU64,
    /// Lookups with no matching entry.  Normal for the first packet of any
    /// new flow and for reply packets that miss the TTL window.
    pub lookups_miss: AtomicU64,
    /// Entries removed by the per-protocol TTL sweep.
    pub evictions_ttl: AtomicU64,
    /// Entries removed by the LRU trim after a TTL sweep that left the
    /// table above the configured cap.
    pub evictions_lru: AtomicU64,
    /// Inserts refused on the hot path because the table was already at
    /// or above the 2× cap emergency valve.  Indicates the GC task is
    /// falling behind insertion rate and the cap / interval should be
    /// retuned or the upstream traffic audited.
    pub evictions_cap_overflow: AtomicU64,
}

impl ConntrackMetrics {
    /// Build a zeroed `ConntrackMetrics`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot counters for debug logging or JSON monitor export.
    ///
    /// Returned in `(entries, insertions, hits, misses, ttl, lru, overflow)`
    /// order — no named struct to keep the telemetry crate leaf-light.
    pub fn snapshot(&self) -> (u64, u64, u64, u64, u64, u64, u64) {
        (
            self.entries.load(Ordering::Relaxed),
            self.insertions.load(Ordering::Relaxed),
            self.lookups_hit.load(Ordering::Relaxed),
            self.lookups_miss.load(Ordering::Relaxed),
            self.evictions_ttl.load(Ordering::Relaxed),
            self.evictions_lru.load(Ordering::Relaxed),
            self.evictions_cap_overflow.load(Ordering::Relaxed),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    // ── ProxyMetrics ──────────────────────────────────────────────────────────

    #[test]
    fn proxy_metrics_new_initialises_all_fields_to_zero() {
        let m = ProxyMetrics::new("res-1");
        assert_eq!(m.resource_id, "res-1");
        assert_eq!(m.bytes_tx.load(Ordering::Relaxed), 0);
        assert_eq!(m.bytes_rx.load(Ordering::Relaxed), 0);
        assert_eq!(m.active_connections.load(Ordering::Relaxed), 0);
        assert_eq!(m.total_connections.load(Ordering::Relaxed), 0);
        assert_eq!(m.upstream_timeouts.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn proxy_metrics_bytes_tx_and_rx_increment_correctly() {
        let m = ProxyMetrics::new("res-2");
        m.bytes_tx.fetch_add(100, Ordering::Relaxed);
        m.bytes_rx.fetch_add(200, Ordering::Relaxed);
        assert_eq!(m.bytes_tx.load(Ordering::Relaxed), 100);
        assert_eq!(m.bytes_rx.load(Ordering::Relaxed), 200);
    }

    #[test]
    fn proxy_metrics_active_connections_increments_and_decrements() {
        let m = ProxyMetrics::new("res-3");

        m.active_connections.fetch_add(1, Ordering::Relaxed);
        assert_eq!(m.active_connections.load(Ordering::Relaxed), 1);

        m.active_connections.fetch_add(1, Ordering::Relaxed);
        assert_eq!(m.active_connections.load(Ordering::Relaxed), 2);

        m.active_connections.fetch_sub(1, Ordering::Relaxed);
        assert_eq!(m.active_connections.load(Ordering::Relaxed), 1);

        m.active_connections.fetch_sub(1, Ordering::Relaxed);
        assert_eq!(m.active_connections.load(Ordering::Relaxed), 0);
    }

    // ── TunnelMetrics ─────────────────────────────────────────────────────────

    #[test]
    fn tunnel_metrics_new_initialises_all_fields_to_zero() {
        let m = TunnelMetrics::new("tun-1");
        assert_eq!(m.tunnel_id, "tun-1");
        assert_eq!(m.wg_handshakes.load(Ordering::Relaxed), 0);
        assert_eq!(m.wg_rx_bytes.load(Ordering::Relaxed), 0);
        assert_eq!(m.wg_tx_bytes.load(Ordering::Relaxed), 0);
        assert_eq!(m.last_handshake.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn tunnel_metrics_counters_increment_correctly() {
        let m = TunnelMetrics::new("tun-2");
        m.wg_handshakes.fetch_add(1, Ordering::Relaxed);
        m.wg_rx_bytes.fetch_add(512, Ordering::Relaxed);
        m.wg_tx_bytes.fetch_add(256, Ordering::Relaxed);
        m.last_handshake.store(1_700_000_000, Ordering::Relaxed);

        assert_eq!(m.wg_handshakes.load(Ordering::Relaxed), 1);
        assert_eq!(m.wg_rx_bytes.load(Ordering::Relaxed), 512);
        assert_eq!(m.wg_tx_bytes.load(Ordering::Relaxed), 256);
        assert_eq!(m.last_handshake.load(Ordering::Relaxed), 1_700_000_000);
    }
}
