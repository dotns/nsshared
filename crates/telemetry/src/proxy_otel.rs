//! Global OTel facade for proxy-path metrics.
//!
//! The legacy [`crate::metrics::ProxyMetrics`] is per-resource raw atomics,
//! never aggregated across resources and never exported for Prometheus
//! (nothing reads them for external consumption). This module provides a
//! **global, label-aware** replacement:
//!
//! - `nsn_proxy_bytes_total{service, protocol, direction}` — bidirectional
//!   byte count.
//! - `nsn_proxy_active_connections{service, protocol}` — currently open
//!   proxy connections.
//! - `nsn_proxy_connections_total{service, protocol}` — cumulative accepted
//!   connections.
//! - `nsn_proxy_results_total{service, protocol, result}` — per-outcome
//!   terminal count (ok / timeout / error / denied).
//! - `nsn_proxy_upstream_timeouts_total{service, protocol}` — upstream
//!   recv-timeout events.
//!
//! Cardinality: `service` comes from `services.toml` (tens), `protocol` is
//! `{tcp, udp}`, `direction` is `{tx, rx}`, `result` is one of four values
//! from [`crate::labels::Outcome`]. Bounded across all dimensions.
//!
//! Instruments are lazily created behind `OnceLock` — first call wins, all
//! later calls share the same handles.

use std::sync::OnceLock;

use opentelemetry::KeyValue;
use opentelemetry::metrics::{Counter, Histogram, UpDownCounter};

use crate::labels::{LABEL_PROTOCOL, LABEL_RESULT, LABEL_SERVICE, Outcome, Protocol};
use crate::meter::{counter_u64, histogram_seconds, meter, up_down_counter_i64};

/// Direction label value for the bytes counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Tx,
    Rx,
}

impl Direction {
    pub fn as_str(self) -> &'static str {
        match self {
            Direction::Tx => "tx",
            Direction::Rx => "rx",
        }
    }
}

/// `direction` label key (scoped to proxy).
const LABEL_DIRECTION: &str = "direction";

struct Instruments {
    bytes: Counter<u64>,
    active: UpDownCounter<i64>,
    total: Counter<u64>,
    results: Counter<u64>,
    timeouts: Counter<u64>,
    connect_duration: Histogram<f64>,
}

fn instruments() -> &'static Instruments {
    static INST: OnceLock<Instruments> = OnceLock::new();
    INST.get_or_init(|| {
        let m = meter("nsn.proxy");
        Instruments {
            bytes: counter_u64(
                &m,
                "nsn_proxy_bytes_total",
                "Bytes relayed through the proxy path",
            ),
            active: up_down_counter_i64(
                &m,
                "nsn_proxy_active_connections",
                "Currently active proxy connections",
            ),
            total: counter_u64(
                &m,
                "nsn_proxy_connections_total",
                "Total proxy connections accepted",
            ),
            results: counter_u64(
                &m,
                "nsn_proxy_results_total",
                "Proxy connection terminal outcomes",
            ),
            timeouts: counter_u64(
                &m,
                "nsn_proxy_upstream_timeouts_total",
                "Upstream recv timeouts on UDP relays",
            ),
            connect_duration: histogram_seconds(
                &m,
                "nsn_proxy_connect_duration_seconds",
                "Latency from proxy entry to upstream connect outcome",
            ),
        }
    })
}

/// Record `n` bytes in the given direction for a `{service, protocol}` flow.
pub fn record_bytes(service: &str, protocol: Protocol, direction: Direction, n: u64) {
    instruments().bytes.add(
        n,
        &[
            KeyValue::new(LABEL_SERVICE, service.to_owned()),
            KeyValue::new(LABEL_PROTOCOL, protocol.as_str()),
            KeyValue::new(LABEL_DIRECTION, direction.as_str()),
        ],
    );
}

/// Increment the active-connections gauge when a new proxy connection starts.
///
/// Pair with [`dec_active`] on every exit path (including error and cancel).
pub fn inc_active(service: &str, protocol: Protocol) {
    let labels = [
        KeyValue::new(LABEL_SERVICE, service.to_owned()),
        KeyValue::new(LABEL_PROTOCOL, protocol.as_str()),
    ];
    instruments().active.add(1, &labels);
    instruments().total.add(1, &labels);
}

/// Decrement the active-connections gauge when a proxy connection ends.
pub fn dec_active(service: &str, protocol: Protocol) {
    instruments().active.add(
        -1,
        &[
            KeyValue::new(LABEL_SERVICE, service.to_owned()),
            KeyValue::new(LABEL_PROTOCOL, protocol.as_str()),
        ],
    );
}

/// Record the terminal outcome of a proxy flow.
pub fn record_result(service: &str, protocol: Protocol, outcome: Outcome) {
    instruments().results.add(
        1,
        &[
            KeyValue::new(LABEL_SERVICE, service.to_owned()),
            KeyValue::new(LABEL_PROTOCOL, protocol.as_str()),
            KeyValue::new(LABEL_RESULT, outcome.as_str()),
        ],
    );
}

/// Record the latency (seconds) of establishing the upstream connection for a
/// proxy flow, labeled by terminal `outcome`.
///
/// Measures connect/bind latency only — not the duration of the subsequent
/// relay copy. Taken once per connection, so it stays off the per-packet path.
pub fn record_connect_duration(service: &str, protocol: Protocol, outcome: Outcome, secs: f64) {
    instruments().connect_duration.record(
        secs,
        &[
            KeyValue::new(LABEL_SERVICE, service.to_owned()),
            KeyValue::new(LABEL_PROTOCOL, protocol.as_str()),
            KeyValue::new(LABEL_RESULT, outcome.as_str()),
        ],
    );
}

/// Record an upstream recv-timeout on a UDP relay.
pub fn record_upstream_timeout(service: &str, protocol: Protocol) {
    instruments().timeouts.add(
        1,
        &[
            KeyValue::new(LABEL_SERVICE, service.to_owned()),
            KeyValue::new(LABEL_PROTOCOL, protocol.as_str()),
        ],
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direction_round_trips_through_as_str() {
        assert_eq!(Direction::Tx.as_str(), "tx");
        assert_eq!(Direction::Rx.as_str(), "rx");
    }

    #[test]
    fn record_bytes_does_not_panic_on_empty_service() {
        record_bytes("", Protocol::Tcp, Direction::Tx, 0);
    }

    #[test]
    fn inc_and_dec_active_are_symmetric() {
        // Pure API smoke; the noop meter provider is fine — we just assert
        // these calls do not panic or trip the debug_assert on naming.
        inc_active("web", Protocol::Tcp);
        dec_active("web", Protocol::Tcp);
    }

    #[test]
    fn record_result_accepts_all_outcomes() {
        for o in [
            Outcome::Ok,
            Outcome::Denied,
            Outcome::Timeout,
            Outcome::Error,
        ] {
            record_result("web", Protocol::Udp, o);
        }
    }

    #[test]
    fn record_bytes_accepts_both_directions() {
        record_bytes("web", Protocol::Tcp, Direction::Tx, 100);
        record_bytes("web", Protocol::Tcp, Direction::Rx, 200);
    }

    #[test]
    fn record_upstream_timeout_does_not_panic() {
        record_upstream_timeout("dns", Protocol::Udp);
    }

    #[test]
    fn record_connect_duration_accepts_all_outcomes() {
        for o in [
            Outcome::Ok,
            Outcome::Denied,
            Outcome::Timeout,
            Outcome::Error,
        ] {
            record_connect_duration("web", Protocol::Tcp, o, 0.001);
        }
    }
}
