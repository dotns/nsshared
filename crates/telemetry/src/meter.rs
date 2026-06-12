//! Thin wrapper around the global OpenTelemetry meter.
//!
//! All instrument creation goes through this module so the meter-name
//! vocabulary and the histogram bucket layout are centralised. Callers pass
//! a crate-level scope name (e.g. `"nsn"`, `"proxy"`) which becomes the OTel
//! `instrumentation scope`; Prometheus flattens scopes away, but traces
//! exporters preserve them.
//!
//! # Naming convention
//!
//! - Counters end in `_total` (Prometheus convention).
//! - Gauges are present-tense (`nsn_active_connections`, not `_gauge`).
//! - Histograms end in `_seconds` or `_bytes` (unit-suffixed).
//! - Every instrument name starts with `nsn_`.
//!
//! # Label discipline
//!
//! Only use label keys from [`crate::labels`]. Do not invent new labels in
//! call sites.

use opentelemetry::metrics::{Counter, Histogram, Meter, UpDownCounter};

/// Latency histogram buckets, in **seconds**.
///
/// Chosen to span sub-millisecond local ACL evaluation up to pathological
/// upstream connect timeouts. Keep this list short — each bucket is a
/// separate Prometheus time series per label combo.
pub const LATENCY_BUCKETS_SECONDS: &[f64] =
    &[0.0001, 0.0005, 0.001, 0.005, 0.025, 0.1, 0.5, 2.0, 10.0];

/// Obtain a [`Meter`] scoped to the given crate / subsystem.
///
/// `scope` becomes the OTel instrumentation scope name. Cheap to call
/// repeatedly — the global provider caches meters by scope name.
pub fn meter(scope: &'static str) -> Meter {
    opentelemetry::global::meter(scope)
}

/// Build a monotonic u64 counter with the standard NSN naming convention.
///
/// `name` must end with `_total`.
pub fn counter_u64(meter: &Meter, name: &'static str, description: &'static str) -> Counter<u64> {
    debug_assert!(
        name.ends_with("_total"),
        "counter name {name:?} must end with _total"
    );
    meter
        .u64_counter(name)
        .with_description(description)
        .build()
}

/// Build a bidirectional gauge-like counter (e.g. active connections, active
/// NAT entries) that can be incremented and decremented.
pub fn up_down_counter_i64(
    meter: &Meter,
    name: &'static str,
    description: &'static str,
) -> UpDownCounter<i64> {
    meter
        .i64_up_down_counter(name)
        .with_description(description)
        .build()
}

/// Build an f64 latency histogram with NSN's shared bucket layout.
///
/// `name` should end with `_seconds`. Records values in **seconds**.
pub fn histogram_seconds(
    meter: &Meter,
    name: &'static str,
    description: &'static str,
) -> Histogram<f64> {
    debug_assert!(
        name.ends_with("_seconds"),
        "histogram name {name:?} must end with _seconds"
    );
    meter
        .f64_histogram(name)
        .with_description(description)
        .with_boundaries(LATENCY_BUCKETS_SECONDS.to_vec())
        .with_unit("s")
        .build()
}

/// Build a u64 byte histogram (e.g. frame sizes) with an order-of-magnitude
/// bucket layout suitable for packet / frame payload distributions.
pub fn histogram_bytes(
    meter: &Meter,
    name: &'static str,
    description: &'static str,
) -> Histogram<u64> {
    debug_assert!(
        name.ends_with("_bytes"),
        "histogram name {name:?} must end with _bytes"
    );
    let buckets = vec![
        64.0, 256.0, 1024.0, 4096.0, 16384.0, 65536.0, 262144.0, 1048576.0,
    ];
    meter
        .u64_histogram(name)
        .with_description(description)
        .with_boundaries(buckets)
        .with_unit("By")
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn latency_buckets_are_strictly_increasing() {
        let mut prev = 0.0f64;
        for &b in LATENCY_BUCKETS_SECONDS {
            assert!(b > prev, "bucket {b} is not greater than {prev}");
            prev = b;
        }
    }

    #[test]
    fn latency_buckets_span_expected_range() {
        let first = LATENCY_BUCKETS_SECONDS.first().copied().unwrap();
        let last = LATENCY_BUCKETS_SECONDS.last().copied().unwrap();
        assert!(first <= 0.001, "sub-ms bucket missing: first = {first}");
        assert!(last >= 1.0, "multi-second bucket missing: last = {last}");
    }

    #[test]
    fn meter_returns_a_usable_scope() {
        // Does not assert provider is SDK-backed; global default is a noop
        // meter which is still callable. The assertion here is that the
        // call does not panic and instrument creation works end-to-end.
        let m = meter("telemetry-test");
        let _c = counter_u64(&m, "nsn_test_total", "test counter");
        let _h = histogram_seconds(&m, "nsn_test_latency_seconds", "test histogram");
        let _g = up_down_counter_i64(&m, "nsn_test_gauge", "test gauge");
    }
}
