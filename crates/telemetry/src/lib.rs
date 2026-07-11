#![forbid(unsafe_code)]
#![allow(missing_docs)]

//! Telemetry initialisation for NSN.
//!
//! Sets up the OpenTelemetry metrics pipeline backed by a Prometheus exporter.
//! Call [`init_telemetry`] once at startup; the returned [`Registry`] is passed
//! to the monitoring endpoint so it can render `/api/metrics`.
//!
//! Key exports:
//! - [`init_telemetry`] — initialise OTel + Prometheus and return the registry.
//! - [`metrics`] — per-subsystem metric structs (`ProxyMetrics`, etc.).
//! - [`labels`] — label-key constants and value enums (cardinality contract).
//! - [`meter`] — thin wrapper around the global OTel meter / bucket defaults.
//! - [`spawn`] — [`spawn::spawn_supervised`] for long-lived supervised tasks.
//! - [`proxy_otel`] — global OTel facade for proxy-path counters / gauges.
//! - [`tunnel_otel`] — global OTel facade for tunnel-path counters / gauges.
//! - [`acl_otel`] — ACL evaluation latency histogram.
//! - [`nat_otel`] — service-resolution latency histogram.
//! - [`control_otel`] — SSE delivery latency histogram.

pub mod acl_otel;
pub mod control_otel;
pub mod labels;
pub mod meter;
pub mod metrics;
pub mod nat_otel;
pub mod proxy_otel;
pub mod spawn;
pub mod tunnel_otel;

use opentelemetry_sdk::metrics::SdkMeterProvider;
use prometheus::Registry;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("telemetry init error: {0}")]
    Init(String),
}

/// Initialise the OpenTelemetry metrics pipeline with a Prometheus exporter.
///
/// Sets the global OTel meter provider so any crate can obtain a meter via
/// `opentelemetry::global::meter("crate_name")`.  Returns the underlying
/// Prometheus registry so the monitoring endpoint can render it.
pub fn init_telemetry() -> Result<Registry, Error> {
    let registry = Registry::new();
    let exporter = opentelemetry_prometheus::exporter()
        .with_registry(registry.clone())
        .build()
        .map_err(|e| Error::Init(e.to_string()))?;
    let provider = SdkMeterProvider::builder().with_reader(exporter).build();
    opentelemetry::global::set_meter_provider(provider);
    Ok(registry)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_telemetry_returns_registry() {
        let result = init_telemetry();
        assert!(result.is_ok(), "init_telemetry should succeed");
    }
}
