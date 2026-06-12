//! Global OTel facade for ServiceRouter resolution latency.
//!
//! - `nsn_service_resolve_duration_seconds{service, result}` — latency of
//!   `ServiceRouter::resolve*`, covering the service lookup, ACL check, and
//!   host (DNS) resolution. Taken once per incoming connection / flow, never
//!   per packet.
//!
//! Cardinality: `service` comes from `services.toml` (tens); `result` is one
//! of [`crate::labels::Outcome`]. The FQID is never used as a label — it is a
//! per-node-identity high-cardinality value; use the bare service name.

use std::sync::OnceLock;

use opentelemetry::KeyValue;
use opentelemetry::metrics::Histogram;

use crate::labels::{LABEL_RESULT, LABEL_SERVICE, Outcome};
use crate::meter::{histogram_seconds, meter};

fn resolve_duration() -> &'static Histogram<f64> {
    static INST: OnceLock<Histogram<f64>> = OnceLock::new();
    INST.get_or_init(|| {
        let m = meter("nsn.nat");
        histogram_seconds(
            &m,
            "nsn_service_resolve_duration_seconds",
            "Latency of ServiceRouter resolution (lookup + ACL + DNS)",
        )
    })
}

/// Record the latency (seconds) of one service-resolution attempt.
///
/// `service` is the bare service name (`""` when no service matched);
/// `outcome` is [`Outcome::Ok`] when a backend address was resolved,
/// [`Outcome::Denied`] when the ACL refused the connection, and
/// [`Outcome::Error`] when lookup / DNS resolution failed.
pub fn record_resolve_duration(service: &str, outcome: Outcome, secs: f64) {
    resolve_duration().record(
        secs,
        &[
            KeyValue::new(LABEL_SERVICE, service.to_owned()),
            KeyValue::new(LABEL_RESULT, outcome.as_str()),
        ],
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_resolve_duration_does_not_panic() {
        record_resolve_duration("web", Outcome::Ok, 0.0003);
        record_resolve_duration("", Outcome::Denied, 0.0001);
        record_resolve_duration("dns", Outcome::Error, 0.5);
    }
}
