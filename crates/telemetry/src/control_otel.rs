//! Global OTel facade for control-plane SSE delivery latency and signed
//! envelope call instrumentation (CTRL-002).
//!
//! - `nsn_sse_delivery_duration_seconds{event_type, result}` — latency from a
//!   decoded SSE control message being received to its downstream dispatch
//!   completing. Taken once per control message, a low-rate event stream.
//! - `control_call_duration_seconds{transport, api, status}` — latency of one
//!   signed-envelope control call (request → verified response, or stream
//!   open). One observation per call.
//! - `control_envelope_replay_rejected_total{transport, api}` — count of calls
//!   the server rejected as replays (HTTP 409 / native replay status), surfaced
//!   on the client as [`crate::labels`]-bounded labels only.
//!
//! Cardinality: `event_type` is a small fixed enum of control-message kinds
//! (`wg_config`, `proxy_config`, `acl_config`, `ping`, …); `result` is one of
//! [`crate::labels::Outcome`]. `transport` ∈ {sse, noise, quic}; `api` is the
//! bounded `ControlEnvelope::api` enum; `status` ∈ {ok, error}. No nonce,
//! token, or thumbprint is ever used as a label.

use std::sync::OnceLock;

use opentelemetry::KeyValue;
use opentelemetry::metrics::{Counter, Histogram};

use crate::labels::{
    LABEL_API, LABEL_EVENT_TYPE, LABEL_RESULT, LABEL_STATUS, LABEL_TRANSPORT, Outcome,
};
use crate::meter::{counter_u64, histogram_seconds, meter};

fn delivery_duration() -> &'static Histogram<f64> {
    static INST: OnceLock<Histogram<f64>> = OnceLock::new();
    INST.get_or_init(|| {
        let m = meter("nsn.control");
        histogram_seconds(
            &m,
            "nsn_sse_delivery_duration_seconds",
            "Latency from SSE control message receipt to dispatch completion",
        )
    })
}

/// Record the latency (seconds) of dispatching one SSE control message.
///
/// `event_type` is a bounded control-message kind string; `outcome` is
/// [`Outcome::Ok`] on successful dispatch, [`Outcome::Error`] when the
/// downstream channel was closed / the dispatch failed.
pub fn record_sse_delivery_duration(event_type: &'static str, outcome: Outcome, secs: f64) {
    delivery_duration().record(
        secs,
        &[
            KeyValue::new(LABEL_EVENT_TYPE, event_type),
            KeyValue::new(LABEL_RESULT, outcome.as_str()),
        ],
    );
}

// ── Signed-envelope control call instrumentation (CTRL-002) ──────────────────

fn call_duration() -> &'static Histogram<f64> {
    static INST: OnceLock<Histogram<f64>> = OnceLock::new();
    INST.get_or_init(|| {
        let m = meter("nsn.control");
        histogram_seconds(
            &m,
            "control_call_duration_seconds",
            "Latency of one signed-envelope control-plane call (request → verified response / stream open)",
        )
    })
}

fn replay_rejected() -> &'static Counter<u64> {
    static INST: OnceLock<Counter<u64>> = OnceLock::new();
    INST.get_or_init(|| {
        let m = meter("nsn.control");
        counter_u64(
            &m,
            "control_envelope_replay_rejected_total",
            "Signed-envelope control calls rejected by the server as replays",
        )
    })
}

/// Record the latency (seconds) of one signed-envelope control call.
///
/// `transport` is the bounded transport name (`"sse"`, `"noise"`, `"quic"`);
/// `api` is the bounded `ControlEnvelope::api` identifier; `status` is `"ok"`
/// on a verified response / opened stream and `"error"` on any failure. All
/// three are `&'static str` drawn from finite enums — never a nonce, token,
/// or key thumbprint.
pub fn record_control_call_duration(
    transport: &'static str,
    api: &'static str,
    status: &'static str,
    secs: f64,
) {
    call_duration().record(
        secs,
        &[
            KeyValue::new(LABEL_TRANSPORT, transport),
            KeyValue::new(LABEL_API, api),
            KeyValue::new(LABEL_STATUS, status),
        ],
    );
}

/// Increment the replay-rejection counter for one control call.
///
/// Called when the server rejected the envelope as a replay (HTTP 409 over
/// SSE, or the native replay status over Noise/QUIC). Labels are bounded
/// `transport` + `api` only.
pub fn record_control_envelope_replay_rejected(transport: &'static str, api: &'static str) {
    replay_rejected().add(
        1,
        &[
            KeyValue::new(LABEL_TRANSPORT, transport),
            KeyValue::new(LABEL_API, api),
        ],
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_sse_delivery_duration_does_not_panic() {
        record_sse_delivery_duration("wg_config", Outcome::Ok, 0.002);
        record_sse_delivery_duration("acl_config", Outcome::Error, 0.01);
    }

    #[test]
    fn record_control_call_metrics_do_not_panic() {
        record_control_call_duration("sse", "machine.heartbeat", "ok", 0.003);
        record_control_call_duration("noise", "machine.register", "error", 0.5);
        record_control_envelope_replay_rejected("quic", "services.report");
    }
}
