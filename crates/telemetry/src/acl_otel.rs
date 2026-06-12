//! Global OTel facade for ACL-engine evaluation latency.
//!
//! - `nsn_acl_eval_duration_seconds{protocol, result}` — wall-clock latency of
//!   a single `AclEngine::is_allowed` evaluation. Pure in-memory match, so the
//!   distribution lives entirely in the sub-millisecond buckets under normal
//!   operation.
//!
//! Cardinality: `protocol` is a small fixed enum (`tcp`, `udp`, `both`,
//! `http`, `https`), `result` is `{ok, denied}` (an ACL eval never times out
//! or errors). No source / destination IP is recorded as a label — those are
//! span fields, never metric labels (see [`crate::labels`]).

use std::sync::OnceLock;

use opentelemetry::KeyValue;
use opentelemetry::metrics::Histogram;

use crate::labels::{LABEL_PROTOCOL, LABEL_RESULT, Outcome};
use crate::meter::{histogram_seconds, meter};

fn eval_duration() -> &'static Histogram<f64> {
    static INST: OnceLock<Histogram<f64>> = OnceLock::new();
    INST.get_or_init(|| {
        let m = meter("nsn.acl");
        histogram_seconds(
            &m,
            "nsn_acl_eval_duration_seconds",
            "Latency of a single ACL policy evaluation",
        )
    })
}

/// Record the latency (seconds) of one ACL evaluation.
///
/// `protocol` is the L4/L7 protocol string of the request; `outcome` is
/// [`Outcome::Ok`] when an accept rule matched, [`Outcome::Denied`] otherwise.
pub fn record_eval_duration(protocol: &'static str, outcome: Outcome, secs: f64) {
    eval_duration().record(
        secs,
        &[
            KeyValue::new(LABEL_PROTOCOL, protocol),
            KeyValue::new(LABEL_RESULT, outcome.as_str()),
        ],
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_eval_duration_does_not_panic() {
        record_eval_duration("tcp", Outcome::Ok, 0.00002);
        record_eval_duration("udp", Outcome::Denied, 0.00005);
    }
}
