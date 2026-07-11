//! Global metrics for direct-P2P candidate gathering and reporting.

use std::sync::OnceLock;

use opentelemetry::metrics::{Counter, Gauge};

use crate::meter::{counter_u64, meter};

struct Instruments {
    active_candidates: Gauge<u64>,
    confirmed_misses: Counter<u64>,
    age_expirations: Counter<u64>,
    inconclusive_cycles: Counter<u64>,
    empty_reports: Counter<u64>,
}

fn instruments() -> &'static Instruments {
    static INST: OnceLock<Instruments> = OnceLock::new();
    INST.get_or_init(|| {
        let meter = meter("nsn.p2p");
        Instruments {
            active_candidates: meter
                .u64_gauge("nsn_p2p_active_candidates")
                .with_description("Active local direct-P2P candidates")
                .build(),
            confirmed_misses: counter_u64(
                &meter,
                "nsn_p2p_candidate_confirmed_misses_total",
                "Confirmed socket sends that received no reflexive response by cycle close",
            ),
            age_expirations: counter_u64(
                &meter,
                "nsn_p2p_candidate_age_expirations_total",
                "Candidates retired after exceeding their observation-age bound",
            ),
            inconclusive_cycles: counter_u64(
                &meter,
                "nsn_p2p_inconclusive_cycles_total",
                "Gather cycles with a local submission, send, or completion-path failure",
            ),
            empty_reports: counter_u64(
                &meter,
                "nsn_p2p_empty_reports_total",
                "Successfully acknowledged empty candidate replacement reports",
            ),
        }
    })
}

pub fn record_active_candidates(count: usize) {
    instruments()
        .active_candidates
        .record(u64::try_from(count).unwrap_or(u64::MAX), &[]);
}

pub fn record_confirmed_misses(count: usize) {
    instruments()
        .confirmed_misses
        .add(u64::try_from(count).unwrap_or(u64::MAX), &[]);
}

pub fn record_age_expirations(count: usize) {
    instruments()
        .age_expirations
        .add(u64::try_from(count).unwrap_or(u64::MAX), &[]);
}

pub fn record_inconclusive_cycle() {
    instruments().inconclusive_cycles.add(1, &[]);
}

pub fn record_empty_report() {
    instruments().empty_reports.add(1, &[]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p2p_metrics_accept_bounded_values() {
        record_active_candidates(16);
        record_confirmed_misses(2);
        record_age_expirations(1);
        record_inconclusive_cycle();
        record_empty_report();
    }
}
