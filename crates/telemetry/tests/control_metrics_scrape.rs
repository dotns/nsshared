//! Scrape test for the CTRL-002 control-plane metrics.
//!
//! Asserts that both `control_call_duration_seconds` and
//! `control_envelope_replay_rejected_total` appear in the Prometheus text
//! rendered from the shared registry after the control_otel facades record a
//! sample. This runs in its own integration-test binary so it is the only
//! code touching the global OTel meter provider — the facade `OnceLock`
//! instruments bind to the SDK provider installed by `init_telemetry`.

use prometheus::TextEncoder;
use telemetry::control_otel;

#[test]
fn control_metrics_appear_in_prometheus_scrape() {
    let registry = telemetry::init_telemetry().expect("telemetry init should succeed");

    // Record one of each metric across the bounded label space.
    control_otel::record_control_call_duration("sse", "machine.heartbeat", "ok", 0.004);
    control_otel::record_control_call_duration("noise", "machine.register", "error", 0.25);
    control_otel::record_control_call_duration("quic", "config.stream", "ok", 0.01);
    control_otel::record_control_envelope_replay_rejected("sse", "services.report");

    let text = TextEncoder::new()
        .encode_to_string(&registry.gather())
        .expect("encode prometheus text");

    assert!(
        text.contains("control_call_duration_seconds"),
        "missing control_call_duration_seconds:\n{text}"
    );
    assert!(
        text.contains("control_envelope_replay_rejected_total"),
        "missing control_envelope_replay_rejected_total:\n{text}"
    );

    // Bounded labels must be present; no nonce/token/thumbprint leaks.
    assert!(
        text.contains("transport=\"sse\"") && text.contains("transport=\"noise\""),
        "missing transport labels:\n{text}"
    );
    assert!(
        text.contains("api=\"machine.heartbeat\"") && text.contains("api=\"config.stream\""),
        "missing api labels:\n{text}"
    );
    assert!(
        text.contains("status=\"ok\"") && text.contains("status=\"error\""),
        "missing status labels:\n{text}"
    );
}
