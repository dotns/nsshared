# USAGE-001 Define gateway.usage_report wire contract

- **status**: completed
- **priority**: P1
- **owner**: main session (nsgw PLAN-098 S1)
- **createdAt**: 2026-07-09
- **completedAt**: 2026-07-09

## Description

Add the additive envelope wire contract for the `gateway.usage_report` op
(NSGW → NSD traffic metering for billing, nsgw `docs/plan/PLAN-098.md` §2.2).
Mirrors the `gateway.report` template already in `control`:

- `envelope::api::GATEWAY_USAGE_REPORT = "gateway.usage_report"` (op const).
- `transport::api_label` bounded metric label for the new op.
- `api.rs` payloads: `GatewayUsageReportRequest` (top-level report),
  `UsageRow`, `UsageSubject`, `UsageSubjectKind`, `PathClass`, and
  `GatewayUsageReportResponse { accepted_through_seq }`.

Bytes are the primary billed signal (`rx_bytes` / `tx_bytes`); connection
counts are optional secondary telemetry. `subject` is present only on
subject-attributable paths; `path_class` carries the attribution confidence.
No producer/consumer wiring here — that is S2 (nsd) and S3 (nsgw).

Naming: the request struct follows the crate's `…Request`/`…Response`
convention (`GatewayUsageReportRequest`), consistent with the neighboring
`GatewayReportRequest`; the plan doc used the shorthand `GatewayUsageReport`
and was synced to the concrete name.

## Acceptance

- `GatewayUsageReportRequest` with populated `rows` (subject + telemetry set)
  round-trips through CBOR.
- A legacy row without `subject` / `connections_*` decodes with those fields
  absent (additive `#[serde(default, skip_serializing_if)]`), and an empty
  optional serializes away (no key on the wire).
- `PathClass` / `UsageSubjectKind` serialize as their `snake_case` string
  values.
- Existing control-crate tests stay green; `cargo clippy` clean.

## ActiveForm

Defining gateway.usage_report envelope wire contract

## Dependencies

- **blocks**: nsd PLAN-098 S2 (dispatch/store), nsgw PLAN-098 S3 (emit)
- **plan**: nsgw `docs/plan/PLAN-098.md` (S1)

## Notes

- 2026-07-09: additive-only, no consumers yet; contract defined at source.
