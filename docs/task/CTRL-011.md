# CTRL-011 Add ordered multi-endpoint control-transport fallback

- **status**: completed
- **priority**: P2
- **owner**: sc
- **createdAt**: 2026-06-20

## Description

Make the dial-out side try an ordered list of NSD control endpoints in
priority order, falling back to the next on failure, sticky once connected,
re-running from the primary on reconnect. Implements slice S1 of PLAN-009 in
`crates/control` (+ the `crates/common` config schema).

Acceptance criteria:

- Reuse `common::ConnectorConfig.control_centers` as the ordered NSD control
  endpoint list (priority-ordered, lowest priority = primary); no new
  `nsd_urls` / `nsd_default_mode` schema is added.
- `server_url` stays the single-endpoint back-compat path via
  `effective_control_centers()`; the legacy single path keeps `control_mode`
  unchanged.
- New `nsd_endpoint_attempt_timeout_secs` (default 8) bounds each endpoint's
  connect/handshake/register attempt only, never the established live stream.
- First success becomes a sticky stream; no reselection or primary re-probe
  while connected. A real disconnect re-runs selection from the primary; when
  all endpoints fail, the existing boot backoff retries the whole sequence.
- Each endpoint rebuilds its own transport, auth/heartbeat clients, and
  JWT/envelope trust so per-endpoint key material and pins do not leak across
  endpoints.
- Unit tests cover ordering/priority, single-URL back-compat, per-endpoint
  identity, all-fail aggregation, per-endpoint timeout advance, established
  stream outliving the timeout, no-thrash stickiness, and reconnect-from-primary.

## ActiveForm

Adding ordered multi-endpoint control-transport fallback to ns-shared control.

## Dependencies

- **blocked by**: PLAN-009 (design)
- **blocks**: nsgw list-config adoption (S2), ns list-config adoption (S3),
  integration real-binary fallback E2E (S4)

## Notes

- 2026-06-20: Proposal-first investigation found the codebase already had an
  unwired `control_centers: Vec<ControlCenterConfig>` (with per-endpoint
  noise/quic bootstrap keys, envelope pins, realm, and `priority`) plus
  `effective_control_centers()`; reused it instead of adding the design's flat
  `nsd_urls` (which cannot carry per-endpoint trust material) and dropped
  `nsd_default_mode` in favour of `priority`. Deviation from PLAN-009's literal
  schema recorded in PLAN-009 and reported to the coordinator mailbox.
- 2026-06-20: Landed on `feat/control-fallback` as `522cce1` (5 files,
  +887/-35). QA green: `cargo build`, `cargo clippy --all-targets -- -D
  warnings`, `cargo nextest run` (full ns-shared workspace 499/499 passed).
