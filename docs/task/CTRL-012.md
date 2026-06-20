# CTRL-012 Add nsd_default_mode primary-by-transport selector

- **status**: completed
- **priority**: P2
- **owner**: sc
- **createdAt**: 2026-06-20

## Description

Slice S5a of PLAN-009. Add the explicit `nsd_default_mode` selector (ratified
amendment A2): an optional scheme-preference that reorders the effective control
endpoint sequence before the ordered fallback, naming the primary endpoint by
transport independent of list order. Re-adds the user-requested selector that
S1 had dropped in favour of `priority`.

Acceptance criteria:

- `common::ConnectorConfig.nsd_default_mode: Option<String>` (sse/noise/quic),
  `#[serde(default, skip_serializing_if)]`.
- `control::order_endpoints_by_default_mode<T>(items, default_mode, url_of)`:
  stably moves the FIRST endpoint whose URL scheme maps to the mode to the front
  (noise://→noise, quic://→quic, http(s)://|scheme-less→sse). `None` / no match /
  already-primary leave the order unchanged (byte-for-byte back-compat). pub, so
  nsgw (S5b) + ns (S5c) reuse it.
- Wired into `ControlPlane` endpoint selection so nsc/nsn get it via the shared
  `ControlPlane` path.
- Unit tests: first-scheme-match-as-primary, unset→first, no-match→first, stable
  remainder, already-primary no-op, scheme-less→sse, generic-over-T accessor.

## ActiveForm

Adding the nsd_default_mode primary-by-transport selector to ns-shared control.

## Dependencies

- **blocked by**: CTRL-011 (S1 ordered fallback)
- **blocks**: nsgw nsd_default_mode wiring (S5b), ns nsd_default_mode wiring (S5c)

## Notes

- 2026-06-20: Landed on `feat/control-fallback` as `dcfac46` (3 files, +287/-3).
  QA green (SC-verified): cargo fmt --check, cargo build, clippy --all-targets
  -- -D warnings, cargo nextest run -p control -p common = 373 passed (11 new
  order_endpoints_tests + nsd_default_mode_reorders_effective_sequence). Aligns
  with PLAN-009 ratified amendment A2.
