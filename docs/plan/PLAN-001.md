# PLAN-001 Proxy OTel path label

- **status**: completed
- **createdAt**: 2026-06-13 00:00
- **approvedAt**: 2026-06-13 11:36
- **relatedTask**: OBS-001

## Context

`crates/telemetry/src/labels.rs` already defines `LABEL_PATH` and
`Path::{Tun, Userspace, Wss}` with stable string values `tun`, `userspace`, and
`wss`.

`crates/telemetry/src/proxy_otel.rs` currently emits:

- `nsn_proxy_bytes_total{service, protocol, direction}`
- `nsn_proxy_active_connections{service, protocol}`
- `nsn_proxy_connections_total{service, protocol}`
- `nsn_proxy_results_total{service, protocol, result}`
- `nsn_proxy_upstream_timeouts_total{service, protocol}`
- `nsn_proxy_connect_duration_seconds{service, protocol, result}`

The sibling `ns` workspace has already wired UserSpace proxy relay metrics, and
`tunnel-ws` in this workspace has already wired WSS relay metrics. Without the
`path` label, dashboards cannot distinguish UserSpace relay traffic from WSS
relay traffic.

TUN traffic is not represented by a proxy relay loop in the current code path;
it is handled by TUN/NAT/tunnel metrics. `Path::Tun` remains part of the bounded
label vocabulary for future proxy-surface call sites, but this change should
not invent TUN proxy samples.

## Proposal

Update `crates/telemetry/src/proxy_otel.rs`:

- Import `LABEL_PATH` and `Path`.
- Add a `path: Path` parameter to `record_bytes`, `inc_active`, `dec_active`,
  `record_result`, `record_connect_duration`, and `record_upstream_timeout`.
- Add `KeyValue::new(LABEL_PATH, path.as_str())` to every proxy metric label
  set.
- Update module docs and tests to include the `path` dimension.

Update `crates/tunnel-ws/src/lib.rs`:

- Store `Path::Wss` in the WSS relay telemetry guard.
- Pass `Path::Wss` from TCP/UDP byte helpers, denial/error accounting, connect
  duration recording, active gauge updates, and upstream timeout accounting.
- Extend the existing WSS proxy metric tests to assert `path="wss"`.

Coordinate the sibling `ns` workspace:

- Update `crates/nsn/src/main.rs` UserSpace proxy relay calls to pass
  `Path::Userspace`.
- Extend `ns` proxy metric tests and `docs/observability.md` accordingly.

## Risks

- This is a breaking Rust API change for every local consumer of
  `telemetry::proxy_otel`. The sibling `ns` workspace must be migrated in the
  same window.
- Prometheus time-series cardinality increases by one bounded 3-value label.
  Existing dashboards that query without `path` continue to work; dashboards
  that match exact label sets may need adjustment.
- Denied branches currently record `service=""`; those should keep their
  existing semantics and add only `path`.

## Scope

In this repository: `crates/telemetry/src/proxy_otel.rs`,
`crates/tunnel-ws/src/lib.rs`, and focused tests.

In the sibling `ns` repository: `crates/nsn/src/main.rs`,
`docs/observability.md`, PMA tracking files, and focused tests.

## Alternatives

Use separate metric names for UserSpace and WSS traffic. Rejected because the
existing observability design intentionally keeps one proxy metric family and
uses bounded labels for slicing.

Add `path` only to byte counters. Rejected because active connections,
connection totals, results, timeouts, and connect latency need the same
dimension to explain traffic movement and failures consistently.

## Annotations

- 2026-06-13 00:00: Investigation complete; awaiting approval before code
  changes.
- 2026-06-13 11:36: Approved by coordinator; implementation started.
- 2026-06-13 11:42: Implementation completed. Verification:
  `cargo build` and `cargo nextest run` both passed in this workspace; logs are
  `tmp/proxy-otel-path-cargo-build.log` and
  `tmp/proxy-otel-path-cargo-nextest.log`.
