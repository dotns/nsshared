# PLAN-009 Multi-endpoint control-transport fallback

- **status**: implementing
- **priority**: P2
- **owner**: coordinator
- **createdAt**: 2026-06-20
- **approvedAt**: 2026-06-20
- **relatedTask**: CTRL-011 ns-shared (S1, 522cce1) / CTRL-011 nsgw (S2, 3072a30) / CTRL-013 ns (S3, 5777dcb) / integration (S4)

## Context

The NSD control transport is selected by a single `control_mode`
(sse/noise/quic) over a single `nsd_url` endpoint. `ns-shared/crates/control`
builds exactly one transport (`lib.rs` `match config.control_mode`) — there is
no fallback. If the chosen transport is blocked or its endpoint is down, the
dial-out side (nsgw / nsc / nsn) cannot reach NSD at all.

Goal: configure an ordered list of control endpoints and try them in priority
order, falling back to the next on failure (e.g. `noise` blocked → `quic` →
`sse`), for resilience. CTRL-010 (shipped) already makes each URL's scheme
authoritative for its transport, so a single list can mix transports.

nsd is unaffected — it is the server (accepts connections), not a dialer.

## Decisions (settled)

> ⚠ **Superseded in part during S1 — see "Decisions — ratified amendments
> (2026-06-20)" below.** §1 (schema) and §2 (selector) changed: the ordered list
> reuses `common` `control_centers` + `priority`; the user-facing CLI/env surface
> in "Config syntax" below did **not** change. §3 (sticky) stands as written.

1. **Schema: list** — `nsd_urls: Vec<String>` (not "primary + fallbacks").
2. **Default selector** — `nsd_default_mode: Option<ControlMode>` names the
   primary endpoint by transport; if unset, the **first** list entry is primary.
3. **Sticky** — once connected, stay until disconnect; no automatic fail-back
   while connected. On disconnect, reconnect re-runs the sequence from the
   primary (so a recovered primary is preferred again without a periodic timer).
   Periodic primary re-check while connected is **deferred**.

## Design

### Config (ns-shared control `Config`, mirrored in nsgw / ns)

- `nsd_urls: Vec<String>` — ordered control endpoints. Each URL's scheme selects
  its transport (`noise://`/`quic://`/`http(s)://`), per CTRL-010 generalized
  per-endpoint.
- `nsd_default_mode: Option<ControlMode>` — optional primary selector by
  transport. Unset → `nsd_urls[0]`.
- **Back-compat**: keep `nsd_url` (single). Effective list =
  `nsd_urls` if non-empty, else `[nsd_url]`. Existing single-URL configs and the
  CTRL/SLIM-009 CLI flags keep working unchanged.
- Per-endpoint bootstrap keys (`noise_bootstrap_pubkey`,
  `quic_bootstrap_cert_sha256`) are already independent fields and may coexist;
  each transport reads its own. `nsd_envelope_key_pins` is shared.

### Config syntax (mirrors the existing `nsd_envelope_key_pins` Vec field)

- **TOML**: `nsd_urls = ["noise://…:4001", "quic://…:4002", "https://…:443"]`
  (native array; order = priority) + `nsd_default_mode = "noise"`.
- **Env**: `NSGW_NSD_URLS=["noise://…","quic://…","https://…"]` (JSON-array
  string, as `NSGW_NSD_ENVELOPE_KEY_PINS` already is) + `NSGW_NSD_DEFAULT_MODE=noise`.
- **CLI**: `--nsd-url` becomes repeatable (`--nsd-url … --nsd-url …`; order =
  priority) + `--nsd-default-mode noise`. A single `--nsd-url` / `nsd_url` still
  works (one-element list).

### Fallback sequence

`sequence = [primary] ++ [remaining endpoints in list order]`, where `primary`
is the first URL whose scheme matches `nsd_default_mode` (or `nsd_urls[0]` when
unset / no match).

### Bootstrap (ns-shared control)

Replace the single `match control_mode → build one transport` with an ordered
attempt loop:

1. For each endpoint in `sequence`: derive transport from scheme, attempt
   connect + boot handshake/register within a per-endpoint timeout.
2. First success → use it (sticky). Failure (connect timeout / handshake reject
   / register fail) → advance to the next endpoint.
3. All endpoints fail → the existing boot-retry backoff wraps the whole
   sequence and retries from the primary.
4. On a live-connection drop, reconnect re-enters at step 1 (primary first).

`nsd_endpoint_attempt_timeout` (new, default ~8s) bounds each attempt.

## Scope / Slices (same-window cascade — ns-shared change breaks nsgw/ns compile)

| Slice | Repo | Work | Engine |
|---|---|---|---|
| S1 | ns-shared | `nsd_urls` + `nsd_default_mode` schema (back-compat with `nsd_url`) + ordered fallback bootstrap loop (sticky, per-endpoint timeout) + unit tests (ordering, default_mode selection, fallback-on-failure, single-url back-compat) | **codex** (connection lifecycle / ordering / retry) |
| S2 | nsgw | adopt list config; `--nsd-url` → repeatable + `--nsd-default-mode`; wire effective list into the bootstrap call; keep single-URL CLI working | claude-code |
| S3 | ns (nsc/nsn) | adopt list config + wiring | claude-code |
| S4 | integration | real-binary netns E2E: endpoints `[noise(primary), sse]`, block noise → verify fallback to sse + register; unblock → reconnect lands on noise | codex (review) |

## Blast radius

ns-shared `control` (Config schema + bootstrap) + nsgw config + ns config
(nsc/nsn). The schema change breaks nsgw/ns compile the instant it lands →
S1+S2+S3 land in one window. nsd untouched.

## Risks

- **Schema break across the workspace** — the `Config` field add/rename must be
  back-compatible (keep `nsd_url`) and land same-window with consumers.
- **Sticky vs reconnect re-evaluation** — must not thrash: a flapping primary
  should not cause connect/disconnect loops. Per-endpoint timeout + the existing
  backoff cover this; verify in S4.
- **Per-endpoint identity** — each endpoint advertises/uses its own transport
  keys; envelope-pin trust is shared. Ensure register/heartbeat re-bind cleanly
  when the active endpoint changes.

## Decisions — ratified amendments (2026-06-20, M)

Ratified after S1's investigation. These supersede "Decisions (settled)" §1–2 and
the "Config" schema where they conflict; the internal schema changed, the
user-facing surface did not.

- **A1 — reuse `common` `control_centers`, not a new `nsd_urls`.** The ordered
  endpoint list IS `ConnectorConfig.control_centers: Vec<ControlCenterConfig>`
  (already present + tested via `effective_control_centers()`). Rationale:
  `ControlCenterConfig` already carries per-endpoint `noise_bootstrap_pubkey` /
  `quic_bootstrap_cert_sha256` / `nsd_envelope_key_pins` / `realm` / `priority`;
  a flat `Vec<String>` cannot, and would add a second overlapping multi-endpoint
  schema to `common`. Back-compat: a single `server_url` synthesizes a
  one-element list.
- **A2 — primary selector is `priority` (lower = primary), not transport-mode.**
  Declared order with default priorities ⇒ first entry primary. `nsd_default_mode`
  is **retained** but as an *optional* scheme-preference reorder applied before
  the fallback sequence (`control::order_endpoints_by_default_mode`, stable;
  `None` = priority/list order authoritative = byte-for-byte back-compat) — not
  as the primary selector. (S5.)
- **A3 — one additive field** `nsd_endpoint_attempt_timeout_secs: u64 = 8` bounds
  each connect/register attempt only; a live stream outlives it.
- **A4 — user-facing surface unchanged.** `--nsd-url` (repeatable) / `nsd_urls`
  (env) / `--nsd-default-mode` remain; consumers translate them into
  `control_centers` (generated ids, declared-order priorities) via
  `connector::control_centers_from_urls`.
- **A5 — per-consumer strategy is intentionally split.** nsc & nsgw use S1
  **sequential** fallback (single live connection, ordered failover); **nsn keeps
  simultaneous multi-home** (`control::multi::MultiControlPlane`) — strictly more
  resilient for nsn, so sequential fallback is **not** added to nsn. Both consume
  the same ordered `control_centers` list.

## Known limitations / follow-ups (NOT in PLAN-009 scope)

- **nsgw distinct-host fallback** — `bootstrap_control_transport_fallback` returns
  `(NsdInfo, transport)`, not the winning endpoint, so nsgw's stateless re-dial
  assumes a single front door (endpoints share host:port, differ by scheme). True
  distinct-host failover needs S1 to return the winner + nsgw to stick to it. nsc
  (`ControlPlane`) already sticks to the winner. → separate follow-up task.
- **nsc cold-registration while primary blocked** — first-run REGISTER uses
  `primary_nsd_url` (primary-only) before `ControlPlane`, so a cold node whose
  primary is down cannot register via fallback. S1 fallback covers a *registered*
  node's auth / services_report / config_stream (PLAN-009's core property). Cold
  registration over the fallback list is a separate nsc-bootstrap follow-up.

## Deferred

- Periodic primary re-check while connected (auto-fail-back).
- Health scoring / weighted selection (sequence is static priority only).
