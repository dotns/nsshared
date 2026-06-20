# CTRL-014 nsc pre-control discovery + registration over the fallback list

- **status**: todo
- **priority**: P1
- **owner**: unassigned
- **createdAt**: 2026-06-20

## Description

Follow-up to PLAN-009 (ratified amendment / known-limitation, M rulings #3/#5).
**NOT folded into the current PLAN-009 slices** — M decides fold-in-as-S6 vs an
immediate P1 fast-follow at merge-readiness, once the S4 live-drop core property
passes. Severity raised to **P1** (was P3): this is not a rare edge.

nsc `run_daemon` does discover_nsd_info / discover_nsc_info_via_bootstrap over
`primary_nsd_url` (the PRIMARY endpoint ONLY) at startup
[`crates/nsc/src/main.rs:729/762/766`], BEFORE building `control_centers` and
spawning `control.run()` [:1004/:1033] where S1's ordered fallback lives. So a
node that STARTS while its primary transport is blocked/down fails at the
pre-control discovery and never reaches the fallback. This covers BOTH:

- **Registered-restart while primary blocked** (COMMON: deploy / reboot / crash /
  OOM during exactly the outage this feature targets — bricks the node until the
  primary recovers). Empirically proven by the S4 real-binary E2E
  (blocked_run_reached_controlplane=false).
- **Cold first-ever registration** while primary blocked (rarer).

Both share ONE root cause (primary-only pre-control discovery) and ONE fix.
PLAN-009's delivered core property — a RUNNING registered node falling back on a
live control-stream drop — is unaffected (handled inside `control.run()` /
`connect_active_endpoint`); see the S4 live-drop E2E.

Proposed scope (when scheduled):

- Build `control_centers` first, then run the pre-control discovery + first-run
  registration over the ORDERED control_centers list (per-endpoint attempt +
  fallback in priority order), not just `primary_nsd_url`. Reuse the existing
  `connector::control_centers_from_urls` + the per-endpoint discovery so a
  starting node can discover/register over a surviving fallback endpoint.
- This completes PLAN-009's own Bootstrap design intent (the design's "ordered
  attempt loop ... connect + boot handshake/register" applied to the startup
  path, one layer above S1's in-`ControlPlane` fallback).

## Dependencies

- **related**: PLAN-009 (CTRL-011 ordered fallback), ns CTRL-013 (S3), S4 E2E
  (records this as a known_limitation / the live-drop boundary).
