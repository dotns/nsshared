# PLAN-011 Control-stream stale-policy detection

- **status**: draft
- **createdAt**: 2026-07-03 06:55
- **relatedTask**: CTRL-016, CTRL-017

## Context

The 2026-07-03 control-plane design review
(`nsiod-docs/_design-review-2026-07-03.md`) found that a node cannot detect a
black-holed control connection: the config-stream client never enforces
arrival of the NSD 15s SSE keepalive, so on a half-open path the fail-closed
`FetchFailed` signal never fires and the node honors stale ALLOW rules
indefinitely (finding DR-H3). A companion finding (DR-H4) raises the
cross-repo design question of how stale policy must be bounded end to end.

## Scope

- CTRL-016 — config-stream idle read deadline (45s = 3x the server keepalive)
  plus TCP keepalive on the control socket. ns-shared `control` crate only,
  no wire-format change. Investigation and proposal are recorded in the task
  file; implement-ready once the proposal is accepted.
- CTRL-017 — the DR-H4 stale-policy design decision spanning repos; requires
  explicit approval before any implement phase.

## Risks

- Idle deadlines can cause reconnect churn on lossy links; bounded by the
  existing exponential backoff and the 3x keepalive margin (details in
  CTRL-016).
- The client deadline is coupled to the NSD keepalive interval contract
  (`nsiod-docs/control-plane/02-transport-sse.md`); a server-side interval
  change must revisit the client constant.

## Annotations

- 2026-07-03 06:55: drafted from the design-review findings; CTRL-016
  investigation + proposal recorded and awaiting approval; CTRL-017 tracked
  in parallel.
