# PLAN-014 Structured framed-WSS tunnel task lifecycle

- **status**: implementing
- **createdAt**: 2026-07-25 12:26
- **approvedAt**: 2026-07-25 12:26
- **relatedTask**: WSS-001

## Context

The independent review of the NS PLAN-122 candidate found that
`tunnel-ws::WsTunnel::run` detached its WebSocket writer and each framed
per-stream relay. Joining the outer NS connector leg therefore did not prove
that an old writer or backend stream had stopped before endpoint replacement,
revocation, or shutdown completed.

## Proposal

Own the writer and all framed relay tasks in one tunnel-local `JoinSet`.
Normal WebSocket termination and cooperative cancellation abort and join the
complete set before `run_until` returns. Dropping a cancelled parent remains a
fail-safe that aborts every child through `JoinSet` ownership.

Keep `run` as the compatibility entry point by delegating to `run_until` with
a pending shutdown future. The NS connector uses the cooperative entry point
and owns that proxy future directly; the existing make-before-break auto-mode
promotion remains the only intentional spawned handoff.

Add a real WebSocket-to-TCP regression proving that cooperative tunnel
shutdown closes an active backend socket before the tunnel runner completes.
The coordinated NS tests cover active-stream revocation, replacement,
join-timeout, and whole-pool shutdown.

## Scope

Only framed `tunnel-ws` task ownership, its additive cooperative-run API,
focused tests, architecture tracking, and the coordinated NS caller are in
scope. No wire frame, endpoint, dependency, control message, NSD, NSGW, opaque
WSS pump, or auto/UDP selection behavior changes.

## Risks

- Serializing relay futures behind frame dispatch would introduce
  head-of-line blocking. Relays remain independently scheduled inside the
  owned task set.
- Cancelling only the parent without joining children would retain the
  original race. Cooperative shutdown must drain the owned task set.
- A writer exit must terminate the tunnel rather than leave a read-only
  session alive.

## Acceptance

- `tunnel-ws` focused tests and strict all-target Clippy pass.
- The exact coordinated NS tree passes connector/NSN focused gates and full
  repository QA.
- Active backend streams close on cooperative revoke and shutdown.
- A fresh independent adversarial review reports P0=0 and P1=0 for the exact
  NS plus ns-shared candidate pair.

## Annotations

- 2026-07-25 12:26: Explicitly approved as the minimal coordinated amendment
  required to close the remaining PLAN-122 lifecycle finding.
