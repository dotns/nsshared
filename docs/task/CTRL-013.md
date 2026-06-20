# CTRL-013 Distinct-host control-transport fallback (return winning endpoint)

- **status**: completed
- **priority**: P3
- **owner**: s7
- **createdAt**: 2026-06-20

## Description

Follow-up to PLAN-009 (ratified amendment / known-limitation, M ruling #4).
**FOLDED into PLAN-009 as S7** (P3) per M/the user; codex proposal-first, in progress.

`control::bootstrap::bootstrap_control_transport_fallback` currently returns only
`(NsdInfo, Arc<dyn ControlTransport>)`, not the winning `ControlCenterConfig`.
nsgw's transports are stateless and re-dial `control_endpoint` (= the primary
host:port) per call, so nsgw fallback only works for the "single front door,
multiple transports" model (endpoints share host:port, differ by scheme). True
distinct-host failover (primary host down, fall back to a different host) does
not work for nsgw. nsc (`ControlPlane`) already sticks to the winning endpoint's
transport, so nsc is unaffected.

Proposed scope (when scheduled):

- Extend `bootstrap_control_transport_fallback` to also return the winning
  `ControlCenterConfig` (or its endpoint URL).
- Make nsgw stick to the winning endpoint for subsequent control calls instead
  of re-dialing the configured primary host:port.
- Document the same-host assumption in nsgw config docs so the current limit is
  not silent (interim).

## Dependencies

- **related**: PLAN-009 (CTRL-011 ordered fallback), nsgw CTRL-011 (S2).
