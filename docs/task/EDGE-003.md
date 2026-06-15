# EDGE-003 Define gateway-owned backend contract

- **status**: completed
- **priority**: P0
- **owner**: branch-coordinator
- **createdAt**: 2026-06-15 07:35

## Description

Implement the PLAN-076 S0 shared control contract for gateway-owned backends:
data-carrying `PublicEdgeBackendKind`, separate `ServiceBackendKind` for
`RouteEntry`, `target_vip`, gateway service declaration and exit profile types,
and the `gateway.services_report` control message.

Acceptance:

- `NsnBacked` preserves its existing wire token.
- `GatewayEgress`, `GatewayExit`, and `ExitScope::DefaultRoute` round-trip on
  the wire.
- `RouteEntry` remains backward compatible for legacy payloads.
- S5/S6 runtime behavior remains deferred; this task is contract-only.

## ActiveForm

Defining the gateway-owned backend shared contract.

## Dependencies

- **blocked by**: nsgw PLAN-076
- **blocks**: nsd/nsgw/ns PLAN-076 S0 consumer adaptation

## Notes

- 2026-06-15 07:35: Claimed for PLAN-076 S0 same-window contract cascade.
- 2026-06-15 08:13 UTC: Completed S0 shared contract. Verified with `just qa`.
