# EDGE-001 Define public edge shared contract

- **status**: completed
- **priority**: P0
- **owner**: s1-public-edge-contract
- **createdAt**: 2026-06-13 14:53

## Description

Define the shared public edge contract for Envoy dynamic ingress and coordinate
the same-window compile cascade across the `ns`, `nsd`, and `nsgw` feat/envoy
worktrees.

Acceptance criteria:

- `control` exposes target-state `gateway_http_config` and `gateway_l4_map`
  control messages with HTTP and L4 route contract types.
- `common` advertises the new public edge capability and scope tokens.
- Shared serde tests cover HTTP config round-trip, L4 map round-trip, default
  HTTP route shape, and TCP/UDP L4 route entries.
- `ns`, `nsd`, and `nsgw` compile against the new contract without preserving
  `public_ingress_config.v1` as the source of truth.
- The same-window verification commands pass or any blocker is recorded with
  evidence.

## ActiveForm

Defining the shared public edge control contract and adapting same-window
consumers.

## Dependencies

- **blocked by**: (none)
- **blocks**: nsgw Envoy ADS/runtime slices and nsd public edge synthesis

## Notes

- 2026-06-13 14:53: Claimed from the S1 assignment for the Envoy dynamic public
  ingress campaign. Proposal is recorded in `docs/plan/PLAN-002.md` before any
  crate code edits.
- 2026-06-13 15:49: Completed the shared public edge contract, same-window
  consumer cascade, adversarial enumeration, and full `just qa` verification
  across `ns-shared`, `ns`, `nsd`, and `nsgw`.
