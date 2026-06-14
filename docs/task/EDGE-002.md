# EDGE-002 Define gateway certificate distribution contract

- **status**: completed
- **priority**: P0
- **owner**: p071-s1-gateway-certificate-contract
- **createdAt**: 2026-06-14 05:19

## Description

Define the shared certificate distribution contract for nsgw PLAN-071 slice 1
and adapt the same-window `nsd` and `nsgw` consumers so the three feat/envoy
worktrees compile against the breaking shared-crate change.

Acceptance criteria:

- `control` exposes a secret-bearing `gateway_certificate_bundle.v1`
  `ControlMessage` variant that is separate from the key-free
  `GatewayHttpConfig` / `GatewayL4Map` policy snapshots.
- `PublicEdgeCertificatePolicy` carries a `challenge_preference` with a
  backwards-compatible default.
- Shared non-secret certificate status / gateway ACK shapes exist for NSD
  status exposure and later gateway activation acknowledgement.
- Serde tests cover the bundle, challenge preference, status shape, and
  key-free policy snapshots never serializing private key material.
- `nsd` and `nsgw` compile with TODO markers for the later store/push/ACK and
  SDS consumption slices.
- `PATH="$HOME/.cargo/bin:$PATH" just qa` passes in `ns-shared`, `nsd`, and
  `nsgw`, or any blocker is recorded with evidence.

## ActiveForm

Defining the secret-bearing gateway certificate distribution contract and
same-window compile cascade.

## Dependencies

- **blocked by**: nsgw PLAN-071 trust model
- **blocks**: nsgw PLAN-071 S3 certificate store/push and S4 gateway SDS
  consumption

## Notes

- 2026-06-14 05:19: Created from the PLAN-071 S1 assignment after reading
  `../nsgw/docs/plan/PLAN-071.md`. Proposal is recorded in
  `docs/plan/PLAN-003.md` before crate code edits.
- 2026-06-14 05:19: Claimed for implementation after the user explicitly
  requested proposal-first followed by implementation in the same window.
- 2026-06-14 05:40: Completed the shared certificate bundle contract,
  challenge preference, non-secret certificate status/ACK shape, same-window
  `nsd` and `nsgw` compile cascade, focused contract tests, adversarial grep,
  and `just qa` verification in all three worktrees.
