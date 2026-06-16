# CAPTURE-003 Define GatewayExit gateway nft input contract

- **status**: completed
- **priority**: P0
- **owner**: codex
- **createdAt**: 2026-06-16 03:19

## Description

Define the shared control-plane contract needed by PLAN-079 H3 so NSD can project GatewayExit nft inputs to NSGW.

Acceptance criteria:

- Add an additive gateway-only control message variant for GatewayExit nft input.
- Carry per-profile owned destination CIDRs and authorized source /32 CIDRs.
- Preserve forward compatibility for older consumers through the existing unknown-variant path.

## ActiveForm

Defined the shared GatewayExit gateway nft input contract.

## Dependencies

- **blocked by**: PLAN-079 H3
- **blocks**: nsd projection and nsgw consumption

## Proposal

Add `GatewayExitNftConfig` and `GatewayExitNftProfile` message structs plus a `gateway_exit_config.v1` control-message variant. Keep the field additive and gateway-scoped so existing connector/client projections remain unchanged.

## Notes

- 2026-06-16 03:19 — Existing `CaptureRoute.source` is NSC-facing only; no current shared message sends the same authorized source /32 set to gateways.
- 2026-06-16 04:12 — Added `gateway_exit_config.v1` with per-profile owned CIDRs and authorized source CIDRs. Verification: `cargo test -p control gateway_exit_nft -- --nocapture`; `just qa` via tmux, `/tmp/h3-ns-shared.log` ended with `DONE_0` and `/tmp/h3-ns-shared.DONE_0` exists.
