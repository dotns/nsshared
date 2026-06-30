# EGRESS-002 Carry GatewayEgress selected owner hint

- **status**: completed
- **priority**: P0
- **owner**: bkd-236-worker
- **createdAt**: 2026-06-30 18:46 UTC

## Description

Add a backward-compatible selected gateway owner hint to the shared
`ServiceBackendKind::GatewayEgress` route backend so NSD can project the same
GatewayEgress owner used by WireGuard routing and NSC can fail closed instead
of dialing the global primary gateway.

Acceptance:

- `GatewayEgress` routes can carry an optional `selected_gateway_id`.
- Old payloads without the field deserialize successfully.
- Payloads with no owner skip the field on serialization.
- All downstream construction sites compile in the same dependency window.

## ActiveForm

Completed the GatewayEgress selected owner wire contract for BKD issue #236.

## Dependencies

- **blocked by**: approved BKD issue #236 design
- **blocks**: NSD owner projection and NSC per-owner WSS selection

## Notes

- 2026-06-30 18:46 UTC: Claimed on branch `feat/gwegress-wss-owner`.
- 2026-06-30 19:10 UTC: Added optional
  `GatewayEgress.selected_gateway_id` with serde back-compat coverage.
- 2026-06-30 19:10 UTC: Verification passed with `just qa`.
