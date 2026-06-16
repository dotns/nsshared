# CAPTURE-004 Define exit-node selection and pairing contracts

- **status**: completed
- **priority**: P0
- **owner**: contract-cascade
- **createdAt**: 2026-06-16 10:42

## Description

Define the S0 shared control-plane contract for exit-node selection and selection-scoped GatewayExit nft pairings. This task covers contract types only: no NSD persistence, no real route projection, no nft rendering behavior, and no NSC route installation.

## ActiveForm

Defined exit-node selection and GatewayExit pairing contract types.

## Dependencies

- **blocked by**: nsgw PLAN-080 S0 scope
- **blocks**: downstream compile adaptation in nsd, nsgw, and ns

## Notes

Current state:
- `ControlEnvelope` already carries a logical `api` string over the existing `call()` path, so a selection API needs only a new logical API constant and payload structs.
- `ExitScope::DefaultRoute` exists but is documented as reserved.
- `CaptureRoute` carries destination CIDRs, source, table policy, and kill-switch policy, but lacks logical scope, split-default metadata, exclusions, bypass hints, DNS policy, reserved pools, and selection generation.
- `GatewayExitNftConfig` currently exposes per-profile destination and source sets, which lets consumers build source-set x destination-set cartesian authorization.

Proposal:
- Add `client.exit_node_selection.v1` request/response payload types and the matching envelope API constant.
- Promote `ExitScope::DefaultRoute` as a valid advertised capability while preserving old consumers that ignore it.
- Extend `CaptureRoute` additively with optional S0 default fields for logical scope, split-default CIDRs, exclusions, endpoint bypass hints, DNS policy, configured reserved pools, IPv6 fail-closed metadata, and selection generation.
- Replace the GatewayExit nft payload shape with selection-scoped pairings that preserve source `/32`, destination CIDRs, exclusions, realm id, gateway id, profile ref, and selection generation.
- Add focused serde/CBOR tests for selection payloads, default-route scope, pairing shape, and empty `RoutingConfig` compatibility.

Risks:
- Adding required `CaptureRoute` fields would break older stored test payloads; use serde defaults for additive fields.
- Replacing the nft config shape forces all downstream consumers to adapt in the same window.

Scope:
- Shared Rust contract types and tests only.
- No DB schema, NSD handler, projection behavior, nft rendering behavior, or route install behavior.
- The issue prompt pre-authorized implementation after this proposal.

Outcome:
- Added the signed selection API payload contract for `client.exit_node_selection.v1`.
- Promoted `ExitScope::DefaultRoute` to an advertised capability and extended `CaptureRoute` with S0 selection metadata.
- Replaced the GatewayExit nft payload with selection-scoped source-to-destination pairings.
- Added focused CBOR/serde contract tests.

Verification:
- `just qa` completed with `/tmp/s0-ns-shared.DONE_0`.
