# EDGE-004 Add public edge upstream TLS policy contract

- **status**: completed
- **priority**: P0
- **owner**: implementation
- **createdAt**: 2026-07-01 15:29

## Description

Add the shared public-edge upstream TLS re-encryption wire contract for HTTPS
NSN-backed backends. The contract must remain backward-compatible when older
payloads omit the new field.

Acceptance criteria:

- `GatewayHttpRoute` carries optional upstream TLS policy metadata.
- The new gateway capability scope is defined in the shared constants.
- Serde compatibility tests cover old payloads without `upstream_tls`.

## ActiveForm

Completed the public-edge upstream TLS shared wire contract.

## Dependencies

- **blocked by**: #241 approval
- **blocks**: NSD projection and NSGW runtime support

## Notes

- Implementation branch: `feat/public-edge-upstream-tls-blite`.
- Verification passed with `just qa`.
