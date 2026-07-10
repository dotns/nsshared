# EDGE-005 Add route-level upstream authority wire contract

- **status**: completed
- **priority**: P0
- **owner**: public-edge workstream
- **createdAt**: 2026-07-10 11:01
- **completedAt**: 2026-07-10 11:42

## Description

Add an optional route-level upstream HTTP authority to `GatewayHttpRoute` while preserving legacy JSON and CBOR payload behavior. The explicit authority is the route-level configuration source for Host rewriting and, when upstream TLS is enabled, the producer derives `PublicEdgeUpstreamTlsPolicy.sni` from the same value.

Acceptance requires explicit round-trip coverage, legacy decoding to `None`, and omission from serialized payloads when absent.

## ActiveForm

Added the route-level upstream authority wire contract.

## Dependencies

- **blocked by**: (none)
- **blocks**: NSD projection and NSGW activation/runtime support

## Notes

- User approved the generic route-level product fix and backward-compatible optional wire shape.
- Red: `cargo test -p control gateway_http_route_upstream_authority_round_trips`
  decoded the missing field as `None` before the contract change.
- Green: `cargo test -p control gateway_http_route_` passed all three focused
  round-trip and legacy cases.
- Full verification: `just qa` passed with 573 tests plus formatting, clippy,
  cargo-deny, cargo-shear, and typos.
