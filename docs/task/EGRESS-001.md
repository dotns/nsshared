# EGRESS-001 Define WG GatewayEgress control contract

- **status**: completed
- **priority**: P0
- **owner**: contract-cascade
- **createdAt**: 2026-06-17 20:00

## Description

Define the additive shared control-plane contract that lets NSD project
WireGuard GatewayEgress pairings and source identity data to NSGW. This task
covers ns-shared contract types and documentation only: no NSD producer, no
NSGW consumer, no nsd-remote work, and no nft, TPROXY, policy-routing, or
runtime behavior. `nsd-remote` is outside the campaign scope.

## ActiveForm

Defined the WG GatewayEgress contract types, control-message variant, design
note, and serialization tests.

## Dependencies

- **blocked by**: approved GatewayEgress WG contract scope
- **blocks**: downstream nsd projection and nsgw consumption

## Notes

Current state:
- `GatewayExitNftConfig` already provides the closest server-to-gateway
  config-stream pattern: additive control-message variant, event label, and
  JSON/CBOR tests.
- `GatewayServicesReport` declares the gateway service floor but does not carry
  selected WireGuard GatewayEgress pairings.
- ACL terminate mode already accepts a verified subject plus
  `SourceAssertion::Terminate { binding: TerminateBinding { anchor } }`, so the
  WG source VIP identity map must carry both the canonical subject and terminate
  anchor.

Proposal:
- Add a `gateway_egress_wg_config.v1` server-to-gateway control message.
- Split the snapshot into `pairings` and `source_identities` so the source VIP
  to subject/anchor mapping is not duplicated for each service port.
- Use existing conventions: `realm_id`/`service_ref` strings, `Ipv4Addr` VIPs,
  `RouteProtocol` for TCP/UDP matches, and `u64` generations.
- Document producer and consumer responsibilities, including fail-closed
  duplicate or stale source VIP handling.

Risks:
- Consumers must enforce uniqueness and generation consistency; the shared type
  is a wire contract and does not install runtime validation policy.

Scope:
- Shared Rust contract types, control-message variant, focused tests, and a
  design note only.

Outcome:
- Added the `gateway_egress_wg_config.v1` control-message contract.
- Split pairings from source identity mappings.
- Documented source VIP identity recovery, producer/consumer responsibilities,
  and compatibility rules.
- Added focused JSON/CBOR round-trip tests.

Verification:
- `just qa` completed successfully.
