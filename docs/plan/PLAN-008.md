# PLAN-008 WG GatewayEgress control contract

- **status**: completed
- **createdAt**: 2026-06-17 20:00
- **approvedAt**: 2026-06-17 20:00
- **completedAt**: 2026-06-17 20:03
- **relatedTask**: EGRESS-001

## Context

`crates/control/src/messages.rs` owns the existing server-to-gateway control
messages. `GatewayExitNftConfig` is the closest precedent: it is a
config-stream-only snapshot with a stable `gateway_exit_config.v1` wire tag,
bounded `event_type()` label, and JSON/CBOR round-trip coverage.

Gateway-owned service declaration lives in `GatewayServicesReport` as the local
floor reported by the gateway. That report advertises `GatewayEgress`
capability through service declarations but does not carry NSD-selected source
VIP to service VIP authorizations.

The ACL crate already models gateway-terminated flows through
`SourceAssertion::Terminate` and `TerminateBinding { anchor }`. Therefore the
GatewayEgress WG contract needs enough identity data for NSGW to recover a
verified subject and terminate-mode source anchor from a cryptokey-authenticated
WireGuard source VIP.

## Proposal

Add `GatewayEgressWgConfig` as a server-to-gateway snapshot with two additive
lists:

- `pairings`: `(realm_id, source_vip, service_vip, protocol, port,
  service_ref, generation)`.
- `source_identities`: `(realm_id, source_vip, subject,
  terminate_binding_anchor, generation)`.

Use `Ipv4Addr` for WG and service VIPs to match existing tunnel/VIP fields,
`RouteProtocol` for concrete TCP/UDP nft matches, strings for realm and service
references, and `u64` for generations.

Add `ControlMessage::GatewayEgressWgConfig` with wire tag
`gateway_egress_wg_config.v1` and an event label with the same token.

## Risks

- The split identity map reduces duplication but requires consumers to join by
  `(realm_id, source_vip)` and fail closed on duplicates or stale generation
  mismatches.
- The contract intentionally stays IPv4-only because current WG VIP contracts
  are IPv4-only. A future IPv6 expansion should be versioned or additive.

## Scope

Touch only PMA tracking files, the control message contract/tests, and a design
note. No producer or consumer runtime behavior is in scope.

## Alternatives

- Embed source identity in every pairing: rejected because one source VIP can
  authorize multiple service ports and duplicating subject/anchor data raises
  stale-row risk.
- Reuse `GatewayExitNftConfig`: rejected because GatewayEgress pairings target
  service VIP/protocol/port and require source identity recovery, while
  GatewayExit targets destination CIDR capture.

## Annotations

- 2026-06-17 20:00: Plan created from the approved WG GatewayEgress contract
  assignment.
- 2026-06-17 20:03: Implemented the additive control contract and verified
  with `just qa`.

## Outcome

- Added `GatewayEgressWgConfig` with split `pairings` and
  `source_identities` lists.
- Added `GatewayEgressWgPairing` for `(realm_id, source_vip, service_vip,
  protocol, port, service_ref, generation)`.
- Added `GatewayEgressWgSourceIdentity` for source VIP to canonical subject and
  terminate binding anchor recovery.
- Added `ControlMessage::GatewayEgressWgConfig` with wire tag and event label
  `gateway_egress_wg_config.v1`.
- Added a design note under `docs/design/`.
- Added JSON and CBOR round-trip coverage.

## Verification

- `PATH="$HOME/.cargo/bin:$PATH" cargo test -p control gateway_egress_wg`
- `PATH="$HOME/.cargo/bin:$PATH" just qa`
