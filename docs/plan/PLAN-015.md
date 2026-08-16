# PLAN-015 Unified node capability and subnet-route contracts

- **status**: approved
- **createdAt**: 2026-08-16 06:06 UTC
- **approvedAt**: 2026-08-16 07:31 UTC
- **relatedTask**: NODE-001
- **relatedPlans**: ns PLAN-124, nsd PLAN-129, nsgw PLAN-123

## Context

The current shared control contract distinguishes connector and gateway
registration, while subscriber behavior is inferred by product endpoint and
role-specific messages. `RegisterRequest.capabilities` is additive, but there
is no canonical capability vocabulary for a node that consumes and publishes
services simultaneously.

The current `RouteEntry` is an L4 logical-service route and `CaptureRoute` is a
client capture/exit instruction. Neither can represent a provider-advertised,
NSD-approved L3 prefix without changing its existing meaning.

## Proposal

1. Keep the unified node registered as the existing connector machine type in
   the first compatible version. Select behavior from explicit capabilities,
   not a new mutually exclusive node type.
2. Define versioned capability names for service consumption, service
   publication, subnet advertisement, and subnet acceptance. Unknown
   capabilities remain ignorable on old peers and cannot grant authority.
3. Add a bounded node-route report carrying a canonical route ID, canonical
   IPv4 network prefix, generation, and requested SNAT mode. It expresses
   intent only.
4. Add a distinct approved-subnet-route projection carrying the exact owner
   identity, realm, prefix, next-hop WireGuard peer identity, generation,
   forwarding mode, and authorization scope required by the consumer.
5. Add explicit full-snapshot and withdrawal semantics. An omitted or older
   route cannot survive a newer authoritative generation.
6. Preserve existing service, capture, GatewayExit, GatewayEgress, direct-P2P,
   and relay messages byte-for-byte when the new fields/messages are absent.
7. Let one identity request a scoped WSS **leg** token. `AuthPayload` today
   expresses only `control` or `wss` and cannot name a leg role, which is what
   forces NSD's scalar `resolve_role` (service rows present → `relay`, else
   `client`) and makes the opaque WSS carrier exclusive per machine. Adding the
   leg role as a request input is the smallest contract change that unblocks a
   unified node; NSD remains the sole authority for granting it, and the
   requested role is never self-asserting.

The concrete serialized capability values proposed for the first version are:

- `node.consume-services.v1`;
- `node.publish-services.v1`;
- `node.advertise-subnet-routes.v1`;
- `node.accept-subnet-routes.v1`.

Final Rust type and control-message names are selected during implementation,
but their wire semantics and separation from `RouteEntry`/`CaptureRoute` are
fixed by this plan.

## Bounds and validation

- IPv4 CIDRs must be canonical network prefixes; host bits, default routes,
  multicast, loopback, and link-local are rejected for the MVP.
- Overlay-reserved ranges are rejected against the control plane's **effective
  runtime configuration**, never against hard-coded constants. The
  authoritative inputs are NSD's configured VIP pool (`vip_pool`, default
  `100.64.0.0/10`) and gateway tunnel-IP pool (`tunnel_ip_pool`, default
  `10.100.0.0/24`) at `nsd/crates/nsd-api/src/config.rs`. Both are
  operator-configurable through `Config::parse_vip_pool` and
  `Config::parse_tunnel_ip_pool`, so a validator pinned to the default CIDRs
  would accept an advertisement that swallows the overlay's own address space
  in any deployment that overrides either pool. The shared validator takes the
  effective ranges as an input rather than recomputing or assuming them.
- Reports and projections have explicit route-count and encoded-size limits.
- Route IDs and generations are stable and deterministic; duplicate IDs,
  duplicate prefixes, and conflicting owners fail closed.
- Deserialization is backward compatible and rejects malformed or oversized
  input before allocation can grow without bound.

## Scope

In scope are additive shared types/messages, validation helpers, fixtures,
round-trip tests, compatibility tests, and shared architecture tracking.

Out of scope are database storage, approval APIs, Linux route/NAT changes,
gateway packet forwarding, deployment, and legacy message removal.

## Acceptance

- Old messages decode with unchanged semantics and new optional fields absent.
- New capability and subnet-route fixtures round-trip deterministically across
  all consuming repositories.
- Unknown capabilities do not activate a role or authorize a route.
- Invalid CIDRs, reserved ranges, duplicates, stale generations, oversized
  collections, and conflicting ownership are rejected deterministically.
- ns, nsd, and nsgw compile and pass their focused compatibility tests against
  the exact shared candidate **inside one merge window** together with the
  shared change. Landing the shared crate ahead of its consumers is not
  permitted: new message and enum variants arrive in exhaustive consumer
  matches that carry no wildcard arm, so a shared-only merge leaves all three
  consumer mains red.
- Locked ns-shared QA and stack-aware review pass.

## Risks

- Capability strings can drift across repositories. Constants and fixtures
  must have one owner in `ns-shared`.
- Treating route advertisement as authorization would bypass NSD policy. The
  report and approved projection remain distinct types.
- Adding a machine-type enum variant would cascade through persistence and old
  consumers. The MVP deliberately keeps the existing connector type.

## Alternatives

- Extend `RouteEntry` or `CaptureRoute`. Rejected because their current L4 and
  capture/exit meanings must remain stable.
- Add a `Node` machine-type variant immediately. Rejected for the first phase
  because capabilities provide additive compatibility without a migration
  cascade.

## Annotations

- 2026-08-16 06:06 UTC: Drafted from exact main
  `9b17c991efd40e29aad2cd87fa09731da4dce21c`. No task is claimed and no wire
  implementation is authorized before plan approval.
- 2026-08-16 06:27 UTC: Plan review applied. Overlay-reserved range rejection
  is now bound to NSD's effective runtime `vip_pool` / `tunnel_ip_pool`
  configuration instead of the default CIDRs, because both pools are
  operator-configurable and a constant-pinned validator would accept a prefix
  that swallows the overlay's own address space. Consumer compatibility is now
  required inside one merge window with the shared change rather than merely
  "before integration".
- 2026-08-16 06:38 UTC: Cross-repository consult folded in. Added proposal
  item 7: `AuthPayload` must be able to request a scoped WSS **leg** token.
  Its current `control`-or-`wss` shape is what forces NSD's scalar
  `resolve_role` and makes the opaque WSS carrier exclusive per machine, which
  is the hard blocker for a unified node. The leg role is a request input only;
  NSD stays the sole granting authority.
