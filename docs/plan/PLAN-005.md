# PLAN-005 Shared route-capture contract

- **status**: completed
- **createdAt**: 2026-06-15
- **relatedTask**: CAPTURE-001

## Context

The gateway-exit and NSC-TUN plans define the same dependency root: captured
exit CIDRs must not be encoded as normal service routes.

Investigation found:

- `crates/control/src/messages.rs` uses `RouteEntry` / `RoutingConfig.routes`
  for service DNS and reverse-proxy routing. `RouteEntry` carries service
  domain, site, service, port, backend, and optional VIP fields, so putting
  exit CIDRs there risks service-VIP allocation by old consumers.
- `PublicEdgeBackendKind` and `ServiceBackendKind` already have
  `GatewayExit` variants from the gateway-owned backend contract, but this
  slice must not add route capture by iterating those existing route lists.
- `RoutingConfig` is the existing NSC/NSGW service route snapshot. Adding a
  separate `capture_routes` field with `serde(default)` and
  `skip_serializing_if` keeps old consumers tolerant of the new data while
  making empty payloads byte-identical.
- `common::state` already holds shared capability tokens for public edge. A
  new capture-route capability token can be defined there without advertising
  it from NSD yet.

## Proposal

Add the inert contract in `control::messages` and `common::state`:

1. Define `CAPABILITY_CAPTURE_ROUTES_V1 = "capture_routes.v1"` as the NSC
   opt-in token for receiving non-empty capture routes.
2. Extend `RoutingConfig` with:
   `#[serde(default, skip_serializing_if = "Vec::is_empty")] pub capture_routes:
   Vec<CaptureRoute>`.
3. Define `CaptureRoute` with required fields for `route_id`, `generation`,
   `realm_id`, `gateway_id`, `profile_ref`, `destination_cidrs`,
   `source`, `table_policy`, and `kill_switch`.
4. Define `CaptureRouteSource` with `address: Ipv4Addr` and `prefix_len: u8`.
   The default NSD projection will use the connector VIP as `/32`; a distinct
   TUN-source address remains a later option.
5. Define `CaptureRouteTablePolicy` / `CaptureRouteTable` and
   `CaptureRouteKillSwitchPolicy` as declarative policy fields only. No route
   manager or kill-switch behavior is implemented in this slice.
6. Document on the types that capture routes are not service routes and never
   allocate service VIPs; type-level separation is enforced by omitting
   `domain`, `service`, `port`, `backend`, and `target_vip` from
   `CaptureRoute`.
7. Add focused tests:
   - CBOR round-trip for a populated capture route.
   - Empty `capture_routes` is omitted from JSON and CBOR-equivalent to a
     legacy mirror struct containing only `routes`.
   - Existing `RouteEntry`, `WgConfig`, and public-edge sample encodings are
     unchanged by the new contract.

## Scope

In scope:

- `crates/common/src/state.rs` capability token.
- `crates/control/src/messages.rs` additive types, field, docs, and tests.

Out of scope:

- NSC TUN device, local route manager, nft/SNAT, forwarding, or kill-switch
  implementation.
- New `PublicEdgeBackendKind` variants or new service-route backend variants.
- Runtime synthesis of non-empty capture routes.

## Risks

- Adding a required field directly to an existing struct would churn tests and
  old wire payloads. The plan avoids that by adding a defaulted, omitted list.
- A future builder may accidentally populate capture routes for an old NSC.
  NSD must add a publisher-side capability gate in the same window.
- `CaptureRouteSource.prefix_len` cannot fully validate address/prefix
  consistency at the type level. Runtime validation remains a future producer
  responsibility.

## Alternatives

- Reuse `RouteEntry.backend = GatewayExit`: rejected because old service-route
  consumers iterate `routes` and may allocate service VIPs.
- Add `GatewayExit` to `PublicEdgeBackendKind`: rejected for the same reason
  and because public-edge snapshots target gateways, not NSC route capture.
- Create a new top-level `ControlMessage`: deferred. The requested contract is
  an additive projection alongside existing service routing, and a field on
  `RoutingConfig` preserves snapshot ordering and old consumer tolerance.

## Verification

- `PATH="$HOME/.cargo/bin:$PATH" cargo test -p control` passed.
- Full `just qa` in tmux with output redirected to `/tmp/gx0-ns-shared.log`
  and a trailing `DONE_$?` marker before commit.
