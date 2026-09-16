# ns-shared Architecture

`ns-shared` is a Rust workspace that packages shared crates for the NSIO control and transport stack. The workspace root `Cargo.toml` declares five members: `crates/acl`, `crates/common`, `crates/control`, `crates/telemetry`, and `crates/tunnel-ws`.

## Workspace Crates

`common` contains shared configuration, machine-state, service, and protocol primitives. Its crate-level source docs export configuration structs for control centers and gateways, machine identity/state management, service definitions, tunnel protocol primitives, and NSD key pin helpers. `common::tunnel::DEFAULT_WIREGUARD_PLAINTEXT_MTU` is the one local data-plane default shared by NS and NSGW; it is not a control-plane field or wire contract. `common::node_capability` owns the unified-node capability vocabulary (`node.consume-services.v1`, `node.publish-services.v1`, `node.advertise-subnet-routes.v1`, `node.accept-subnet-routes.v1`); it is the single definition of those wire tokens, and an unrecognized token resolves to nothing so it can never activate a role or authorize a route.

`acl` contains the accept-only ACL engine. Its crate-level source docs describe a default-deny policy evaluator, policy and lint models, access-decision inputs, merge helpers for layered policies, and deny-scope handling.

`control` contains the control-plane client. Its crate-level source docs describe machine registration/authentication, server-sent event control streams, control-envelope handling, control message types, retry and merge helpers, multi-NSD support, and Noise/QUIC/SSE transport modules.

Standalone Mesh v1/v2 is not part of this workspace. Its protocol module,
dedicated fixtures, and Mesh-only signing helpers were removed by
[SH-MESH-003](task/SH-MESH-003.md); account-mode node/relay contracts remain.
Historical Mesh task and plan records describe the removed implementation,
which is preserved at `archive/main-before-mesh-removal-20260916` and in the
existing Mesh feature branches. This removal does not integrate Keynet.

`control::messages::GatewayWgRelayPair` carries both authoritative node tunnel
addresses and an explicit `GatewayWgRelayIndexScheme`. Omitted/default
`address_xor` preserves existing serialized defaults; NSD emits `device_key` to
match current NS directional indices. The scheme is independent of the reserved
port-addressing mode. Consumers must retain canonical pair admission and cannot
treat an absent address or an unknown scheme as usable forwarding authority.

`control::subnet_route` holds the L3 subnet-route contracts. Advertisement and authority are separate types on purpose: `NodeSubnetRouteReport` (envelope api `node.subnet_routes.report.v1`) is a node's intent and authorizes nothing, while `SubnetRouteConfig` (control message `subnet_route_config.v1`) is NSD's approved projection and is the only shape that authorizes a route. Neither replaces `RouteEntry` (L4 logical service route) or `CaptureRoute` (NSC capture/exit instruction). Both are full snapshots: an omitted route is withdrawn, and a snapshot that does not advance its generation is stale and dropped whole. Prefix validation takes the control plane's **effective** `vip_pool` / `tunnel_ip_pool` as an `OverlayReservedRanges` input rather than pinning NSD's documented defaults, because both pools are operator-configurable and a pinned validator would accept a prefix that swallows the overlay's own address space wherever a deployment overrides either one.

`control::types::WssLegRole` lets one identity request a `client` or `relay` WSS leg through `AuthPayload::leg_role`. It is a request input only: NSD remains the sole granting authority and the requested leg is never self-asserting.

The public-edge `GatewayHttpRoute` contract carries an optional
`upstream_authority`. It is omitted when absent for legacy JSON/CBOR
compatibility. `host` remains the public listener, certificate, authentication,
OIDC, and ACL identity; producers derive upstream TLS SNI from the explicit
authority when present and otherwise from `host`.

`telemetry` contains telemetry initialization and metric helpers. Its crate-level source docs describe OpenTelemetry metrics backed by a Prometheus exporter, subsystem metric structs, label contracts, global meter helpers, supervised task spawning, and per-subsystem OTel facades.

`tunnel-ws` contains the pure WebSocket proxy transport. Its crate-level source
docs describe logical stream multiplexing over WebSocket connections to NSIO
relay endpoints, TLS connector helpers, opaque relay URL helpers,
access-control integration, connection events, and relay error types. Each
framed tunnel owns its writer and per-stream relays in one task set;
cooperative shutdown aborts and joins the complete set before returning, and
parent cancellation aborts the set through structured drop ownership.

## Consumers

The sibling `Cargo.toml` manifests in `/workspace/nsiod/ns`, `/workspace/nsiod/nsd`, and `/workspace/nsiod/nsgw` consume these crates through path dependencies rooted at `../ns-shared/crates/*`.

| Consumer | Verified path dependencies |
|----------|----------------------------|
| `ns` | `acl`, `common`, `control`, `telemetry`, `tunnel-ws` |
| `nsd` | `acl`, `common`, `control` |
| `nsgw` | `acl`, `common`, `control`, `telemetry`, `tunnel-ws` |

## Live Dependency Root

This checkout is a live dependency root for the sibling workspaces listed above because their manifests point directly at `../ns-shared/crates/*`. Changes in this tree can affect local builds of those consumers without publishing a package or updating a version.

The workspace package configuration sets `publish = false`, and all member crates inherit that setting. These crates are therefore consumed from source through path dependencies or immutable repository refs rather than as published package artifacts.

Docs-only changes and additive Rust API changes can land in this repository after local quality gates pass. Breaking API or behavior changes require a coordinated cascade across the affected consumers before landing, because the sibling path dependencies resolve against this working tree.

## Quality Gates

The root `justfile` defines the full local gate as:

```text
just qa = fmt-check lint test deny shear typos
```

The recipes expand to `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo nextest run --workspace`, `cargo deny check`, `cargo shear`, and `typos`.
