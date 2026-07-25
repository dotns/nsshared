# ns-shared Architecture

`ns-shared` is a Rust workspace that packages shared crates for the NSIO control and transport stack. The workspace root `Cargo.toml` declares five members: `crates/acl`, `crates/common`, `crates/control`, `crates/telemetry`, and `crates/tunnel-ws`.

## Workspace Crates

`common` contains shared configuration, machine-state, service, and protocol primitives. Its crate-level source docs export configuration structs for control centers and gateways, machine identity/state management, service definitions, tunnel protocol primitives, and NSD key pin helpers.

`acl` contains the accept-only ACL engine. Its crate-level source docs describe a default-deny policy evaluator, policy and lint models, access-decision inputs, merge helpers for layered policies, and deny-scope handling.

`control` contains the control-plane client. Its crate-level source docs describe machine registration/authentication, server-sent event control streams, control-envelope handling, control message types, retry and merge helpers, multi-NSD support, and Noise/QUIC/SSE transport modules.

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
