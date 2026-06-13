# PLAN-002 Public edge contract: gateway_http_config / gateway_l4_map (nsgw PLAN-066 S1)

- **status**: completed
- **approvedAt**: 2026-06-13 14:53
- **completedAt**: 2026-06-13 15:49
- **parentPlan**: nsgw/PLAN-066 (Envoy dynamic public ingress)
- **relatedTask**: EDGE-001

## Context

Slice 1 (dependency root) of nsgw PLAN-066. This is a breaking shared-crate
schema change in the `control` and `common` crates that the consumer repos
(`ns`, `nsd`, `nsgw`) depend on via `../ns-shared/crates/*` path deps. It must
land as one coordinated same-window change set across all four feat/envoy
worktrees, because the type change breaks every consumer's compile the instant
it lands.

Current state anchors (validate against tip during investigation):

- `crates/control/src/messages.rs` currently has the only public edge wire
  contract as `ControlMessage::PublicIngressConfig`, serialized as
  `public_ingress_config.v1`; `PublicIngressScope` has only
  `http_1_1_reverse_proxy`.
- `crates/common/src/state.rs` currently advertises
  `CAPABILITY_PUBLIC_INGRESS_CONFIG_V1 = "public_ingress_config.v1"` and
  `PUBLIC_INGRESS_SCOPE_HTTP_1_1_REVERSE_PROXY =
  "http_1_1_reverse_proxy"`.
- `nsd/crates/nsd-policy/src/snapshot/public_ingress.rs` builds HTTP-only
  routes from active services with a domain, VIP, tunnel token, subject policy,
  and optional virtual port. It ignores TCP/UDP protocol synthesis today.
- `nsd/crates/nsd-api` gates, publishes, and tests the old
  `PublicIngressConfig` variant through `VariantKind::PublicIngressConfig`.
- `nsgw/crates/nsgw-control/src/config_stream.rs` receives the old variant and
  forwards it to the optional public ingress runtime channel.
- `nsgw/crates/nsgw-routing/src/public_ingress.rs` normalizes old wire routes
  into an internal HTTP route table, then joins them with `RoutingConfig`.
- `nsgw/crates/nsgw-control/src/client.rs` and gateway report code advertise
  the old capability/scope pair when public ingress is enabled.
- `ns` has no production Rust public-edge consumer, but its docker NSD/NSGW
  mocks define and test the old `public_ingress_config.v1` shape and capability
  tokens.

## Proposal

Define a target-state public edge contract in `control::messages` and advertise
it from `common::state`.

New common tokens:

```rust
pub const CAPABILITY_GATEWAY_PUBLIC_EDGE_V1: &str = "gateway_public_edge.v1";
pub const PUBLIC_EDGE_SCOPE_GATEWAY_HTTP_CONFIG: &str = "gateway_http_config.v1";
pub const PUBLIC_EDGE_SCOPE_GATEWAY_L4_MAP: &str = "gateway_l4_map.v1";
```

Keep `NsdInfo.public_ingress_scopes` as the existing field name for same-window
API compatibility, but populate it with the new public edge scope tokens. The
old `public_ingress_config.v1` token stops being the advertised source of truth.

New shared route-policy primitives:

```rust
pub enum PublicEdgeProtocol { Http, Tcp, Udp }
pub enum PublicEdgeTransportPolicy { Wg, Wss, PreferWg, PreferWss }
pub enum PublicEdgeBackendKind { NsnBacked }

pub struct PublicEdgeAclRef {
    pub realm_id: String,
    pub resource_id: String,
}

pub struct PublicEdgePolicyRevision {
    pub generation: u64,
    pub version: String,
    pub previous_generation: Option<u64>,
    pub rollback_of: Option<u64>,
}

pub struct PublicEdgeRouteIdentity {
    pub protocol: PublicEdgeProtocol,
    pub realm_id: String,
    pub gateway_id: String,
    pub route_id: String,
    pub public_port: u16,
    pub nsgw_internal_port: u16,
    pub nsn_wg_vip: Ipv4Addr,
    pub upstream_port: u16,
    pub acl: PublicEdgeAclRef,
    pub subject_policy: PublicIngressSubjectPolicy,
    pub transport_policy: PublicEdgeTransportPolicy,
    pub policy_revision: PublicEdgePolicyRevision,
}
```

`PublicEdgeProtocol` is part of route identity so one TCP and one UDP route may
share the same `public_port`; same-protocol collisions remain expressible and
must fail closed during later synthesis. The first cut keeps
`PublicEdgeBackendKind` as an enum with only `NsnBacked`; future
`GatewayEgress` and `GatewayExit` are plan notes, not constructible runtime
variants.

`gateway_http_config.v1` shape:

```rust
pub struct GatewayHttpConfig {
    pub gateway_id: String,
    pub realm_id: String,
    pub routes: Vec<GatewayHttpRoute>,
    pub certificates: Vec<PublicEdgeCertificateRef>,
}

pub struct GatewayHttpRoute {
    pub identity: PublicEdgeRouteIdentity, // protocol = Http
    pub host: String,
    pub backend: PublicEdgeBackendKind, // NsnBacked only
    pub service: String,
    pub site: String,
    pub identity_import: HttpExternalIdentityImport,
    pub signed_subject_headers: SignedSubjectHeaderPolicy,
    pub middleware: HttpMiddlewarePolicy,
    pub edge_limits: EdgeLimitPolicy,
    pub transforms: HttpTransformPolicy,
    pub audit: EdgeAuditPolicy,
    pub certificate_ref: Option<String>,
}
```

HTTP subject policy preserves current semantics: `anonymous` and
`external_idp` round-trip and the `nsgw` HTTP runtime adapts the new route to
the current effective table; identity import and middleware fields are inert
contract shape for follow-up runtime.

`gateway_l4_map.v1` shape:

```rust
pub struct GatewayL4Map {
    pub gateway_id: String,
    pub realm_id: String,
    pub routes: Vec<GatewayL4Route>,
    pub certificates: Vec<PublicEdgeCertificateRef>,
}

pub struct GatewayL4Route {
    pub identity: PublicEdgeRouteIdentity, // protocol = Tcp or Udp
    pub backend: PublicEdgeBackendKind, // NsnBacked only
    pub service: String,
    pub site: String,
    pub virtual_port: u16,
    pub l4: L4Policy,
    pub certificate_ref: Option<String>,
}
```

`virtual_port` is mandatory for L4 and becomes `identity.public_port`. The NSN
upstream remains `identity.nsn_wg_vip:identity.upstream_port`. `L4Policy`
carries connection/session limit references and a certificate reference slot,
but no TCP/UDP runtime is implemented in S1.

Certificate policy/reference shape is transport-agnostic:

```rust
pub struct PublicEdgeCertificateRef {
    pub id: String,
    pub hostnames: Vec<String>,
    pub policy: PublicEdgeCertificatePolicy,
    pub source: PublicEdgeCertificateSource,
}
```

It carries references and policy only; private keys, ACME account keys, and
provider credentials remain outside the shared contract.

Control message changes:

```rust
#[serde(rename = "gateway_http_config.v1")]
GatewayHttpConfig(GatewayHttpConfig),
#[serde(rename = "gateway_l4_map.v1")]
GatewayL4Map(GatewayL4Map),
```

Remove the old `PublicIngressScope`, `PublicIngressRoute`, and
`PublicIngressConfig` shared wire types from consumers. No long-lived
`public_ingress_config.v1` source-of-truth bridge is planned. The only allowed
compatibility is an `nsgw-routing` private conversion from the new
`GatewayHttpConfig` into its existing internal HTTP route state so current
HTTP behavior is preserved until S3 replaces the runtime.

Same-window consumer cascade:

- `ns`: update docker mocks/types/tests to emit/accept new
  `gateway_http_config.v1` capability and message names. No NSN runtime is
  changed in S1; signed-subject verification remains TODO for the identity
  follow-up.
- `nsd`: update public-edge snapshot generation and publisher/gating tests to
  use `GatewayHttpConfig` and `GatewayL4Map` types. For S1, preserve current
  HTTP behavior by projecting existing eligible HTTP/domain routes into
  `GatewayHttpConfig`; leave `// TODO(PLAN-066 S2)` on incomplete L4 synthesis,
  internal port assignment, and cross-realm collision enforcement.
- `nsgw`: update advertisement, config-stream dispatch, and routing adapters to
  consume `GatewayHttpConfig`; ignore/log `GatewayL4Map` until S3/S4/S5
  runtime lands with `// TODO(PLAN-066 S3)` markers. HTTP effective routing
  stays behavior-compatible.

## Dependencies

- **blocked by**: (none — dependency root)
- **blocks**: nsd PLAN-036 (S2), nsgw PLAN-067/068/069/070 (S3–S5, S7)

## Risks

- This is a coordinated breaking wire rename. Any old `public_ingress_config.v1`
  call site left behind will either fail to compile or silently stop receiving
  route updates.
- The current HTTP projection lacks final `nsgw_internal_port`,
  certificate-reference, and L7 middleware runtime decisions. S1 must carry
  explicit shape without silently choosing runtime defaults inside a symptom
  window.
- `nsd` DB-facing serialization should not require migrations in this slice.
  If compile work touches persistence, both SQL dialects must stay consistent
  through generated schema changes only.
- `nsgw` runtime remains HTTP-only in S1. L4 messages must be representable and
  ignored fail-closed until the dedicated runtime slices implement them.

## Scope

In this slice:

- Shared Rust contract types and serde tests in `ns-shared`.
- Capability/scope advertisement token updates in `common`.
- Minimal consumer edits in `ns`, `nsd`, and `nsgw` required for compile-green
  behavior on the new contract.
- Clear TODO markers for S2/S3 runtime fields.

Out of scope:

- Envoy ADS, xDS resource generation, TCP/UDP runtime listeners, certificate
  issuance, private key handling, full external identity import, L7 middleware
  enforcement, and GatewayEgress/GatewayExit runtime.

## Alternatives

- Preserve `public_ingress_config.v1` as an alias: rejected because PLAN-066
  requires converging on one NSD public edge policy model and forbids a parallel
  legacy source of truth.
- Model `GatewayEgress` / `GatewayExit` enum variants now but reject them at
  runtime: rejected for the first cut because the assignment says only
  `NsnBacked` is constructible/valid now; future backend expansion should be a
  deliberate contract change.

## Verification

S1 implementation completed the shared contract and same-window consumer
cascade:

- `ns-shared/control` exposes `gateway_http_config.v1` and `gateway_l4_map.v1`
  with `PublicEdgeRouteIdentity`, HTTP middleware/identity/audit/limit
  contract-only fields, transport-agnostic certificate references, and L4
  TCP/UDP route entries.
- `ns-shared/common` advertises `gateway_public_edge.v1` plus
  `gateway_http_config.v1` / `gateway_l4_map.v1` public edge scopes.
- `nsd` publishes `GatewayHttpConfig` and an explicit empty `GatewayL4Map`
  placeholder for capable gateways; S2-only fields are marked with
  `// TODO(PLAN-066 S2)`.
- `nsgw` consumes `GatewayHttpConfig` through a private adapter into its
  existing HTTP runtime state and logs/ignores `GatewayL4Map` fail-closed until
  S3; S3-only fields are marked with `// TODO(PLAN-066 S3)`.
- `ns` docker NSD/NSGW mocks emit and consume the new public edge tokens and
  nested route identity shape.

Commands run:

- `ns-shared`: `PATH="$HOME/.cargo/bin:$PATH" just qa` -> PASS
  (`.local/s1-just-qa.log`).
- `ns`: `PATH="$HOME/.cargo/bin:$PATH" just qa` -> PASS
  (`.local/s1-just-qa.log`).
- `nsd`: `PATH="$HOME/.cargo/bin:$PATH" just qa` -> PASS
  (`.local/s1-just-qa.log`). A focused
  `cargo test -p nsd-api --test sse_publisher public_ingress` also passed
  after updating the new HTTP+L4 snapshot counts.
- `nsgw`: `PATH="$HOME/.cargo/bin:$PATH" just qa` -> PASS
  (`.local/s1-just-qa.log`). The run required a one-word typo fix in
  `docs/plan/PLAN-066.md` so the repository `typos` gate could complete.

Adversarial enumeration results:

- Old shared wire tokens/types were grepped across the four worktrees
  excluding `target`, `node_modules`, `.local`, and docs:
  `public_ingress_config.v1`, `http_1_1_reverse_proxy`,
  `PublicIngressScope`, old capability constants, and old scope constants have
  no dangling code call sites. A broader `PublicIngressConfig` name grep still
  finds `nsgw` private HTTP runtime state and `ns` docker mock helper names;
  those now consume/emit `GatewayHttpConfig` / `GatewayHttpConfigV1` and are
  not the old shared wire contract. The retained API field
  `public_ingress_scopes` carries the new public edge scope tokens.
- Serde round-trips cover `GatewayHttpConfig`, default HTTP route shape,
  `GatewayL4Map` with both TCP and UDP entries, and the `ControlMessage`
  variants with `gateway_http_config.v1` / `gateway_l4_map.v1` type strings.
  Nested `acl`, `subject_policy`, transport policy, middleware, transform,
  limit, audit, and certificate reference fields remain explicit in the wire
  shape.
- No `nsd` migrations were edited. DB-facing persistence remains the existing
  config outbox JSON serialization path, with updated variant tests covering
  the new event kinds; both SQL dialect paths remain schema-compatible.
- `PublicEdgeRouteIdentity.protocol` is mandatory. The L4 round-trip test
  pins one TCP and one UDP route sharing `public_port = 10000`, while the type
  still permits same-protocol same-port collisions for S2 fail-closed
  synthesis enforcement.
- No runtime-sensitive value is silently inferred inside S1. Missing
  `nsgw_internal_port`, policy generation, and L4 synthesis decisions are
  explicit S2/S3 placeholders or empty maps; HTTP subject-policy behavior stays
  status quo.
- No long-lived `public_ingress_config.v1` compatibility bridge remains. The
  only bridge-like code is the private `nsgw` HTTP adapter from the new shared
  wire type into the existing internal runtime table.

## Annotations

- 2026-06-13 - Stub created from nsgw PLAN-066 S1 during decomposition. Sub-plan
  to be expanded proposal-first by the S1 sub-coordinator before implementation;
  the same-window cascade is mandatory.
- 2026-06-13 14:53 - Proposal recorded after inspecting current shared types
  and consumer call sites. The S1 assignment explicitly authorizes
  proposal-first implementation in the same session, so implementation proceeds
  after this plan update.
- 2026-06-13 15:49 - S1 implementation, same-window cascade, adversarial
  enumeration, and four-worktree `just qa` verification completed.
