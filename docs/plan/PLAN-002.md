# PLAN-002 Public edge contract: gateway_http_config / gateway_l4_map (nsgw PLAN-066 S1)

- **status**: draft
- **approvedAt**: (pending)
- **parentPlan**: nsgw/PLAN-066 (Envoy dynamic public ingress)

## Context

Slice 1 (dependency root) of nsgw PLAN-066. This is a breaking shared-crate
schema change in the `control` and `common` crates that the consumer repos
(`ns`, `nsd`, `nsgw`) depend on via `../ns-shared/crates/*` path deps. It must
land as one coordinated same-window change set across all four feat/envoy
worktrees, because the type change breaks every consumer's compile the instant
it lands.

Current state anchors (validate against tip during investigation):

- `crates/control/src/messages.rs` — `PublicIngressScope` with only
  `http_1_1_reverse_proxy`.
- `crates/common/src/state.rs` — advertises only the `http_1_1_reverse_proxy`
  public-ingress scope.

## Proposal

Define the shared public edge contract types consumed by NSD synthesis, the
NSGW local ADS adapter, and NSGW runtime:

- `gateway_http_config` — HTTP host routes plus contract-shape fields for L7
  middleware, external identity import, signed-subject-header policy, edge
  rate/connection limits, request transforms, and edge audit policy (runtime
  for identity/middleware is a deferred follow-up; first cut carries shape
  only with status-quo `anonymous`/`external_idp` semantics).
- `gateway_l4_map` — TCP/UDP public listener maps, `NsnBacked` backend only for
  the first cut. Route identity includes protocol, realm id, gateway id,
  `public_port` (from `virtual_port`), `nsgw_internal_port`, NSN WG VIP +
  upstream `port`, ACL reference + subject policy, transport policy, and policy
  generation / rollback metadata. `virtual_port` required for L4.
- Certificate policy/reference fields (transport-agnostic) for the public edge.
- Capability/scope advertisement extensions in `common` state.

This is a target-state contract: do not preserve `public_ingress_config.v1` as
the source of truth. Same-window consumer adapt:

- `ns` — adapt to the new control/common types (compile-green; NSN-side runtime
  is a deferred identity follow-up).
- `nsd` — adapt projection/serialization callsites (synthesis logic lands in
  nsd PLAN-036 / S2).
- `nsgw` — adapt control/common consumption callsites (runtime lands in nsgw
  PLAN-067+ / S3+).

## Dependencies

- **blocked by**: (none — dependency root)
- **blocks**: nsd PLAN-036 (S2), nsgw PLAN-067/068/069/070 (S3–S5, S7)

## Verification

- Shared contract tests for `gateway_http_config` and `gateway_l4_map` JSON
  round-trips, default HTTP route shape, and TCP/UDP route entries.
- Same-window: `cargo check` / `just qa` green in all four feat/envoy
  worktrees (ns-shared, ns, nsd, nsgw) after the cascade.

## Annotations

- 2026-06-13 - Stub created from nsgw PLAN-066 S1 during decomposition. Sub-plan
  to be expanded proposal-first by the S1 sub-coordinator before implementation;
  the same-window cascade is mandatory.
