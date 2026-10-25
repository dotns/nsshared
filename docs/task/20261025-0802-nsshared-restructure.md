# 20261025-0802-nsshared-restructure Restructure the shared crates and apply the review revisions

- **status**: in_progress
- **priority**: P1
- **owner**: restructure/20261025
- **createdAt**: 2026-10-25 08:02

## Description

Split `nsshared-proto` and `nsshared-service-control` into focused crates
(`nsshared-codec`, `nsshared-identity`, `nsshared-relay`, `nsshared-rendezvous`,
`nsshared-control`, `nsshared-testkit`), keep `nsshared-proto` and
`nsshared-service-control` as facades with their existing public paths, reorganize
the account contracts by layer and family, apply the review revisions (decoder
allocation bound, one scope-text validator, review-request disposition and revision
pointer, export rule, error types, metadata), fold the appended specification deltas
into per-family specifications and consolidate tests, vectors and generators.

Acceptance:

- Every existing vector case is byte-identical in content; the old path to new path
  mapping is checked case by case against `1bc1d39e`.
- The only behaviour change is the stricter scope-text rule; it is recorded in the
  changelog and in the review request.
- `just qa` passes after every phase; the facade crates keep their public API;
  the paths used by the consumer workspaces still resolve.
- Pure contracts only: no I/O, runtime state or v1 compatibility code.

Plan: [20261025-0802-nsshared-restructure](../plan/20261025-0802-nsshared-restructure.md).

## ActiveForm

Restructuring the shared crates

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Notes

Owner decisions of 2026-10-25 approve the scope; see the plan annotations.
