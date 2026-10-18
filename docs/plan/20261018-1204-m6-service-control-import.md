# Import the existing M6 service-control contract

- **status**: completed
- **createdAt**: 2026-10-18 12:04
- **approvedAt**: 2026-10-18 12:04

## Context

The base `09879c84029262be86aba5c66c238d57ede3762a` precedes the M6
service-control contract. The existing lineage ends at
`aba1c5d5350550f85631034cf613e780bc4dbbe0` and includes typed messages,
digit-leading service labels, canonical declaration bytes, independent CBOR
vectors, and the rustls update. L8 extends these shared contracts.

## Proposal

Merge the exact revision with a merge commit. Preserve its three commits and
all imported bytes. Run formatting and lint checks before crate tests,
vector drift verification, and `just qa` on the combined source tree.

## Risks

A workspace check can expose an incompatibility in the imported contract.
Such a failure requires a separate contract change agreement; this import
preserves the existing contract.

## Scope

The existing service-control crate, root Cargo manifests, lockfile, recipes,
and these import records. Runtime clients and sessions remain outside scope.

## Alternatives

A parallel L8 service-control contract would duplicate the existing types.
Rebasing or squashing would discard the exact revision required by consumers.

## Annotations

The exact lineage was merged and its bytes preserved. The complete `just qa`
passed with exit 0 on source commit
`98fcca901019f8d880710f51a148d3d8f65ed557`: 393 tests passed with 0 skipped,
including all 9 service-control tests; 1 documentation test passed. Both
vector drift checks, API compatibility checks, and documentation generation
passed. Only these import records were updated afterward.
