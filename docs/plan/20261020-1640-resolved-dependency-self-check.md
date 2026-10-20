# Resolved dependency scoped self-check

- **status**: implementing
- **createdAt**: 2026-10-20 16:40
- **approvedAt**: 2026-10-20 16:40
- **relatedTask**: 20261020-1640-resolved-dependency-self-check

## Context

The selector treats every manifest and lockfile as global. Cargo metadata
already includes all features and reverse dependency selection preserves static checks.

## Proposal

Export the merge-base tree to a temporary directory and compare locked,
all-feature metadata with the working tree. Normalize local package paths and
include lockfile checksums and enabled features in each member's closure.
Select changed manifests, changed closures and reverse dependencies, with
dependency diagnostics. Preserve global configuration and conservative failure behavior.

## Risks

Missing nodes, changed membership and metadata failures must select complete QA.
Temporary exports must be removed without touching the working tree.

## Scope

Only the selector, its existing tests and these records change.

## Alternatives

Running complete QA for every lockfile is safe but needlessly broad.
Comparing manifest text alone misses resolved transitive changes.
