# Resolved dependency scoped self-check

- **status**: completed
- **priority**: P1
- **createdAt**: 2026-10-20 16:40

## Description

Scope dependency edits by resolved package closures while preserving global
configuration checks and complete delivery verification.

## ActiveForm

Implementing dependency comparison and temporary workspace regressions

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Investigation

Member manifest and lockfile changes currently select complete QA.
The selection API can retain its conservative behavior without a base graph,
while the command entry point supplies both real metadata snapshots.

## Proposal

Compare normalized resolved closures including versions, sources, checksums
and enabled features. Preserve static checks, reverse consumers and existing
input classification. Fail closed on metadata or comparison errors.

## Verification

- The first focused regression, `test_added_leaf_dependency_scopes_consumers`,
  failed because `select_changes` did not exist.
- `just fmt-check lint` passed before the selection suite.
- `just self-check-tests` passed all 41 tests. Existing assertions are unchanged.
- Real temporary workspaces cover added and removed dependencies, shared
  version changes, enabled features, member manifests, merge-base selection,
  unchanged closures, global policies and metadata failures on either side.
- The checksum comparison is fixture-fed: two valid directory-source metadata
  snapshots have identical packages and different lockfile checksums. Selecting
  only `Cargo.lock` chooses exactly the three consumers and names both checksums.
  An inconsistent registry checksum was rejected by Cargo, so the fixture uses
  independently valid snapshots rather than bypassing metadata validation.
- Manual review covered the complete selector and test diff, including command
  construction, failure handling, local path normalization and temporary cleanup.

- `just self-check feat/l8-account-profile` passed on source commit
  `9320b3f1c0fee57141d1de4142e6ea45d76fd0f5`: 41 selection tests, 434 Rust
  tests with zero skips, one documentation test and warning-free documentation.
  Formatting, lint, dependency policy, spelling, generated vectors and API
  compatibility checks all passed.
- Only the completion records changed after that passing self-check.
