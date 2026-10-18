# Scoped workspace self-check

- **status**: in_progress
- **priority**: P1
- **createdAt**: 2026-10-18 22:14

## Description

Add a conservative path-based self-check while preserving complete workspace
QA, vector drift checks and API compatibility checks.

## ActiveForm

Implementing and verifying scoped workspace checks

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Investigation

The existing recipes run workspace formatting, lint, dependency policy,
spelling, vectors, semver, nextest, documentation tests and documentation
builds. Cargo metadata can map package directories and reverse dependencies,
including example consumers outside the contract crate directories.

## Proposal

Use a Python standard-library selector with real Git and Cargo fixture tests.
Run complete QA for global inputs or uncertainty. Retain every static check
for scoped changes, and restrict Rust tests and documentation to affected
packages. Stop at the first failed command with its original exit status.

## Notes

The implementation is complete. Acceptance of a crate-only invocation remains
open because the introduced recipes, scripts and records themselves require
complete QA, and the implementation scope contains no crate source changes.

## Verification

- Before implementation, the selection tests failed with `FileNotFoundError`
  because `scripts/self_check.py` did not exist.
- The initial fixture setup lacked a lockfile. Generating its local-only
  lockfile with `cargo generate-lockfile --offline` made the fixture compatible
  with the production selector's unchanged `--locked` policy.
- `just fmt-check lint` passed before running the selection tests.
- `just self-check-tests` passed all 10 tests, including a repeated independent
  invocation. Real Git histories cover committed, staged, unstaged, untracked
  and renamed paths, merge-base comparison and invalid comparison refs.
- The real Cargo fixture selects `contract-core`, `contract-api` and
  `contract-client` for a core-only edit. Its nextest invocation uses
  `rdeps(contract-core)` and verifies the summary `3 tests run: 3 passed`.
  Documentation tests and warning-free documentation builds pass for all
  three selected packages. These observations come from a temporary fixture.
- An initial static-check invocation failed when semver's dependency update
  encountered a TLS EOF while fetching the crates.io serde index. No check
  was changed or weakened.
- `just qa` subsequently passed: 10 selection tests, 393 Rust tests with
  0 skipped, 1 documentation test and the workspace documentation build.
  Dependency policy, spelling, both vector generators and semver passed.
- `just self-check main` printed the full-QA branch, its global-path reasons,
  and `nsshared-service-control` as the changed and affected package set.
  Its complete QA invocation passed the same checks and test counts.
- Both complete checks tested source commit
  `4f25f4fbd2f48c50a8a33012ecdcc5a0ce18034b`; only these records changed
  afterward.

The final source tree has no ancestor comparison that contains the new check
infrastructure while differing only in crate sources. A crate-only invocation
and its comparison against complete-QA duration remain unverified outside the
fixture.
