# Scoped workspace self-check

- **status**: completed
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

The implementation and acceptance checks are complete. A temporary,
uncommitted comment exercised crate-only selection, then was restored before
the final complete QA run. The imported contract remains unchanged.

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

## Final acceptance

- At commit `35476e4dffd462e0780e5fee5b1cdea95c414f4d`, a clean working tree
  received only the temporary first-line comment
  `// Validate scoped checks for contract-only changes.` in
  `crates/nsshared-service-control/src/lib.rs`.
- `just self-check HEAD` selected the scoped branch and printed
  `nsshared-service-control` as both the changed and affected package set.
  Workspace formatting, lint, deny, shear, typos, both vector checks and
  semver all passed, followed by all 10 selection tests.
- The selected command was `cargo nextest run --workspace --locked -E
  'rdeps(nsshared-service-control)'`. Its summary was
  `9 tests run: 9 passed, 0 skipped`. Documentation tests and the warning-free
  documentation build passed for the same package. The observed scoped
  duration was compared with the complete-QA duration.
- The comment was removed without committing it. Byte-for-byte comparison
  against the committed file passed, `git status --short` was empty, and
  `git diff --exit-code 6dd3a93 HEAD -- crates/nsshared-service-control`
  confirmed the imported contract was unchanged from the implementation base.
- On that restored clean commit, `just qa` passed all static checks,
  10 selection tests, 393 Rust tests with 0 skipped, 1 documentation test
  and the workspace documentation build. All commands used
  `CARGO_INCREMENTAL=0` and `RUSTC_WRAPPER=/usr/bin/sccache`.
- Only these completion records changed after the passing complete check.

All acceptance checks are complete. No contract changes are committed.
