# SH-MESH-003 Remove the standalone Mesh shared protocol

- **status**: completed
- **priority**: P1
- **owner**: shared protocol maintenance
- **createdAt**: 2026-09-16
- **relatedPlan**: [PLAN-019](../plan/PLAN-019.md)

## Description

Remove standalone Mesh from the latest main tree without integrating Keynet or
reverting unrelated account-mode contracts and fixes. Preserve historical task
and plan records, feature branches, and a backup of the original main tip.

## ActiveForm

Removing the standalone Mesh shared protocol and verifying account compatibility.

## Dependencies

- **blocked by**: coordinated NS and NSGW consumer removal before integration
- **blocks**: (none)

## Notes

- The user approved surgical removal on 2026-09-16. Scope is this repository only.
- Clean main and origin/main both started at
  `3aef14fd3678ebe1c113750c3ce36d6a67dd0389`.
- Backup: `archive/main-before-mesh-removal-20260916` at the original tip.
- Working branch: `chore/remove-mesh-from-main`.
- Existing account crates are unchanged since the pre-Mesh baseline except for
  Mesh-only control exports, signing helpers, and dependencies; retained account
  code will be compared to that baseline without resetting the repository.
- Compilation is coordinated with the parent task to avoid concurrent builds.

## Verification

- `cargo fmt --all -- --check`: passed.
- `cargo metadata --locked --offline --no-deps --format-version 1`: passed; only
  the five existing account/shared crates remain.
- `CARGO_BUILD_JOBS=1 cargo nextest run --workspace --locked --offline
  --test-threads 2`: 709 passed, zero skipped; build 40.66 seconds, run 4.455 seconds.
- `CARGO_BUILD_JOBS=1 cargo clippy --workspace --all-targets --locked --offline
  -- -D warnings`: passed in 21.88 seconds, using the existing repository gate.
- `CARGO_BUILD_JOBS=1 cargo test --doc --workspace --locked --offline`: passed;
  the existing crates contain zero doctests.
- `cargo shear --locked`, changed-file `typos`, and `git diff --check`: passed.
- `git diff d02a29c -- crates Cargo.toml Cargo.lock`: empty. All surviving account
  code, tests, manifests, and locked versions match the verified pre-Mesh tree;
  this was a surgical removal, not a repository reset.
- Review found no remaining Mesh/Keynet runtime reference and no non-Mesh caller
  of the removed signing helpers. Existing Mesh task/plan detail files are unchanged.
- `cargo deny --locked --offline check`: **failed advisories** on the pre-existing
  `rustls 0.23.41`, [RUSTSEC-2026-0285](https://rustsec.org/advisories/RUSTSEC-2026-0285),
  "TLS 1.3 handshake messages incorrectly accepted across encryption level
  boundaries"; the cached advisory recommends `>=0.23.45`. Bans, licenses, and
  sources passed. Existing duplicate/wildcard and yanked `chacha20 0.10.1` warnings
  remain. No dependency version was upgraded, and this is not a full-QA pass.
- Local commit is approved with this existing advisory explicitly recorded;
  dependency remediation is outside this removal. No push, deployment,
  runtime-state change, or history rewrite is performed.
