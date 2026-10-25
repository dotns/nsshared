# Import the existing M6 service-control contract

- **status**: completed
- **priority**: P1
- **createdAt**: 2026-10-18 12:04

## Description

Import the existing M6 service-control lineage so that the L8 account payload
profile extends the shared contract instead of defining parallel types for
service declarations and M6 service-control messages.

Imported commits:

- `fd35cd4994794bc83f1cf9c19c55f249daf9d424`: typed M6 wire contract.
- `24ae9efe8debc440d1cddd9b3b35502a3601609b`: digit-leading service labels.
- `aba1c5d5350550f85631034cf613e780bc4dbbe0`: canonical declaration bytes.

Merge base: `09879c84029262be86aba5c66c238d57ede3762a`.

## ActiveForm

Importing and verifying the existing service-control contract

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Investigation

The base does not contain the M6 lineage. The imported crate provides pure
contracts, strict canonical CBOR, typed message validation, canonical
service declarations, service-label validation, and independent vectors.
The workspace placement rule keeps runtime behavior in consuming repositories.

## Proposal

Merge `aba1c5d5350550f85631034cf613e780bc4dbbe0` with both parents preserved.
Keep the crate, root Cargo manifests, lockfile, and recipes identical to that
revision, including the rustls update. Verify ancestry, workspace quality
checks, the crate tests, and vector drift before completing the import.

## Notes

- Before import, `git merge-base --is-ancestor
  aba1c5d5350550f85631034cf613e780bc4dbbe0 HEAD` exited 1 because the
  required revision was absent; the same assertion exited 0 after import.
- The merge preserves `09879c84029262be86aba5c66c238d57ede3762a` as its first
  parent and `aba1c5d5350550f85631034cf613e780bc4dbbe0` as its second parent.
- `git diff aba1c5d5350550f85631034cf613e780bc4dbbe0 HEAD --
  crates/nsshared-service-control Cargo.toml Cargo.lock justfile` is empty.
- `just fmt-check lint` passed with exit 0 before running tests.
- `cargo nextest run -p nsshared-service-control --locked` passed all 9 tests,
  with 0 skipped and exit 0: 4 cases in
  `crates/nsshared-service-control/tests/vectors.rs` and 5 cases in
  `crates/nsshared-service-control/tests/message_schema.rs`.
- `just vectors-check` exited 0. Both independent generators passed their
  drift checks; the workspace generator reported 8 fixture files up to date.
- The initial `just qa` exited 101 at `semver` because
  `cargo-semver-checks` was unavailable. No imported files were changed.
- With `cargo-semver-checks` 0.51.0 available, the complete `just qa`, with
  `CARGO_INCREMENTAL=0` and `RUSTC_WRAPPER=/usr/bin/sccache`, passed with exit 0:
  393 tests passed, 0 skipped, and 1 documentation test passed. This includes
  all 4 vector tests and all 5 message-schema tests in the service-control
  crate. Formatting, lint, dependency checks, spelling, both vector drift
  checks, API compatibility checks, and documentation generation passed.
- The complete passing check tested source commit
  `98fcca901019f8d880710f51a148d3d8f65ed557`; only these import records were
  updated afterward. The imported source, recipes, and dependencies remain
  identical to `aba1c5d5350550f85631034cf613e780bc4dbbe0`.

The import and verification are complete. No contract changes were needed.
