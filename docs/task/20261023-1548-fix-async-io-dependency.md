# Fix asynchronous I/O dependency

- **status**: completed
- **priority**: P1
- **createdAt**: 2026-10-23 15:48

## Description

Remove the affected tokio version from the shared lockfile without changing manifests or advisory policy.

## Investigation and proposal

The advisory check fails with `advisories FAILED` for tokio 1.53.2. Update only tokio and resolver-required lock records using `cargo update -p tokio`. No matching AsyncFd constructor calls were found in Rust sources. Verify advisory resolution and the complete self-check.

## Acceptance

Only necessary lock records change; no affected tokio remains; formatting, lint and the scoped quality check pass.

## Verification

`cargo deny check advisories` failed before the update with `advisories FAILED`, identifying tokio 1.53.2. `cargo update -p tokio` selected 1.54.1 under existing requirements. Unrelated Windows dependency reference changes were excluded; the locked checks accepted the minimal version and checksum update. No manifest or advisory policy changed.

`just fmt-check lint` and `just self-check feat/l8-account-profile` passed, including advisories, compatibility checks, workspace tests, doctests and documentation generation. The workspace suite passed all 536 tests with zero skips. No test infrastructure was changed.
