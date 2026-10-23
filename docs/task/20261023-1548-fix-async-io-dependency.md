# Fix asynchronous I/O dependency

- **status**: in_progress
- **priority**: P1
- **createdAt**: 2026-10-23 15:48

## Description

Remove the affected tokio version from the shared lockfile without changing manifests or advisory policy.

## Investigation and proposal

The advisory check fails with `advisories FAILED` for tokio 1.53.2. Update only tokio and resolver-required lock records using `cargo update -p tokio`. No matching AsyncFd constructor calls were found in Rust sources. Verify advisory resolution and the complete self-check.

## Acceptance

Only necessary lock records change; no affected tokio remains; formatting, lint and the scoped quality check pass.
