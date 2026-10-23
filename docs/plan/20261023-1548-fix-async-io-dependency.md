# Fix asynchronous I/O dependency

- **status**: completed
- **createdAt**: 2026-10-23 15:48
- **approvedAt**: 2026-10-23 15:48

## Context

The shared lockfile contains tokio 1.53.2. The advisory check identifies unsound safe AsyncFd constructors and requires a patched release. The advisory policy has no exceptions. A Rust-source search found no calls matching AsyncFd::new, with_interest, try_new or try_with_interest.

## Proposal

Run `cargo update -p tokio` and retain only resolver-required lock changes. Keep manifests and advisory policy unchanged. Use the existing advisory check as the failing regression check, then run formatting, lint and the complete self-check.

## Risks

A dependency update can affect compatibility; the complete self-check validates the resolved graph.

## Scope

Cargo.lock and the dependency repair records.

## Alternatives

Advisory exceptions and unsafe constructor replacements are excluded. Existing requirements must accept the patched release.

## Verification

`cargo deny check advisories` failed before the update with `advisories FAILED`, identifying tokio 1.53.2. `cargo update -p tokio` selected 1.54.1 under existing requirements. Unrelated Windows dependency reference changes were excluded; the locked checks accepted the minimal version and checksum update. No manifest or advisory policy changed.

`just fmt-check lint` and `just self-check feat/l8-account-profile` passed, including advisories, compatibility checks, workspace tests, doctests and documentation generation. The workspace suite passed all 536 tests with zero skips. No test infrastructure was changed.
