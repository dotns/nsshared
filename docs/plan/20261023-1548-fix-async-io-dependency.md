# Fix asynchronous I/O dependency

- **status**: implementing
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
