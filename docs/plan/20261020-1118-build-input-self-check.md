# Build input scoped self-check

- **status**: implementing
- **createdAt**: 2026-10-20 11:18
- **approvedAt**: 2026-10-20 11:18
- **relatedTask**: 20261020-1118-build-input-self-check

## Context

The selector treats every path outside crates as global and adds packages for
crate-local documents. This makes documentation-only edits run complete QA.

## Proposal

Scan tracked executable sources and build configuration for literal references,
file-relative references, joined paths and directory readers. Conservatively
select complete QA for unresolved reads, configurations and vectors. Report
input classification for every non-Rust path. Documentation-only changes
retain static checks without scheduling package tests.

## Risks

Computed file access cannot generally be resolved statically. Uncertain reads
must retain complete QA. Changes in the index and working tree must be scanned
alongside the checked head to avoid overlooking newly added dependencies.

## Scope

Only the selector, its temporary-repository tests and these records change.

## Alternatives

A documentation-directory allowlist would overlook included build inputs and
is therefore unsuitable.
