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

## Acceptance

The selector reports input status and referring sources, preserves complete QA
for configuration, vectors and unresolved readers, and schedules only static
checks for proven non-input changes without affected packages. Temporary Git
repositories cover literal includes, compile-time joins, directory readers,
checked-head dependencies, unincluded documents and lock reads.

`just self-check feat/l8-account-profile` passed on source commit
`9f097123d0ea71592dcbea1c0497de48a3106567`: 23 selection tests, 416 Rust tests with zero skips,
one documentation test and warning-free documentation builds. All static
checks and API compatibility checks passed.

## Executable reader coverage

The scanner omitted command-style shell readers and the Rust `include!`
macro, allowing unresolved executable inputs to appear unreferenced. Extend
conservative detection to shell file commands, input redirection and directory
commands, and recognize every Rust inclusion macro delimiter. Preserve
selection for a shell command that reads a known unrelated literal path.
Temporary repositories must commit each reader before changing only a fixture.
