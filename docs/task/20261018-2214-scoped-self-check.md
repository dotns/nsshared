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

Implementation and acceptance checks are in progress.
