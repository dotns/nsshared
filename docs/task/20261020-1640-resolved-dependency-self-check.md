# Resolved dependency scoped self-check

- **status**: in_progress
- **priority**: P1
- **createdAt**: 2026-10-20 16:40

## Description

Scope dependency edits by resolved package closures while preserving global
configuration checks and complete delivery verification.

## ActiveForm

Implementing dependency comparison and temporary workspace regressions

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Investigation

Member manifest and lockfile changes currently select complete QA.
The selection API can retain its conservative behavior without a base graph,
while the command entry point supplies both real metadata snapshots.

## Proposal

Compare normalized resolved closures including versions, sources, checksums
and enabled features. Preserve static checks, reverse consumers and existing
input classification. Fail closed on metadata or comparison errors.
