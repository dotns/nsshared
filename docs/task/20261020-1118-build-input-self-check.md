# Build input scoped self-check

- **status**: in_progress
- **priority**: P1
- **createdAt**: 2026-10-20 11:18

## Description

Select tests from actual build inputs, preserving static checks and complete QA
for configurations, vectors, included fixtures and uncertain file access.

## ActiveForm

Implementing input classification and temporary-repository regression coverage

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Investigation

`select` currently escalates any path outside a known crate and an empty
package set. `commands` always constructs package test commands. Existing
coverage exercises reverse dependencies, Git state and complete QA selection.

## Proposal

Implement tracked-source input scanning with explicit diagnostic reasons and
return static checks alone when no package is selected. Preserve existing
selection assertions by making their global fixture document an actual input.

## Verification

Pending.
