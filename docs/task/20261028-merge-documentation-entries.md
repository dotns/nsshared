# Preserve appended documentation entries

- **status**: completed
- **priority**: P1
- **createdAt**: 2026-10-28

## Description

Use the Git union merge driver for the changelog and plan/task indexes while preserving existing attributes.

## Validation

A merge-tree check of two branches appending distinct changelog entries completed successfully and retained each entry exactly once. The temporary branches were deleted and their commits were excluded from the final history. Spelling and whitespace checks passed.
