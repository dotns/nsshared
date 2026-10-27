# Merge release history

- **status**: completed
- **createdAt**: 2026-10-27 19:09
- **approvedAt**: 2026-10-27 19:09

## Context

Commit 8f136f8 adds only the v0.7.0 release entry to docs/changelog.md above 95f1688. The current tree starts at 95f1688.

## Proposal

Merge 8f136f8 with an explicit merge commit, preserving 95f1688 and 8f136f8 as parents. Verify tree equality except for these records, CI tool availability, and the repository self-check.

## Scope

The upstream changelog addition and these records only.

## Risks

Source synchronization does not inherit runtime evidence; checks must run independently.

## Alternatives

A fast-forward would omit the required merge structure.

## Results

The merge preserves parents 95f1688 and 8f136f8. Its tree equals 8f136f8 apart from these records. CI tool inspection passed with no missing or mismatched tools and two unparsed installation commands. The repository self-check passed with exit 0, including formatting, lint, dependency checks, API compatibility, tests, and documentation generation. Validation used merge 19321bc; only these records changed afterward.
