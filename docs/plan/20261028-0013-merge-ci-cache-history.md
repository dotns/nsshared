# Merge CI cache history

- **status**: completed
- **createdAt**: 2026-10-28 00:13
- **approvedAt**: 2026-10-28 00:13

## Context

Main at `6b5490ec834e80cbe33f60cb9ac7a0fbb7aad4d6` adds shared compiler-cache configuration and documentation. The current development history retains the retention seal contract.

## Proposal

Merge main with two parents, preserving both sides of any documentation conflicts in chronological order. Preserve all source and tests unchanged. Check CI tool availability, formatting, lint, and the repository self-check.

## Scope

Upstream CI and documentation changes, documentation conflict resolutions, and these verification records.

## Risks

Documentation conflicts can discard entries. Compare both parents and verify the second parent explicitly. Previous runtime evidence does not establish results for the merged tree.

## Alternatives

Rebasing would discard the requested merge ancestry.

## Verification

The merge retains main at `6b5490ec834e80cbe33f60cb9ac7a0fbb7aad4d6` as its second parent. The changelog conflict preserves both sides; the index merged automatically. Source, tests and vector generators are identical to the development parent.

CI tool discovery reported no missing tools or version mismatches, with three installation statements left unparsed. `just dev-check` and the repository self-check against the development parent passed locally. Only these documentation records changed after the successful check. No failing-first test applies to this history-only merge.
