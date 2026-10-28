# Merge CI cache history

- **status**: completed
- **priority**: P1
- **createdAt**: 2026-10-28 00:13

## Description

Merge main at `6b5490ec834e80cbe33f60cb9ac7a0fbb7aad4d6`, retaining the retention seal contract and both sets of documentation entries.

## Acceptance

- The resulting head has main as its second parent.
- Only existing development changes and verification records differ from main.
- CI tool availability and repository self-check pass.

## Notes

Investigation found only upstream CI and documentation changes. The approved approach is a merge with documentation-only conflict resolution. No new behavior or regression test is introduced by this synchronization.

## Verification

The merge retains main at `6b5490ec834e80cbe33f60cb9ac7a0fbb7aad4d6` as its second parent. The changelog conflict preserves both sides; the index merged automatically. Source, tests and vector generators are identical to the development parent.

CI tool discovery reported no missing tools or version mismatches, with three installation statements left unparsed. `just dev-check` and the repository self-check against the development parent passed locally. Only these documentation records changed after the successful check. No failing-first test applies to this history-only merge.
