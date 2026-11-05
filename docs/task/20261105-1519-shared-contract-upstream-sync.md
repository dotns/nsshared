# 20261105-1519-shared-contract-upstream-sync Shared contract upstream synchronization

- **status**: completed
- **priority**: P1
- **createdAt**: 2026-11-05 15:19

## Description

Combine the exact compatible shared contract histories while preserving six-element registration conditions, independent captured identifiers, five-element refusal, Node-only Echo and Default Exit behavior.

## ActiveForm

Shared contract synchronization validated.

## Dependencies

The captured authentication condition implementation is already present.

## Investigation and proposal

See [the synchronization plan](../plan/20261105-1519-shared-contract-upstream-sync.md). The overlapping exchange test already contains every upstream assertion plus exact request and explicit-null vector equality checks. Preserve this stronger test and merge one-sided upstream changes.

## Acceptance

- Both `8b16c5ac65da57dfcf87c3013c74f30fd8d552ef` and `dddba6ca4255bb7bf91ba6306047f28c36efead9` are ancestors of merge `a783898f3defaf68d36ec7a70fe9b76c88ec7872`.
- The exchange test conflict retains all upstream assertions and both stronger exact-byte checks: captured registration canonical bytes and the explicit-null gateway vector. Rust contracts, tests, fixtures and independent producers remain byte-identical to the verified input.
- The upstream self-check path resolution fix and its symlinked-workspace test remain byte-identical to upstream. One-sided upstream documentation is preserved.
- `just fmt-check lint` passed before tests.
- `cargo nextest run --locked -p nsshared-control --features unstable-account --test account`: 166 passed, zero skipped. The existing exchange controls cover independent captured identifiers, exact bytes and malformed/five-element refusals.
- `python3 -B -m unittest discover -s scripts/tests -p test_self_check.py -v`: 43 passed, including symlinked-workspace selection.
- `just self-check` passed on the merged source: 71 script tests, 424 default-feature tests and 591 Account-feature tests passed; both nextest runs had zero skips. All 48 fixture files matched their independent producers. Formatting, lint, supply-chain, spelling, semver, doctests and documentation passed.
- The pre-existing testkit example remains ignored once in each doctest mode; no ignored tests or exceptions were added.
- No new failing-first test was introduced: the merge retains established product behavior and existing upstream regression controls without a new implementation.
