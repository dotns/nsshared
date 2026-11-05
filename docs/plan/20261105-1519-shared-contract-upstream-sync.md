# 20261105-1519-shared-contract-upstream-sync Shared contract upstream synchronization

- **status**: completed
- **createdAt**: 2026-11-05 15:19
- **approvedAt**: 2026-11-05 15:19
- **relatedTask**: 20261105-1519-shared-contract-upstream-sync

## Context

The source at `8b16c5ac65da57dfcf87c3013c74f30fd8d552ef` already restores the exact six-element authentication request and independent registration conditions. Upstream `dddba6ca4255bb7bf91ba6306047f28c36efead9` carries the same codec and vectors, a weaker overlapping test, and a self-check fix for symlinked workspaces.

## Proposal

Merge the exact upstream commit, retaining all assertions from both inputs. Preserve Node-only Echo authorization, Default Exit profiles, explicit null semantics, five-element refusal and independent authority requirements. Keep one-sided upstream changes, including the self-check regression control. Use the existing pinned QA tools and run formatting and lint before the existing exchange controls and self-check.

## Risks

Dropping either exact-byte assertion would weaken registration coverage. Replacing the codec or vectors would duplicate compatible changes. Missing one-sided upstream changes would lose workspace-check behavior.

## Scope

The upstream merge, the exchange test conflict and these acceptance records. No dependency upgrades or consumer adoption.

## Alternatives

Retaining the stronger existing test satisfies both input behaviors without duplicating the test or changing the authentication contract.

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
