# Publication subscription

- **status**: completed
- **priority**: P1
- **owner**: subscription-contract
- **createdAt**: 2026-10-20 18:39

## Description

Complete authenticated publication subscription requests with exact scopes, declared capabilities, requested public ingress scopes and restart-unique logical attempts. Refuse malformed, noncanonical and oversized input. Add no runtime or I/O.

## ActiveForm

Implementing canonical publication subscriptions and independent consumer vectors.

## Dependencies

- **blocked by**: none
- **blocks**: none

## Notes

Investigation and approved proposal are recorded in the matching plan. Independent specification and vectors precede implementation. Shared indexes and changelog are maintained separately.

## Acceptance results

- `publication_subscription_vectors` and `publication_subscription_signed_carrier` passed, covering 35 independent Python-produced cases: four canonical payloads, 24 payload refusals, one valid signed carrier and six signed carrier refusals. Corrupt signatures and replay are also refused.
- The initial `cargo test -p nsshared-proto --test publication_subscription_vectors` failed with unresolved subscription API imports before implementation. The same focused test command passed after implementation.
- `just fmt-check` and `just lint` passed before the focused verification.
- `just self-check feat/l8-account-profile` passed on the implementation commit, including static checks, independent vector regeneration checks, API compatibility, workspace tests, doctests and documentation.
- Local review of the added Rust contract, Python producer, consumer tests and specification found no outstanding correctness defects. Runtime state, I/O and publication acceptance/version logic are unchanged.
- NSD producer confirmation and matching producer vectors remain external. Shared documentation indexes and changelog are updated separately.
