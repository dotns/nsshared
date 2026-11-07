# 20261107-1726-exit-readiness-contract Define provider-confirmed Exit observations

- **status**: completed
- **priority**: P1
- **owner**: contract/20261107-1726
- **createdAt**: 2026-11-07 17:26

## Description

Implement the approved reduced Exit readiness exchange: GatewayReport challenge/observation, one consumer Snapshot, installation incarnation, canonical helpers and adversarial vectors. Bump the clean-break version to 0.9.0. Require tests first, just qa, and an unmerged PR.

## ActiveForm

Defining and verifying provider-confirmed Exit observations.

## Dependencies

- **blocked by**: (none)
- **blocks**: Consumer adoption of the frozen shared contract.

## Notes

Owner approved the reduced exchange, dedicated client query, naming and application-lifetime custody. No new method, provider publication, persistence, packet authority or ABI change is included.

Implemented the frozen eight-type contract, strict GatewayReport/response and subscription slots, family-4 observational Snapshot and canonical helpers. Initial focused test failed with missing readiness APIs (exit 101); the implementation passes the shared regressions. Full just qa passed on 6b5bcae67d37501980d152bbfa4a3375bfe070f3: 606 workspace tests, 71 script tests, all static checks, 49 independent vector fixtures, doctests and warning-denied docs. The API migration map was regenerated and account-migration-check passed. This includes the existing 0.8.0-to-0.9.0 clean break and no unrelated dependency upgrades.

PR: https://git.pvv.cc/nsiod/nsshared/pulls/28. No merge, tag, release, lab or deployment action occurred. A final clean-head gate follows the verification record; its exact head and log are reported with the PR. Consumer implementation and release remain separate work.

- complete: Shared contract implemented, complete QA and migration map check passed; unmerged PR opened.
