# Release-ready contract inventory

- **status**: completed
- **priority**: P2
- **createdAt**: 2026-11-06 23:58

## Description

Refresh the candidate release inventory with one row per contract: producer
and consumers, shared candidate vectors, NSD producer corpus and slice, ns copy
and review state, at the current NSD, ns and nsgw revisions.

## ActiveForm

Refreshing the release-ready contract inventory.

## Dependencies

External review answers, the NSD bootstrap corpus merge, matching consumer
readers and the actual release remain separate prerequisites.

## Notes

Investigation and scope are recorded in the matching plan. No executable
behavior changes; `unstable-account` stays required.

Result: the release-ready table lists thirteen contract rows at nsshared
`24fb97f`, NSD `3928f73e`, ns `b5a8e18e` and nsgw `ab89f809`, plus the
bootstrap corpus proposed in NSD pull request 572. Every named slice and vector
was checked against those revisions, and the ns copies were compared byte for
byte. `just qa` passes.
