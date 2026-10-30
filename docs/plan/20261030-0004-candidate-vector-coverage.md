# Candidate vector coverage

- **status**: implementing
- **createdAt**: 2026-10-30 00:04
- **approvedAt**: 2026-10-30 00:04
- **relatedTask**: 20261030-0004-candidate-vector-coverage

## Context

The candidate inventory lists fixture files without individual positive, empty,
refusal, scope and limit cases. Producer corpora and matching consumer readers
are separately bounded in the handoff. The current service fixtures reside in
the control crate; historical standalone service-control tests are absent.

## Proposal

Replace the starting-point list with eleven distinct family rows containing
exact fixture case names, shared coverage gaps and external owners. Add an M6
composition index and link existing export/spec descriptions. Extend only the
release-time substitutions and examples still dependent on the actual cohort.

## Risks

A fixture name must not imply a complete family suite, producer approval,
byte-matched downstream corpus or live qualification. Keep all release holds.

## Scope

The four account review documents; no code, vectors, dependencies or release changes.

## Alternatives

Adding vectors would mix documentation reconciliation with missing contract work;
record exact gaps and owners instead.

## Validation

Documentation-only: no executable regression test applies. Check every cited
fixture case against the existing corpus, then run static checks and self-check.
