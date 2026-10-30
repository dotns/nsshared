# Candidate vector coverage

- **status**: completed
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

## Acceptance results

- Eleven family rows distinguish positive, empty/removal, refusal, scope and
  limit cases, with exact fixture names and explicit shared coverage gaps.
- Export/specification and external producer/consumer responsibilities are
  reconciled separately; existing adoption claims retain their evidence limits.
- The M6 index references current control-crate fixtures and leaves standalone
  service-label agreement, independent boundaries and composition approval open.
- Release substitutions and consumer examples still require the actual immutable
  release and cohort. Review, producer, matching-reader, live, retention and
  release obligations remain open.
- The initial documentation assertion failed with `Missing exact eleven-family
  candidate case index`. Final validation passed for eleven rows, 127 exact
  fixture references, 17 M6 JSON keys and local document link targets. Literal
  fixture outcomes distinguish refused empty catalogue lists from withdrawal.
- `just dev-check` passed before the complete self-check. The final
  `just self-check` passed at documentation commit
  `e843654`: 48 fixture files current, 70 script tests, 421 default tests and
  581 account tests passed, with zero skipped tests in both suites. Formatting,
  lint, dependencies, spelling, semver, doctests and documentation passed.
- An earlier complete check also passed; the final check covers the subsequent
  documentation clarification of ResourceAuthority scope and own-node withdrawal
  gaps. No source, vector, API or dependency changed.
- Local documentation review completed with no remaining finding. No external
  component tests, producer corpus comparisons or live qualification ran.
