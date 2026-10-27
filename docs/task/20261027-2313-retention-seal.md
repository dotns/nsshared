# Retention seal and acknowledgement

- **status**: completed
- **priority**: P1
- **createdAt**: 2026-10-27 23:13

## Description

Implement a participant-session-only retention seal and correlated committed
acknowledgement behind unstable-account. Verify independent bytes and digest,
empty and populated manifests, authenticated scope, generation, immutable replay,
strict ordering, bounds, and acknowledgement correlation.

## ActiveForm

Implemented and verified retention contracts.

## Notes

Investigation and approved design: [plan](../plan/20261027-2313-retention-seal.md).

## Acceptance

- The first `empty_retention_seal_roundtrip` compilation failed with unresolved
  import `RetentionSeal`, establishing the missing API before implementation.
- Five focused retention tests passed, covering independent canonical vectors and
  digests, authenticated scope and generation, exact replay and conflicting parts,
  all acknowledgement identity fields, explicit refusals, ordering and bounds.
- The independent fixture contains two accepted seals, ten accepted correlated
  outcomes, and 33 rejected encodings. Empty closure and all-incarnation manifests
  round-trip byte-for-byte; maximum-sized part collections fit participant frames.
- `just dev-check` passed before focused tests. `just self-check` passed all selected
  checks, including `just vectors-check` (43 fixtures), default-feature semver,
  70 script tests, 413 default-feature tests and 550 tests with unstable-account,
  zero skipped tests, doctests and documentation with warnings denied.
- Local review covered all changed contracts, tests, generator and specifications;
  no unresolved correctness findings. Consumers still own authentication, durable
  closure, historical receipt comparison and deletion eligibility.
