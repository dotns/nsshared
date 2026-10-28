# Snapshot admission history

- **status**: completed
- **priority**: P1
- **createdAt**: 2026-10-28 01:31

## Description

Carry required admission-start history through validated schema-3 snapshots,
refusing legacy schemas and invalid history without changing signed rosters.

## Acceptance

- Return identity, class and admission_since for continuous admission and readmission.
- Refuse schema 2, absent history, zero history and history above the epoch.
- Preserve strict shape, bounds and freshness checks.
- Independent vectors, signed roster regression tests and semver checks pass.

## Notes

Investigation and approved implementation are recorded in the matching plan.

The schema-three regression failed against the previous validator after formatting
and lint passed. The snapshot entry is exported through the relay facade.
Independent history vectors and the existing strict validation cases cover the
schema migration. Acceptance checks passed.

## Acceptance results

- The initial schema_three_admission_history_is_required regression failed at the
  acceptance assertion against schema 2 after formatting and lint passed.
- admission_history_vectors validates 14 independent cases, including continuous
  admission, readmission, empty snapshots, legacy schema refusal, missing and
  malformed history, zero and upper bounds, and the maximum u64 version.
  Accepted results compare identity, class and admission_since exactly.
- Existing strict field, identity count, byte size and supplied-clock tests pass
  with schema-3 fixtures. Duplicate admission_since fields are refused.
- All six signed roster profile cases and the participant-roster vector file are
  byte-for-byte unchanged.
- just dev-check and just self-check passed. The self-check includes 45 current
  vector files, default-feature semver compatibility, 70 selection-script tests,
  413 default-feature tests and 556 account-feature tests, with zero skipped
  nextest tests, plus doctests and warning-free documentation builds.
- The final check includes the account profile schema reference correction.
