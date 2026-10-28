# Participant custody generation

- **status**: completed
- **priority**: P1
- **owner**: participant-session
- **createdAt**: 2026-10-28 11:56

## Description

Carry NSD committed positive custody generations in versioned Enrolled and
Authenticated answers, bound to the exact participant and issuer. Refuse missing,
zero and legacy delivery. Preserve all other frames and retention seal bytes.

## Acceptance

- Independent vectors round-trip both answer kinds and reject invalid delivery.
- Pending authentication and enrollment pair checks reject mismatches.
- Format, lint, scoped self-check, vectors-check and semver pass.

## Notes

Investigation and approved implementation are recorded in
[the plan](../plan/20261028-1156-participant-custody-generation.md). Existing authenticated metadata lacks an identity
pair; enrollment already has a nonzero request correlation.

## Validation

The local fixture regression `participant_custody_answer_version_roundtrip` first
failed with `versioned custody answer: Frame` against the old decoder. It now passes,
alongside the independent producer vectors and pending-exchange checks. Fixtures
cover both answer kinds, absent and finite deadlines, generations 1 and u64::MAX,
zero and missing generations, legacy and unsupported versions, malformed deadlines,
wrong issuer/participant, wrong enrollment correlation and expired authorization.

`just dev-check` passed before the focused session suite (6 tests passed).
`just self-check` against the integration baseline passed: 70 script tests,
413 default-feature tests and 565 unstable-account tests, with zero nextest skips,
plus doctests and documentation builds. Its static checks included formatting,
lint, dependency checks, spelling, `just vectors-check` (46 fixture files current)
and `just semver` (no public stable API change required).

All 54 unrelated session vectors remain identical to the baseline, as do retention
seal source and vectors. Review covered the codec, tests, independent generator and
specification changes with no unresolved findings. TLS exchange tracking and durable
consumer persistence remain the responsibilities documented by the pure contract.
