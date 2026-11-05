# Service authority and scope refusals

- **status**: in_progress
- **priority**: P1
- **createdAt**: 2026-11-05 18:04

## Description

Allow `authority-unavailable` and `scope-mismatch` only in the existing exact Error
body. Preserve all twenty-nine previous codes, canonical encoding, envelope and
authenticated correlation rules, and success/grant/duration validation. Reject
the two additions in snapshot acknowledgements and refused lease results.

## ActiveForm

Extending existing service refusal controls and validating the bounded codec change.

## Dependencies

- **blocked by**: none
- **blocks**: compatible immutable producer and consumer dependency reconciliation

## Notes

Investigation and approved implementation are recorded in
[the plan](../plan/20261105-1804-service-error-refusals.md).
The existing raw-envelope body validator owns both encode and decode acceptance;
the typed conversion requires no new API or alternate validation path.
Older decoders at `9969abd8507ea3de057b0b870492755908206e89` and
`26e5aa7db741ea027df30799b1c9c3ff8f366b2e` reject the new values.
The extension does not authorize automatic retry or scope substitution.

## Acceptance

- [x] Both codes round-trip only in Error bodies with canonical vectors.
- [x] Existing codes remain accepted; unknown, malformed, wrong-type and misplaced
  values remain rejected by the existing encode/decode validation paths.
- [ ] Formatting, linting and the prescribed self-check pass.

## Validation results

Before correction, the existing message and canonical controls ran eleven tests:
eight passed and three failed. The independent canonical assertion rejected
`authority-unavailable`; both message controls encountered `UnsupportedField`
while encoding the newly supported values. Formatting and both lint configurations
passed before these tests.

After correcting only the Error branch, formatting and both lint configurations
passed again. All twenty-two service integration tests passed with
`unstable-account`, including the existing authenticated pending-floor controls.
The canonical vector producer adds two valid Error messages and five invalid
body controls. Its generated canonical fixture is the only changed test support
file. The typed encoder constructs exactly a text-valued Error body; raw decoding
additionally checks wrong types, missing fields and extra fields. Both paths share
the unchanged exact-map and type validation before canonical acceptance.
