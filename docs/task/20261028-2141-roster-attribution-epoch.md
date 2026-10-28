# Separate roster attribution epochs

- **status**: completed
- **createdAt**: 2026-10-28 21:41
- **priority**: P1

## Description

Separate signed roster publication ordering from historical billing attribution, retaining legacy canonical bytes and enforcing non-decreasing positive attribution epochs.

## ActiveForm

Implementing and verifying independent roster attribution epochs.

## Dependencies

None.

## Notes

Investigation and approved implementation are recorded in the matching plan. Acceptance requires failing-first evidence, canonical vector round trips, epoch rollback refusal, vectors-check, semver and the scoped self-check.

## Acceptance

- The initial `separate_attribution_epoch_schema_round_trips` test failed with `Cbor(ArrayLength { expected: 7, actual: 8 })` before implementation.
- `cargo fmt --all --check` and `just lint` passed before test execution.
- `cargo test -p nsshared-control --features unstable-account --locked --test account`: 157 passed, none failed or ignored.
- The self-check passed on implementation commit `c2151f7f5c4bb1e29456511fe6c12df1d71c1acd`: 413 default-feature tests and 570 opt-in tests passed, zero skipped; script tests, doctests and documentation checks also passed.
- `just vectors-check`: all 47 generated fixture files matched. Existing participant roster vectors remain a byte-identical prefix, with new independently signed cases appended.
- `just semver`: passed against v0.7.0; default-feature APIs require no version update. The intentional source-breaking change is confined to the opt-in `unstable-account` API.
- Local fixture evidence covers schema preservation, independent counter magnitudes, repeated epochs across publications, rollback refusal, canonical encoding, signature coverage and retained usage attribution.
- Review found no remaining defects in the changed contracts and tests. External producer and runtime consumer adoption is outside this library change.
