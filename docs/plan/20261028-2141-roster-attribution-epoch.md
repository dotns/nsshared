# Separate roster attribution epochs

- **status**: completed
- **createdAt**: 2026-10-28 21:41
- **approvedAt**: 2026-10-28 21:41

## Context

Signed rosters currently encode one version as both publication and billing epoch. Both decoding paths assume seven fields; verification persists only the publication floor.

## Proposal

Preserve schema 1 exactly with attribution epoch equal to version. Add schema 2 with an explicit positive attribution epoch and preserve the schema on decode/re-encode. Require independent publication and epoch floors in both verification APIs. Expose the authenticated epoch in participant generations and document producer and consumer custody. Add independent signed vectors and regression tests.

## Risks

The unstable-account Rust API changes: constructors supply schema and epoch, and verification callers supply the persisted epoch floor. Released default-feature APIs remain unchanged. Schema 1 signatures must remain byte-identical.

## Scope

Relay roster contracts, usage terminology, account tests, independent vectors and account specifications.

## Alternatives

Inferring the epoch from publication version cannot represent unchanged membership renewal. Keeping a verification overload without an epoch floor would permit rollback.

## Acceptance

- The initial `separate_attribution_epoch_schema_round_trips` test failed with `Cbor(ArrayLength { expected: 7, actual: 8 })` before implementation.
- `cargo fmt --all --check` and `just lint` passed before test execution.
- `cargo test -p nsshared-control --features unstable-account --locked --test account`: 157 passed, none failed or ignored.
- The self-check passed on implementation commit `c2151f7f5c4bb1e29456511fe6c12df1d71c1acd`: 413 default-feature tests and 570 opt-in tests passed, zero skipped; script tests, doctests and documentation checks also passed.
- `just vectors-check`: all 47 generated fixture files matched. Existing participant roster vectors remain a byte-identical prefix, with new independently signed cases appended.
- `just semver`: passed against v0.7.0; default-feature APIs require no version update. The intentional source-breaking change is confined to the opt-in `unstable-account` API.
- Local fixture evidence covers schema preservation, independent counter magnitudes, repeated epochs across publications, rollback refusal, canonical encoding, signature coverage and retained usage attribution.
- Review found no remaining defects in the changed contracts and tests. External producer and runtime consumer adoption is outside this library change.
