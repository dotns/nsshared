# Default Exit floor encoding

- **status**: completed
- **priority**: P1
- **owner**: (assigned)
- **createdAt**: 2026-11-05 12:50

## Description

Support canonical Default selections in complete M6 floor reports without changing explicit
bytes, custody checks, identity validation or authorization. Require compatible immutable
producer and consumer revisions; unsupported tuples remain unavailable.

## ActiveForm

Encoding and validating Default Exit floor profiles.

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Notes

Investigation and approved implementation are recorded in
[the plan](../plan/20261105-1250-default-exit-floor.md). Shared indexes and changelog are updated separately.

## Acceptance

- [x] Canonical Default complete-floor and authenticated round trips.
- [x] Explicit bytes unchanged; malformed selections and ownership mismatches refused.
- [x] Compatibility and immutable delivery documented without implicit authority.
- [x] Failing-first evidence and scoped self-check completed.

## Results

Default now encodes and decodes as `[0]` through the complete M6 floor path. Explicit
encoding and existing error codes remain unchanged. Independent fixtures cover Default
messages and authenticated replies without treating accepted profile publication as a grant.
The service specification documents exact compatible-consumer requirements, immutable
revision delivery, explicit-only refusal and authority boundaries.

The failing-first run exposed `DefaultExitUnsupported` in five floor tests. After the
change, format, both lint configurations and `just self-check` passed: 48 fixture files,
70 script tests, 424 default-feature tests and 584 account-feature tests. No nextest tests
were skipped; the pre-existing ignored doctest remained unchanged. The passing source tree
was unchanged afterward except for these detail records.

The independent fixture producer was updated because Default is now valid and generated
fixtures must agree with the schema. Shared indexes and changelog remain for separate
integration. Downstream consumers must adopt a verified pushed immutable revision and
implement their Default handling before enabling a supported tuple.
