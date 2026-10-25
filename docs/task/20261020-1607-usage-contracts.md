# feat: service and relay usage contracts

- **status**: completed
- **priority**: P1
- **owner**: (assigned)
- **createdAt**: 2026-10-20 16:07

## Description

Deliver realm-local payer bytes, completed service and encoded relay DATA units,
immutable report parts and correlated acknowledgements with independent accepted
and refused consumer vectors. Preserve historical attribution and typed repair.

## ActiveForm

Completed pure usage contracts and independent consumer vectors.

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Notes

Investigation and approved implementation are recorded in
[the plan](../plan/20261020-1607-usage-contracts.md). No runtime or compatibility implementation is included.

## Acceptance results

- Service subject is exactly 16 big-endian ULID bytes paired with the realm;
  nine-field version-1 tuple preserved, with no identity fallback.
- Relay units retain both endpoint classes, original scope/version and reporter
  lifecycle; missing or inconsistent historical mapping returns typed repair.
- Report digests bind profile, reporter, lifecycle, window, sequence, partition
  and quantities; answers correlate the exact immutable pending part.
- Independent fixture consumers cover 77 accepted/refused cases; the initial
  payer test failed because the predecessor expected 32 bytes instead of 16.
- Focused tests passed 11 cases. Final self-check at
  `e01471b92fc860dee8b4c2bb05efb7a597abce05` passed full QA with 439 tests,
  zero skipped, one doctest and all static/documentation checks.

The detailed acceptance and remaining producer/consumer boundaries are in the
plan. Shared index and changelog entries are composed separately.
