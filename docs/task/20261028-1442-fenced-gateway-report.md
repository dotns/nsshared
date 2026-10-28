# Fenced gateway reports

- **status**: completed
- **createdAt**: 2026-10-28 14:42
- **priority**: P1

## Description

Implement fenced shared gateway observations and correlated receipts without changing existing observation encoding or other operations.

## Acceptance

Independent vectors round-trip exactly and reject malformed, noncanonical, missing or zero runtime fields and mismatched receipts with typed errors. Signed requests require persisted scope and endpoint identities. Vectors, compatibility and scoped checks pass.

## Notes

Investigation and proposal completed; implementation approved.

## Validation

- The initial `fenced_gateway_operation_accepts_scoped_payload` regression failed with `Cbor(ArrayLength { expected: 12, actual: 4 })` before implementation.
- Formatting and both default-feature and account-feature Clippy checks passed before testing.
- The scoped self-check passed: 413 default-feature tests and 569 account-feature tests, with zero skips; all four fenced gateway tests passed.
- `just vectors-check` confirmed all 47 fixture files; `just semver` passed with no compatibility update required. Existing gateway, Node heartbeat and posture fixture bytes are unchanged.
- Local diff review covered all changed contract, test, generator and specification files with no blocking findings. The existing report fixture harness now tests legacy payload encoding directly and asserts rejection by shared dispatch.

Runtime freshness, source custody and persisted accepted profile comparisons remain consumer responsibilities, as documented in the control specification.
