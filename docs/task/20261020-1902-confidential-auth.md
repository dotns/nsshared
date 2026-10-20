# Confidential authentication configuration

- **status**: in-progress
- **priority**: P1
- **owner**: account-contract
- **createdAt**: 2026-10-20 19:02
- **plan**: ../plan/20261020-1902-confidential-auth.md

## Investigation and implementation

The catalog needs provider client secrets, cookie keys, API/Basic verifiers,
signed URL keysets, mTLS joins and public JWT key-source configuration. Existing
subject bindings retain credential identity, enabled state, subject and expiry.
Route imports retain supplied method order, bypass/failure flags and explicit
redirect overrides. NSD management API credentials are outside gateway projection.

## Acceptance

- Independent confidential_auth_generation fixtures bind exact request, realm,
  reference and generation; mismatches refuse.
- Strict canonical, size, shape, missing-value and nested-value refusals.
- Existing authenticated control envelopes only; no public payload secrets.
- Formatting, lint and the current self-check pass.

## ActiveForm

Implementing confidential authentication configuration

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)
