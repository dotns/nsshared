# Exact registration recovery

- **status**: completed
- **priority**: P1
- **createdAt**: 2026-10-29 12:38

## Description

Preserve exact original signed acceptance bytes in a versioned attachment with operation, membership and canonical request digest. Validate against independently retained request, previous binding, issuer and custody floors, without coupling recovery to an old transport nonce.

## ActiveForm

Implementing pure registration recovery validation.

## Dependencies

None.

## Notes

Investigation and approved proposal are recorded in the matching plan.

## Acceptance results

- Added versioned operation/membership/request-digest context and original acceptance attachment, with independent source and custody expectations.
- Shared enrollment/profile/lifecycle comparisons preserve the original registration behavior. Recovery does not accept or compare a historical transport nonce.
- Independent Python vectors construct original signed acceptance bytes; Rust validates and round-trips those bytes without signing. Existing exchange fixture bytes remain an unchanged prefix.
- Wrong operation, NSD/Network, digest, issuer, recipient, WireGuard key, capabilities, profile, decision, signature, source tuple, baseline, lifecycle and floors are refused.
- The initial regression failed before implementation with `cannot find type RegistrationRecoveryQuery in this scope`. Both focused recovery tests subsequently passed.
- `just fmt-check` and `just lint` passed before tests. `just self-check` against the integration baseline passed on commit `6a5ea834642f4f7a9574f8849418fb273beffa41`: 70 script tests, 421 default-feature tests and 581 account-feature tests passed; both nextest runs had zero skips. Existing doctest and documentation checks passed.
- `just vectors` regenerated the fixtures; the self-check's `just vectors-check` confirmed 48 fixture files up to date. Its existing `just semver` entry point required no default-feature version update. New exports are additive under the opt-in unstable account feature, outside the stable default surface.
- Local review covered the changed Rust contracts, Python producer, tests and specification, with no blocking findings.

Persistence, the named-field receipt adapter, current-authority observation and retained-plan publication remain their existing consumers' responsibilities.
