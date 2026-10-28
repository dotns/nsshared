# Participant custody generation

- **status**: completed
- **createdAt**: 2026-10-28 11:56
- **approvedAt**: 2026-10-28 11:56
- **relatedTask**: 20261028-1156-participant-custody-generation

## Context

Authenticated frames currently contain only an optional deadline. Enrolled frames
contain the issuer, participant, correlation and deadline. Neither delivers the
committed custody generation needed by retention seals.

## Proposal

Add answer version 2 after the identity pair (and enrollment correlation), followed
by the existing optional deadline and a positive big-endian u64 owner generation.
Reject old answer lengths as incompatible versions. Validate the authenticated
answer against the pending authentication on the same verified connection, and
retain exact enrollment correlation checks. Add independent Python vectors and
Rust checks for round trips, missing/zero generations and incompatible versions.

## Risks

The unstable account answer wire format and constructors intentionally change.
Consumers must update together and persist original custody without relabeling
older parts. No runtime storage or TLS behavior is implemented here.

## Scope

Participant session codecs, account tests, their vector producer and fixture,
and relay/usage specifications. Signed rosters and retention seals are unchanged.

## Alternatives

An optional generation would let old answers silently supply no custody and is
rejected. Renewal retains its existing contract and dedicated constructor path.

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
