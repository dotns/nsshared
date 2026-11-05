# Service authority and scope refusals

- **status**: implementing
- **createdAt**: 2026-11-05 18:04
- **approvedAt**: 2026-11-05 18:04
- **relatedTask**: 20261105-1804-service-error-refusals

## Context

The typed message codec validates both encoding and decoding through the raw
envelope and its exact body schemas. One closed list currently supplies the
twenty-nine codes for Error, snapshot acknowledgements and refused lease results.
It rejects `authority-unavailable` and `scope-mismatch` in every position.

## Proposal

Admit precisely these two additional strings in Error bodies, keeping the shared
list unchanged. Extend existing message and canonical controls and the independent
canonical vector producer. Keep the body exactly `{code: text}` and retain all
envelope, authentication, pending-request, grant and duration validation.

`authority-unavailable` means that another unexpired owner holds the addressed
service-control authority. `scope-mismatch` refuses the addressed NSD scope; it is
neither an Account credential failure nor a redirect. Both end the failed call and
authorize no automatic retry, recovery, reset, enrollment or scope substitution.

## Risks

Decoders at `9969abd8507ea3de057b0b870492755908206e89` and
`26e5aa7db741ea027df30799b1c9c3ff8f366b2e` reject both new codes. These responses
are not backward-compatible with those decoders. Compatible immutable decoder
revisions must be reconciled before a producer exposes these responses to them.
No downgrade or negotiation is added. The six-element RegistrationCondition,
Default M6 and Node-only L3 contracts remain unchanged.

## Scope

The service body validator, existing service message/canonical tests, canonical
vector producer and its generated fixture, and these records. No consumer
dependency, producer, carrier, runtime or deployment change is included.

## Alternatives

Extending the shared list would also admit the codes in snapshot acknowledgements
and lease results. Aliasing authority contention to storage failure or scope
mismatch to credential failure would lose the distinct refusal meanings.

## Validation

Run the extended existing message and canonical controls before correcting the
validator, retain the expected unsupported-field failures, then run them after
the correction. Run formatting and linting before tests, followed by the prescribed
self-check, including independent vector and compatibility checks.
