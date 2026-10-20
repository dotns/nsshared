# feat: complete candidate control exchange

- **status**: completed
- **createdAt**: 2026-10-20 17:44
- **approvedAt**: 2026-10-20 17:44
- **relatedTask**: 20261020-1744-control-exchange

## Context

Enrollment has binding/lifecycle comparison; bootstrap already exposes signing
input. Existing machine bearer validation ignores audience, uses 30-second
expiry leeway and refreshes within 300 seconds. Token trust is pin-qualified,
realm/address owned, with immutable first-use pins. Wrong encryption-key use
is refused during qualification, independently of the thumbprint helper.

## Proposal

Specify canonical exchange tuples, extend enrollment with authenticated matching,
and add pure machine claim/key-set validation. Generate independent Python bytes
before implementation, then consume them in Rust with typed refusal checks.
Document every inventoried consumer disposition and outstanding producer review.

## Risks

Confusing receipt with accepted identity, audience verifier boundaries or token
pins with envelope pins would grant unintended authority. Keep explicit inputs.

## Scope

Protocol contract, vector producer/fixtures, consumer tests and documentation.

## Alternatives

A compatibility facade or runtime token/session owner would duplicate consumer
behavior and violate the pure-contract boundary.

## Acceptance

The candidate specification and independent Python producer preceded the pure
implementation. The consumer reads 66 independent vectors across registration,
authenticated acceptance, lifecycle replacement/rotation, authentication,
information, public claims and qualified keys. Typed scope, binding, profile,
capability, authority, lifecycle, audience-boundary, expiry and key refusals match.
Signing input equals the existing bootstrap bytes in both directions.
All 264 pinned inventory rows have dispositions, including four retained
historical fixture records. No runtime, dependency or publication-kind changes
were introduced; RSA signature execution and pin custody remain external.

The first consumer compilation failed with unresolved new exchange/claim imports.
A later retained-predicate vector rejected array-shaped NSD audience while the
implementation still accepted it; the comparison was corrected to match the
producer's string-shaped claims. Gateway array audiences remain accepted.
Leading-zero RSA component qualification remains unchanged, as confirmed against
the existing public qualifier. No additional unsigned-component policy was added.

`just dev-check` passed before tests. The focused six-test consumer passed, then
`just self-check feat/l8-account-profile` passed on
`88533c48c97d279277d673c7134e873d850568e6`: 455 tests passed, zero skipped,
41 selection tests passed, doctests and warning-free API documentation passed.
Formatting, lint, dependency policy, spelling, fixture regeneration and API
compatibility checks passed. Only these completion records changed afterward.

NSD producer confirmation, independently owned producer vectors and the possible
later gateway audience requirement remain open review inputs, not agreement.
