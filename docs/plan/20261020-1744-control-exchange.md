# feat: complete candidate control exchange

- **status**: implementing
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
