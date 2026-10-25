# Explicit anonymous public-edge selectors

- **status**: completed
- **priority**: P1
- **createdAt**: 2026-10-23 11:18
- **approvedAt**: 2026-10-23 11:18

## Context

SubjectRule currently uses optional PolicySubject values. A sole null admits
verified principals only; there is no representation for anonymous visitors.
Family 7 embeds SubjectPolicy unchanged. Existing group, realm, order and
material validation must retain their meaning.

## Proposal

Specify SubjectSelector with AnyVerified, Subject and Anonymous variants.
Preserve null and qualified subject bytes; encode Anonymous as the byte string
820103. Publish independent policy and HTTP/TCP/UDP fixtures before implementing
the pure codec. Document the matching truth table and required Auth dependency
semantics without adding a runtime evaluator.

## Risks

This extends the accepted wire domain and changes the candidate SubjectRule API.
Older consumers must reject Anonymous. Missing authentication input must never
be promoted to anonymous, and required material dependencies remain mandatory.

## Scope

SubjectPolicy and its public export, affected contract tests, independent vector
producer and fixtures, account profile, public-edge and confidential-auth
specifications, and the review request.

## Alternatives

A new PolicySubject namespace or route bypass would conflate identity with
anonymous authorization and is excluded.

## Acceptance

Verify unchanged existing bytes, explicit selector decoding, mixed ordered sets,
invalid encodings and ordering, matching outcomes, and family 7 no-Auth routes.
Run format and lint before focused tests, then the scoped self-check.

## Progress

Investigation, proposal, implementation and validation are complete. Shared
indexes and changelog are left for integration.


## Verification

The failing-first `anonymous_public_edge_vectors` test rejected the independently
encoded Anonymous policy with `anonymous: Err(InvalidField)` before the codec
change. The implemented codec accepts its exact bytes and continues rejecting
null mixed with other selectors, noncanonical/unknown selector encodings,
unordered sets and invalid destination/protocol values.

The independent producer now supplies 88 fixtures, including 42 documented
matching outcomes and 18 HTTP/TCP/UDP route fixtures. Anonymous remains rejected
as a PolicySubject, credential binding, group member or admin principal. Required
Auth materials still require exact installation acknowledgement even when the
route policy contains Anonymous. Existing policy and public-edge fixtures retain
their bytes; the existing typed group-field assertion retains its property.

`just fmt-check lint` passed before tests. The focused anonymous, policy/claims
and public-edge suites passed all 13 tests. `just self-check` against the accepted
comparison base passed on source revision
`5c0e45dc64fcc123ff01e29ddc65e3c803002b0b`: 535 tests passed with zero skips,
41 selection tests passed, doctests and documentation passed. Static checks,
independent vector regeneration, dependency checks and API compatibility passed.
The local Rust/Python diff review found no remaining correctness or scope issues.
Only these completion records changed after that passing source revision.

## Remaining work

External NSD producer adoption remains outstanding; fixture output does not
establish external agreement or interoperability. No runtime evaluator or
authentication implementation is included.
