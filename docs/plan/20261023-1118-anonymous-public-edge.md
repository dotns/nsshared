# Explicit anonymous public-edge selectors

- **status**: implementing
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

Investigation and proposal complete; implementation authorized. Shared indexes
and changelog are left for integration.
