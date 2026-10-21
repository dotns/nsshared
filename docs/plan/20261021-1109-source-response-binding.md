# Signed source authority in control responses

- **status**: completed
- **createdAt**: 2026-10-21 11:09
- **approvedAt**: 2026-10-21 11:09

## Context

Registration and authentication responses omit signed source authority. A separate
SourceAcceptance payload displaces their normal results and duplicates correlation.

## Proposal

Specify incompatible response tuples and independent producer vectors first.
Require SignedSourceBinding in every successful response, remove SourceAcceptance,
and verify nested authority against independent enrollment facts and pending nonce.
Extend source_selection_fence without changing publication or receipt semantics.

## Risks

Existing candidate consumers must adopt the incompatible arities. NSD adoption and
producer-owned interoperability evidence remain outstanding.

## Scope

Pure control exchange, source authority, independent vectors and candidate documents.

## Alternatives

A standalone payload or old-shape fallback loses the single response contract and
is excluded.

## Acceptance results

- Specification and independent Python producer vectors preceded implementation.
- `successful_responses_require_signed_source_binding` first failed with
  `registration must carry its signed source binding` against the previous decoder.
- Extended registration and authentication responses round-trip independent bytes;
  Initial, Equal, identity replacement and record rotation retain lifecycle checks.
- `source_selection_fence` accepts both normal results with nested signed authority,
  refuses missing/mismatched binding and wrong nonce, and preserves fixed Node
  identity, key and addresses, source replacement and immutable clear replay checks.
- The focused control exchange and source selection suites passed all 11 tests.
- `just fmt-check lint` passed. `just self-check` against the integration baseline
  passed on `a68401441b73228c1a77b7dd8ba27120d9a223c0`: 500 tests passed,
  zero skipped; independent vector consistency, API checks and doctests passed.
- Static review of the changed pure contracts, producers and consumer tests found
  no remaining defects. Production code adds no runtime, session or I/O behavior.
- NSD N04 adoption, producer-owned vectors and real interoperability remain open.
