# Signed source authority in control responses

- **status**: completed
- **createdAt**: 2026-10-21 11:09
- **priority**: P1

## Description

Carry signed source authority alongside every successful registration result and
authentication token. Refuse missing or mismatched binding and wrong correlation.

## ActiveForm

Extending response contracts and verifying independent vectors.

## Dependencies

None.

## Notes

Investigation: existing response arities are five and two; SourceAcceptance has
its own three-field payload and whole-envelope decoder. The approved proposal
replaces these with six and three fields, retaining existing normal-result checks.

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
