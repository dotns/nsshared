# Default Exit floor encoding

- **status**: completed
- **createdAt**: 2026-11-05 12:50
- **approvedAt**: 2026-11-05 12:50
- **relatedTask**: 20261105-1250-default-exit-floor

## Context

`ExitSelection::Default` exists, but both profile encoding and decoding refuse it.
Floor v1 already uses selection tag 1 for explicit CIDRs and reserves tag 0 for Default.
The complete report digest, authenticated carrier and acknowledgement bind all floor content.
The independent Python fixture producer currently classifies Default as invalid.

## Proposal

Encode Default as the exact one-element CBOR array `[0]`; retain `[1, prefixes]` unchanged.
Decode only those exact shapes and retain all reference, scope, order, size and CIDR checks.
Extend independent complete-floor, message and signed-envelope fixtures with Default cases,
malformed selection refusal and unchanged explicit controls. Document immutable consumer
pins and refusal of unsupported tuples without adding authority or capability fields.

## Risks

Floor v1 alone cannot identify Default support: old explicit-only decoders refuse `[0]`.
Publication is configured intent and supplies no grant. Runtime authorization remains separate.

## Scope

Floor codec, floor integration tests, independent fixture producer and generated floor fixture,
service contract documentation and these detail records.

## Alternatives

A version bump, capability bit or parallel report would alter the existing contract unnecessarily.
Silently rewriting Default to explicit prefixes would lose the selection's meaning.

## Validation

The failing-first floor suite reported five passing and five failing tests. The new
`independent_default_floor_round_trip_and_digest` test failed with
`DefaultExitUnsupported`; authenticated Default and digest-correlation cases also failed
before the codec change. No product code had changed at that point.

After implementation, `just fmt-check` and both workspace Clippy configurations passed.
`just self-check` passed all static checks, all 48 generated fixtures, API compatibility,
70 script tests, 424 default-feature tests and 584 account-feature tests. Both nextest
configurations reported zero skipped tests. Doctests and documentation builds also passed.
The existing ignored doctest remained unchanged.

The explicit floor bytes, digest, message and signed-envelope fixtures are unchanged.
The previously refused Default fixture is now the positive fixture without byte changes.
Malformed and unknown selections retain refusal; Default and Explicit both retain complete
floor digest, authenticated correlation, identity, scope, runtime and profile validation.
Mixed and disabled Default profiles round-trip, with duplicate and unordered profiles refused.

Local diff review covered the codec, independent producer, fixture, tests and contract
documentation. No unresolved correctness or compatibility finding remains within this
schema scope. Runtime grant issuance, enrollment, routes and NAT are separate consumers.
No dependency pins or deployment state changed.
