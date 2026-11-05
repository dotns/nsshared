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

## Documentation alignment

The primary M6 specification still describes Default as universally refused, including
disabled profiles. The account carrier summary still names explicit-only profiles and
requires the legacy decoder for every nonempty payload. These statements conflict with
the implemented complete-floor contract.

Align the M6 validation and consumer sections with canonical `[0]` for either enabled value,
retain explicit encodings and all custody comparisons, and link the compatible immutable
consumer requirements. Update the existing account carrier section to name both selection
variants and its complete-floor decoder. This is documentation only; the existing wire
shape, authority boundaries and acceptance criteria stay unchanged.

The primary M6 specification now permits canonical Default `[0]` for enabled and
disabled profiles, retains `DefaultExitUnsupported` for explicit-only consumers, and
links compatible immutable delivery requirements. The account carrier names both
selections and the complete-floor decoder. Existing explicit bytes, complete-floor
replacement, custody checks and grant boundaries remain unchanged.

Format and both workspace Clippy configurations passed. The updated tree passed
`just self-check`, including all 48 fixture files, API compatibility, 70 script tests,
424 default-feature tests and 590 account-feature tests, with zero nextest skips.
Doctests and documentation builds passed. This documentation-only change required no
new failing test; the original failing-first evidence remains applicable to the codec.
Local review found no remaining mismatch between these descriptions and the Default
contract. Only these detail records changed after the passing check.
