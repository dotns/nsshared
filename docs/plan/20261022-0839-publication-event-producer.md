# 20261022-0839-publication-event-producer Publication event producer

- **status**: completed
- **createdAt**: 2026-10-22 08:39
- **approvedAt**: 2026-10-22
- **relatedTask**: 20261022-0839-publication-event-producer

## Context

The decoder checks structural fields and byte bounds. Channel ownership,
completeness and typed payload acceptance are separate consumer decisions.
Independent vectors include unknown kinds, signed channel mismatches and partial
content, so producer round trips distinguish valid content from producer refusals.

## Proposal

Expose PublicationContent::canonical and signing_input, encode_publication with
a supplied signature, and exact PublicationEvent signature/input accessors.
One shared validation path refuses unknown registry pairs, ownership mismatch,
invalid scope/kind lengths, zero version, invalid validity, invalid FetchFailed
kind/payload and complete-event overflow. Known partial content remains valid;
family payloads stay opaque. Preserve decoder, decision and wire behavior.

## Risks

Producer acceptance does not authenticate supplied signatures or validate family
payloads. Producers must use family codecs and retain private signing keys.
Consumers continue to authenticate and apply independent acceptance context.

## Scope

Publication module and exports, independent Python vectors, Rust producer tests,
payload profile, source publication specification and review request.

## Alternatives

A separate structural encoder is unnecessary; every producer entry point uses
the same validated content encoding.

## Annotations

Specification and independent fixtures were extended before implementation.
The focused producer and existing decoder vector tests both pass. Final self-check passed all static checks, API compatibility, documentation
and 504 tests with zero skips.

## Acceptance results

`publication_event_producer` passes independent byte equality and matching
refusal cases, including partial and opaque payload acceptance. A test-key
signature verifies through decide_publication. Existing decoder vectors pass
unchanged. The initial test compilation failed on absent producer APIs before
implementation; focused tests and the final self-check both pass afterward.
Local source and test review found no actionable defects. Independent fixtures
remain contract evidence, not live NSD interoperability.
