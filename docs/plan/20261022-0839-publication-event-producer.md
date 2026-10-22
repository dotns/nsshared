# 20261022-0839-publication-event-producer Publication event producer

- **status**: draft
- **createdAt**: 2026-10-22 08:39
- **approvedAt**: (pending clarification)
- **relatedTask**: 20261022-0839-publication-event-producer

## Context

`PublicationEvent::decode` validates structural fields and byte bounds. Channel ownership, completeness and typed profile payload checks occur later in `decide_publication`. The independent vectors include structurally valid events with a signed channel mismatch, partial content and unknown kinds.

## Proposal

Add canonical content encoding, domain-prefixed signing input and complete event encoding with a supplied signature. Preserve the wire format and keep private keys outside the crate. Extend independent vectors and document the producer revision.

## Risks

The requested round trip for every existing inner event conflicts with refusing channel ownership mismatches before encoding: `publication-signed-channel-mismatch` must both reproduce its bytes and be refused. Implementation is blocked until the round-trip domain is defined. Completeness, unknown-kind and typed profile payload validation also need an explicit producer policy because decoding and acceptance apply different checks.

## Scope

Publication producer API, account exports, independent vectors, tests and producer documentation.

## Alternatives

Either require exact round trips only for producer-valid content and assert refusal for decoded invalid content, or allow structural re-encoding and enforce ownership through a separate validated producer API. The former matches the requested refusal policy more closely.

## Annotations

No implementation has started. The wire contract remains unchanged.
