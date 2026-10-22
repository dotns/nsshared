# 20261022-0839-publication-event-producer Publication event producer

- **status**: in_progress
- **priority**: P1
- **owner**: (unassigned)
- **createdAt**: 2026-10-22 08:39

## Description

Expose canonical signed content, domain-separated signing input and complete
inner event encoding using a producer-supplied signature, with unchanged bytes.

## ActiveForm

Verifying validated publication producers.

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Notes

Investigation distinguishes structural decoding from producer registry validation
and consumer acceptance. The approved boundary permits known partial content and
opaque family payloads, and refuses unknown pairs and signed channel mismatches.
Specification and independent Python fixtures preceded executable implementation.

The first compilation of publication_event_producer failed because
encode_publication and canonical/signing_input/signature methods were absent.
After implementation, formatting and workspace lint pass. Both
publication_event_producer and publication_decoder_vectors pass, covering exact
bytes, domain inputs, signature acceptance, partial and opaque payload acceptance,
matching refusal errors, exact-limit acceptance and one-byte overflow refusal.
Final self-check remains pending. Shared indexes and changelog are unchanged.
