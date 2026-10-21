# Shared participant credentials and directory bindings

- **status**: in_progress
- **priority**: P1
- **createdAt**: 2026-10-21 04:47

## Description

Define shared participant enrollment, authentication, renewal and revocation plus
separate signed directory eligibility without changing directory or roster/report bytes.

## ActiveForm

Specifying and validating participant authority and directory bindings.

## Dependencies

None.

## Notes

Investigation: existing authentication uses exporter-bound Ed25519 proofs and
frame identifiers 1 through 6. The directory uses permanent nonzero u16 relay ids.
The implementation will preserve these contracts and add independent vectors
before codecs, with supplied trust, authorization, floors and clock only.
