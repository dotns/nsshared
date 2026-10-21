# Shared participant credentials and directory bindings

- **status**: completed
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

## Acceptance

- Shared exporter label, context and proof bytes preserve the existing protocol.
- Enrollment and renewal have bounded operation frames, independent provisioned
  authority checks, exact client correlation and actual optional deadlines.
- Independent vectors cover initial signed admission, canonical relay report/ACK,
  realm withdrawal, complete-empty revocation and persisted-floor replay refusal.
- Directory binding signatures cover every field; supplied-clock acceptance,
  complete replacement, idempotence and scope checks are exercised.
- Existing roster/report/answer implementations, account/usage vectors and global
  directory implementation have no changes against the integration base.
- No TLS runtime, storage, credential-file custody or compatibility layer added.

## Validation

The first contract test compilation failed because the participant session and
binding APIs did not exist. After implementation, all four contract tests passed
against 61 independently generated vectors. Extending the sequence first failed
for its absent initial roster fixture, then passed with signed initial and empty
rosters and canonical report/ACK bytes. An additional invalid-key fixture was
corrected from the valid all-zero point encoding to the invalid y=2 encoding;
existing identity semantics were preserved.

`just fmt` and `just lint` passed before focused tests. The final
`just self-check feat/l8-account-profile` passed: 496 tests, zero skipped,
independent vector consistency, static checks, API compatibility, doctests and
warning-free documentation. NSD producer review and runtime adoption remain open.
