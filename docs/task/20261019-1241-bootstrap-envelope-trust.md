# Bootstrap discovery and envelope trust

- **status**: in_progress
- **priority**: P1
- **createdAt**: 2026-10-19 12:41

## Description

Detail discovery and envelope verification within family 11, preserving confidential
endpoint order, transport and signing pins, signatures, opaque service-control bytes
and canonical size/time bounds. Independently generated decisions must cover trust
downgrades, malformed encodings and supplied-clock boundaries.

## ActiveForm

Implementing bootstrap trust contracts and independent consumer vectors.

## Dependencies

Enrollment binding and the existing service-control message codec.

## Notes

The implementation is approved. The plan records investigation, proposal and risks.
Acceptance: bootstrap_envelope_vectors and trust_downgrade_refusals, deterministic
vector regeneration and the scoped self-check.

## Implementation and verification

- Specified discovery and authenticated opaque carriers within registry family 11.
- Added pure discovery, ordered endpoint selection, pin intersection, signature,
  recipient, kind, supplied-clock and replay-observation validation.
- Added 100 independently generated vectors, preserving all 106 earlier entries.
- Updated Q11 and Q21 with forms, signature domains, limits and producer requests;
  their dispositions remain prepared.
- The initial consumer build failed on missing required bootstrap APIs, establishing
  the missing interface before implementation.
- The focused account/bootstrap suites passed ten tests. The bootstrap tests cover
  typed refusals, construction, canonical-byte preservation and altered encodings.
- Format/lint, vector regeneration, static checks, API compatibility and the first
  complete scoped self-check passed; that run reported 410 passed, zero skipped.
- Final scoped self-check: failed, exit 100, in the unchanged
  external_mode_announces_wss_without_a_tcp_listener at
  examples/mock-relay/tests/external.rs:269 (AddrInUse). It reported 35 passed,
  one failed, zero skipped, cancelling the remaining tests.

## Remaining acceptance

Implementation is ready for review; final acceptance is blocked by the unrelated
relay test bind failure. Diagnose its socket ownership and underlying cause, then
complete the scoped check without weakening the test or adding retries. The exact
failure and preceding pass are retained outside the repository. Independent NSD
producer confirmation remains requested in the prepared review questions.
