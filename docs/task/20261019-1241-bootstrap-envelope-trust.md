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
- Earlier scoped self-check: failed, exit 100, in the unchanged
  external_mode_announces_wss_without_a_tcp_listener at
  examples/mock-relay/tests/external.rs:269 (AddrInUse). It reported 35 passed,
  one failed, zero skipped, cancelling the remaining tests.

- A subsequent `just self-check` invocation with the integration base passed on
  the unchanged implementation at `6fbb1eccd34516ced170c043b538db815fbe003a`:
  410 tests passed, zero skipped, all doctests and static checks passed, exit 0.
  Vector verification reported all nine fixture files up to date.

## Completion and remaining producer review

The initial candidate contracts, independent consumer vectors and verification
were completed; the canonical IDNA origin correction below remains outstanding. The previous failed bind's socket ownership and cause
remain undetermined; its failure evidence is retained, and listener code and
runtime/test settings are unchanged. Independent NSD producer confirmation
remains requested in Q11 and Q21, whose dispositions remain prepared.

## Canonical IDNA origin validation

The preserved behavioural test `ascii_idna_origins_reject_invalid_a_labels` passes
its valid DNS/IDNA controls, then fails because malformed A-labels are accepted
through decoding, canonical encoding, endpoint selection and effective pin
establishment. This affects the HTTPS discovery source and all three confidential
endpoint kinds through their shared `canonical_host` predicate. The failure was
recorded before any validator correction.

A standards-conformant IDNA dependency and exact ASCII roundtrip validation are
required; the dependency declaration is not yet present. The product validator is
unchanged, and no denylist or blanket A-label refusal has been introduced.

Upstream Subnet registrations and test kinds were retained, and the shared fixture
was regenerated from the merged producers. All 206 earlier account vector records
and 158 integrated records are preserved field for field in the 258-record result.
The registry and M6 files are unchanged. Formatting/lint and ten existing focused
account/bootstrap tests pass. The IDNA behavioural assertion remains failing.

The latest scoped self-check exits 101 in the telemetry API compatibility baseline
because fetching serde from the registry fails with an unexpected connection EOF.
It does not run the test phase. Earlier listener-bind failure evidence remains
retained and its cause is still undiagnosed. Independent NSD producer questions
and their prepared dispositions remain unchanged.

Remaining work: declare the IDNA dependency, fix the shared hostname predicate,
extend independent origin vectors, retain valid DNS/IDNA controls and require typed
Origin refusals through all four public paths, then complete the focused and scoped
checks. A separate ASCII-only RelayId DNS predicate also requires contract review;
that implementation is unchanged.
