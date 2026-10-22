# Confidential certificate and client-CA acquisition

- **status**: completed
- **priority**: P1
- **owner**: protocol-maintenance
- **createdAt**: 2026-10-22 22:27

## Description

Deliver pure certificate/client-CA acquisition codecs and typed validation over
the existing confidential authenticated carrier. Independent vectors must prove
exact request/response bytes, kind agreement, pending echo and malformed refusals.
Auth configuration and installation ACK codecs remain unchanged.

## ActiveForm

Completed confidential material contracts and validation.

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Notes

Investigation and approved proposal are recorded in
[the plan](../plan/20261022-2227-confidential-material.md).
Specification and independent producer fixtures were committed before the pure
implementation. The first consumer build failed with unresolved imports for the
new module and operation constant, establishing the missing API before delivery.

Acceptance: 82 independent vectors cover both material kinds, exact canonical
bytes and signed carriers, realm/generation/echo refusals, kind disagreement,
malformed fields, hostname rules, bounds and unavailable-value refusals. The
consumer also checks actual fixture PEM fields, retained CA CRLs, Debug redaction
and the unchanged auth-only boundary. Focused material and auth tests passed;
the complete self-check repeated those tests successfully.

`just fmt-check lint` passed before behavioral tests. `just self-check` against
the integration baseline passed on implementation commit
`f435616c613219fda0f31c5fbcaf0a64d5775b87`: all static checks, API compatibility,
28 generated fixture checks, selection tests, 517 workspace tests with zero skips,
doctests and warning-free documentation passed. Subsequent changes affect only
these completion records.

The auth codecs/fixtures and installation ACK bytes remain unchanged. Current
custody, dependency, host coverage, trust-domain, clock and X.509 installation
checks stay external. NSD producer/dispatch adoption and producer-owned vectors
remain outstanding and are explicitly requested in the review package.

Local review covered the changed Rust, Python and contract documentation with
no confirmed findings. Shared documentation indexes and changelog remain for
integration bookkeeping.
