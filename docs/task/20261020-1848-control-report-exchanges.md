# Complete control report exchanges

- **status**: in_progress
- **priority**: P1
- **owner**: control-report-exchanges
- **createdAt**: 2026-10-20 18:48

## Description

Complete heartbeat, gateway observation, service, usage and material status
operations using existing confidential signed envelopes. Preserve exact correlation
and all retained floor metadata, with independent canonical/refusal vectors.

## ActiveForm

Completed pure report contracts and independent vectors.

## Dependencies

- **blocked by**: none
- **blocks**: candidate report consumers

## Notes

Investigation and approved implementation scope are recorded in the linked plan.

## Acceptance

The independent Python report producer and Rust control_report_contract_vectors
consumer cover every operation request/response, authenticated signing inputs,
unknown operations, noncanonical bytes, oversized lists, exact material/confidential-auth
request correlation and relay-only UnknownMapping refusal on service reports.
Material payload acquisition remains separately owned; installation is an external
actual-effect obligation, never derived from a receipt. Service kind 1 includes
complete metadata/Exit declarations and exact per-reference outcomes with reasons;
missing/unknown outcomes produce distinct typed refusals. Other public-edge bytes
remain unchanged: 145 fixture vectors are identical, with exactly six report-related
vectors updated. These are candidate fixture observations, not NSD agreement.

Failing first: `cargo test -p nsshared-proto --test public_edge_vectors
material_declaration_vectors --locked` failed for request-1 with
`ArrayLength { expected: 9, actual: 11 }` before the service codec extension.
A prior invocation lacked the toolchain PATH and exited before running tests;
with the configured PATH the expected behavioral failure was observed.

Verification: `just fmt-check lint` passed before behavioral tests.
The focused public-edge and report suites passed all eight tests.
`just self-check feat/l8-account-profile` passed at
`367a714156a27ec985d75ba0acb84d32f1294749`: full static/API/vector checks,
41 check-selection tests, 469 runtime/contract tests with zero skips, doctests
and documentation. Only these completion records changed after that passing run.
The local Rust/Python diff review found no remaining issue within this scope.

NSD confirmation and producer-owned vectors remain outstanding. No runtime,
I/O, confidential auth acquisition payload or new dependency was added.

## Floor text preservation

Investigation: the floor wrapper reused policy_subject's whitespace-free token
predicate for declaration references, Exit references, policy-label keys and
outcome reference sets. Valid unchanged M6 keys and control-free data text with
internal spaces were therefore rejected before exact correlation.

Approved correction: apply one local bounded nonempty control-free data-text
predicate consistently to floor requests and outcomes, preserving exact UTF-8
bytes. Retain existing capability-token validation, byte/list bounds and strict
ordering/uniqueness. Add independent accepted/refused request/answer vectors,
including exact matching and normalization-mismatch controls. Preserve the
existing floor_preserves_private_declaration_keys regression assertions.
