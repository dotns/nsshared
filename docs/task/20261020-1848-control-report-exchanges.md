# Complete control report exchanges

- **status**: completed
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

## Floor text validation results

The floor wrapper now uses one bounded nonempty control-free data-text predicate
for metadata/Exit references, policy-label keys, accepted reference sets and
rejected references. Rejection reasons use the same predicate without changing
their existing meaning. Label values still allow empty strings within their
existing bound and control-character refusal. Capabilities retain enrollment's
64-item/64-byte token grammar. Raw UTF-8 ordering, uniqueness, request equality,
complete floor digests and exact per-kind outcome correlation remain unchanged.

The unchanged floor_preserves_private_declaration_keys tests first failed all
three assertions with InvalidField. Independent floor_data_text_vectors also
failed on spaces-request before the correction. The regression assertions were
not edited. The new independent fixture has 168 cases covering spaces, padding,
Unicode whitespace, NFC/NFD distinction, byte bounds, controls, capability syntax,
ordered sets and exact accepted/rejected acknowledgement correlation. Existing
public-edge.vec and control-reports.vec bytes are unchanged.

The focused regression, independent floor, public-edge and control-report suites
passed all 12 tests. The first complete self-check stopped at the spelling checker
on an escaped Unicode sample prefix. Equivalent Unicode samples corrected that
failure without changing regression assertions or check policy. The subsequent
`just self-check feat/l8-account-profile` passed at
`6356f815d7c8a7f0f3777a924b932025dd02b0b4`: 475 tests passed with zero skips,
41 check-selection tests passed, and all static/API/vector, doctest and documentation
checks passed. Only the completion records changed after that passing run.

The same-class inspection covered every floor text writer, bounded reader,
ordering check, digest and exact comparison. The shared policy token helper,
other token consumers and the unchanged M6 declaration validator were inspected
without changing their contracts; no additional confirmed finding remains.
NSD confirmation and producer-owned vectors remain outstanding.
