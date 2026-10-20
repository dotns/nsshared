# Complete control report exchanges

- **status**: completed
- **createdAt**: 2026-10-20 18:48
- **approvedAt**: 2026-10-20 18:48
- **relatedTask**: 20261020-1848-control-report-exchanges

## Context

The existing control exchange has registration/authentication/information only.
Usage, material acknowledgement and M6 service bodies already have pure codecs.
The service floor requires explicit Exit declarations, metadata and per-reference
outcomes; a whole-report boolean cannot acknowledge individual references.

## Proposal

Specify report tuples and predecessor dispositions in control-report-candidate.md.
Generate independent Python bytes before implementing Rust codecs. Extend only
report-kind EdgeServiceRequest/Response bytes, retaining unchanged M6 bodies.
Reuse SubnetSelection for non-authoritative Exit profile declarations. Authenticate
all report operations through the existing envelope and sole signing-input API.
Keep auth configuration acquisition separate and correlate its material status to
its exact pending request. Validate unknown-mapping answers only for relay reports.

## Risks

Service report bytes explicitly change; consumers must adopt the candidate delta.
Receipt, declaration and observation must never become installation or authority.
Producer review remains outstanding and cannot be inferred from fixture acceptance.

## Scope

Pure account contracts, independent producers/consumers and candidate specifications.

## Alternatives

A duplicate service-floor contract would split ownership and is excluded.

## Results

All five pure report exchanges and the existing service report extension are
implemented. `control_report_contract_vectors` and the affected public-edge tests
pass. The complete self-check passed with 469 tests and no skips, 41 check-selection
tests, API compatibility, static/vector checks, doctests and documentation.
The review request pins the exact source/fixture candidate revision and keeps NSD
confirmation outstanding. Material correlation uses the entire reference, realm,
generation and exact pending request id; private auth request/response acquisition
is separate.

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
