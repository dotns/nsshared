# Publication stream and snapshot delivery

- **status**: completed
- **priority**: P1
- **owner**: publication-delivery
- **createdAt**: 2026-10-23 09:05
- **approvedAt**: 2026-10-23 09:05

## Context

The snapshot carrier currently decodes plain PublicationEvent entries, while source snapshots already enforce exact independently accepted bindings and delivery context. Stream framing identifiers and expansion bounds need shared definitions.

## Proposal

Define publication event/query constants and derived inclusive bounds beside control exchange constants. Specify and independently generate source-bound snapshot carriers and stream boundary vectors before changing pure validation. Replace the response validator with exact pending scope/source checks and request-derived delivery context, then validate the complete ordered container before returning decisions.

## Risks

The response API deliberately rejects plain and mixed entries. Snapshot entries retain the decoded publication ceiling independently of stream framing. SourcePublication signatures, directory payloads and M6 carriers stay unchanged.

## Scope

Protocol constants, pure snapshot validation, independent vector producers/consumers and publication specifications.

## Alternatives

A second response form or compatibility fallback would weaken the single response contract and is excluded.

## Acceptance

Verify framing expansion and LF/CRLF boundaries, correlated large source-bound snapshots, directory and unknown-kind ordering, and atomic refusal for invalid source, context or encoding. Run formatting, lint and the scoped self-check.

## ActiveForm

Implementing publication delivery contracts and vectors.

## Dependencies

- **blocked by**: none
- **blocks**: none

## Validation results

- The initial `snapshot_carrier_refuses_plain_entries` run failed with `plain publication response must be refused`, establishing that the previous carrier accepted the forbidden plain form.
- Formatting and workspace Clippy passed before test execution, including after the final changes.
- The final focused protocol run passed all 11 tests across publication delivery, snapshot request vectors, plain response refusal, unknown-kind retention, stream ownership and source selection. No tests were ignored.
- `just vectors-check` confirmed all 32 independently generated fixture files are current.
- Stream fixtures cover the exact decoded ceiling with LF and CRLF, the inclusive CRLF framing ceiling, an over-framing event and an LF event whose decoded bytes exceed the ceiling while framing remains within its ceiling.
- Snapshot fixtures cover an 800,000-byte payload alongside directory and unknown Snapshot entries, two independently accepted scopes, and whole-response refusal for plain, mixed, miscorrelated, stale-source, wrong-delivery, unordered, duplicate and oversized entries.
- Existing source-publication/source-binding implementations, source-selection fixtures and M6 carrier implementation/fixtures have no changes. The directory fixture reuses the existing directory payload with numeric id 17 and code HK.
- Local review found no additional implementation defect. The intentional response API change requires independently retained current sources and returns a complete validated collection of borrowed-event decisions.

## Initial qualification failure (resolved)

`just self-check feat/l8-account-profile` stopped at `cargo deny`: the unchanged locked dependency ctutils 0.4.2 is affected by RUSTSEC-2026-0385; the advisory requires at least 0.4.4. Dependency resolution is outside this change's scope. This initial failure is retained as history. After integrating the upstream dependency repair, the complete self-check passed as recorded below. Shared index and changelog updates are deferred to integration.

## Adoption wording and qualification history

The review request directly identifies the NSD N09 producer and Node S23 adapter. Their adoption remains outstanding, and fixture bytes and shared delivery do not record agreement. This wording correction changes no implementation. Dependency repair remains separate; no lockfile, manifest or advisory policy is changed. At that point, full qualification remained pending until the dependency repair was integrated, the branch synchronized and one complete self-check passed. The candidate is ready for source review and independent conformance after the scoped static and focused checks.

After the wording correction, `just fmt-check`, workspace `just lint`, `just vectors-check` and the same six focused protocol test binaries passed: 32 fixture files current, 11 tests passed and none ignored. Source review and independent conformance may proceed; full qualification and completion were still pending the synchronized complete self-check.

## Pending request encoding boundary

A publicly constructed pending request could satisfy scope and field rules while exceeding the canonical 8192-byte request ceiling, then accept an authenticated empty response. The response validator will call the full request encoder before carrier validation. Independent fixtures will cover an accepted 8192-byte request and a refused 8193-byte request with individually valid scopes and an authenticated empty response. Existing source/scope equality, authentication, correlation and atomic decisions remain unchanged. Equivalent pending-response paths will be checked for canonical encoded bounds. Qualification was held pending the complete self-check after synchronization with the dependency repair.

## Completed qualification

The complete pending request is now canonicalized before a response can be accepted, enforcing the inclusive 8192-byte total ceiling as well as semantic bounds. The supplied `empty_poll_refuses_a_pending_request_that_cannot_be_encoded_within_its_limit` test failed before the fix and passed after it; its file, controls and assertions are unchanged. Independently generated 8192-byte and 8193-byte fixtures use 32 valid sorted scopes and the same authenticated empty response: the boundary succeeds and the over-bound pending request is refused.

Formatting, workspace Clippy, vector consistency and all 13 focused tests passed, with no ignored tests. All 33 protocol fixture files are current. The complete `just self-check feat/l8-account-profile` passed at commit `dd2007e32875850e9ca9ff9bc1559d54c159145e`: 532 tests passed, zero skipped; doctests and workspace documentation also passed. Only these qualification records changed after that run. The earlier advisory failure is historical evidence, not a waiver; the synchronized upstream dependency repair is retained without independent dependency or policy changes.

Equivalent pending-response paths were inspected: registration, confidential auth/material acquisition, heartbeat/gateway/material receipts, edge service acknowledgements, Node L3 status, provider route reports, route receipts and usage answers already canonicalize their pending requests and enforce their encoded ceilings. Subscription decoding retains its 8192-byte limit. M6 pending requests have private fields and can only be built from authenticated bounded carriers; participant pending correlations and delivery contexts have fixed-size fields. No additional confirmed instance was found. Source/scope equality, carrier trust, correlation and whole-container source decisions are unchanged.

The implementation and qualification are complete. External NSD producer and Node adapter adoption remains outstanding and is not inferred from fixture conformance. Shared index and changelog entries remain for integration.
