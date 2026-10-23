# Publication stream and snapshot delivery

- **status**: in_progress
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

## Remaining work

`just self-check feat/l8-account-profile` stopped at `cargo deny`: the unchanged locked dependency ctutils 0.4.2 is affected by RUSTSEC-2026-0385; the advisory requires at least 0.4.4. Dependency resolution is outside this change's scope. The implementation remains in progress until the dependency is repaired and the complete self-check passes. Shared index and changelog updates are deferred to integration.
