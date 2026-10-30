# Independent service-label input boundaries

- **status**: completed
- **createdAt**: 2026-10-30 00:06
- **approvedAt**: 2026-10-30 00:06
- **relatedTask**: 20261030-0006-service-label-boundaries

## Context

Resource.service_label is a String field. Existing snapshot tests cover digit starts, internal hyphens, empty input, uppercase and invalid hyphen edges. Canonical bytes and digests already have independent assertions.

## Proposal

Add independent label fixture inputs for missing length, non-ASCII, separator and whitespace boundaries. Exercise them through recipient-qualified Snapshot::canonical/decode. Preserve existing cases and canonical fixtures. Update only the service-label inventory row.

## Risks

Snapshot validation coverage supplies neither a standalone public operation nor owner API agreement or NSD producer evidence.

## Scope

Service tests, one service fixture, the service-label inventory row and these records.

## Alternatives

A new public validator would change the contract and is excluded.

## Results

Added six independent label inputs: 63 ASCII bytes accepted, 64 bytes refused, and non-ASCII, dot, underscore and embedded-space inputs refused. Both snapshot encoding and decoding exercise these outcomes with existing recipient-qualified context. Existing cases and canonical snapshot bytes/digests are unchanged.

The service suite passed all 19 tests. Formatting and lint checks passed before test execution; `just self-check` passed. Diff review found no required corrections. Standalone API agreement/operation and NSD producer evidence remain open; no release is selected.
