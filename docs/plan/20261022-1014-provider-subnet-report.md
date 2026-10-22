# Provider Subnet route report

- **status**: completed
- **createdAt**: 2026-10-22 10:14
- **approvedAt**: 2026-10-22 10:14
- **relatedTask**: 20261022-1014-provider-subnet-report

## Context

SourceBinding supplies signed, profile-qualified nodes authority. SubnetSelection
already defines canonical default and explicit prefix sets. ServiceRef remains
an M6 object. No existing provider report expresses complete offered-route custody.

## Proposal

Specify the report and response before independent Python fixtures and Rust code.
Add bounded canonical codecs, request/response carrier checks and pure decisions
against caller-supplied current source, committed mappings and retained history.
Compare stable allocations even after withdrawal; never allocate or persist here.

## Risks

Confusing source scopes or mapping ownership could grant unintended authority.
Discarding withdrawal history could restore stale offers or replace references.
Exact comparisons and a restart/retirement sequence cover these boundaries.

## Scope

Protocol crate, independent vector producer, fixtures and candidate documentation.

## Alternatives

Runtime ingestion and allocation belong to external consumers and are excluded.

## Annotations

Implementation is approved together with the contract requirements.

## Acceptance

The specification and independent Python fixture producer preceded the Rust API.
The complete provider sequence and five focused companion tests pass. Response
comparison retains accepted generation/content as well as allocation history, so
a delayed response cannot restore withdrawn offers even within the current source.
The self-check passed formatting, workspace lint, dependency policy, spelling,
all 26 independent fixture files, API compatibility, 510 tests without skips,
doctests and documentation generation. No runtime, allocation or persistence was
added. Source implementation is recorded at `7e84ad5543f8265ed41f0c099f17dd2d37dc7157`.
