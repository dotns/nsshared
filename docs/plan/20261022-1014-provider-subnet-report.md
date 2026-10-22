# Provider Subnet route report

- **status**: implementing
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
