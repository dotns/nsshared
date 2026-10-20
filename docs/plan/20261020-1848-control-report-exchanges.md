# Complete control report exchanges

- **status**: implementing
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
