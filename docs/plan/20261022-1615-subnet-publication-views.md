# 20261022-1615-subnet-publication-views Subnet publication views

- **status**: implementing
- **createdAt**: 2026-10-22 16:15
- **approvedAt**: 2026-10-22 16:15
- **relatedTask**: 20261022-1615-subnet-publication-views

## Context

Family 4 currently registers only provider exit-grants. Standalone B40 route
publications already validate route ordering, membership IDs and client consistency.
The source carrier compares exact independently retained bindings before decisions.

## Proposal

Document the two typed kinds first and generate independent signed fixtures.
Add snapshot subnet-routes with its separate replacement rule. Dispatch payloads
by kind and compare accepted identity, membership and event revision independently.
Require nodes source scope for Exit views and egress scope for Egress grants.
Keep existing route and grant encodings unchanged.

## Risks

Same-family payload confusion and accidental withdrawal across collections require
negative vectors and a multi-provider replacement sequence.

## Scope

Pure publication contracts, independent vectors and specification/review documents.

## Alternatives

A family-only decoder cannot distinguish provider grants from client route views.

## Annotations

Implementation is approved. NSD projection and client route installation remain external.
