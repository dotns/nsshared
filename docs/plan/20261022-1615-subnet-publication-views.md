# 20261022-1615-subnet-publication-views Subnet publication views

- **status**: completed
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

## Acceptance

- `subnet_publication_views` consumes 23 independent signed events: seven accepted
  snapshots and sixteen refusals. Exact-key collection assertions preserve Q and
  the client view when P withdraws, retain Q on client omission, and preserve Q's
  grant on client withdrawal. Both payload types round-trip to the independent bytes.
- Kind swaps, wrong recipient/source/source Node/scope, NSD/Network/revision
  mismatches and nodes substitution for Egress are refused.
- The failing-first test reached `subnet-routes must be registered` before the
  implementation. An initial invalid constructed test identity was corrected to
  the RFC 8032 public key before establishing that behavioral failure.
- `just fmt-check lint` passed. Focused publication, source and route view suites
  passed. `just self-check feat/l8-account-profile` passed on implementation commit
  `83a8e60`, including static checks, vectors, API compatibility, tests and docs.
- Local Rust/Python diff review found no remaining correctness defects.
- NSD N07/N08 projection and producer vectors, and ns installation/adoption remain
  external. Shared index and changelog entries are maintained separately.
