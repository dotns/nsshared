# 20261107-1808-exit-publication-validation Validate Exit observations at publication acceptance

- **status**: completed
- **createdAt**: 2026-11-07 18:08
- **approvedAt**: 2026-11-07 18:08
- **relatedTask**: 20261107-1808-exit-publication-validation

## Context

The generic decide_publication chain omits the existing readiness payload decoder. Plain and source-bound Snapshot delegates therefore accept invalid readiness payloads. The source wrapper omits this kind from its nodes-only guard. The dedicated tests bypassed both entry points.

## Proposal

Write independent signed fixtures and failing tests through generic decisions, plain/source Snapshot APIs and the authenticated snapshot response. Wire the existing decoder and source-kind guard into their existing chains. Extend conformance vectors to distinguish the /11 alias pool, foreign observation IDs with an unchanged digest, a shorter confirmation expiry and two-selection ordering. Add a role table distinguishing independently held client facts from NSD attestations.

## Risks

Whole-Snapshot refusal must happen before any action is exposed. No wire layout, domain label, owner fence or authority check may change. Dedicated exact-source/membership validation remains mandatory after generic acceptance.

## Scope

Two existing production predicates, focused tests/vectors, normative clarification and PMA records. Full just qa and migration check on the final head, one push to the existing PR, no merge or release.

## Alternatives

Leaving checks only in consumers would retain the shared API inconsistency and is rejected. Adding new wire fields or a discovery stream is unnecessary and outside scope.

## Annotations

The requested fixes and conformance clarification were approved before implementation.

Verification: six behavioral failures before the fix, all 14 readiness tests green afterward, four conformance mutations detected, unchanged prior vectors and wire codecs, and full QA/migration check passed. Final head is verified before the single PR update push.
