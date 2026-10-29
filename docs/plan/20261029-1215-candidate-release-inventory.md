# Candidate release and migration inventory

- **status**: completed
- **createdAt**: 2026-10-29 12:15
- **approvedAt**: 2026-10-29 12:15
- **relatedTask**: 20261029-1215-candidate-release-inventory

## Context

The current candidate adds versioned whole-floor M6 content and independently
tracked roster publication and attribution counters. Existing adoption evidence
predates these additions. Shared fixture coverage does not establish downstream
adoption, producer agreement or release readiness.

## Proposal

Map public types and existing vectors in the inventory, retain exact adoption
boundaries in the adoption and handoff records, and add minimal migration deltas.
Distinguish legacy byte preservation from extended-input support. Keep every
unanswered review, producer, live and release prerequisite open.

## Scope

Only account inventory, adoption, handoff and migration documentation changes.
No source, test, vector, dependency, feature restriction or release changes.

## Risks

Existing M6 and roster adoption could be misread as support for the new deltas.
Explicitly retain their separate consumer obligations and unset release cohort.

## Alternatives

Deferring all documentation until release would leave candidate consumers without
an accurate compatibility boundary. Candidate-only guidance supplies that boundary
without selecting a release revision.

## Validation

`just dev-check` passed before tests. `just self-check feat/r3-campaign-2`
passed on documentation commit `252f9b9`: format/lint, dependencies, typos,
48 fixture files, semver/API checks, 70 script tests, 421 default-feature and
579 account-feature tests (zero skipped), doctests and Rust documentation.
Only these completion records changed afterward. Local documentation review
found no remaining issue; no downstream or live qualification was performed.
