# 20261107-1808-exit-publication-validation Validate Exit observations at publication acceptance

- **status**: completed
- **priority**: P1
- **owner**: contract/20261107-1808
- **createdAt**: 2026-11-07 18:08

## Description

Integrate the existing readiness decoder into generic publication decisions and the nodes-only source guard. Establish failing public decision and Snapshot regressions first. Strengthen independent alias, observation correlation, confirmation expiry and collection-order vectors, and clarify role-specific expected facts without changing wire layouts. Run just qa and account-migration-check; update the existing PR with one push.

## ActiveForm

Validating readiness through every publication acceptance path.

## Dependencies

- **blocked by**: (none)
- **blocks**: Shared contract review acceptance.

## Notes

The requested revision is explicitly approved. Existing wire types, field order, domains and product shapes remain fixed. The original tests covered the dedicated validator but missed generic acceptance integration.

Six public-path tests failed behaviorally before the fix (exit 101), including positive FetchFailed, revision mismatch, malformed payload and both positive/empty foreign-source cases. After the two predicate changes, all 14 readiness tests pass through generic, plain Snapshot, source decision/single-and-multi Snapshot and authenticated response entry points. Four temporary mutations independently failed the conformance assertion: /10 modulo, removed challenge equality, removed provider-incarnation equality and removed confirmation-specific expiry. Original sources were restored in finally blocks.

The original 76 readiness records remain byte-identical; eight conformance records and nine signed publication-path cases were added. The contract and specification now distinguish independently held client inputs from remote NSD attestations. All DTO codecs, domains, report/subscription wire slots, Cargo manifests and lock are unchanged.

Complete just qa passed: 612 workspace tests, 71 script tests, all static checks, 50 vector fixtures, semver, doctests and warning-denied documentation. account-migration-check passed without changing the map. Final committed-head gates will be retained with the delivery report. The existing PR is https://git.pvv.cc/nsiod/nsshared/pulls/28; one push updates it after final verification. No merge, tag, release, lab or deployment action.

- complete: Publication integration corrected; behavioral RED/GREEN, four mutation checks, complete QA and migration check passed.
