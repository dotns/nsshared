# Complete realm publication payloads

- **status**: completed
- **priority**: P1
- **createdAt**: 2026-10-20 16:20

## Description

Deliver canonical realm-peers collections and observation-only policy-version
content carried by the existing signed publication contract.

## ActiveForm

Completed complete membership replacement and diagnostic observation contracts.

## Dependencies

Existing NodeBinding, NodeRecord and signed publication contracts.

## Notes

Investigation and approved implementation proposal are recorded in
[the plan](../plan/20261020-1620-realm-publication-payloads.md).
The specification and 47 independently generated fixtures preceded the pure
implementation. The initial consumer test run failed with unresolved imports for
RealmPeers and PolicyVersion. The completed consumer suite passes all four tests.
The replacement sequence verifies malformed refusal without expiry renewal,
omitted-realm removal, valid empty withdrawal and rejection of older publications
after restoring the accepted version tombstone. Policy observations accept a lower
counter only under a newer authenticated publication and retain the previous
observation on malformed, wrong-scope or replayed input.

`just self-check feat/l8-account-profile` passed: 438 tests passed, zero skipped;
format, lint, vectors, dependency checks, API compatibility, doctests and strict
documentation checks passed. Scope is pure account types/validation, independent
vectors and documentation; no runtime, persistence implementation or M6 clone.
Producer confirmation and producer-owned vectors remain outstanding.
