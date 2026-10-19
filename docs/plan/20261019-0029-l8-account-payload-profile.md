# L8 account payload profile

- **status**: completed
- **createdAt**: 2026-10-19 00:29
- **approvedAt**: 2026-10-19 00:29
- **relatedTask**: [Account payload profile](../task/20261019-0029-l8-account-payload-profile.md)

## Context

The protocol crate already supplies identity derivation and canonical array CBOR.
The service-control crate supplies the complete M6 lineage. Admission currently
has a controlled-file JSON carrier without attribution classes or a roster epoch.
The maintenance policy permits a new pure module at the workspace minor version.

## Proposal

Specify the candidate before implementing an `account` module. Add a typed
family registry, distinct lifecycle counters and opaque incarnations, normalized
Node L3 scopes/rules, service byte units and an explicitly unset loss window.
Provide strict JSON admission validation and an independently signed participant
roster with atomic membership/class attribution. Generate candidate fixtures
independently in Python and decode them in Rust tests. Keep M6 bytes untouched.

## Risks

A missing list must never revoke authority. Incarnations cannot be numerically
ordered. Roster rollback and recipient confusion require caller-supplied trust,
time and version bounds. An unset loss window cannot be treated as zero.

## Scope

The protocol module, its tests and vectors, generator registration, architecture
link and account specification. No runtime, state machine or compatibility code.

## Alternatives

Embedding M6 objects would require a crate dependency without adding semantics
at this candidate layer. Instead the registry references their existing public
names and fixture location; detailed family contracts compose them later.

## Annotations

Implemented the pure account module and 50 independently generated candidate
vectors. The final `just self-check feat/l8-account-profile` selected the complete
`just qa` and passed with exit 0: 399 tests, 0 skipped, 10 check-selection tests
and 1 documentation test. Static checks, both vector generators, API compatibility
and documentation generation passed. Both roster carriers enforce atomic
identity/class attribution. The local validator requires string class values.
Existing M6 source and fixture bytes are unchanged.

The candidate schema remains subject to contract review. The reviewed integration
revision and documentation-site copy are pending. Only acceptance records changed
after the passing check.
