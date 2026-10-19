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
vectors. The initial candidate `just self-check feat/l8-account-profile` selected the complete
`just qa` and passed with exit 0: 399 tests, 0 skipped, 10 check-selection tests
and 1 documentation test. Static checks, both vector generators, API compatibility
and documentation generation passed. Both roster carriers enforce atomic
identity/class attribution. The local validator requires string class values.
Existing M6 source and fixture bytes are unchanged.

The candidate schema remains subject to contract review. The reviewed integration
revision and documentation-site copy are pending. Only acceptance records changed
after the passing check.

## Named-object validation correction

Derived structs accept sequences unless their JSON entry points require maps.
Add a generic map-only deserialization wrapper for the root snapshot and each
identity/class entry. Forward map access directly to the existing derived
struct deserializers so duplicate and unknown fields are still rejected.
Retain all canonical CBOR array carriers. Verify the named-field regressions,
existing vector suite and equivalent JSON peers before completing acceptance.

The object-only correction is complete in source commit
`e46d8481e8b32cbca07febb989734b60fd3dbeb4`. Both root and entry arrays fail,
while valid objects and all existing semantic checks remain accepted or rejected
as specified. Direct map forwarding preserves duplicate keys for validation.
The same-shape audit found no other affected JSON boundary; rendezvous and its
directory consumers already protect object shape. M6 and canonical CBOR arrays
remain unchanged.

Formatting and lint passed before the focused tests (3 named-field tests plus
6 candidate tests, all passed). The final source self-check exited 0, selecting
complete QA: 402 tests passed, 0 skipped; 10 check-selection tests and 1
documentation test passed. Static checks, vector drift, API compatibility and
documentation generation passed. Only the two acceptance records changed afterward.
