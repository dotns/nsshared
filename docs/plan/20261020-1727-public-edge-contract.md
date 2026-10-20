# Public edge, material and service operation contracts

- **status**: completed
- **createdAt**: 2026-10-20 17:27
- **approvedAt**: 2026-10-20 17:27
- **relatedTask**: 20261020-1727-public-edge-contract

## Context

Family 7 has a registry entry and signed stream carrier but no content codec.
Existing subject policies, JWT bindings and header policies are pure values.
M6 already owns service references, declarations, reports and listener intents.
Its snapshot Resource supplies the validated DNS service label.

## Proposal

Specify three bounded modules: public-edge realm contributions, material and
embedded auth metadata, and correlated service operations reusing M6 bytes.
Write independent Python producer vectors and Rust consumer tests before codecs.
Reject malformed and noncanonical complete replacements without advancing state.
Use M6 ServiceRef to resolve labels from authenticated snapshots. Keep standalone
label rows open for the M6 contract owner; no extra validator or M6 modification.

## Risks

A material ACK must not authorize another scope or generation. A valid identity
can still be the wrong publisher; consumers must join against snapshot resources.
Candidate fixtures are independent of Rust but are not NSD confirmation.

## Scope

Pure protocol modules, independent vectors, profile and review documentation.
No evaluator, transport, session, persistence or private-key serialization.

## Alternatives

A compatibility copy would duplicate identities and M6 serialization and is
excluded. Standalone service labels await the existing public API request.

## Acceptance

The specification and 76 independent candidate vectors accompany three pure
family modules. The two acceptance tests and four additional correlation,
dependency and replacement tests pass. The complete self-check at implementation
commit `673f5fc6ca8d793b9dbaf777669ff5e90918124a` passed, including 455 tests with
zero skipped and 41 check-selection tests. Existing M6 bytes remain unchanged;
standalone labels and OIDC carrier questions retain their explicit external
owners in the specification and review request.
