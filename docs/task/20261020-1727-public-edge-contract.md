# Public edge, material and service operation contracts

- **status**: in_progress
- **priority**: P1
- **owner**: public-edge-contract
- **createdAt**: 2026-10-20 17:27

## Description

Deliver complete scoped public-edge contributions, generation-qualified material
references, embedded subject policy and correlated M6 service operations.
Independent producer and consumer vectors cover preservation, replacement,
withdrawal, malformed/noncanonical refusal, duplicate names/aliases, port
conflicts, publisher identity mismatch and material generation mismatch.

## ActiveForm

Implementing pure public-edge contracts and independent consumer vectors.

## Dependencies

- **blocked by**: none for reference-based service entries
- **blocks**: public routing, auth, material and report consumer adoption

## Notes

Investigation and proposal: [plan](../plan/20261020-1727-public-edge-contract.md).
Specification precedes the independent Python producer and Rust consumer tests.
The initial Rust test run refused the missing exported candidate APIs. The
implementation now provides exactly three family modules and 76 independent
candidate fixture vectors. The two acceptance tests public_edge_vectors and
material_declaration_vectors pass, alongside four tests for snapshot identity
joins, dependency installation, correlated ACKs and signed atomic replacement.

Additional negative vectors established cross-route domain/alias collisions and
malformed HTTPS issuer acceptance before the corresponding validation fixes.
A producer negative case originally shared a material list between the expected
reference and authority; separating those references made the generation-mismatch
case independent. Malformed backend length and a distinct valid wrong publisher
cover encoding and authenticated ownership separately.

M6 source, serializers and vectors are unchanged. Its existing snapshot Resource
provides service DNS labels; standalone label inventory rows stay excluded and
open pending M01/M02 with the M6 contract owner. OIDC provider/cookie/organization/
redirect carrier fields remain explicitly open with auth consumer and NSD owners.
Public transport, upstream TLS, policy references, source CIDRs and audit metadata
have explicit bounded fields rather than arbitrary extension dictionaries.

Acceptance completed: public_edge_vectors retains names, aliases, domains,
virtual ports, explicit no-connector state and full Node identity. The
material_declaration_vectors test retains auth/certificate/client-CA generations
and exact existing M6 body bytes and digest ownership. Correlation tests refuse
wrong request ids, scope, owner, revision, body kind, digest and generation.

Verification: `just fmt-check lint` passed before tests; focused consumer tests
reported 6 passed. `just self-check feat/l8-account-profile` selected complete QA
and passed at implementation commit `673f5fc6ca8d793b9dbaf777669ff5e90918124a`:
455 nextest tests passed with 0 skipped, 41 check-selection tests passed, 15
independent fixture files were current, semver required no update, doctests and
warning-free documentation passed. Only these completion records changed after
that passing run. No additional dependency, runtime, I/O or M6 changes were made.

Local review covered the three pure modules, public exports, registry changes,
independent producer and all consumer assertions. Cross-route hostname conflicts,
raw TCP/HTTP listener conflicts, issuer URL shape, exact material generations and
multi-Network snapshot scope joins are explicitly validated. No unresolved code
finding remains in that reviewed scope; open external carriers and producer
confirmation remain stated above without claiming wire equivalence.

## Gateway-wide conflict validation

Reopened to correct physical listener and backend endpoint ownership across
realm contributions. The retained regression checks that isolated contributions
are valid before rejecting their conflicting combined TCP listener. The approved
change expands only physical conflict registries; discovery names and material
references stay realm-qualified. Investigation and verification results are
tracked in the related plan and recorded below when complete.
