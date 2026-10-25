# Public edge, material and service operation contracts

- **status**: completed
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

### Ownership validation results

The existing `served_realms_cannot_claim_the_same_tcp_listener` test failed before
the fix: both isolated contributions encoded successfully, but their duplicate
TCP listener was accepted. Independent producer cases then demonstrated the same
scope error in four consumer tests: raw listeners, HTTP hostnames, HTTP/TCP overlap
and backend endpoints. Their isolated accepted controls ran before the composed
refusal assertions. Both canonical construction and decoding now reject each
conflicting combination.

The producer adds 25 composed cases and 50 isolated contributions, bringing the
fixture to 151 cases. Accepted controls preserve same-number TCP/UDP listeners,
HTTP hosts on separate ports, distinct HTTP hosts sharing a port, backend endpoints
separated by identity/port/transport, no-connector routes, realm-local discovery
names and realm-qualified material references with distinct generations.

| Inspected validation site | Disposition |
|---|---|
| public_edge.rs public_names and hostname_owners | Retained inside each realm for discovery ownership; physical HTTP ownership checked separately |
| public_edge.rs listeners | Expanded to the complete publication; raw protocol/port and every HTTP name/alias/domain plus port |
| public_edge.rs http_ports and tcp_ports | Expanded to the complete publication; reject both HTTP/TCP contribution orders |
| public_edge.rs backend_ports | Expanded to the complete publication using full Node identity, underlying transport and virtual port |
| public_edge.rs decode | Retains canonical validation, so malformed combinations cannot bypass constructor checks |
| public_edge.rs material membership and validate_materials | Retained realm-qualified references and exact installation context |
| edge_material.rs materials_valid, EdgeAuth::canonical and EdgeMaterialAck::validate_installation | Retained per-realm uniqueness and exact realm/request/generation correlation |
| grants.rs virtual-port validation and GrantPublication::validate | Separate client/resource authorization domain, not a public listener registry; unchanged |

Repository searches for the conflict registries and public/virtual-port fields
found no additional physical public-listener owner outside these sites. No
out-of-scope defect was established and no unrelated implementation was edited.

Verification: format and workspace lint passed before focused tests. All 12
focused tests passed. The current `just self-check feat/l8-account-profile` at
`a83d47b7fc2c82220380fb6c563eb0cd5c508acf` passed: 461 nextest tests, zero skipped,
41 check-selection tests, 15 current fixture files, API compatibility, supply-chain
checks, doctests and warning-free documentation. The preceding complete check
also passed at `2141dc5f82e06572b49703213d9ada6fdb7abc62`; the final run includes direct
decoding assertions for every isolated namespace control. Only the task-owned
completion records changed after the final passing run.
