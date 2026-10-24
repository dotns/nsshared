# L8 immutable candidate handoff

Selected shared package: `50dc9db5fe106536d0a7d8b113b5bb4a3e210368`.
Verified gateway consumer inputs: `e506df51e5e580d20d5cdaa25a8f134f87bf3caf`.
All three delivered library packages have version `0.6.0`.

The earlier `41149fe1febf2ecee07f077d68a500e18822442c` package remains a
historical delivery reference. It does not include the later contracts below.
The current review request supersedes its package selection without rewriting
historical evidence. Neither package preparation nor a review request establishes
approval. No external owner forwarding, received answer, NSD/ns adoption or live
interoperability is established by the gateway pins. Merge into main and release
remain separate decisions.

## Delivered contracts

Every row is included at the selected revision. The revision column identifies
the initial shared implementation; corrections below are required parts of the
selected package, rather than claims about the earlier bytes. Vector links point
to independent Python-produced fixtures consumed by the named Rust integration
test in `crates/nsshared-proto/tests/`. Fixtures are labelled candidate authority,
never NSD output. The generator does not use Rust output as producer input.

P08 and P10 own gateway runtime adoption, not additional shared contracts. Their
rows identify the shared support package only. The specified gateway pins prove
package consumption, not successful execution of those runtime acceptance cases.

| Contract | Delivered surface | Shared implementation revision | Independent fixture / Rust consumer |
| --- | --- | --- | --- |
| P02 | Control exchange | `d118947ac53376b4849530734f72411b9322b92d` | [control-exchange.vec](../crates/nsshared-proto/tests/fixtures/vectors/control-exchange.vec) / [control_exchange_vectors](../crates/nsshared-proto/tests/control_exchange_vectors.rs) |
| P03 | Realm publication and policy version | `f7e7faab5f9086e806184269d0a64c25b4ba68cc` | [realm-publication.vec](../crates/nsshared-proto/tests/fixtures/vectors/realm-publication.vec) / [realm_publication_vectors](../crates/nsshared-proto/tests/realm_publication_vectors.rs) |
| P04 | Confidential authentication configuration | `5fdeff356d49de6b1ec6f1fe33d2e96abb4e52ee` | [confidential-auth.vec](../crates/nsshared-proto/tests/fixtures/vectors/confidential-auth.vec) / [confidential_auth_vectors](../crates/nsshared-proto/tests/confidential_auth_vectors.rs) |
| P05 | Canonical RealmId | `43dc4fb116fb0ecf081cd07364bc98a0af995a75` | [realm-identity-membership.vec](../crates/nsshared-proto/tests/fixtures/vectors/realm-identity-membership.vec) / [realm_identity_membership](../crates/nsshared-proto/tests/realm_identity_membership.rs) |
| P06 | Signed source and route commands | `8a19c87c938bae9c6a03a1b1dedc7c47087ef5d7` | [source-selection.vec](../crates/nsshared-proto/tests/fixtures/vectors/source-selection.vec) / [source_selection_vectors](../crates/nsshared-proto/tests/source_selection_vectors.rs) |
| P07 | Participant credentials and directory binding | `0135ed72888374fcbcc186d2e4fd38f129f637c7` | [participant-authority.vec](../crates/nsshared-proto/tests/fixtures/vectors/participant-authority.vec) / [participant_authority_vectors](../crates/nsshared-proto/tests/participant_authority_vectors.rs) |
| P08 | Gateway participant adoption: shared support only | `50dc9db5fe106536d0a7d8b113b5bb4a3e210368` | [participant-authority.vec](../crates/nsshared-proto/tests/fixtures/vectors/participant-authority.vec) / [participant_authority_vectors](../crates/nsshared-proto/tests/participant_authority_vectors.rs) |
| P09 | Protocol-qualified grants and renewal | `1c23bbaf67db27461de5f8b038b974ceb33ba535` | [grant-authority.vec](../crates/nsshared-proto/tests/fixtures/vectors/grant-authority.vec) / [grant_authority_vectors](../crates/nsshared-proto/tests/grant_authority_vectors.rs) |
| P10 | Gateway per-Network sessions: shared support only | `50dc9db5fe106536d0a7d8b113b5bb4a3e210368` | [service-control-carrier.vec](../crates/nsshared-proto/tests/fixtures/vectors/service-control-carrier.vec) / [service_control_carrier_vectors](../crates/nsshared-proto/tests/service_control_carrier_vectors.rs) |
| P11 | Scoped usage and Node-control profiles | `752e1591169d326567d756075e31fc1edaaf1be7` | [profile-publications.vec](../crates/nsshared-proto/tests/fixtures/vectors/profile-publications.vec) / [profile_publication_vectors](../crates/nsshared-proto/tests/profile_publication_vectors.rs) |
| P12 | Ordinary-provider Subnet reports | `997c693d78a9cc1052f684535448521e139cce01` | [provider-subnet-report.vec](../crates/nsshared-proto/tests/fixtures/vectors/provider-subnet-report.vec) / [provider_subnet_report_vectors](../crates/nsshared-proto/tests/provider_subnet_report_vectors.rs) |
| P13 | Exit grants and client subnet-routes | `83a8e603e3982551ccae0d8fd4c858e8180a85e1` | [subnet-publication-views.vec](../crates/nsshared-proto/tests/fixtures/vectors/subnet-publication-views.vec) / [subnet_publication_views](../crates/nsshared-proto/tests/subnet_publication_views.rs) |
| P14 | Confidential certificate/client-CA acquisition | `f435616c613219fda0f31c5fbcaf0a64d5775b87` | [confidential-material.vec](../crates/nsshared-proto/tests/fixtures/vectors/confidential-material.vec) / [confidential_material_vectors](../crates/nsshared-proto/tests/confidential_material_vectors.rs) |
| P15 | Unary and bound-stream M6 carrier | `52075779946dfe1327c341cd6d7a3830fa5b1ad2` | [service-control-carrier.vec](../crates/nsshared-proto/tests/fixtures/vectors/service-control-carrier.vec) / [service_control_carrier_vectors](../crates/nsshared-proto/tests/service_control_carrier_vectors.rs) |
| P16 | Node-L3 admission and applied status | `d851101e145650cc85529651ea768f340a7d1ab6` | [node-l3-status.vec](../crates/nsshared-proto/tests/fixtures/vectors/node-l3-status.vec) / [node_l3_status_vectors](../crates/nsshared-proto/tests/node_l3_status_vectors.rs) |
| P17 | SSE and source-bound snapshot delivery | `b4bf192a2d88a37a6de7a33d9c7ae3cfc5bd58a5` | [publication-delivery.vec](../crates/nsshared-proto/tests/fixtures/vectors/publication-delivery.vec) / [publication_delivery_vectors](../crates/nsshared-proto/tests/publication_delivery_vectors.rs) |
| P18 | Explicit anonymous policy selector | `5c0e45dc64fcc123ff01e29ddc65e3c803002b0b` | [anonymous-public-edge.vec](../crates/nsshared-proto/tests/fixtures/vectors/anonymous-public-edge.vec) / [anonymous_public_edge_vectors](../crates/nsshared-proto/tests/anonymous_public_edge_vectors.rs) |
| P19 | Protocol-specific public-edge names | `e0dac1ed216d81db3988109c8837fb3a42db9d6f` | [public-edge.vec](../crates/nsshared-proto/tests/fixtures/vectors/public-edge.vec) / [public_edge_vectors](../crates/nsshared-proto/tests/public_edge_vectors.rs) |
| B38 | Enrollment and identity lifecycle | `c98b38123b64d28fdbe842f3b021904e912099f9` | [account.vec](../crates/nsshared-proto/tests/fixtures/vectors/account.vec) / [enrollment_vectors](../crates/nsshared-proto/tests/enrollment_vectors.rs) |
| B39 | Grants, payer and Node L3 | `09dcebb0ad598287eb5477729853c33a4a0ff8ac` | [grant-authority.vec](../crates/nsshared-proto/tests/fixtures/vectors/grant-authority.vec) / [grant_authority_vectors](../crates/nsshared-proto/tests/grant_authority_vectors.rs) |
| B40 | Subnet selection and coverage | `3b93b9bd26e206ac9c0d4fc68f6b49b30ef317c0` | [account.vec](../crates/nsshared-proto/tests/fixtures/vectors/account.vec) / [subnet_selection_vectors](../crates/nsshared-proto/tests/subnet_selection_vectors.rs) |
| B41 | Participant roster and lifetime | `c425e777b8382aefb85386d91d1314ebca573dc3` | [account.vec](../crates/nsshared-proto/tests/fixtures/vectors/account.vec) / [participant_roster_vectors](../crates/nsshared-proto/tests/participant_roster_vectors.rs) |
| B42 | Service I/O and historical relay usage | `05ee100f4eba547cd1e7025c92860a20f79fefc2` | [usage.vec](../crates/nsshared-proto/tests/fixtures/vectors/usage.vec) / [usage_vectors](../crates/nsshared-proto/tests/usage_vectors.rs) |
| B43 | Bootstrap and confidential envelopes | `6fbb1eccd34516ced170c043b538db815fbe003a` | [account.vec](../crates/nsshared-proto/tests/fixtures/vectors/account.vec) / [bootstrap_envelope_vectors](../crates/nsshared-proto/tests/bootstrap_envelope_vectors.rs) |
| B44 | Signed scoped publications | `53cbc4c11abd9963d9d8165b034dd7668fa1f000` | [account.vec](../crates/nsshared-proto/tests/fixtures/vectors/account.vec) / [publication_decoder_vectors](../crates/nsshared-proto/tests/publication_decoder_vectors.rs) |
| B45 | Policy, subject and admin claims | `5ce1e6fc2052a3e7da358dfa61668f37b38e0fa3` | [policy-claims.vec](../crates/nsshared-proto/tests/fixtures/vectors/policy-claims.vec) / [policy_claim_vectors](../crates/nsshared-proto/tests/policy_claim_vectors.rs) |
| B46 | Public edge, material and declarations | `673f5fc6ca8d793b9dbaf777669ff5e90918124a` | [public-edge.vec](../crates/nsshared-proto/tests/fixtures/vectors/public-edge.vec) / [public_edge_vectors](../crates/nsshared-proto/tests/public_edge_vectors.rs) |
| B47 | Identical Node-control v2 | `52ac36af5e2565c41f33054a91d90820535b1735` | [node_control.vec](../crates/nsshared-proto/tests/fixtures/vectors/node_control.vec) / [vectors_node_control](../crates/nsshared-proto/tests/vectors_node_control.rs) |

P16 additionally uses `node-l3-route-admission.vec` and
`node_l3_route_admission_vectors.rs`: a mapped service route grants no ordinary
host permission. B42 includes both service and relay cases in `usage.vec`, with
historical realm/UserId payer pairs and captured roster class/version.
B46 composes the existing M6 declaration/report/listener/snapshot contract;
`crates/nsshared-service-control/vectors/service-control-v1.json` and
`crates/nsshared-service-control/tests/vectors.rs` remain its independent owner.
B47 also checks `fixtures/node_control_predecessor.json` against pinned node bytes.

## Changes after the historical package

The delivered list above records all added shared families, including P02–P11,
B38–B47, subscription and snapshot polling. In particular the current package adds:

- P12: complete `node.subnet.report`, stable M6 allocations, source/generation
  fencing, updates and withdrawal. Gateway self-reporting remains deferred.
- P13: snapshot `subnet-routes` is client route information; `exit-grants` is
  provider authority. Both use the recipient's nodes source; egress grants keep
  their egress contribution source. The Exit enablement floor is local.
- P14: confidential `edge.material.get` with exact current dependency/generation,
  pending correlation, certificate/client-CA values and independent install status.
- P15: `service.control.v1`, typed optional M6 stream binding, SnapshotPush,
  PortCancel/PortQuery, correlated empty receipts and singleton lease requests.
  The lifecycle reference is node documentation commit
  `0e5adc17c9b05ae7fa351de00a5184a57b92e584`, sections 1–6 and 10;
  the implementation source remains frozen at
  `50f8e3fd95fac8bbc72aea9b132459103c3b206a`.
- P16: `node.l3.status` binds the exact signed inner event digest, current source
  and issuance. Applied requires actual enforcement application; empty Applied
  confirms removal. Existing NodeL3/grant/Subnet bytes are unchanged.
- P17: the sole source-bound `config.snapshot` form and SSE `request` query /
  `config-envelope.v1` event; inclusive 1,398,139 encoded framing bytes and
  independent 1,048,576 decoded event bytes. M6 events retain their own carrier.
- P18: Anonymous selector bytes `43 82 01 03`; null remains AnyVerified only.
  Anonymous classification is payload-free and never a verified principal.
- P19: HTTP keeps canonical hostnames; raw TCP/UDP require null and empty
  aliases/domains. Raw routes own protocol/port listeners, never hostname claims.

Required corrections and related incompatible deltas are retained at these revisions:

| Revision | Correction / independent coverage |
| --- | --- |
| `a330e1327772cc9b6a68a71df1ca1b5f6df97fbd` | Independently verify every enrollment lifecycle identity |
| `b496fd6fe9ed3e690afb128d587e3b94a7738ce3` | Canonical IDNA bootstrap origins |
| `449de664890980517cf92b124aa5ee8f7480c1d3` | Preserve exact JWT claim string data |
| `1c9602c5e626e186ea6c8c0d85b42536c43c508e` | Preserve exact machine verifier predicates |
| `2141dc5f82e06572b49703213d9ada6fdb7abc62` | Gateway-wide public listener ownership |
| `71461c0a20737ec1beb1438cebcc940153e3abe2` | Preserve floor data text without normalization |
| `34c53e2eb2daffde1283580e4cb48a6d07e166fc` | Unique credential anchors and exact JWKS queries |
| `15dbb371bae6cbcff6d57a5af6e825b1275eb615` | Retain valid snapshot updates beside unknown extensions |
| `4655d7a0679502c6788fd442899af4aa71efa3f6` | Multi-scope polls and fresh receipt transmission attempts |
| `619eacf7addf91c1c3b8662c22f831fb0699e4d0` | Atomic wrong-channel snapshot refusal |
| `237605185d5e21d8c33067c785341f7263534094` | Encode retired protocol-lifetime refusal independently |
| `28bf972db2e1f434114adc324a26fabad545aed1` | Complete independent participant authority sequence |
| `a68401441b73228c1a77b7dd8ba27120d9a223c0` | Signed source binding inside register/auth responses |
| `6e438b4985026a268bfff4d845a507976d770609` | Explicit authentication source selection |
| `2391ebd5e59574cb318fbc2c7b1ca3615426796a` | Validated inner publication producer API |
| `19bd717572d6f1eafd13ce7b63e19b7379271329` | Nonzero M6 runtime/session identifiers in subscriptions |
| `dd2007e32875850e9ca9ff9bc1559d54c159145e` | Pending snapshot request encoding ceiling |
| `179518e5fded87eb0f3254b22f3dfcc3c0dd0b43` | Refuse group-label principals in independent anonymous fixtures |

The local Node naming declaration at
`f3062fd96ba041e74e7ec9df27d9aa9d8dfda70d` retires four legacy naming pins and
Short DNS authority only at authenticated R3 acceptance. Failed acceptance keeps
prior custody; old profiles remain isolated. Retired compact names are not aliases.
The service payer is a realm plus realm-local binary UserId, with no old IdentityKey
fallback. Earlier delivery evidence does not prove these changed bytes.

## Exact consumer inputs and comparison

Only these current gateway inputs at
`e506df51e5e580d20d5cdaa25a8f134f87bf3caf` are selected:

| Manifest | Matching lockfile | Direct shared inputs | Shared lock resolutions |
| --- | --- | --- | --- |
| `Cargo.toml` | `Cargo.lock` | proto, service-control, telemetry | 3 |
| `e2e/r2/direct-peer/Cargo.toml` | `e2e/r2/direct-peer/Cargo.lock` | proto | 3 |
| `e2e/r3/authority/Cargo.toml` | `e2e/r3/authority/Cargo.lock` | proto | 2 |
| `e2e/r3/control-authority/Cargo.toml` | `e2e/r3/control-authority/Cargo.lock` | proto, service-control | 2 |

Every direct revision and every shared lock source query/commit is exactly
`50dc9db5fe106536d0a7d8b113b5bb4a3e210368`; every shared resolved version is
`0.6.0`. Each URL is the same shared repository. No branch, tag or path input
substitutes. Lockfiles include transitive shared packages, hence different counts.
Their external dependency graphs belong to consumers and need not equal the
shared workspace's `Cargo.lock` byte for byte.

Frozen `e2e/r1/client/Cargo.toml` pins proto and the three mocks to
`fc1c884dd9d27d4b2238961b0e64d9442baf8ad8`. These are historical pre-adoption
inputs, excluded from the current candidate comparison. No NSD/ns pin is claimed.

Run from this repository, supplying the read-only gateway checkout:

```bash
python3 -B tools/candidate_handoff.py \
  --candidate 50dc9db5fe106536d0a7d8b113b5bb4a3e210368 \
  --consumer "$GATEWAY_CHECKOUT" \
  --consumer-revision e506df51e5e580d20d5cdaa25a8f134f87bf3caf
python3 -B tools/test_candidate_handoff.py
```

The comparison passed: 251 candidate package/lock/API/vector inputs are identical,
and all four consumer manifest/lock pairs agree (3, 3, 2, 2 shared resolutions).
It compares current files with immutable candidate blobs, including Cargo.lock,
workspace/package manifests, complete library source and tests, both vector
producers and fixtures. Missing, added or changed inputs fail. It reads consumers
only with `git show`; it never fetches, builds or edits the gateway.
The focused test uses temporary Git inputs and refuses mismatched manifest pins,
lock commits/versions, missing packages, floating branches and changed/added files.

Independent checks remain `just vectors-check`, `just semver`, and the existing
format/lint/dependency/test/documentation checks through `just self-check` / `just qa`.
The comparison neither regenerates vectors nor substitutes for API compatibility.
Purity inspection retains the proto/service-control manifest boundary: no async
runtime, TLS or consumer client dependency is introduced, and candidate package
source/manifests are unchanged. Telemetry retains its existing logging role;
mock runtimes remain outside the pure contracts. No new runtime or v1 adapter is
introduced by this handoff. Package equality is not a new whole-source purity proof.

## Unresolved producer, consumer and review obligations

All Q01–Q23 and M01–M02 in the [review request](l8-candidate-review-request.md)
retain their individually recorded prepared/unanswered state and named addressees.
There is no recorded owner-forwarding date or received producer answer. Q18's
separate design choice is settled; shared P07 definitions are delivered, while
producer review/adoption remains open. Gateway manifest delivery is established
only for the four pairs above. Silence supplies no agreement.

| Surface | Outstanding external delivery / review |
| --- | --- |
| Enrollment/lifecycle/control | NSD confirmation, producer-owned bytes, capability meanings, accepted identity transitions, independent key/address comparisons; stable-I self-initiated K-only rebind stays disabled without producer-profile authority |
| Realm, grants and source | NSD canonical RealmId and complete publication production, durable source/profile allocation and retirement, signed register/auth source selection; N04 adoption; N06 protocol/token/deadline joins; ns exact-source consumers |
| Inner publication producer API | NSD N06/N08/N21 adoption of `2391ebd5e59574cb318fbc2c7b1ca3615426796a`, producer-owned refusal/canonical vectors |
| Subnet selection | NSD transactional source recheck, stable generations and immutable all-receipt history; ns pending journal, CLI/libns and route application; live default Exit awaits matched ns nesting |
| P12 provider reports | NSD N30 ingestion/allocation/persistence, N07/N08 projection; ns S11/S25 report production and response custody; gateway self-reporting deferred |
| P13 subnet-routes | NSD N07/N08 provider-grant/client-view projection and nodes-source binding; ns installation, replacement and withdrawal; no remote enablement floor |
| P14 material | NSD confidential certificate/client-CA production and dispatch, producer vectors; received acquisition is not installed status |
| P15 M6 | Actual NSD unary/stream carrier production, empty receipts, reverse port operations, singleton lease and independent producer vectors; real per-Network interoperability |
| P16 status | NSD N08 exact issuance/digest/source retention and status persistence; ns S03/S24 actual application/status association |
| P17 delivery forms | NSD N09 producer and ns S23 adapter adoption of framing, bounds and source-bound snapshot, independent producer vectors |
| P18 selector | NSD N20 public-ingress policy/ACL production, distinct anonymous versus verified matching and accepted/refused vectors |
| P19 names | NSD N20 HTTP public_host and raw protocol/port projection, null raw names, empty name collections and producer vectors |
| Local Node naming | NSD N04/N09 producer adoption; ns S05/S06/S11 authenticated old-pin cutover/restart and consumer adoption |
| Usage and profiles | NSD completed-I/O/history/repair and realm-local payer assignment, relay class history by original roster scope/version, usage and Node-control profile producer adoption; ns consumers; no current-role reinterpretation |
| Roster | NSD atomic membership/class/version signed and local-schema-2 writer, independent canonical/refusal vectors, rollback custody and historical lookup; ns consumer confirmation; old schema-1 fixture projection is not real writer adoption |
| Public edge/auth/policy/admin | NSD confidential configuration/material generations, qualified subjects and exact admin principal/realm projection; producer-owned vectors and ns review; public-edge candidate serving remains unbilled, with shared/NSD billing contract and gateway capture follow-up still open |
| Independent family production and M6 composition | Q22 requires producer-owned vectors for all eleven families; Q23 requires exact M6 type/variant/domain composition confirmation from NSD and ns |
| M6 labels | M01 public standalone existing label validator and M02 independent label vectors remain requested; existing M6 bytes/domains stay owned by service-control |
| External release assets | Shared main/publication ownership, placement/trust, durable security/registry store, settlement/rollback and release cohorts remain external; no release or live promotion follows from preparation |

NSD and ns adoption tracked by the parallel adoption effort remains unresolved;
no package pin is inferred for either repository. Each producer must supply its
own vectors; candidate fixture success cannot close that obligation.

## Five ownership dispositions

| Surface | Shared drafting/delivery owner | External implementation owner / remaining disposition |
| --- | --- | --- |
| Node/route select-clear | P06, delivered source-selection contract | NSD transaction/persistence/producer; ns pending journal, CLI/libns and route application; committed receipt never means applied routing |
| Directory entry-to-participant binding | P07, separate signed binding | NSD N10 produces; N26 and S17 consume; immutable global directory rules stay unchanged, withdrawal changes eligibility only |
| Participant credential | P07 shared credential/session contract; P08 gateway adoption | NSD N13 producer/review/vectors and real interoperability; C10 adoption/qualification; no binary-local replacement |
| Retained profiles and retired surfaces | P06 small profile/refusal vocabulary; NSD/ns inventory owners | NSD N21/N29/N31 inventory and cohort retirement, ns corresponding consumers; predecessor cohort deletion remains with R3/NSD owners; original custody preserved |
| Exact source binding | P06 signed binding/publication/command definitions | NSD committed source identity/epoch/generation, register/auth production and durable retirement; ns exact-current-source/session application; local attachment generation never becomes producer authority |

These assignments define candidate drafting responsibility. They neither transfer
external runtime ownership into shared code nor record external review approval.
