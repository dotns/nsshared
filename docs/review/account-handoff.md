# L8 immutable candidate handoff

Selected shared package: the delivered revision recorded in the
[review request status](account-review-request.md) (`DELIVERED_REVISION` below).
Verified gateway consumer inputs: `e70a90abb1a53567bfb6eb28f6ee057d7b9f0dc8`.
All three delivered library packages have version `0.6.0`.

The earlier `41149fe1febf2ecee07f077d68a500e18822442c` package remains a
historical delivery reference. It does not include the later contracts below.
The current review request supersedes its package selection without rewriting
historical evidence. Neither package preparation nor a review request establishes
approval. No external owner forwarding, received answer, NSD/ns adoption or live
interoperability is established by the gateway pins. Merge into main and release
remain separate decisions.


2026-10-27 reconciliation: ns `6ea11348` (request #543) and NSD `ff278641`
(request #467) adopted shared `95f1688a9d210a5ea4b9ad46c5e8623e5ba3adfa`
with `unstable-account` in their root manifests and locks. This supersedes the
unimplemented status below, not the historical package comparison or unanswered
review questions. The evidence table separates source adoption from missing live
confirmation. The feature restriction remains until review approval, the retention
seal contract and real-component evidence support the later shared release.

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
| P02 | Control exchange | `d118947ac53376b4849530734f72411b9322b92d` | [control-exchange.vec](../../crates/nsshared-control/tests/vectors/account/control/exchange.vec) / [control_exchange_vectors](../../crates/nsshared-control/tests/account/control/exchange.rs) |
| P03 | Realm publication and policy version | `f7e7faab5f9086e806184269d0a64c25b4ba68cc` | [realm-publication.vec](../../crates/nsshared-control/tests/vectors/account/realm/peers.vec) / [realm_publication_vectors](../../crates/nsshared-control/tests/account/realm/peers.rs) |
| P04 | Confidential authentication configuration | `5fdeff356d49de6b1ec6f1fe33d2e96abb4e52ee` | [confidential-auth.vec](../../crates/nsshared-control/tests/vectors/account/edge/auth.vec) / [confidential_auth_vectors](../../crates/nsshared-control/tests/account/edge/auth.rs) |
| P05 | Canonical RealmId | `43dc4fb116fb0ecf081cd07364bc98a0af995a75` | [realm-identity-membership.vec](../../crates/nsshared-control/tests/vectors/account/realm/membership.vec) / [realm_identity_membership](../../crates/nsshared-control/tests/account/realm/membership.rs) |
| P06 | Signed source and route commands | `8a19c87c938bae9c6a03a1b1dedc7c47087ef5d7` | [source-selection.vec](../../crates/nsshared-control/tests/vectors/account/publication/source-selection.vec) / [source_selection_vectors](../../crates/nsshared-control/tests/account/publication/source_selection.rs) |
| P07 | Participant credentials and directory binding | `0135ed72888374fcbcc186d2e4fd38f129f637c7` | [participant-authority.vec](../../crates/nsshared-control/tests/vectors/account/relay/session.vec) / [participant_authority_vectors](../../crates/nsshared-control/tests/account/relay/session.rs) |
| P08 | Gateway participant adoption: shared support only | `50dc9db5fe106536d0a7d8b113b5bb4a3e210368` | [participant-authority.vec](../../crates/nsshared-control/tests/vectors/account/relay/session.vec) / [participant_authority_vectors](../../crates/nsshared-control/tests/account/relay/session.rs) |
| P09 | Protocol-qualified grants and renewal | `1c23bbaf67db27461de5f8b038b974ceb33ba535` | [grant-authority.vec](../../crates/nsshared-control/tests/vectors/account/grants/grant-authority.vec) / [grant_authority_vectors](../../crates/nsshared-control/tests/account/grants/grant_authority.rs) |
| P10 | Gateway per-Network sessions: shared support only | `50dc9db5fe106536d0a7d8b113b5bb4a3e210368` | [service-control-carrier.vec](../../crates/nsshared-control/tests/vectors/account/control/service-control.vec) / [service_control_carrier_vectors](../../crates/nsshared-control/tests/account/control/service_control.rs) |
| P11 | Scoped usage and Node-control profiles | `752e1591169d326567d756075e31fc1edaaf1be7` | [profile-publications.vec](../../crates/nsshared-control/tests/vectors/account/usage/catalog.vec) / [profile_publication_vectors](../../crates/nsshared-control/tests/account/usage/catalog.rs) |
| P12 | Ordinary-provider Subnet reports | `997c693d78a9cc1052f684535448521e139cce01` | [provider-subnet-report.vec](../../crates/nsshared-control/tests/vectors/account/subnet/report.vec) / [provider_subnet_report_vectors](../../crates/nsshared-control/tests/account/subnet/report.rs) |
| P13 | Exit grants and client subnet-routes | `83a8e603e3982551ccae0d8fd4c858e8180a85e1` | [subnet-publication-views.vec](../../crates/nsshared-control/tests/vectors/account/subnet/views.vec) / [subnet_publication_views](../../crates/nsshared-control/tests/account/subnet/views.rs) |
| P14 | Confidential certificate/client-CA acquisition | `f435616c613219fda0f31c5fbcaf0a64d5775b87` | [confidential-material.vec](../../crates/nsshared-control/tests/vectors/account/edge/material-request.vec) / [confidential_material_vectors](../../crates/nsshared-control/tests/account/edge/material_request.rs) |
| P15 | Unary and bound-stream M6 carrier | `52075779946dfe1327c341cd6d7a3830fa5b1ad2` | [service-control-carrier.vec](../../crates/nsshared-control/tests/vectors/account/control/service-control.vec) / [service_control_carrier_vectors](../../crates/nsshared-control/tests/account/control/service_control.rs) |
| P16 | Node-L3 admission and applied status | `d851101e145650cc85529651ea768f340a7d1ab6` | [node-l3-status.vec](../../crates/nsshared-control/tests/vectors/account/control/node-l3-status.vec) / [node_l3_status_vectors](../../crates/nsshared-control/tests/account/control/node_l3_status.rs) |
| P17 | SSE and source-bound snapshot delivery | `b4bf192a2d88a37a6de7a33d9c7ae3cfc5bd58a5` | [publication-delivery.vec](../../crates/nsshared-control/tests/vectors/account/publication/delivery.vec) / [publication_delivery_vectors](../../crates/nsshared-control/tests/account/publication/delivery.rs) |
| P18 | Explicit anonymous policy selector | `5c0e45dc64fcc123ff01e29ddc65e3c803002b0b` | [anonymous-public-edge.vec](../../crates/nsshared-control/tests/vectors/account/edge/anonymous.vec) / [anonymous_public_edge_vectors](../../crates/nsshared-control/tests/account/edge/anonymous.rs) |
| P19 | Protocol-specific public-edge names | `e0dac1ed216d81db3988109c8837fb3a42db9d6f` | [public-edge.vec](../../crates/nsshared-control/tests/vectors/account/edge/routing.vec) / [public_edge_vectors](../../crates/nsshared-control/tests/account/edge/routing.rs) |
| B38 | Enrollment and identity lifecycle | `c98b38123b64d28fdbe842f3b021904e912099f9` | [account.vec](../../crates/nsshared-control/tests/vectors/account/node/enrollment.vec) / [enrollment_vectors](../../crates/nsshared-control/tests/account/node/enrollment.rs) |
| B39 | Grants, payer and Node L3 | `09dcebb0ad598287eb5477729853c33a4a0ff8ac` | [grant-authority.vec](../../crates/nsshared-control/tests/vectors/account/grants/grant-authority.vec) / [grant_authority_vectors](../../crates/nsshared-control/tests/account/grants/grant_authority.rs) |
| B40 | Subnet selection and coverage | `3b93b9bd26e206ac9c0d4fc68f6b49b30ef317c0` | [account.vec](../../crates/nsshared-control/tests/vectors/account/subnet/selection.vec) / [subnet_selection_vectors](../../crates/nsshared-control/tests/account/subnet/selection.rs) |
| B41 | Participant roster and lifetime | `c425e777b8382aefb85386d91d1314ebca573dc3` | [account.vec](../../crates/nsshared-control/tests/vectors/account/relay/participant-roster.vec) / [participant_roster_vectors](../../crates/nsshared-control/tests/account/relay/participant_roster.rs) |
| B42 | Service I/O and historical relay usage | `05ee100f4eba547cd1e7025c92860a20f79fefc2` | [usage.vec](../../crates/nsshared-control/tests/vectors/account/usage/reports.vec) / [usage_vectors](../../crates/nsshared-control/tests/account/usage/reports.rs) |
| B43 | Bootstrap and confidential envelopes | `6fbb1eccd34516ced170c043b538db815fbe003a` | [account.vec](../../crates/nsshared-control/tests/vectors/account/control/envelope.vec) / [bootstrap_envelope_vectors](../../crates/nsshared-control/tests/account/control/envelope.rs) |
| B44 | Signed scoped publications | `53cbc4c11abd9963d9d8165b034dd7668fa1f000` | [account.vec](../../crates/nsshared-control/tests/vectors/account/publication/envelope.vec) / [publication_decoder_vectors](../../crates/nsshared-control/tests/account/publication/envelope.rs) |
| B45 | Policy, subject and admin claims | `5ce1e6fc2052a3e7da358dfa61668f37b38e0fa3` | [policy-claims.vec](../../crates/nsshared-control/tests/vectors/account/realm/claims.vec) / [policy_claim_vectors](../../crates/nsshared-control/tests/account/realm/claims.rs) |
| B46 | Public edge, material and declarations | `673f5fc6ca8d793b9dbaf777669ff5e90918124a` | [public-edge.vec](../../crates/nsshared-control/tests/vectors/account/edge/routing.vec) / [public_edge_vectors](../../crates/nsshared-control/tests/account/edge/routing.rs) |
| B47 | Identical Node-control v2 | `52ac36af5e2565c41f33054a91d90820535b1735` | [node_control.vec](../../crates/nsshared-control/tests/vectors/node_control/messages.vec) / [vectors_node_control](../../crates/nsshared-control/tests/node_control/messages.rs) |

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

The current comparison selects these gateway inputs at
`e70a90abb1a53567bfb6eb28f6ee057d7b9f0dc8`:

| Manifest | Matching lockfile | Direct shared inputs | Shared lock resolutions |
| --- | --- | --- | --- |
| `Cargo.toml` | `Cargo.lock` | proto, service-control, telemetry | 3 |
| `e2e/r2/direct-peer/Cargo.toml` | `e2e/r2/direct-peer/Cargo.lock` | proto | 3 |
| `e2e/r3/authority/Cargo.toml` | `e2e/r3/authority/Cargo.lock` | proto | 2 |
| `e2e/r3/control-authority/Cargo.toml` | `e2e/r3/control-authority/Cargo.lock` | proto, service-control | 2 |

All four manifests pin their shared inputs to the delivered revision. Every shared lock source
query and resolved commit matches that exact revision; all shared resolved
versions are `0.6.0`. No branch, tag or path input substitutes. Lockfiles include
transitive shared packages, hence different counts. Their external dependency
graphs belong to consumers and need not equal the shared workspace's
`Cargo.lock` byte for byte. These verified pins do not establish complete
snapshot qualification or external producer adoption on their own.

Frozen `e2e/r1/client/Cargo.toml` pins proto and the three mocks to
`fc1c884dd9d27d4b2238961b0e64d9442baf8ad8`. These are historical pre-adoption
inputs, excluded from the current candidate comparison. That historical gateway comparison establishes no NSD/ns pin; the 2026-10-27 source inspection above records their later root pins.

Run the package comparison against an immutable export of the selected shared
revision. Supply an empty `SELECTED_EXPORT` directory and the read-only gateway
checkout. The `.git` pointer permits the unchanged tool's read-only object queries
against this repository; it does not create a checkout or alter Git metadata.
Run the separate tool test from the current shared repository.

```bash
set -o pipefail
git archive "$DELIVERED_REVISION" | tar -x -C "$SELECTED_EXPORT"
printf 'gitdir: %s\n' "$(git rev-parse --absolute-git-dir)" > "$SELECTED_EXPORT/.git"
python3 -B "$SELECTED_EXPORT/tools/candidate_handoff.py" \
  --candidate "$DELIVERED_REVISION" \
  --consumer "$GATEWAY_CHECKOUT" \
  --consumer-revision e70a90abb1a53567bfb6eb28f6ee057d7b9f0dc8
python3 -B tools/test_candidate_handoff.py
```

The immutable export comparison passed: 259 selected package/lock/API/vector
inputs are identical and all four consumer manifest/lock pairs agree (3, 3, 2, 2
shared lock resolutions). This qualifies the delivered package at the exact
shared and gateway revisions above. The tool checks the complete selected
snapshot, including tests, generators and fixtures, without suppressing input
differences. It reads gateway inputs only with `git show` and never fetches,
builds or edits that checkout.

The registration placeholder producer, test and fixture extension is additive
after the delivered package. Crate sources resolved by the consumer remain unchanged,
as do their manifests, workspace manifest and lockfile. The new test/fixture
bytes are not attributed to the delivered snapshot. Qualify this current
extension separately with `just self-check feat/l8-account-profile` at its
recorded immutable commit; that result does not replace the delivered-package
comparison. Neither result establishes external review, producer adoption or
live interoperability.
The focused test uses temporary Git inputs and refuses mismatched manifest pins,
lock commits/versions, missing packages, floating branches and changed/added files.

The earlier comparison of shared package
`50dc9db5fe106536d0a7d8b113b5bb4a3e210368` with gateway inputs
`e506df51e5e580d20d5cdaa25a8f134f87bf3caf` remains historical comparison
evidence: 251 inputs and four manifest/lock pairs agreed at that package.
Rechecking that historical selection against the later shared tree failed on
`crates/nsshared-proto/src/account.rs`; that failure is preserved and is not
reclassified as a pass. The current comparison selects the delivered package
and the aligned gateway inputs above at the immutable export boundary.

The intermediate gateway revision
`96fa0dca57c3af5e96ab9f72d710f2cbe6d8cf93` also remains historical failure
evidence. Before the placeholder vector extension, comparison with selected
shared package at the delivered revision confirmed 259
identical shared inputs and three workspace lock resolutions, then failed with
`manifest pin differs: nsshared-proto` at direct-peer. Its authority manifest
also retained the old proto pin. The aligned revision supersedes that consumer
selection; the previous failure remains a failure.

Independent checks remain `just vectors-check`, `just semver`, and the existing
format/lint/dependency/test/documentation checks through `just self-check` / `just qa`.
The comparison neither regenerates vectors nor substitutes for API compatibility.
Purity inspection retains the proto/service-control manifest boundary: no async
runtime, TLS or consumer client dependency is introduced, and candidate package
source/manifests are unchanged. Telemetry retains its existing logging role;
mock runtimes remain outside the pure contracts. No new runtime or v1 adapter is
introduced by this handoff. Package equality is not a new whole-source purity proof.

## Unresolved producer, consumer and review obligations

All Q01–Q23 and M01–M02 in the [review request](account-review-request.md)
retain their individually recorded sent/unanswered state and named addressees.
The [review request delivery](account-review-request.md) was completed
through the owner route on 2026-10-25 (UTC), at the delivered revision. The owner forwarded the candidate
review package to the NSD owner as producer and the ns owner as consumer reviewer.
No answer has been received. Silence approves nothing. Q18's separate design
choice is settled; shared P07 definitions are delivered, while the owner answer and live confirmation remain open; merged adoption is recorded below. Gateway manifest delivery is established only
for the four pairs above.

The following evidence is source inspection at NSD `ff278641` and ns `6ea11348`,
not a new execution of either repository's tests. Every NSD or ns locator in this
table is relative to its named repository at that commit. `producer_core_readers`
is in NSD `crates/nsd-api/tests/producer_core/mod.rs`; its slice files and producer
corpora below are relative to `crates/nsd-api/tests/producer_core/`. Shared vector
paths are relative to `crates/nsshared-control/tests/vectors/` at `95f1688`.
An adopted slice does not answer its owner's review question.

| Surface | Adoption evidence and exact remaining confirmation |
| --- | --- |
| <a id="adoption-core"></a>Enrollment/lifecycle/control | **Adopted in source:** NSD `producer_core_readers`, `enrollment.rs`, `enrollment/mounted.rs` and `enrollment/verify.rs` exercise actual Connector Initial/Equal registration, signed source responses, explicit authentication selection and approved identity/key transitions; corpus `fixtures/enrollment.json`. NSD `crates/nsd-store/tests/m6_lineage_vectors.rs::enrollment_consumer_vectors` compares zero-placeholder cases in shared `account/node/enrollment.vec`. ns `crates/control/tests/channel_trust_control_exchange_vectors.rs::fixture_fed_control_exchange_vectors` reads `crates/control/tests/fixtures/channel-trust/control-exchange.vec`; `crates/control/tests/recorded_control_cases/enrollment.rs::recorded_enrollment_exchanges` reads its historical `enrollment.json`. **Answered:** [Q07](account-review-request.md#q07-identity-lifecycle--node-owner-with-nsd-confirmation) records the read-only check of nsshared `v0.7.0`, ns main `c96fe8fc` and NSD refactor/unified-engine `58f20210`; [Q11](account-review-request.md#q11-enrollment-payload--nsd-owner) records bounded answers at NSD `3cd5f2bd`, ns `3349fe16` and nsshared `v0.7.0`, plus the shared-form adoption decision. `node.control` is opaque with no semantics today. **Open:** these two enrollment JSON corpora are not byte-identical at the named merges; matching current producer bytes, live enrollment and owner approval of any stable-I rebind profile remain unconfirmed. Complete remaining producer-owned vectors stay with NSD before H03. No self-initiated rotation is authorized by this record. |
| <a id="adoption-publication"></a>Realm, source and inner publication producer API | **Adopted:** NSD `producer_core_readers`, `mod.rs::check`, `corpus.rs::compare`, `NodeL3Producer::publish_network` produce and reread signed family 2/11 content with canonical RealmId and I/K authority, plus family 4. `fixtures/publications.json` is byte-identical to ns `crates/control/tests/fixtures/channel-trust/publications.json`, consumed by `crates/control/tests/channel_trust_producer_publications.rs::independent_producer_consumer_families`. NSD `crates/nsd-api/tests/account_scope.rs::subscription_scope_rejects_whitespace` and `producer_core/delivery.rs::mounted_snapshot` cover scope refusal, including unchanged custody and reuse of a valid nonce; ns `crates/control/tests/channel_trust_publication_vectors.rs::signed_publication_scope_whitespace_is_refused_without_installing` covers consumer refusal. **Open:** full owner confirmation of collection authority, all requested refusal/limit cases and live source retirement; this evidence does not cover every active consumer. |
| <a id="adoption-grants"></a>Protocol grants, payer and withdrawal | **Adopted in source:** NSD `crates/nsd-api/tests/effective_grant_ownership/captured_retirements.rs::projected_family_payloads_join_captured_history_and_withdrawal` exercises `encode_projected_families`, families 3/5/6, complete payer/resource/protocol joins, retained tokens and withdrawal. `crates/nsd-api/tests/effective_grant_ownership.rs::effective_grant_incarnation` and `ambiguous_payer_withheld` cover accepted assignment and ambiguity. These are decoded-field/storage assertions, not an independently exported byte corpus for every requested grant case. **Open:** owner answers for Q13/Q15/Q16, complete independent canonical/refusal vectors, live protocol/deadline/payer and consumer joins. |
| <a id="adoption-routes"></a>Subnet selection | **Adopted:** NSD `producer_core_readers`, `routes.rs::check` exercises mounted select/reselect/clear, retained immutable receipts and wrong-source refusal; `fixtures/routes.json` equals ns `crates/control/tests/fixtures/channel-trust/routes.json` byte for byte. ns `crates/control/tests/channel_selection_roundtrip.rs::channel_selection_roundtrip` checks request/receipt bytes; `crates/ns/src/config_store/store/node_route/tests.rs::recorded_route_receipts_survive_reopen_and_clear_replay` checks durable replay. **Open:** live CLI/libns-to-routing confirmation, matched default/nested Exit qualification and the owner's review answer. |
| <a id="adoption-provider"></a>P12 provider reports | **Adopted in source:** NSD `crates/nsd-api/src/envelope/node_routes.rs` dispatches the shared report to persistent selection custody; `crates/nsd-api/tests/machine_plane_day2b_flow/gateway_enrollment/source_issuance_responses/node_routes.rs::provider_subnet_report_history` and `provider_report_qualifies_its_own_mapping` cover the producer boundary. ns `crates/control/tests/provider_report_adapter.rs::shared_vectors_replace_withdraw_and_reoffer_keep_exact_allocations` and `shared_vectors_restart_resends_pending_generation_and_content` cover reporting/custody against `crates/control/tests/fixtures/channel-trust/provider-subnet-report.vec`. **Open:** independent matched actual producer report corpus and real provider activation/complete report custody; gateway self-reporting remains deferred. |
| <a id="adoption-subnet"></a>P13 subnet-routes | **Adopted:** NSD `crates/nsd-api/tests/subnet_publications.rs::subnet_selection_projection` and `producer_core_readers` cover provider grants/client routes and current nodes authority; shared `account/subnet/views.vec` is read by `subnet_vectors.rs`. The matching `publications.json` pair and ns `independent_producer_consumer_families` above prove consumer handling of actual recorded family-4 bytes and withdrawal. **Open:** live route installation/replacement/withdrawal and default/nesting acceptance; no remote enablement floor is introduced. |
| <a id="adoption-mapping"></a>Provider mapping inventory | **Open:** source inspection finds provider report/selection implementation, but no demonstrated NSD producer of the separate `provider-mappings` snapshot or matching ns installation of that inventory at these merges. ns `crates/ns/src/provider_report_driver.rs::AuthenticatedProviderMapping` is a supplied runtime input, not proof of that signed publication. Need the N07/N09 producer and source handoff, S25/S11 authenticated activation and matching independent populated/changed/empty/refused vectors. Report/grant corpus evidence does not close this inventory; gateway consumption remains deferred. |
| <a id="adoption-material"></a>P14 material and confidential auth | **Adopted in source:** NSD `crates/nsd-api/tests/machine_plane_day2b_flow/gateway_enrollment/source_issuance_responses/edge_material_acquisition.rs::edge_material_acquisition` covers mounted certificate/client-CA acquisition, correlation and rotation. `crates/nsd-api/tests/machine_plane_day2b_flow/gateway_enrollment/public_edge_publications/wire/auth_configuration.rs::acquire_current` exercises signed `edge.auth.config.get` with exact current dependency/request comparison. **Open:** independent producer-owned material/auth canonical/refusal corpus, full JWT issuer projection review and live consumer installation; acquisition is not installation ACK evidence. |
| <a id="adoption-m6"></a>P15 M6 | **Adopted:** NSD `producer_core_readers`, `service_control/mod.rs::check`, `service_control/flow.rs` and `service_control/verify.rs` cover mounted unary, eight-element subscription, empty receipts and reverse events. `fixtures/service_control.json` equals ns `crates/control/tests/fixtures/channel-trust/service_control.json`; ns `crates/control/tests/recorded_control_corpora.rs::independent_producer_consumer_families` invokes `recorded_control_cases/service.rs::check`. NSD `crates/nsd-store/tests/m6_lineage_vectors.rs::m6_lineage_vectors` checks unchanged report/listener/snapshot bytes and digests against shared `service/canonical.json`. **Open:** Q23 agreement on every composition variant and real per-Network contribution/session/proposal/lease interoperability. |
| <a id="adoption-status"></a>P16 status | **Adopted:** NSD `producer_core_readers`, `status.rs::check` and `status/custody.rs` correlate actual issuance/digest/source with stored status. `fixtures/status.json` equals ns `crates/control/tests/fixtures/channel-trust/status.json`; the ns `recorded_control_corpora.rs::independent_producer_consumer_families` selector invokes `recorded_control_cases/status.rs::check` through `NodeL3StatusSender`. **Open:** actual remote enforcement-to-Applied association and empty removal in live components; stored or fixture-fed Applied is not that proof. |
| <a id="adoption-delivery"></a>P17 delivery forms | **Adopted:** NSD `producer_core_readers`, `delivery.rs::check` covers snapshot/SSE bounds and signed source binding with shared `account/publication/delivery.vec`, `subscription.vec`, `snapshot-request.vec` and `snapshot-pending-boundaries.vec`. `fixtures/delivery.json` equals ns `crates/control/tests/fixtures/channel-trust/delivery.json`; ns `recorded_control_corpora.rs::independent_producer_consumer_families` invokes `recorded_control_cases/delivery.rs::check` and framing controls. **Open:** live adapter/producer confirmation of complete delivery, disconnect and expiry behavior; Q21 answers remain absent; Q11 has code-check answers with remaining NSD producer vectors due before H03. |
| <a id="adoption-edge"></a>P18 selector / P19 names / public edge | **Adopted producer slice:** NSD `producer_core_readers`, `edge.rs::check` and `edge.rs::compare` exercise `PublicEdgeProducer` compile/sign/commit, actual HTTP/raw route projection and withdrawal against exact `fixtures/edge.json`; `edge/vectors.rs::load` reads shared `account/edge/routing.vec` and `anonymous.vec`. **Open:** independent matching downstream producer-corpus reader and live accepted policy/ACL, anonymous-versus-verified enforcement, names/material joins and owner answers. This is not public-ingress billing qualification. |
| <a id="adoption-naming"></a>Local Node naming | **Adopted:** NSD enrollment production above accepts the local-name capability; ns `crates/ns/src/engine/startup/source_registration/shared_enrollment_tests.rs::r3_runtime_enrollment_selects_approves_commits_and_authenticates_after_restart` covers authenticated commit/restart and retired-field refusal. ns `crates/control/tests/channel_trust_control_exchange_vectors.rs::fixture_fed_r3_runtime_enrollment_requires_local_names` and `fixture_fed_r3_runtime_enrollment_builder_is_canonical` read `control-exchange.vec`. **Open:** live NSD/ns cutover confirmation and owner answer; historical producer-corpus drift is recorded under enrollment. Pending ns `3b9adf5156ad` (request #545), `docs/task/20261027-1748-portable-subnet-naming-tests.md`, records environment-independent subnet/rollback fixtures, not a new naming contract or a merged fix. |
| <a id="adoption-usage"></a>Usage and historical ledgers | **Adopted producer/storage slice:** NSD `producer_core_readers`, `ledger/resource.rs::check`, `ledger/relay.rs` and `ledger.rs::check_vectors` cover mounted resource answers and actual TLS participant answers with reopened receipts; `fixtures/ledger.json`, shared `account/usage/reports.vec` and `account/relay/session.vec` retain payer pairs, domains and historical classes. Resource outer carriers use time-dependent signatures with verified field/payload comparison; relay application frames compare exactly. **Open:** actual completed-I/O capture and live exclusion/repair across components, exact downstream ledger-corpus consumer and owner agreement on units; fixtures supply completed quantities/history and cannot prove capture. Retention deletion also awaits the seal contract. |
| <a id="adoption-profiles"></a>Usage and Node-control profiles | **Adopted producer slice:** NSD `producer_core_readers`, `mod.rs::check_profiles`, `corpus.rs::compare_profiles` exercise `ProfileProducer::publish_network`, exact `fixtures/profiles.json` and shared `account/usage/catalog.vec` with scoped empty replacement and unrelated-Network retention. **Open:** independently demonstrated ns/gateway consumption of that actual corpus, live preserved capture/control custody, Q19/Q20 review and standalone Node-control transport agreement. Catalogue adoption is not proof of every Node-control runtime. |
| <a id="adoption-roster"></a>Roster and participant/directory | **Adopted producer slice:** NSD `producer_core_readers`, `rosters.rs::check`, `fixtures/rosters.json` compare production Renderer signatures and immutable epochs; shared `account/relay/participant-roster.vec` supplies independent refusals. `directory.rs::check` and `fixtures/directory.json` cover actual assignment/removal/source replacement. This directory corpus equals ns `crates/control/tests/fixtures/channel-trust/directory.json`, consumed by `crates/ns/src/account_engine/relay_v2/tests/recorded_directory.rs::recorded_directory_snapshots_preserve_source_local_custody`. Participant TLS and shared FrameKind adoption are covered by the ledger slice. **Open:** executable local schema-2 file writer/controlled replacement proof (the corpus uses a fixture-fed local union), complete rollback/carrier-switch and live participant confirmation. NSD retention `56d65c1a256a`, included in `ff278641`, preserves history but production deletion remains held until a seal supplies complete unsettled-reference coverage; see `docs/task/20261027-1222-roster-history-retention.md`. |
| <a id="adoption-policy"></a>Policy/admin and remaining control reports | **Partially adopted:** family-7 producer and confidential acquisition slices above exist. NSD `producer_core_readers`, `retained.rs::check` and `fixtures/retained.json` exercise legacy heartbeat and service reports, explicitly including R3 heartbeat HTTP 403; they are not the shared five-operation report contract. **Open:** exact shared heartbeat/gateway/material/service report producer corpus including floor-text cases, authenticated admin scope projection, complete subject/JWT/signed-URL/header vectors and unplaced policy carriers. Gateway machine audience remains an owner decision; source merges supply no answer. |
| <a id="adoption-vectors"></a>Independent family production and M6 composition | **Partially adopted:** the named actual NSD corpora and six byte-identical ns copies above replace the blanket claim that no producer vectors exist. Enrollment copies differ, and profiles/edge/ledger/roster lack a demonstrated matching downstream corpus reader here. **Open:** Q22's complete eleven-family positive/empty/refusal/scope/limit inventory and Q23's owner confirmation of all types/variants/domains, beyond the bounded tests above. |
| <a id="adoption-labels"></a>M6 labels | **Open:** M01's explicit owner answer for the standalone API and M02's independent boundary vectors are not established by these producer/consumer merges. Existing labels inside M6 objects and unchanged digest checks do not close either request. |
| <a id="adoption-release"></a>External release assets | **Open:** review answers, retention seal contract, live real-component evidence, released immutable shared revision and re-verification at that revision; placement/trust, durable security/registry store, settlement/rollback and release cohorts remain externally owned. `unstable-account` stays enabled. Pending NSD `aa2caaf381fd` (request #468), `docs/task/20261027-1734-fixture-python.md`, repairs provisioned Python selection for `pair_authority` tests; it supplies no live qualification or new contract approval. |

The six byte-identical JSON pairs were compared directly at the named merge
commits. Enrollment request/response carrier bytes differ in all nine records;
no current byte-for-byte enrollment pairing is claimed. Independent vectors and
actual producer corpora remain distinct, and neither replaces owner review.

## Later matched external handoffs

NSD D-N1–D-N7 and ns D-S1–D-S4 now have the bounded merged implementation
and corpus evidence above. Their matched real-component handoffs remain open:
each still needs live producer/consumer identity, source, service, accounting and
fault/restart observations. The released shared-contract handoff also awaits
review, the retention seal contract and re-verification at a released revision.
The explicit dependencies retained for later real-component qualification are:

| Continuation | Required external inputs |
| --- | --- |
| C03 direct | NSD D-N1/D-N2 ordinary gateway registration/classification, reciprocal identity WgConfig and eligible Node L3; ns D-S1 |
| C05 Egress | D-N2/D-N6 and D-N7 service/grant/report and public-edge producers; applicable ns D-S1/D-S3/D-S4 |
| C06 explicit Exit | D-N2/D-N6 service/grant/report producers; applicable ns D-S1/D-S3/D-S4; P12 ordinary-provider report adoption before gateway self-reporting |
| C09–C12 relay | NSD D-N3–D-N6 and applicable ns D-S1/D-S3/D-S4; shared P07 participant/directory contract, N10/N13/N26/S17 adoption and C10 interoperability |
| C08/C12 faults | Matched service or relay inputs of the behavior exercised; fixture lifecycle results do not prove real-component lifecycle |
| C07/default Exit | Matched ns nesting and later authorized default qualification; no native IPv6 internet Exit activation |

Remaining D-S2 and other D-N/D-S artifacts retain their external owners and
release deadlines; no unverified revision or delivery date is supplied here.
Deferred privileged qualification remains unqualified with its failure history;
source fixes and fixture observations do not establish mechanism success.
OP09 placement/trust is due before live qualification. OP07 scale inputs,
OP08/OP10 owner assets and production R1 durable security/registry delivery are
due before scale/release work. Original report settlement, rollback and release
cohorts remain independently owned. No earlier result is promoted by this handoff.

## Five ownership dispositions

| Surface | Shared drafting/delivery owner | External implementation owner / remaining disposition |
| --- | --- | --- |
| Node/route select-clear | P06, delivered source-selection contract | NSD transaction/persistence/producer; ns pending journal, CLI/libns and route application; committed receipt never means applied routing  Implementation and remaining live/review limits: [evidence](#adoption-routes). |
| Directory entry-to-participant binding | P07, separate signed binding | NSD N10 produces; N26 and S17 consume; immutable global directory rules stay unchanged, withdrawal changes eligibility only  Implementation and remaining live/review limits: [evidence](#adoption-roster). |
| Participant credential | P07 shared credential/session contract; P08 gateway adoption | NSD N13 producer/review/vectors and real interoperability; C10 adoption/qualification; no binary-local replacement  Implementation and remaining live/review limits: [evidence](#adoption-roster). |
| Retained profiles and retired surfaces | P06 small profile/refusal vocabulary; NSD/ns inventory owners | NSD N21/N29/N31 inventory and cohort retirement, ns corresponding consumers; predecessor cohort deletion remains with R3/NSD owners; original custody preserved  Implementation and remaining live/review limits: [evidence](#adoption-policy). |
| Exact source binding | P06 signed binding/publication/command definitions | NSD committed source identity/epoch/generation, register/auth production and durable retirement; ns exact-current-source/session application; local attachment generation never becomes producer authority  Implementation and remaining live/review limits: [evidence](#adoption-core). |

These assignments define candidate drafting responsibility. They neither transfer
external runtime ownership into shared code nor record external review approval.


## Provider mapping inventory delivery

The pure `provider-mappings` contract is delivered at
`110b3d705965a07dd257d5951f44f662850a1756`, with independent
[provider-mapping.vec](../../crates/nsshared-control/tests/vectors/account/subnet/mapping.vec)
and [provider_mapping_replacement](../../crates/nsshared-control/tests/account/subnet/mapping.rs).
It adds the separate family 4 Snapshot inventory and exact `mappings` replacement,
canonical bounded mapping ids and B40 prefixes, and current nodes-source/context
verification. Populated, changed/omitted, typed-empty and authenticated withdrawal
sets remain separate from other providers, grants and client route views.
The report/allocation and grant/client-route bytes remain unchanged.

This is a new contract revision beyond the historical package comparison above;
that comparison does not establish consumer adoption of this inventory. NSD N07/N09 production and ns S25/S11 activation of this separate inventory
remain open for the specific evidence missing in the [mapping row](#adoption-mapping). Review requests record no agreement. Gateway self-reporting
and inventory consumption remain deferred to the existing C06 handoff; fixture
success supplies no evidence of external implementation or live eligibility.

## Registration lifecycle clarification after the selected package

The [registration-only placeholder profile](../spec/account/node.md#registration-only-placeholders)
and [registration exchange](../spec/account/control.md)
clarify the existing six-element lifecycle without changing schema, codec or
comparator. The requesting Node emits sixteen zero bytes in each final slot;
receivers structurally decode and ignore both values. They supply neither
authority nor transition inputs or custody. Existing nonzero fixtures remain
receiver coverage only. Grant and reporter tokens retain their independent
producers, comparisons, retirement and settlement contracts.

The independent `enrollment_consumer_vectors` extension in
`crates/nsshared-proto/tests/enrollment_vectors.rs`, generated by
`tools/vectors/nsvec/producers/enrollment.py` into `account.vec`, covers an
ordinary Node without grants or a reporter. It accepts zero-placeholder identity
replacement and explicitly authorized K rotation while retaining exact
before/after mismatch and unauthorized-rotation refusals.

This documentation/vector addition is later than the selected shared package;
that package's immutable export comparison does not establish these new vectors.
It requires no gateway source change or repin. NSD zero-placeholder vector adoption and the bounded ns enrollment reader are
recorded in the [enrollment row](#adoption-core); current matching producer bytes
and live transition confirmation remain open. Q07 is answered by the read-only
code check of nsshared `v0.7.0`, ns main `c96fe8fc` and NSD
refactor/unified-engine `58f20210`: refresh preserves membership version, I, K
and generation; binding and signed record share one generation; positive `u64`
wire values are not limited by ordinary ns derivation's checked `u32` range.
Restart refusal holds per resolved accepted binding; a freshly approved new I
without a lifecycle link is a new Node. See the [full Q07 answer](account-review-request.md#q07-identity-lifecycle--node-owner-with-nsd-confirmation).
The answer does not establish live interoperability.

## Current candidate handoff delta

The earlier adoption table is historical evidence at its named revisions.
It supplies no implicit adoption of the additions in the
[candidate inventory](account-inventory.md#current-candidate-additions-and-release-inventory).

- Whole-floor M6: gateway production must retain complete `FloorReportMessage`
  bytes for pending retries and compare `ReportAccepted` with the complete digest.
  NSD must decode the complete floor and compare current persisted custody,
  runtime fence, revision and digest. Empty extensions preserve legacy bytes;
  legacy decoders refuse nonempty extensions. Existing matched legacy M6 corpora
  do not demonstrate either consumer's extended-floor behavior.
- Roster counters: NSD must independently derive publication versions and
  classified-history attribution epochs. Relayd must atomically persist both
  scoped floors, restore them after restart and capture the authenticated epoch
  at DATA acceptance. Historical usage must join original custody without
  relabeling. Schema-1 bytes/signatures remain valid with epoch equal to version;
  schema-2 acceptance and billing qualification remain separate consumer work.
- The old local schema-2 writer obligation in the historical table is not a
  current-format adoption claim. The current shared local snapshot is schema 3,
  with required `admission_since`; its controlled writer/replacement, rollback
  persistence and live proof remain open. Signed roster schema 2 is a distinct
  format, not the local file schema.

Current fixture locators and standalone label/candidate-vector gaps are listed
in the inventory. No downstream tests, corpus comparison or live checks were
executed for this documentation. Complete producer-owned vectors, missing
edge/profile/ledger/roster downstream corpus readers, Q22/Q23, M01/M02 and Q24
remain open. Bounded Q07/Q11 answers and Q18's settled design remain bounded;
`node.control` remains opaque. Review approval, retention-seal acceptance,
F04 integration, live qualification and the actual immutable release revision
and cohort remain outstanding. Keep `unstable-account`; production eligibility
requires H03/R01/R02/C01b and C18 re-verification, and deletion remains held
under Q-RET.
