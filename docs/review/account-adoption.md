# Account adoption

Review, delivery, adoption, interoperability and ownership state of the account
contracts, collected from the specifications when they were folded into
[docs/spec](../spec/README.md). Each entry names its contract; identifiers (N.., S..,
C.., Q.., P..) refer to the [review request](account-review-request.md), the
[handoff](account-handoff.md) and the consumer plans. Entries change as owners answer
and adopt; the specifications do not depend on them.

2026-10-27: reconciled with ns `6ea11348` (request #543) and NSD `ff278641`
(request #467), both using shared `95f1688` with `unstable-account`. Source
adoption and actual producer corpora are now recorded separately from unanswered
owner questions and live confirmation. See the linked handoff rows for exact
files, tests, vector comparisons and pending follow-ups; the feature restriction
and later retention-seal/live-evidence release requirements remain unchanged.

## Core: RealmId, profile and Node-control

- Canonical RealmId: Arbitrary realm labels are refused without fallback (an incompatible change to earlier account payloads). Prior evidence applies only to its recorded revision. Original-profile persisted state remains isolated. Canonical realm/source publication production and ns recorded-byte consumption are adopted; complete owner confirmation, refusal coverage and live source retirement remain open. See [adoption evidence](account-handoff.md#adoption-publication).
- Account profile: The account payload record (`docs/task/20261019-0029-l8-account-payload-profile.md`) owns every registry entry. The review request records the delivered revision, family states, producer questions and requested M6 changes. Delivery does not imply approval.
- Account conformance: Fixture vectors are not producer output; existing vectors retain their names and bytes.
- Node-control: The nine gateway fixtures were reproduced from gateway source `a00e6d61b5f0f635e740337131eb35514adbc46f` and original shared revision `019bb7250549f1040a813c599a2ac1b09bd620f3`. No dependency or protocol version changes accompany this contract.

## Control


Sentences removed from the control specification because they state review,
delivery, adoption, interoperability, compatibility or ownership status.

## From control-exchange-candidate.md

- Membership realm identities: This incompatible candidate delta refuses arbitrary realm labels without fallback.
- Membership realm identities: Canonical realm/source publication production and ns recorded-byte consumption are adopted; complete owner confirmation, refusal coverage and live source retirement remain open. See [adoption evidence](account-handoff.md#adoption-publication).
- Scope: Producers independently review these bytes before live adoption.
- Canonical tuples (registration transitions): Existing nonzero fixtures are structural receiver coverage, not a registration producer form. Schema, codecs and comparator remain unchanged.
- Canonical tuples (RecordRotation): RecordRotation keeps I and membership version, changes K and increases generation, with explicit reviewed producer-profile RebindAuthorization.
- Machine claims and key sets: Whether a later gateway candidate should require machine audience remains an open owner-review item.
- Machine claims and key sets: This package exposes the NSD audience comparison alone, not an imitation of its complete verifier or external OIDC.
- Complete pinned consumer disposition: These mappings are candidate replacements, not claims of deployed equivalence.
- Producer checklist and outstanding review: Platform gateway registration, assigned tunnel addresses and server peer stubs are retired here in favor of the ordinary Node binding.
- Producer checklist and outstanding review: The candidate fixture authority must check provisioned membership and credential before returning acceptance; no shared helper can substitute for that external authority lookup.
- Producer checklist and outstanding review: NSD currently emits device-flow authentication, control trust, ordered endpoints and additive features; feature understanding maps to declared capability identifiers without creating grants.
- Producer checklist and outstanding review: Update-distribution metadata, optional attestation and legacy deployment display type are not enrollment authority and are retired from this control exchange.
- Producer checklist and outstanding review: Legacy WSS companion tokens and role-specific legs are retired; they do not acquire a second candidate authentication path.
- Producer checklist and outstanding review: This checklist does not claim current producer compatibility. Registration/source and lifecycle handling are adopted in source; Q07 is answered by the code check, and Q11 has bounded answers with remaining producer-owned vectors due from NSD before H03. Current matched enrollment corpus bytes and live confirmation remain open. See [adoption evidence](account-handoff.md#adoption-core).
- Retained predicate sources: Their existing handlers are a producer checklist, not confirmation of this candidate encoding.
- Control reports: Exact shared control-report producer bytes, admin scope/subject/JWT/signed-URL/header review, unplaced carriers and any gateway audience decision remain open; partial family-7 implementation is recorded. See [adoption evidence](account-handoff.md#adoption-policy).
- Required source authority in responses: The response extension is incompatible: every successful registration decision, including Equal, and every successful authentication requires the canonical byte string of SignedSourceBinding. Standalone SourceAcceptance is retired with no old-shape fallback.
- Required source authority in responses: Registration/source and lifecycle handling are adopted in source; Q07 is answered by the code check, and Q11 has bounded answers with remaining producer-owned vectors due from NSD before H03. Current matched enrollment corpus bytes and live confirmation remain open. See [adoption evidence](account-handoff.md#adoption-core).
- Explicit authentication source selection: This is an incompatible candidate request delta. AuthenticationResponse and SignedSourceBinding encodings and signing domains are unchanged. Registration/source and lifecycle handling are adopted in source; Q07 is answered by the code check, and Q11 has bounded answers with remaining producer-owned vectors due from NSD before H03. Current matched enrollment corpus bytes and live confirmation remain open. See [adoption evidence](account-handoff.md#adoption-core).
- M6 service control candidate: This is breaking for existing consumers; the old seven-element request is refused.
- M6 service control candidate: NSD M6 carrier and ns recorded-byte adapters are adopted; Q23 composition agreement and real per-Network session/proposal/lease confirmation remain open. See [adoption evidence](account-handoff.md#adoption-m6).

## From control-report-candidate.md

- Candidate review: This explicitly changes only kind 1 service request/response bytes in the earlier public-edge candidate; all other public-edge, auth, material, declaration and listener bytes remain unchanged.
- Candidate review: The Python producer and Rust control_report_contract_vectors consumer precede pure codecs.
- Candidate review: This is fixture-produced candidate evidence. Exact shared control-report producer bytes, admin scope/subject/JWT/signed-URL/header review, unplaced carriers and any gateway audience decision remain open; partial family-7 implementation is recorded. See [adoption evidence](account-handoff.md#adoption-policy).
- Complete pinned control-report consumer disposition: All allocated sender, test, transport and fixture rows are explicit candidate mappings; this is not deployed equivalence or producer agreement.

## From service-control-carrier-candidate.md

- Scope: This is a pure candidate contract, with no transport, persistence, session state or I/O. NSD M6 carrier and ns recorded-byte adapters are adopted; Q23 composition agreement and real per-Network session/proposal/lease confirmation remain open. See [adoption evidence](account-handoff.md#adoption-m6).
- Subscription binding: This eight-element tuple is **breaking for existing consumers**; seven elements are refused with no fallback.
- Stream events and reverse operations: Contribution withdrawal or replacement fences pending requests and streams; P06 source epochs/generations are never substituted for M6 epochs/generations.
- Pure API and evidence: Fixture acceptance is candidate evidence, never NSD interoperability agreement.

## From source-selection-candidate.md

- Status: Status: pure candidate definitions and labelled fixture authority. Select/clear production, immutable receipts and ns restart/replay consumption are adopted; live routing and matched default/nested Exit confirmation remain open. See [adoption evidence](account-handoff.md#adoption-routes).
- Route commands and immutable receipts: control carrier confidential operations are `node.route.select` and `node.route.clear`, at the existing control endpoint. They deliberately do not reuse retired gateway-ID operation identifiers.
- Route commands and immutable receipts: Old-profile receipts are refused, not translated.
- Independent consumer sequence: Fixture assertions are contract evidence only; actual producer review and interoperability are open.
- Review boundary: Q12/Q14/Q21 request producer confirmation of these exact bytes and provenance, including durable source generation and all-receipt ownership.
- Explicit authentication source selection: This is an incompatible candidate request delta. AuthenticationResponse and SignedSourceBinding encodings and signing domains are unchanged. Registration/source and lifecycle handling are adopted in source; Q07 is answered by the code check, and Q11 has bounded answers with remaining producer-owned vectors due from NSD before H03. Current matched enrollment corpus bytes and live confirmation remain open. See [adoption evidence](account-handoff.md#adoption-core).

## From l8-account-payload-profile.md

- Bootstrap and envelope trust: This details only discovery/envelope verification in family 11 `v1-replacement`. It changes neither the registry nor its bytes and does not complete the other surface mappings.
- Bootstrap and envelope trust: These are new candidate domains, not historical wire strings.
- Bootstrap and envelope trust: Independent Python discovery/carrier vectors give bytes, signatures, expected pins/order/payload/authority and explicit decisions. Registration/source and lifecycle handling are adopted in source; Q07 is answered by the code check, and Q11 has bounded answers with remaining producer-owned vectors due from NSD before H03. Current matched enrollment corpus bytes and live confirmation remain open. See [adoption evidence](account-handoff.md#adoption-core).
- Complete candidate control exchange: Independent fixtures are `control-exchange.vec`; the consumer is `control_exchange_vectors`.
- Complete candidate control exchange: Possible later gateway enforcement is an open owner-review item.
- Complete candidate control exchange: Registration/source and lifecycle handling are adopted in source; Q07 is answered by the code check, and Q11 has bounded answers with remaining producer-owned vectors due from NSD before H03. Current matched enrollment corpus bytes and live confirmation remain open. See [adoption evidence](account-handoff.md#adoption-core).
- Complete candidate control reports: Kind 1 EdgeServiceRequest/Response is an explicit incompatible candidate delta: unchanged M6 service objects gain complete local metadata/Exit declarations and exact per-reference accepted/rejected outcomes. No other public-edge bytes change.
- Complete candidate control reports: Exact shared control-report producer bytes, admin scope/subject/JWT/signed-URL/header review, unplaced carriers and any gateway audience decision remain open; partial family-7 implementation is recorded. See [adoption evidence](account-handoff.md#adoption-policy).
- Source binding and Node route commands: Select/clear production, immutable receipts and ns restart/replay consumption are adopted; live routing and matched default/nested Exit confirmation remain open. See [adoption evidence](account-handoff.md#adoption-routes).
- Signed source authority response delta: This incompatible candidate extension retires standalone SourceAcceptance and refuses old response arities.
- Signed source authority response delta: Independent fixture vectors precede the pure codecs; fixtures are not NSD output.
- Signed source authority response delta: Registration/source and lifecycle handling are adopted in source; Q07 is answered by the code check, and Q11 has bounded answers with remaining producer-owned vectors due from NSD before H03. Current matched enrollment corpus bytes and live confirmation remain open. See [adoption evidence](account-handoff.md#adoption-core).
- Signed source authority response delta: Prior delivered revisions retain their original attribution; consumers must name the immutable revision containing this response extension when adopting it.
- Explicit authentication source selection: This is an incompatible candidate request delta. AuthenticationResponse and SignedSourceBinding encodings and signing domains are unchanged. Registration/source and lifecycle handling are adopted in source; Q07 is answered by the code check, and Q11 has bounded answers with remaining producer-owned vectors due from NSD before H03. Current matched enrollment corpus bytes and live confirmation remain open. See [adoption evidence](account-handoff.md#adoption-core).
- M6 service control carrier: The subscription request is now an incompatible eight-element tuple with an appended null or exact M6 session binding. Seven-element inputs are refused.
- M6 service control carrier: NSD M6 carrier and ns recorded-byte adapters are adopted; Q23 composition agreement and real per-Network session/proposal/lease confirmation remain open. See [adoption evidence](account-handoff.md#adoption-m6).
- M6 service control carrier (table, External status column): Public edge / service integration: Consumer lifecycle and NSD interoperability remain separate. NSD M6 carrier and ns recorded-byte adapters are adopted; Q23 composition agreement and real per-Network session/proposal/lease confirmation remain open. See [adoption evidence](account-handoff.md#adoption-m6).
- Complete candidate control reports: The independent confidential-auth.vec fixture and confidential_auth_generation consumer validate pending/current dependency correlation and private configuration refusals. The candidate fixture is not NSD producer confirmation. Family 7 registry metadata and public publication bytes are unchanged.

## Publication


Sentences removed from the publication specification because they state review,
delivery, adoption, interoperability, compatibility or ownership status.

## From l8-account-payload-profile.md

- Signed publication events: These are candidate publication identifiers, not copies of v1 transport tags.
- Signed publication events: Existing fixtures retain their names and bytes. NSD source-bound delivery and ns recorded-byte adapters are adopted; live delivery/disconnect/expiry confirmation and Q21 answers remain open; Q11 has code-check answers with remaining NSD producer vectors due before H03. See [adoption evidence](account-handoff.md#adoption-delivery).
- Signed publication events (membership realm text): Membership realm text follows the incompatible canonical identity delta above.
- Publication subscription request: NSD source-bound delivery and ns recorded-byte adapters are adopted; live delivery/disconnect/expiry confirmation and Q21 answers remain open; Q11 has code-check answers with remaining NSD producer vectors due before H03. See [adoption evidence](account-handoff.md#adoption-delivery).
- Publication snapshot poll request: Independent publication-snapshot-request.vec fixture bytes are candidate evidence. NSD source-bound delivery and ns recorded-byte adapters are adopted; live delivery/disconnect/expiry confirmation and Q21 answers remain open; Q11 has code-check answers with remaining NSD producer vectors due before H03. See [adoption evidence](account-handoff.md#adoption-delivery).
- Source binding and Node route commands: An old unbound event is refused by the new form without fallback.
- Source binding and Node route commands: Select/clear production, immutable receipts and ns restart/replay consumption are adopted; live routing and matched default/nested Exit confirmation remain open. See [adoption evidence](account-handoff.md#adoption-routes).
- Source binding and Node route commands (Q18): [Q18](account-review-request.md) records the settled participant/directory choice: a shared participant credential and a separate signed directory binding, with the global directory unchanged. The shared [definitions and independent vectors](../spec/account/relay.md) are delivered; gateway runtime adoption remains pending. NSD signed roster/participant and directory production plus ns recorded directory consumption are adopted; local file-writer proof, live rollback/carrier transitions and complete unsettled-reference sealing remain open. See [adoption evidence](account-handoff.md#adoption-roster).
- Inner publication producer: Independent fixtures round-trip producer-valid content and assert producer refusal for decodable invalid content; they are not NSD output.
- Inner publication producer: NSD adopted shared `95f1688`, containing implementation revision `2391ebd5e59574cb318fbc2c7b1ca3615426796a`; earlier package revisions do not include it. Canonical realm/source publication production and ns recorded-byte consumption are adopted; complete owner confirmation, refusal coverage and live source retirement remain open. See [adoption evidence](account-handoff.md#adoption-publication).

## From control-exchange-candidate.md

- Authenticated publication subscription: `account::publication_subscription::PublicationSubscriptionRequest` is the candidate request.
- Authenticated publication subscription: NSD source-bound delivery and ns recorded-byte adapters are adopted; live delivery/disconnect/expiry confirmation and Q21 answers remain open; Q11 has code-check answers with remaining NSD producer vectors due before H03. See [adoption evidence](account-handoff.md#adoption-delivery).
- Authenticated publication subscription (service control field, from "M6 service control candidate"): This is breaking for existing consumers; the old seven-element request is refused.
- Independent publication snapshot poll: Independent fixture producers and consumers establish candidate bytes only. NSD source-bound delivery and ns recorded-byte adapters are adopted; live delivery/disconnect/expiry confirmation and Q21 answers remain open; Q11 has code-check answers with remaining NSD producer vectors due before H03. See [adoption evidence](account-handoff.md#adoption-delivery).

## From source-selection-candidate.md

- Status: Status: pure candidate definitions and labelled fixture authority. Select/clear production, immutable receipts and ns restart/replay consumption are adopted; live routing and matched default/nested Exit confirmation remain open. See [adoption evidence](account-handoff.md#adoption-routes).
- Source authority: Standalone SourceAcceptance and its whole-envelope decoder are retired; old response shapes have no fallback. This is an incompatible candidate delta.
- Source authority: Registration/source and lifecycle handling are adopted in source; Q07 is answered by the code check, and Q11 has bounded answers with remaining producer-owned vectors due from NSD before H03. Current matched enrollment corpus bytes and live confirmation remain open. See [adoption evidence](account-handoff.md#adoption-core).
- Source-bound publication: This intentional incompatible signed-byte delta adds the outer signature domain, mandatory binding and delivery bytes; an old PublicationEvent is never accepted by this new decoder. There is no fallback or signature reinterpretation.
- Independent consumer sequence: Fixture assertions are contract evidence only; actual producer review and interoperability are open.
- Review boundary: Q12/Q14/Q21 request producer confirmation of these exact bytes and provenance, including durable source generation and all-receipt ownership.
- Review boundary (Q18): [Q18](account-review-request.md) records the settled owner choice: a shared participant credential plus a separate NSD-signed directory binding, with the global directory unchanged. This source-binding and Node route candidate only cross-references them; it does not define participant or directory-binding contracts. NSD signed roster/participant and directory production plus ns recorded directory consumption are adopted; local file-writer proof, live rollback/carrier transitions and complete unsettled-reference sealing remain open. See [adoption evidence](account-handoff.md#adoption-roster).
- Inner publication producer addition: Independent fixtures round-trip producer-valid content and assert producer refusal for decodable invalid content; they are not NSD output.
- Inner publication producer addition: NSD adopted shared `95f1688`, containing implementation revision `2391ebd5e59574cb318fbc2c7b1ca3615426796a`; earlier package revisions do not include it. Canonical realm/source publication production and ns recorded-byte consumption are adopted; complete owner confirmation, refusal coverage and live source retirement remain open. See [adoption evidence](account-handoff.md#adoption-publication).

## Node and Subnet


Sentences removed from the node and Subnet specifications because they state review,
delivery, adoption, interoperability or ownership status.

## From l8-account-payload-profile.md

- Enrollment (Q11): The read-only check of NSD `3cd5f2bd`, ns `3349fe16` and nsshared `v0.7.0` answers capability syntax and current declarations; `node.control` is opaque with no semantics today. Complete remaining producer vectors stay with NSD before H03. See [Q11 answers](account-review-request.md#q11-enrollment-payload--nsd-owner).
- Enrollment (Q11): Shared information and bootstrap forms were not adopted by NSD/ns at `3cd5f2bd`/`3349fe16`; NSD adds the shared forms (owner decision 2026-10-28), ns keeps JSON for now. This answer changes no contract or bytes.
- Enrollment (Q07): Answered by a read-only code check of nsshared `v0.7.0`, ns main `c96fe8fc` and NSD refactor/unified-engine `58f20210`: refresh preserves the binding and generation; there is one signed record generation and no refresh tag. Positive `u64` wire values remain valid for shared/NSD/peer consumers; ordinary ns derivation checks its own `u32` overflow. Restart refusal applies per resolved accepted binding; a freshly approved new I without a lifecycle link is a new Node. See [Q07 answer](account-review-request.md#q07-identity-lifecycle--node-owner-with-nsd-confirmation).
- Registration-only incarnation placeholders: This clarification changes no schema, codec or comparator and requires no gateway repin. Registration/source and lifecycle handling are adopted in source; Q07 is answered by the code check, and Q11 has bounded answers with remaining producer-owned vectors due from NSD before H03. Current matched enrollment corpus bytes and live confirmation remain open. See [adoption evidence](account-handoff.md#adoption-core).
- Subnet selection: These are candidate fixtures, not NSD producer output.
- Ordinary provider Subnet route reports: M6, Subnet publication and select/clear bytes are unchanged.
- Ordinary provider Subnet route reports: Independent fixtures establish pure decisions only. NSD report handling and ns report/custody adapters are adopted in source; matched actual producer report bytes and real provider activation remain open; gateway self-reporting stays deferred. See [adoption evidence](account-handoff.md#adoption-provider).
- Exit grants and consumer Subnet route views: B40 ordering, bounds, prefixes, explicit/default selection, and grant/payer/incarnation/renewal bytes are unchanged.
- Exit grants and consumer Subnet route views: Fixture acceptance proves pure contracts only. NSD grant/client-route production and ns recorded-byte consumers are adopted; live installation/replacement/withdrawal and default/nested Exit qualification remain open. See [adoption evidence](account-handoff.md#adoption-subnet).
- R3 local Node naming and legacy registration retirement: The external R3 runtime consumer owns cutover and its commit/restart regression: matching acceptance must drop every active old pin and Short DNS authority; mismatched acceptance or supplied legacy values must leave the prior profile intact.
- R3 local Node naming and legacy registration retirement (N04/N09, S05/S06/S11): Local-name enrollment and ns authenticated commit/restart handling are adopted in source; live cutover and owner confirmation remain open; the portability follow-up is pending. See [adoption evidence](account-handoff.md#adoption-naming).
- R3 local Node naming and legacy registration retirement: The review delta is a candidate, never agreement or interoperability evidence.
- R3 local Node naming and legacy registration retirement: No new field, carrier, P-item or dependency edge is introduced; previous delivery evidence does not establish this delta or release external cutover acceptance.
- Provider mapping inventory (N07/N09, S25/S11, C06): Gateway self-reporting/inventory consumption remains deferred to C06. The separate provider-mappings publication and authenticated ns activation remain open; report/selection implementations do not establish this inventory or its independent producer vectors. See [adoption evidence](account-handoff.md#adoption-mapping).

## From control-exchange-candidate.md

- R3 local Node naming and legacy registration retirement: The external R3 runtime consumer owns cutover and its commit/restart regression: matching acceptance must drop every active old pin and Short DNS authority; mismatched acceptance or supplied legacy values must leave the prior profile intact.
- R3 local Node naming and legacy registration retirement (N04/N09, S05/S06/S11): Local-name enrollment and ns authenticated commit/restart handling are adopted in source; live cutover and owner confirmation remain open; the portability follow-up is pending. See [adoption evidence](account-handoff.md#adoption-naming).
- R3 local Node naming and legacy registration retirement: The review delta is a candidate, never agreement or interoperability evidence.
- R3 local Node naming and legacy registration retirement: No new field, carrier, P-item or dependency edge is introduced; previous delivery evidence does not establish this delta or release external cutover acceptance.

## From grant-authority-candidate.md

- Exit grants and consumer Subnet route views: B40 ordering, bounds, prefixes, explicit/default selection, and grant/payer/incarnation/renewal bytes are unchanged.
- Exit grants and consumer Subnet route views (N07/N08): Fixture acceptance proves pure contracts only. NSD grant/client-route production and ns recorded-byte consumers are adopted; live installation/replacement/withdrawal and default/nested Exit qualification remain open. See [adoption evidence](account-handoff.md#adoption-subnet).

## From provider-subnet-report-candidate.md

- Status: pure candidate contract; independent fixtures are labelled authority, not NSD producer output or persistence evidence.
- Independent acceptance and adoption (N30/N07/N08, S11/S25): NSD N30 owns ingestion, allocation and persistence; N07/N08 resolve current source/mapping authority before selection/projection. ns S11 produces intent and S25 owns the shared adapter and response custody. NSD report handling and ns report/custody adapters are adopted in source; matched actual producer report bytes and real provider activation remain open; gateway self-reporting stays deferred. See [adoption evidence](account-handoff.md#adoption-provider).
- Independent acceptance and adoption: Gateway self-reporting is deferred to the later ordinary-provider integration; existing Exit consumption, deferred live default Exit, M6 declarations and contribution sessions are unchanged.

## From l8-public-edge-candidate.md

- Provider mapping eligibility (N07/N09, S25/S11): The separate provider-mappings publication and authenticated ns activation remain open; report/selection implementations do not establish this inventory or its independent producer vectors. See [adoption evidence](account-handoff.md#adoption-mapping).
- Provider mapping eligibility (C06): The gateway retains local Exit configuration and grants; its mapping report producer and inventory consumer await the later C06 handoff.

## From source-selection-candidate.md

- Ordinary provider report addition (N30/N07/N08, S11/S25): NSD report handling and ns report/custody adapters are adopted in source; matched actual producer report bytes and real provider activation remain open; gateway self-reporting stays deferred. See [adoption evidence](account-handoff.md#adoption-provider).
- Exit grants and consumer Subnet route views (N07/N08): NSD grant/client-route production and ns recorded-byte consumers are adopted; live installation/replacement/withdrawal and default/nested Exit qualification remain open. See [adoption evidence](account-handoff.md#adoption-subnet).

## Realm and grants


Status sentences removed from spec/account/realm.md and spec/account/grants.md sources.

## Realm (family 2, policy and claim values)

- Membership realm identities (realm-publication-candidate.md and l8-account-payload-profile.md preambles): This incompatible candidate delta refuses arbitrary realm labels without fallback. Canonical realm/source publication production and ns recorded-byte consumption are adopted; complete owner confirmation, refusal coverage and live source retirement remain open. See [adoption evidence](account-handoff.md#adoption-publication).
- Realm publication content (l8-account-payload-profile.md, "Complete realm publication content"): Canonical realm/source publication production and ns recorded-byte consumption are adopted; complete owner confirmation, refusal coverage and live source retirement remain open. See [adoption evidence](account-handoff.md#adoption-publication).
- Realm publication canonical content (realm-publication-candidate.md): The candidate fixture authority is not NSD producer confirmation.
- Realm publication vectors (realm-publication-candidate.md): Independent `realm-publication.vec` fixtures and `realm_publication_vectors` cover canonical content, refusals and `realm_membership_replacement`. Canonical realm/source publication production and ns recorded-byte consumption are adopted; complete owner confirmation, refusal coverage and live source retirement remain open. See [adoption evidence](account-handoff.md#adoption-publication).
- Policy inventory, GatewayAuthJwtAuthority (l8-account-payload-profile.md, "Inventory disposition and carrier boundary"): Exact shared control-report producer bytes, admin scope/subject/JWT/signed-URL/header review, unplaced carriers and any gateway audience decision remain open; partial family-7 implementation is recorded. See [adoption evidence](account-handoff.md#adoption-policy).
- Policy inventory, OIDC claims (l8-account-payload-profile.md, "Inventory disposition and carrier boundary"): NSD confidential acquisition/dispatch is adopted in source; independent material/auth producer corpora, JWT projection review and live installation remain open. See [adoption evidence](account-handoff.md#adoption-material).
- Policy inventory, unplaced items (l8-account-payload-profile.md, "Inventory disposition and carrier boundary"): Unplaced inventory items stay open until an enclosing family or a later design assigns a carrier; no new kind or implicit policy publication is defined here.

## Grants (families 3, 4, 5, 6)

- Grant authority membership realm identities (grant-authority-candidate.md preamble): This incompatible candidate delta refuses arbitrary realm labels without fallback. Canonical realm/source publication production and ns recorded-byte consumption are adopted; complete owner confirmation, refusal coverage and live source retirement remain open. See [adoption evidence](account-handoff.md#adoption-publication).
- Service grants and payer authority (l8-account-payload-profile.md): Independent producer fixtures and `grant_authority_vectors` exercise accepted and typed refused contracts, selective withdrawal and fresh regrant. Family registry bytes are unchanged. Protocol-qualified grant, payer and withdrawal projection is adopted in source; complete independent producer vectors, owner answers and live joins remain open. See [adoption evidence](account-handoff.md#adoption-grants).
- Usage payer revision (l8-account-payload-profile.md, "Service grants and payer authority"): See the [usage contract](../spec/account/usage.md) for the incompatible candidate delta.
- Protocol-qualified grant and renewal (l8-account-payload-profile.md): `protocol_grant_renewal` provides independent fixture producer and consumer coverage. Protocol-qualified grant, payer and withdrawal projection is adopted in source; complete independent producer vectors, owner answers and live joins remain open. See [adoption evidence](account-handoff.md#adoption-grants).
- Grant authority producer mapping (grant-authority-candidate.md): Candidate fixtures supply authority; they do not establish live interoperability. The predecessor producer mapping used string ULIDs, integer-array peer keys and its NodeL3Config resource graph; merged projection evidence is recorded below. Protocol-qualified grant, payer and withdrawal projection is adopted in source; complete independent producer vectors, owner answers and live joins remain open. See [adoption evidence](account-handoff.md#adoption-grants).
- Protocol-qualified identity and renewal (grant-authority-candidate.md): Candidate fixture acceptance does not establish producer adoption. Protocol-qualified grant, payer and withdrawal projection is adopted in source; complete independent producer vectors, owner answers and live joins remain open. See [adoption evidence](account-handoff.md#adoption-grants).

## Edge


- realm identity: This incompatible candidate delta refuses arbitrary realm labels without fallback. Canonical realm/source publication production and ns recorded-byte consumption are adopted; complete owner confirmation, refusal coverage and live source retirement remain open. See [adoption evidence](account-handoff.md#adoption-publication).
- public-edge producer: Python fixtures are labelled candidate sources, independent of the Rust codecs. NSD public-edge projection, anonymous/raw-name vectors and actual producer corpus are adopted; a matching downstream corpus reader, live policy/name enforcement and Q17 confirmation remain open. See [adoption evidence](account-handoff.md#adoption-edge).
- public-edge producer: The independent Python public_edge producer and Rust public_edge_vectors tests exercise complete replacement, valid empty withdrawal, malformed/noncanonical refusal without renewal, names/aliases/ports/domains, full backend identity joins, material generation mismatch and unchanged M6 object bytes/digests. NSD public-edge projection, anonymous/raw-name vectors and actual producer corpus are adopted; a matching downstream corpus reader, live policy/name enforcement and Q17 confirmation remain open. See [adoption evidence](account-handoff.md#adoption-edge).
- confidential configuration: Confidential configuration is specified separately and claims no predecessor wire equivalence.
- confidential configuration: No defaults or predecessor wire equivalence are claimed; installation ACKs remain correlated to the exact reference/generation.
- service labels: M01/M02 remain open for explicit standalone API agreement and independent label-boundary vectors. See [adoption evidence](account-handoff.md#adoption-labels).
- protocol-specific names: Existing HTTP-only fixture bytes are unchanged. Existing raw-route fixture names are deliberately regenerated from text to null, including anonymous-policy fixtures. Version 1 and the thirteen-position tuple remain unchanged; neither old named raw routes nor a compatibility fallback are accepted.
- protocol-specific names: NSD public-edge projection, anonymous/raw-name vectors and actual producer corpus are adopted; a matching downstream corpus reader, live policy/name enforcement and Q17 confirmation remain open. See [adoption evidence](account-handoff.md#adoption-edge).
- protocol-specific names: Confirm NSD HTTP public_host and raw protocol/port projection, with producer-owned accepted/refused vectors. Independent candidate fixtures are not producer agreement. NSD public-edge projection, anonymous/raw-name vectors and actual producer corpus are adopted; a matching downstream corpus reader, live policy/name enforcement and Q17 confirmation remain open. See [adoption evidence](account-handoff.md#adoption-edge).
- anonymous selector: This candidate API and accepted-wire-domain extension preserves all existing selector bytes. Older consumers reject the new selector rather than reading it as null or an identity.
- service report kind 1: The complete kind 1 report now includes local floor metadata, non-authoritative Exit profiles and per-reference outcomes as specified in control report exchanges. That explicit candidate delta replaces the earlier whole-report boolean for kind 1; all other public-edge, material, declaration and listener bytes remain unchanged.
- confidential auth producer: The pinned NSD producer supplies no JWT issuers; its absence is not proof of candidate producer support. The independent Python fixture is a labelled candidate producer. This contract changes no family registry bytes or publication channel. NSD confidential acquisition/dispatch is adopted in source; independent material/auth producer corpora, JWT projection review and live installation remain open. See [adoption evidence](account-handoff.md#adoption-material).
- confidential auth producer: The candidate fixture is not NSD producer confirmation (confidential-auth.vec / confidential_auth_generation).
- confidential material: Status: pure candidate contract. Independent Python fixtures are candidate authority, not NSD output or an interoperability agreement. NSD confidential acquisition/dispatch is adopted in source; independent material/auth producer corpora, JWT projection review and live installation remain open. See [adoption evidence](account-handoff.md#adoption-material).
- confidential material: NSD confidential acquisition/dispatch is adopted in source; independent material/auth producer corpora, JWT projection review and live installation remain open. See [adoption evidence](account-handoff.md#adoption-material).
- confidential material: Family 7 gains confidential value delivery without changing public references, registry bytes, AuthConfigRequest's auth-only restriction or installation ACK bytes.
- confidential material: Existing auth and installation ACK fixtures remain unchanged.

## Relay and usage


- realm identity: This incompatible candidate delta refuses arbitrary realm labels without fallback. (usage-contract-candidate.md preamble) Canonical realm/source publication production and ns recorded-byte consumption are adopted; complete owner confirmation, refusal coverage and live source retirement remain open. See [adoption evidence](account-handoff.md#adoption-publication).
- participant authority: NSD signed roster/participant and directory production plus ns recorded directory consumption are adopted; local file-writer proof, live rollback/carrier transitions and complete unsettled-reference sealing remain open. See [adoption evidence](account-handoff.md#adoption-roster).
- participant authority: Independent vectors are fixture authority, not live NSD qualification. See `participant_auth_transport` in `participant-authority.vec`.
- participant authority: The shared definition is delivered at immutable revision `28bf972db2e1f434114adc324a26fabad545aed1`.
- participant authority: Family 8 now includes shared enrollment/authentication/renewal frames and the separate signed directory binding defined in participant authority. NSD signed roster/participant and directory production plus ns recorded directory consumption are adopted; local file-writer proof, live rollback/carrier transitions and complete unsettled-reference sealing remain open. See [adoption evidence](account-handoff.md#adoption-roster).
- participant authority: The gateway executes TLS/lifecycle/discovery adoption separately. NSD signed roster/participant and directory production plus ns recorded directory consumption are adopted; local file-writer proof, live rollback/carrier transitions and complete unsettled-reference sealing remain open. See [adoption evidence](account-handoff.md#adoption-roster).
- participant roster lifecycle: NSD signed roster/participant and directory production plus ns recorded directory consumption are adopted; local file-writer proof, live rollback/carrier transitions and complete unsettled-reference sealing remain open. See [adoption evidence](account-handoff.md#adoption-roster).
- usage contract: This is a pure candidate contract, not a released NSD producer profile.
- usage contract: The nine-field version-1 ServiceUsage tuple is unchanged except that payer_subject is now exactly 16 unsigned big-endian ULID bytes.
- echo reply billing: The current gateway candidate emits no `EchoReplySend` rows: at frozen nsplane 0.16.0, synthetic replies are delivered but unbilled because the normal outbound path provides no per-packet successful-send receipt.
- echo reply billing: Open: released packet-runtime completed-send evidence and gateway billing qualification are still required; ns packet-engine adoption alone does not establish gateway EchoReplySend capture.
- usage contract: No duration is invented by this candidate.
- usage fixtures: These fixtures establish candidate behavior only. NSD usage receipt/history handling and actual answer corpora are adopted; live completed-I/O capture, exclusion/repair, matching downstream corpus consumption and the retention seal remain open. See [adoption evidence](account-handoff.md#adoption-usage).
- usage fixtures: The existing gateway neutral echo recorder uses message quantities and needs explicit completed-byte instrumentation before adopting this profile; no implicit message-to-byte conversion is authorized.
- usage fixtures: The review request records the incompatible predecessor.
- usage profile catalogue: Existing usage report and ACK bytes are unchanged. NSD usage/Node-control catalogue production and actual corpus are adopted; matching ns/gateway corpus consumption, live preserved state and Q19/Q20 answers remain open. See [adoption evidence](account-handoff.md#adoption-profiles).
- profile publications: This is a new candidate payload delivery for families 9 and 10. Fixture authority is labelled candidate input and establishes no external interoperability. NSD usage/Node-control catalogue production and actual corpus are adopted; matching ns/gateway corpus consumption, live preserved state and Q19/Q20 answers remain open. See [adoption evidence](account-handoff.md#adoption-profiles).
- profile publications: Families 9 and 10 now have explicit candidate payloads: `[1, reporter, profiles]` and `[1, membership_scope, 2, capabilities]`.
- profile publications: NSD usage/Node-control catalogue production and actual corpus are adopted; matching ns/gateway corpus consumption, live preserved state and Q19/Q20 answers remain open. See [adoption evidence](account-handoff.md#adoption-profiles).
- profile publications: Runtime persistence and preservation of captured usage/control state belong to the gateway regression, which must consume these same source-bound bytes.
- profile publications: Existing usage report/ACK and Node-control fixtures retain their bytes; the family registry set is unchanged.
- profile publications: The following canonical bytes and signatures are fixed before codec implementation.

## Current candidate additions

The [candidate inventory](account-inventory.md#current-candidate-additions-and-release-inventory)
and [migration delta](account-migration.md#current-candidate-delta) describe the
shared whole-floor M6 and independent roster-counter additions. Their shared
source and independent fixture delivery establish no new downstream adoption.
The historical matched M6 corpus covers legacy composition, not nonempty
`FloorReportMessage` content. Historical roster/directory production does not
establish schema-2 publication, separate persisted floors or DATA-time epoch capture.

Gateway/NSD whole-floor adoption and NSD/relayd independent-counter adoption
remain to be demonstrated. No consumer checks were executed for this inventory.
Q07/Q11 retain only their recorded bounded answers; complete remaining
producer-owned vectors stay with NSD before H03. Q22/Q23, M01/M02 and Q24 remain
open, as do unmatched downstream corpora, owner review, live qualification,
retention-seal acceptance and F04 integration. `node.control` remains opaque.
The account surface remains behind `unstable-account`; final release revision
and cohort remain unset. Released adoption and production eligibility require
H03/R01/R02/C01b and C18 re-verification, with deletion held under Q-RET.
