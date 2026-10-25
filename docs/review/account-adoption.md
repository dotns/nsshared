# Account adoption

Review, delivery, adoption, interoperability and ownership state of the account
contracts, collected from the specifications when they were folded into
[docs/spec](../spec/README.md). Each entry names its contract; identifiers (N.., S..,
C.., Q.., P..) refer to the [review request](account-review-request.md), the
[handoff](account-handoff.md) and the consumer plans. Entries change as owners answer
and adopt; the specifications do not depend on them.

## Core: RealmId, profile and Node-control

- Canonical RealmId: Arbitrary realm labels are refused without fallback (an incompatible change to earlier account payloads). NSD and ns producer and consumer updates remain outstanding, including the other active consumer delivery. Prior evidence applies only to its recorded revision. Original-profile persisted state remains isolated.
- Account profile: The account payload record (`docs/task/20261019-0029-l8-account-payload-profile.md`) owns every registry entry. The review request records the delivered revision, family states, producer questions and requested M6 changes. Delivery does not imply approval.
- Account conformance: Fixture vectors are not producer output; existing vectors retain their names and bytes.
- Node-control: The nine gateway fixtures were reproduced from gateway source `a00e6d61b5f0f635e740337131eb35514adbc46f` and original shared revision `019bb7250549f1040a813c599a2ac1b09bd620f3`. No dependency or protocol version changes accompany this contract.

## Control


Sentences removed from the control specification because they state review,
delivery, adoption, interoperability, compatibility or ownership status.

## From control-exchange-candidate.md

- Membership realm identities: This incompatible candidate delta refuses arbitrary realm labels without fallback.
- Membership realm identities: NSD/ns producer and consumer updates, including the other active consumer delivery, remain outstanding.
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
- Producer checklist and outstanding review: NSD confirmation of the exact candidate tuples and independent producer vectors remains outstanding. This checklist does not claim current producer compatibility.
- Retained predicate sources: Their existing handlers are a producer checklist, not confirmation of this candidate encoding.
- Control reports: NSD producer confirmation remains outstanding.
- Required source authority in responses: The response extension is incompatible: every successful registration decision, including Equal, and every successful authentication requires the canonical byte string of SignedSourceBinding. Standalone SourceAcceptance is retired with no old-shape fallback.
- Required source authority in responses: NSD N04 adoption and producer review remain outstanding.
- Explicit authentication source selection: This is an incompatible candidate request delta. AuthenticationResponse and SignedSourceBinding encodings and signing domains are unchanged. NSD N04 adoption remains outstanding.
- M6 service control candidate: This is breaking for existing consumers; the old seven-element request is refused.
- M6 service control candidate: NSD adoption and independent real producer confirmation remain outstanding.

## From control-report-candidate.md

- Candidate review: This explicitly changes only kind 1 service request/response bytes in the earlier public-edge candidate; all other public-edge, auth, material, declaration and listener bytes remain unchanged.
- Candidate review: The Python producer and Rust control_report_contract_vectors consumer precede pure codecs.
- Candidate review: This is fixture-produced candidate evidence. NSD producer confirmation and independent producer-owned vectors remain outstanding.
- Complete pinned control-report consumer disposition: All allocated sender, test, transport and fixture rows are explicit candidate mappings; this is not deployed equivalence or producer agreement.

## From service-control-carrier-candidate.md

- Scope: This is a pure candidate contract, with no transport, persistence, session state or I/O. NSD adoption and independent real producer review remain outstanding.
- Subscription binding: This eight-element tuple is **breaking for existing consumers**; seven elements are refused with no fallback.
- Stream events and reverse operations: Contribution withdrawal or replacement fences pending requests and streams; P06 source epochs/generations are never substituted for M6 epochs/generations.
- Pure API and evidence: Fixture acceptance is candidate evidence, never NSD interoperability agreement.

## From source-selection-candidate.md

- Status: Status: pure candidate definitions and labelled fixture authority. NSD producer review, producer vectors and ns/NSD interoperability remain outstanding.
- Route commands and immutable receipts: control carrier confidential operations are `node.route.select` and `node.route.clear`, at the existing control endpoint. They deliberately do not reuse retired gateway-ID operation identifiers.
- Route commands and immutable receipts: Old-profile receipts are refused, not translated.
- Independent consumer sequence: Fixture assertions are contract evidence only; actual producer review and interoperability are open.
- Review boundary: Q12/Q14/Q21 request producer confirmation of these exact bytes and provenance, including durable source generation and all-receipt ownership.
- Explicit authentication source selection: This is an incompatible candidate request delta. AuthenticationResponse and SignedSourceBinding encodings and signing domains are unchanged. NSD N04 adoption remains outstanding.

## From l8-account-payload-profile.md

- Bootstrap and envelope trust: This details only discovery/envelope verification in family 11 `v1-replacement`. It changes neither the registry nor its bytes and does not complete the other surface mappings.
- Bootstrap and envelope trust: These are new candidate domains, not historical wire strings.
- Bootstrap and envelope trust: Independent Python discovery/carrier vectors give bytes, signatures, expected pins/order/payload/authority and explicit decisions. NSD producer confirmation and independent producer vectors remain requested in Q11 and Q21.
- Complete candidate control exchange: Independent fixtures are `control-exchange.vec`; the consumer is `control_exchange_vectors`.
- Complete candidate control exchange: Possible later gateway enforcement is an open owner-review item.
- Complete candidate control exchange: NSD producer confirmation remains outstanding; candidate fixtures do not establish agreement or interoperability.
- Complete candidate control reports: Kind 1 EdgeServiceRequest/Response is an explicit incompatible candidate delta: unchanged M6 service objects gain complete local metadata/Exit declarations and exact per-reference accepted/rejected outcomes. No other public-edge bytes change.
- Complete candidate control reports: Independent producer bytes are in control-reports.vec and public-edge.vec; NSD confirmation remains outstanding.
- Source binding and Node route commands: Independent vectors are labelled fixture authority; NSD producer review and ns/NSD adoption remain open.
- Signed source authority response delta: This incompatible candidate extension retires standalone SourceAcceptance and refuses old response arities.
- Signed source authority response delta: Independent fixture vectors precede the pure codecs; fixtures are not NSD output.
- Signed source authority response delta: NSD N04 adoption, producer-owned vectors and real interoperability remain outstanding.
- Signed source authority response delta: Prior delivered revisions retain their original attribution; consumers must name the immutable revision containing this response extension when adopting it.
- Explicit authentication source selection: This is an incompatible candidate request delta. AuthenticationResponse and SignedSourceBinding encodings and signing domains are unchanged. NSD N04 adoption remains outstanding.
- M6 service control carrier: The subscription request is now an incompatible eight-element tuple with an appended null or exact M6 session binding. Seven-element inputs are refused.
- M6 service control carrier: Independent carrier and regenerated subscription vectors are candidate evidence; NSD M6 carrier adoption and producer review are outstanding.
- M6 service control carrier (table, External status column): Bootstrap / v1 replacement: NSD carrier adoption and real producer vectors outstanding. Public edge / service integration: Consumer lifecycle and NSD interoperability remain separate. Publication subscription: Producer and consumer adoption required; no old-arity fallback.
- Complete candidate control reports: The independent confidential-auth.vec fixture and confidential_auth_generation consumer validate pending/current dependency correlation and private configuration refusals. The candidate fixture is not NSD producer confirmation. Family 7 registry metadata and public publication bytes are unchanged.

## Publication


Sentences removed from the publication specification because they state review,
delivery, adoption, interoperability, compatibility or ownership status.

## From l8-account-payload-profile.md

- Signed publication events: These are candidate publication identifiers, not copies of v1 transport tags.
- Signed publication events: Existing fixtures retain their names and bytes. These are candidate fixtures; NSD production and independent producer confirmation remain requested.
- Signed publication events (membership realm text): Membership realm text follows the incompatible canonical identity delta above.
- Publication subscription request: Independent consumer vectors precede the pure codec; matching NSD production and confirmation remain outstanding.
- Publication snapshot poll request: Independent publication-snapshot-request.vec fixture bytes are candidate evidence. NSD confirmation and real producer vectors remain outstanding.
- Source binding and Node route commands: An old unbound event is refused by the new form without fallback.
- Source binding and Node route commands: Independent vectors are labelled fixture authority; NSD producer review and ns/NSD adoption remain open.
- Source binding and Node route commands (Q18): [Q18](account-review-request.md) records the settled participant/directory choice: a shared participant credential and a separate signed directory binding, with the global directory unchanged. The shared [definitions and independent vectors](../spec/account/relay.md) are delivered; gateway runtime adoption remains pending. NSD producer review and NSD/ns adoption remain outstanding.
- Inner publication producer: Independent fixtures round-trip producer-valid content and assert producer refusal for decodable invalid content; they are not NSD output.
- Inner publication producer: NSD N06, N08 and N21 producers should adopt implementation revision `2391ebd5e59574cb318fbc2c7b1ca3615426796a`; earlier package revisions do not include it. Producer-owned vectors and adoption remain outstanding.

## From control-exchange-candidate.md

- Authenticated publication subscription: `account::publication_subscription::PublicationSubscriptionRequest` is the candidate request.
- Authenticated publication subscription: NSD confirmation of this exact candidate and producer vectors is outstanding; the current predecessor handler is a checklist, not interoperability evidence.
- Authenticated publication subscription (service control field, from "M6 service control candidate"): This is breaking for existing consumers; the old seven-element request is refused.
- Independent publication snapshot poll: Independent fixture producers and consumers establish candidate bytes only. NSD confirmation of the active subscription binding, operation, exact scope selection and response nonce echo, plus independent real producer vectors, remains outstanding.

## From source-selection-candidate.md

- Status: Status: pure candidate definitions and labelled fixture authority. NSD producer review, producer vectors and ns/NSD interoperability remain outstanding.
- Source authority: Standalone SourceAcceptance and its whole-envelope decoder are retired; old response shapes have no fallback. This is an incompatible candidate delta.
- Source authority: NSD N04 producer adoption and producer-owned interoperability vectors are outstanding.
- Source-bound publication: This intentional incompatible signed-byte delta adds the outer signature domain, mandatory binding and delivery bytes; an old PublicationEvent is never accepted by this new decoder. There is no fallback or signature reinterpretation.
- Independent consumer sequence: Fixture assertions are contract evidence only; actual producer review and interoperability are open.
- Review boundary: Q12/Q14/Q21 request producer confirmation of these exact bytes and provenance, including durable source generation and all-receipt ownership.
- Review boundary (Q18): [Q18](account-review-request.md) records the settled owner choice: a shared participant credential plus a separate NSD-signed directory binding, with the global directory unchanged. P07 owns those shared definitions (pending), and P08 owns gateway adoption (pending). This source-binding and Node route candidate only cross-references them; it does not define participant or directory-binding contracts. NSD producer review and NSD/ns adoption remain outstanding.
- Inner publication producer addition: Independent fixtures round-trip producer-valid content and assert producer refusal for decodable invalid content; they are not NSD output.
- Inner publication producer addition: NSD N06, N08 and N21 producers should adopt implementation revision `2391ebd5e59574cb318fbc2c7b1ca3615426796a`; earlier package revisions do not include it. Producer-owned vectors and adoption remain outstanding.

## Node and Subnet


Sentences removed from the node and Subnet specifications because they state review,
delivery, adoption, interoperability or ownership status.

## From l8-account-payload-profile.md

- Enrollment (Q11): Values and their meanings require NSD's Q11 answer; fixture identifiers are examples only.
- Enrollment (Q11): Endpoints and authenticated envelope forms remain Q11 questions; this binding/capability payload does not complete the registry's endpoint contract or change its bytes.
- Enrollment (Q07): Q07 requests agreement on this width, the missing same-I/K refresh tag and the separate signed K generation.
- Registration-only incarnation placeholders: This clarification changes no schema, codec or comparator and requires no gateway repin. NSD producer and ns consumer adoption remain outstanding.
- Subnet selection: These are candidate fixtures, not NSD producer output.
- Ordinary provider Subnet route reports: M6, Subnet publication and select/clear bytes are unchanged.
- Ordinary provider Subnet route reports: Independent fixtures establish pure decisions only. NSD N30/N07/N08 and ns S11/S25 adoption and producer-owned vectors remain outstanding; gateway self-reporting belongs to later ordinary-provider integration.
- Exit grants and consumer Subnet route views: B40 ordering, bounds, prefixes, explicit/default selection, and grant/payer/incarnation/renewal bytes are unchanged.
- Exit grants and consumer Subnet route views: Fixture acceptance proves pure contracts only. NSD N07/N08 projection, producer-owned vectors, and ns route installation/adoption remain outstanding.
- R3 local Node naming and legacy registration retirement: The external R3 runtime consumer owns cutover and its commit/restart regression: matching acceptance must drop every active old pin and Short DNS authority; mismatched acceptance or supplied legacy values must leave the prior profile intact.
- R3 local Node naming and legacy registration retirement (N04/N09, S05/S06/S11): NSD N04/N09 producer adoption and ns S05/S06/S11 consumer/cutover adoption remain outstanding, including independent producer confirmation.
- R3 local Node naming and legacy registration retirement: The review delta is a candidate, never agreement or interoperability evidence.
- R3 local Node naming and legacy registration retirement: No new field, carrier, P-item or dependency edge is introduced; previous delivery evidence does not establish this delta or release external cutover acceptance.
- Provider mapping inventory (N07/N09, S25/S11, C06): NSD N07/N09 publication and current-source handoff, and ns S25/S11 activation adoption remain outstanding requests; no agreement, producer delivery or external adoption is inferred. Gateway self-reporting/inventory consumption remains deferred to C06.

## From control-exchange-candidate.md

- R3 local Node naming and legacy registration retirement: The external R3 runtime consumer owns cutover and its commit/restart regression: matching acceptance must drop every active old pin and Short DNS authority; mismatched acceptance or supplied legacy values must leave the prior profile intact.
- R3 local Node naming and legacy registration retirement (N04/N09, S05/S06/S11): NSD N04/N09 producer adoption and ns S05/S06/S11 consumer/cutover adoption remain outstanding, including independent producer confirmation.
- R3 local Node naming and legacy registration retirement: The review delta is a candidate, never agreement or interoperability evidence.
- R3 local Node naming and legacy registration retirement: No new field, carrier, P-item or dependency edge is introduced; previous delivery evidence does not establish this delta or release external cutover acceptance.

## From grant-authority-candidate.md

- Exit grants and consumer Subnet route views: B40 ordering, bounds, prefixes, explicit/default selection, and grant/payer/incarnation/renewal bytes are unchanged.
- Exit grants and consumer Subnet route views (N07/N08): Fixture acceptance proves pure contracts only. NSD N07/N08 projection, producer-owned vectors, and ns route installation/adoption remain outstanding.

## From provider-subnet-report-candidate.md

- Status: pure candidate contract; independent fixtures are labelled authority, not NSD producer output or persistence evidence.
- Independent acceptance and adoption (N30/N07/N08, S11/S25): NSD N30 owns ingestion, allocation and persistence; N07/N08 resolve current source/mapping authority before selection/projection. ns S11 produces intent and S25 owns the shared adapter and response custody. Their adoption and producer-owned interoperability vectors remain outstanding.
- Independent acceptance and adoption: Gateway self-reporting is deferred to the later ordinary-provider integration; existing Exit consumption, deferred live default Exit, M6 declarations and contribution sessions are unchanged.

## From l8-public-edge-candidate.md

- Provider mapping eligibility (N07/N09, S25/S11): Publication, source handoff and activation adoption remain outstanding for NSD N07/N09 and ns S25/S11.
- Provider mapping eligibility (C06): The gateway retains local Exit configuration and grants; its mapping report producer and inventory consumer await the later C06 handoff.

## From source-selection-candidate.md

- Ordinary provider report addition (N30/N07/N08, S11/S25): NSD N30/N07/N08 and ns S11/S25 adoption remain outstanding.
- Exit grants and consumer Subnet route views (N07/N08): NSD N07/N08 projection and ns route installation/adoption remain outstanding.

## Realm and grants


Status sentences removed from spec/account/realm.md and spec/account/grants.md sources.

## Realm (family 2, policy and claim values)

- Membership realm identities (realm-publication-candidate.md and l8-account-payload-profile.md preambles): This incompatible candidate delta refuses arbitrary realm labels without fallback. NSD/ns producer and consumer updates, including the other active consumer delivery, remain outstanding.
- Realm publication content (l8-account-payload-profile.md, "Complete realm publication content"): Producer confirmation remains outstanding.
- Realm publication canonical content (realm-publication-candidate.md): The candidate fixture authority is not NSD producer confirmation.
- Realm publication vectors (realm-publication-candidate.md): Independent `realm-publication.vec` fixtures and `realm_publication_vectors` cover canonical content, refusals and `realm_membership_replacement`. Producer-owned NSD vectors and confirmation of the realm contribution and binding model remain outstanding; fixture success is not agreement.
- Policy inventory, GatewayAuthJwtAuthority (l8-account-payload-profile.md, "Inventory disposition and carrier boundary"): Family 7 EdgeJwtAuthority; NSD producer confirmation pending.
- Policy inventory, OIDC claims (l8-account-payload-profile.md, "Inventory disposition and carrier boundary"): Confidential AuthConfiguration values; OIDC runtime and label construction remain external; NSD confirmation outstanding.
- Policy inventory, unplaced items (l8-account-payload-profile.md, "Inventory disposition and carrier boundary"): Unplaced inventory items stay open until an enclosing family or a later design assigns a carrier; no new kind or implicit policy publication is defined here.

## Grants (families 3, 4, 5, 6)

- Grant authority membership realm identities (grant-authority-candidate.md preamble): This incompatible candidate delta refuses arbitrary realm labels without fallback. NSD/ns producer and consumer updates, including the other active consumer delivery, remain outstanding.
- Service grants and payer authority (l8-account-payload-profile.md): Independent producer fixtures and `grant_authority_vectors` exercise accepted and typed refused contracts, selective withdrawal and fresh regrant. These are fixture producer observations; NSD producer vectors and owner confirmation remain outstanding. Family registry bytes are unchanged.
- Usage payer revision (l8-account-payload-profile.md, "Service grants and payer authority"): See the [usage contract](../spec/account/usage.md) for the incompatible candidate delta.
- Protocol-qualified grant and renewal (l8-account-payload-profile.md): `protocol_grant_renewal` provides independent fixture producer and consumer coverage. NSD N06 protocol/token/deadline producer adoption and producer-owned vectors remain outstanding; this incompatible candidate delta is not contained in the earlier published package revision.
- Grant authority producer mapping (grant-authority-candidate.md): Candidate fixtures supply authority; they do not establish live interoperability. NSD's current producer uses string ULIDs, integer-array peer keys and its NodeL3Config resource graph. Outstanding producer work must map authenticated machine identities to full I/K bindings, authority namespaces and explicit rules, emit binary payer UserId/realm pairs, Egress floor and exact service references, incarnations and deadlines.
- Protocol-qualified identity and renewal (grant-authority-candidate.md): NSD N06 producer adoption remains outstanding: enabled protocols supply distinct tokens and discriminators, the grant publication supplies the deadline, and signed source binding remains mandatory. Candidate fixture acceptance does not establish producer adoption.

## Edge


- realm identity: This incompatible candidate delta refuses arbitrary realm labels without fallback. NSD/ns producer and consumer updates, including the other active consumer delivery, remain outstanding.
- public-edge producer: Producer confirmation and producer-owned vectors remain outstanding with NSD. Python fixtures are labelled candidate sources, independent of the Rust codecs.
- public-edge producer: The independent Python public_edge producer and Rust public_edge_vectors tests exercise complete replacement, valid empty withdrawal, malformed/noncanonical refusal without renewal, names/aliases/ports/domains, full backend identity joins, material generation mismatch and unchanged M6 object bytes/digests. These are fixture-produced candidate observations; NSD confirmation and producer-owned vectors remain outstanding under Q17.
- confidential configuration: Confidential configuration is specified separately and claims no predecessor wire equivalence.
- confidential configuration: No defaults or predecessor wire equivalence are claimed; installation ACKs remain correlated to the exact reference/generation.
- service labels: Standalone label inventory rows remain open pending M01/M02 with the M6 contract owner through owner-mediated review.
- protocol-specific names: Existing HTTP-only fixture bytes are unchanged. Existing raw-route fixture names are deliberately regenerated from text to null, including anonymous-policy fixtures. Version 1 and the thirteen-position tuple remain unchanged; neither old named raw routes nor a compatibility fallback are accepted.
- protocol-specific names: Real producer adoption remains outstanding; fixture authority does not establish producer agreement.
- protocol-specific names: NSD N20 producer adoption remains outstanding. Confirm NSD HTTP public_host and raw protocol/port projection, with producer-owned accepted/refused vectors. Independent candidate fixtures are not producer agreement.
- anonymous selector: This candidate API and accepted-wire-domain extension preserves all existing selector bytes. Older consumers reject the new selector rather than reading it as null or an identity.
- service report kind 1: The complete kind 1 report now includes local floor metadata, non-authoritative Exit profiles and per-reference outcomes as specified in control report exchanges. That explicit candidate delta replaces the earlier whole-report boolean for kind 1; all other public-edge, material, declaration and listener bytes remain unchanged.
- confidential auth producer: The pinned NSD producer supplies no JWT issuers; its absence is not proof of candidate producer support. The independent Python fixture is a labelled candidate producer. NSD confirmation and producer-owned vectors remain outstanding. This contract changes no family registry bytes or publication channel.
- confidential auth producer: The candidate fixture is not NSD producer confirmation (confidential-auth.vec / confidential_auth_generation).
- confidential material: Status: pure candidate contract. NSD producer implementation, dispatch adoption, confirmation and producer-owned vectors remain outstanding. Independent Python fixtures are candidate authority, not NSD output or an interoperability agreement.
- confidential material: NSD producer implementation, confidential dispatch adoption, confirmation and producer-owned vectors remain outstanding; fixture delivery is not agreement.
- confidential material: Family 7 gains confidential value delivery without changing public references, registry bytes, AuthConfigRequest's auth-only restriction or installation ACK bytes.
- confidential material: Existing auth and installation ACK fixtures remain unchanged.

## Relay and usage


- realm identity: This incompatible candidate delta refuses arbitrary realm labels without fallback. NSD/ns producer and consumer updates, including the other active consumer delivery, remain outstanding. (usage-contract-candidate.md preamble)
- participant authority: Status: shared definition delivered; NSD producer review and adoption outstanding.
- participant authority: Independent vectors are fixture authority, not live NSD qualification. See `participant_auth_transport` in `participant-authority.vec`.
- participant authority: The shared definition is delivered at immutable revision `28bf972db2e1f434114adc324a26fabad545aed1`.
- participant authority: Family 8 now includes shared enrollment/authentication/renewal frames and the separate signed directory binding defined in participant authority. NSD producer review and adoption remain outstanding.
- participant authority: The gateway executes TLS/lifecycle/discovery adoption separately. NSD producer review and ns/NSD interoperability remain outstanding.
- participant roster lifecycle: NSD producer review and adoption remain outstanding.
- usage contract: This is a pure candidate contract, not a released NSD producer profile.
- usage contract: The nine-field version-1 ServiceUsage tuple is unchanged except that payer_subject is now exactly 16 unsigned big-endian ULID bytes.
- echo reply billing: The current gateway candidate emits no `EchoReplySend` rows: at frozen nsplane 0.16.0, synthetic replies are delivered but unbilled because the normal outbound path provides no per-packet successful-send receipt.
- echo reply billing: Reply billing remains deferred until a released packet-runtime capability is adopted and qualified. This is an outstanding runtime capability, not a contract change or recorded agreement.
- usage contract: No duration is invented by this candidate.
- usage fixtures: These fixtures establish candidate behavior only. NSD producer confirmation, historical ownership storage and real producer vectors remain outstanding.
- usage fixtures: The existing gateway neutral echo recorder uses message quantities and needs explicit completed-byte instrumentation before adopting this profile; no implicit message-to-byte conversion is authorized.
- usage fixtures: The review request records the incompatible predecessor.
- usage profile catalogue: Existing usage report and ACK bytes are unchanged. NSD/ns review, producer-owned vectors and producer adoption for this new candidate payload remain outstanding.
- profile publications: This is a new candidate payload delivery for families 9 and 10. NSD/ns review, producer-owned vectors and producer adoption remain outstanding. Fixture authority is labelled candidate input and establishes no external interoperability.
- profile publications: Families 9 and 10 now have explicit candidate payloads: `[1, reporter, profiles]` and `[1, membership_scope, 2, capabilities]`.
- profile publications: NSD/ns review, producer-owned vectors and producer adoption remain outstanding; this new delivery does not retroactively establish earlier payload support.
- profile publications: Runtime persistence and preservation of captured usage/control state belong to the gateway regression, which must consume these same source-bound bytes.
- profile publications: Existing usage report/ACK and Node-control fixtures retain their bytes; the family registry set is unchanged.
- profile publications: The following canonical bytes and signatures are fixed before codec implementation.
