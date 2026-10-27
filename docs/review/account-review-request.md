# L8 candidate review request for NSD and node owners

Membership realm identities follow the [canonical RealmId contract](../spec/realm-id.md).
Affected text positions retain text but require the exact uppercase 26-character
spelling and decode to RealmId; binary positions retain their exact 16 bytes.
This incompatible candidate delta refuses arbitrary realm labels without fallback.
Canonical realm/source publication production and ns recorded-byte consumption are adopted; complete owner confirmation, refusal coverage and live source retirement remain open. See [adoption evidence](account-handoff.md#adoption-publication). Encoding equality is not authentication. Discovery realm hints,
external provider subject namespaces and opaque scopes retain their meanings.
Signed usage bytes and the historical payer pair remain unchanged.


Status: delivered through the owner route on 2026-10-25 (UTC), at revision
`958da3f9b31e70f419035b974977f8d0d2895471`. This is the only record of the
delivered revision; the profile and the handoff refer to it. The owner forwarded
the candidate review package to the NSD owner as producer and the ns owner as
consumer reviewer. Every question and requested change was sent on that date (see
[Disposition](#disposition)). Content added after the delivered revision is listed
in [Changes after delivery](#changes-after-delivery). No answer has been received. Silence approves nothing. NSD independently owns
producer vectors and implementation. Unreceived answers remain outstanding and
do not block the candidate. The candidate is merged into `main` behind the
`unstable-account` feature; review is still required before the gate is removed or a
release is made.

2026-10-27 adoption update: ns `6ea11348` (request #543) and NSD `ff278641`
(request #467) consume shared `95f1688` with `unstable-account`. The
[handoff evidence](account-handoff.md#unresolved-producer-consumer-and-review-obligations)
names adopted source, actual producer corpora, exact byte comparisons and each
remaining confirmation. Neither merge is an answer to the questions below.
Pending ns `3b9adf5156ad` (#545) and NSD `aa2caaf381fd` (#468) repair test
environments only. Review approval, retention sealing and live real-component
evidence still precede the later release and feature restriction removal.

## Candidate package

The package is the delivered revision named in the status above; earlier
package selections are historical comparison evidence in the handoff. Review the
[immutable handoff](account-handoff.md) for the complete
delivered-contract list, P12–P19 additions, vector corrections, exact gateway
manifest/lockfile comparison and unresolved external adoption. Gateway package
consumption does not establish external owner forwarding or approval. Review
these files at the delivered revision:

- [Specification](../spec/account/profile.md): schema 1 canonical CBOR and
  local admission JSON schema 2; replacement, lifecycle and byte-unit rules.
- [Family registry](../../crates/nsshared-control/src/account/publication/registry.rs): all eleven
  identifiers, publication scopes, cleared kinds and M6 reuse groups.
- [Candidate vectors](../../crates/nsshared-control/tests/vectors/account/profile.vec):
  independent Python-generated fixtures, including `family-registry`,
  `identity-replacement`, `record-rotation`, `l3-scoped-rules`,
  `l3-empty-withdrawal`, `usage-unset`, `usage-measured-zero`, `signed-roster`,
  `local-roster`, `local-empty-withdrawal` and malformed-input refusals.
- [Lifecycle](../../crates/nsshared-control/src/account/node/lifecycle.rs),
  [normalized L3](../../crates/nsshared-control/src/account/node/l3.rs) and
  [roster carriers](../../crates/nsshared-control/src/account/families/relay/roster.rs): typed
  validation boundaries accompanying the specification.
- [Gateway consumer inventory summary](#gateway-consumer-inventory-summary):
  repository `nsgw`, immutable commit `51c278cdc63c`,
  `docs/design/v1-consumers.md`, sections “Counting and ownership” and
  “M6 lineage reused by L8”: the inventory summary reproduced below. Its exact
  rows are `deps/v1-consumers.toml` at the same revision. Read with
  `git show 51c278cdc63c:docs/design/v1-consumers.md` in that repository.

The candidate vectors are fixtures, not NSD producer output or evidence of
live interoperability. Every family's producer vectors must be generated
independently by NSD; node and gateway consumers check those bytes separately.
The contracts remain pure types, codecs, validation, constants and vectors.
Sessions, runtime effects, policy compilation and v1 adapters stay in consumers.

## Changes after delivery

These changes follow the delivered revision and were not part of the package
that was sent:

- [Q07](#q07-identity-lifecycle--node-owner-with-nsd-confirmation): registration-only
  lifecycle placeholders and the `enrollment_consumer_vectors` extension; no schema
  or codec change.
- Scope text: every family applies one rule to opaque authority scope text, 1 to
  256 UTF-8 bytes without whitespace or control characters (see the profile's
  [scope text rule](../spec/account/profile.md#scope-text)). Publication
  content previously checked only emptiness and length, and subscription, snapshot
  request, source binding and authentication source selection previously allowed
  whitespace; those inputs are now refused. Refusal vectors were added to the
  publication, subscription, snapshot request, source selection and control
  exchange fixtures. No accepted fixture changes. `GatewayReport.public_ingress_scopes`
  keeps the data text rule pending [Q24](#q24-gateway-report-ingress-scopes--nsd-owner).
- Repository layout, without wire changes: the account contracts are
  `nsshared_control::account`, organized by layer and family with renamed generic
  items and consistent error types; the M6 contract is `nsshared_control::service`;
  the specifications are under [docs/spec](../spec/README.md); tests and vectors are
  under `crates/nsshared-control/tests/`. Every vector case is byte-identical. The
  delivered revision keeps the paths it was delivered with; links in this request
  point to the current paths.

## Family state

Every registration has wire version 1 and candidate owner
`account-payload-profile`. “Frame only” means its identifier, replacement rule
and M6 references exist, not that its detailed payload is ready. The named
contract work below follows the gateway inventory; other payloads remain
explicitly frame only. NSD supplies producer vectors for every row.

| ID / family | State at the candidate revision | Detailed contract work / review question |
| --- | --- | --- |
| 1 `enrollment` | Binding/lifecycle and complete control exchange specified in the control-exchange delta | Registration/source and lifecycle handling are adopted in source; current matched enrollment corpus bytes, live confirmation and the Q07/Q11 owner answers remain open. See [adoption evidence](account-handoff.md#adoption-core). |
| 2 `realms-peers` | Complete canonical realm contributions, NodeBinding/NodeRecord checks and independent replacement/refusal vectors delivered | Canonical realm/source publication production and ns recorded-byte consumption are adopted; complete owner confirmation, refusal coverage and live source retirement remain open. See [adoption evidence](account-handoff.md#adoption-publication). |
| 3 `egress` | Pure grant publication and independent consumer vectors delivered | Protocol-qualified grant, payer and withdrawal projection is adopted in source; complete independent producer vectors, owner answers and live joins remain open. See [adoption evidence](account-handoff.md#adoption-grants). |
| 4 `exit-subnet` | Provider grants and separate client route selection retain exact bytes; mapped route admission needs no ordinary provider host rule | NSD grant/client-route production and ns recorded-byte consumers are adopted; live installation/replacement/withdrawal and default/nested Exit qualification remain open. See [adoption evidence](account-handoff.md#adoption-subnet). |
| 5 `payer` | Binary realm/UserId assignment publication and cardinality refusals delivered | Protocol-qualified grant, payer and withdrawal projection is adopted in source; complete independent producer vectors, owner answers and live joins remain open. See [adoption evidence](account-handoff.md#adoption-grants). |
| 6 `withdrawal` | Resource authority snapshots and pure successor validation delivered | Protocol-qualified grant, payer and withdrawal projection is adopted in source; complete independent producer vectors, owner answers and live joins remain open. See [adoption evidence](account-handoff.md#adoption-grants). |
| 7 `public-edge` | Pure scoped public-edge, confidential AuthConfiguration and certificate/client-CA acquisition request/response, material and exact M6 declaration/report/listener integration with independent consumer vectors delivered | NSD public-edge projection, anonymous/raw-name vectors and actual producer corpus are adopted; a matching downstream corpus reader, live policy/name enforcement and Q17 confirmation remain open. See [adoption evidence](account-handoff.md#adoption-edge). |
| 8 `relay` | Signed roster, shared participant credentials and separate signed directory binding delivered | NSD signed roster/participant and directory production plus ns recorded directory consumption are adopted; local file-writer proof, live rollback/carrier transitions and complete unsettled-reference sealing remain open. See [adoption evidence](account-handoff.md#adoption-roster). |
| 9 `usage` | Typed scoped usage-profile payload and independent publication vectors newly delivered; existing quantities and report/answer bytes unchanged | NSD usage/Node-control catalogue production and actual corpus are adopted; matching ns/gateway corpus consumption, live preserved state and Q19/Q20 answers remain open. See [adoption evidence](account-handoff.md#adoption-profiles). |
| 10 `node-control` | Typed scoped node-control-profile payload and independent publication vectors newly delivered; existing v2 codec unchanged | NSD usage/Node-control catalogue production and actual corpus are adopted; matching ns/gateway corpus consumption, live preserved state and Q19/Q20 answers remain open. See [adoption evidence](account-handoff.md#adoption-profiles). |
| 11 `v1-replacement` | Exact Node L3 applied-status codec, signed-event digest, retained-context comparison and independent vectors delivered; existing policy observation and M6 carrier unchanged | NSD issuance/digest/status persistence and ns recorded status adapters are adopted; live enforcement-to-Applied association remains open. See [adoption evidence](account-handoff.md#adoption-status). |

Only an authenticated, valid, complete publication replaces its listed kinds
in the explicitly named issuer/recipient scope. A complete empty publication
withdraws that scope. Missing, partial or malformed input is an error. Relay
directory and admission roster scopes are distinct. Usage history, durable
watermarks and received control messages are not erased by replacement.

## Gateway consumer inventory summary

At `nsgw` revision `51c278cdc63c`, the inventory covers eleven consumer crates,
2,009 unique `(path, item)` rows and 2,112 role memberships: 375 imports,
1,604 tests, 49 vectors, 17 persisted readers, 16 persisted writers and 51
senders. A row can have several memberships; these are not occurrence counts.
The original first migration owner labels are retained here for traceability.

| Owner | Rows | Responsibility |
| --- | ---: | --- |
| B20 | 6 | Neutral record/seal/report interfaces |
| B21 | 64 | Durable sequence, spool, repair and delivery |
| B22 | 12 | Resource capture and fold |
| B23 | 14 | Resource boundaries |
| B54 | 60 | Policy |
| B55 | 62 | Realm |
| B56 | 114 | Routing |
| B57 | 193 | Edge authentication |
| B58 | 259 | Envoy |
| B59 | 68 | API |
| B60 | 123 | Control stream and snapshot |
| B61 | 264 | Control trust and enrollment |
| B62 | 128 | Control heartbeat, services, material-status and usage reports |
| B63 | 10 | Control material and token handlers |
| B64 | 430 | Server assembly |
| B65 | 11 | Server configuration and floor loading |
| B67 | 124 | Egress |
| B68 | 67 | Exit |
| B53 | 0 | Temporary Node codec switch, outside the eleven consumer crates |
| B69 | 0 | Node/profile bridge, outside the eleven consumer crates |

### Existing M6 reuse

The inventory pins M6 lineage to
`6dd3a930224a85a637e506eddd726b6310e27531`. None of those eleven consumer
crates imports it directly yet. This is the required reuse mapping, not a
claim that v1 payloads and M6 already have equivalent bytes or semantics.

| Existing M6 contract | L8 family need and inventory mapping |
| --- | --- |
| `Id`, `Identity`, `Digest`, `ServiceRef` | Identity B38, grants B39, selection B40, usage B42, declarations B46 retain full service scope; all families carrying service work reuse these identities |
| `Declaration`, `BackendHost`, `Protocols`, `PortMode`, `Declaration::canonical/decode` | Egress grants B39 and declarations/public edge B46 retain deterministic private-service declaration bytes; gateway Exit/public-edge extensions remain distinct |
| `ReportContent::canonical/decode` | B46 retains service report bytes, declaration-key ordering, duplicate rejection and `ns.service.report.v1` digest |
| `ListenerIntent::canonical/decode`, `domain_digest` | Grants B39, selection B40 and declarations B46 retain publisher-only listener intent and `ns.service.listener.v1` digest |
| `Resource`, `Route`, `Grant`, `PublisherListener`, `Withdrawal`, `Snapshot::canonical/decode`, `snapshot_digest` | B39/B40/B44/B46 compose recipient-qualified service snapshots within account scope and preserve `ns.service.snapshot.v1` |
| `Resource::service_label`, existing snapshot validation | B39/B44/B46 retain supplied validated DNS labels, independently of display names or declaration keys; M01/M02 request standalone validation |
| `Message`, `MessageBody`, `MessageKind`, `Message::encode/decode` | B38/B39/B43/B44/B46 retain exact M6 messages and all variants in authenticated transport; the raw M6 envelope remains private |
| `CAPABILITY`, `SCHEMA`, `LOCAL_SCHEMA`, `MAX_LEASE_MS`, `REFRESH_MS`, `ContractError`, `next_revision` | The same service message integrations retain capability, schema, lease, error and revision semantics |
| `vectors/service-control-v1.json`, `tests/vectors.rs` in `crates/nsshared-service-control` | Registry B36 and B39/B43/B44/B46 reference original independent bytes and digests; family vectors compose around them |

Retain every message variant: runtime floor/bind and results; session open/result;
report head/result and replace/accepted; snapshot push/ack; listener ready;
lease refresh and acquire/result; port result/cancel/query/query-result;
service retry-port; error. Typed bodies include `RuntimeBind`,
`RuntimeFloorResult`, `ReportReplace`, `ReportBinding`, `ReportAccepted`,
`PortProposal`, `ReadyProof`, `ServiceLeaseRef`, `LeaseAcquire`, `LeaseResult`,
`PortResult`, `SnapshotAck` and `SnapshotPush`.

No parallel declaration, service reference, listener, lease, port-control or
snapshot type is requested. No M6 bytes or digest domains are re-encoded into
the account format. Future embedding requires an explicit one-way dependency
from proto to service-control; the candidate frame needs none.

## Independently answerable questions

For each answer, name its question, accepted fields/bytes or precise correction,
and the specification or producer-vector location that records it. A response
to one question does not imply acceptance of any other question.

### Q01: Signed roster entry format — NSD and node owners

2026-10-27 status: NSD signed roster/participant and directory production plus ns recorded directory consumption are adopted; local file-writer proof, live rollback/carrier transitions and complete unsettled-reference sealing remain open. See [adoption evidence](account-handoff.md#adoption-roster).

For relay admission, can NSD produce and the node consume atomic `[I, class]`
entries with full validated 32-byte `IdentityKey`, class 0 `ordinary_node` or
1 `gateway_node`, sorted uniquely by identity? Please identify producer vectors
for both classes, empty withdrawal, duplicate identity and unknown class.

### Q02: Local schema 2 entry format — NSD and node owners

2026-10-27 status: NSD signed roster/participant and directory production plus ns recorded directory consumption are adopted; local file-writer proof, live rollback/carrier transitions and complete unsettled-reference sealing remain open. See [adoption evidence](account-handoff.md#adoption-roster).

Can the local relay snapshot writer emit required object fields `identity`
(canonical full key text) and `class` (`ordinary_node` or `gateway_node`) in
every `identities` entry, with required root `schema_version: 2`,
`issued_at_unix_ms` and `roster_version`? Please identify vectors rejecting
missing/duplicate/unknown fields, positional arrays and non-string classes.

### Q03: Signed roster attribution epoch — NSD and node owners

2026-10-27 status: NSD signed roster/participant and directory production plus ns recorded directory consumption are adopted; local file-writer proof, live rollback/carrier transitions and complete unsettled-reference sealing remain open. See [adoption evidence](account-handoff.md#adoption-roster).

Can signed `roster_version` be the positive, strictly increasing attribution
epoch per issuer/participant, captured atomically with membership and class?
Confirm the `ns.account.roster.v1` signature domain plus zero separator,
issuer/recipient binding, at least 24-hour validity, reachable renewal and
consumer persistence of the accepted version. Identify stale-version, wrong
scope, future-time, expiry and signature producer vectors.

Confirm that participant scope is exactly the signed issuer/recipient pair (the
participant's own credential scope), with no new scope field. Confirm diagnostic
degradation at 24 hours since the last authenticated renewal, retaining admission
until the exclusive signed deadline, which renewal never extends locally. Supply
independent NSD canonical signed vectors and expected decisions for accepted,
empty, revocation and class-only replacement; wrong issuer/recipient; lower/equal
version; future issue; one millisecond before and at expiry/degradation; short
lifetime; bad signature; and missing, duplicate or unknown class.

### Q04: Local schema 2 attribution epoch — NSD and node owners

2026-10-27 status: NSD signed roster/participant and directory production plus ns recorded directory consumption are adopted; local file-writer proof, live rollback/carrier transitions and complete unsettled-reference sealing remain open. See [adoption evidence](account-handoff.md#adoption-roster).

Can local `roster_version` identify the same admission/class epoch rather than
the issue timestamp? Specify how the controlled file's configured issuer and
participant scope corresponds to the signed scope, and how its version sequence
is retained across restart and carrier changes. The JSON contains no issuer,
recipient or signature; consumer rollback persistence remains necessary.

### Q05: Historical report lookup — NSD owner

2026-10-27 status: NSD usage receipt/history handling and actual answer corpora are adopted; live completed-I/O capture, exclusion/repair, matching downstream corpus consumption and the retention seal remain open. See [adoption evidence](account-handoff.md#adoption-usage).

For delayed relay usage, can NSD resolve identity/class using the original roster
scope and version, even after reclassification, withdrawal or identity replacement?
Name the report fields that identify that original issuer/participant scope,
epoch and source NodeId, and the history retention/repair contract. Unknown
history requires repair rather than attribution using the current roster.
Provide delayed-report, changed-class and unavailable-history vectors.

### Q06: Delivery of writer fields — NSD owner

2026-10-27 status: NSD signed roster/participant and directory production plus ns recorded directory consumption are adopted; local file-writer proof, live rollback/carrier transitions and complete unsettled-reference sealing remain open. See [adoption evidence](account-handoff.md#adoption-roster).

Which separately owned NSD/`ns` implementation work will deliver both `class`
and `roster_version` in the atomic local schema 2 file? Please name its delivery
reference, field source and mapping to the signed roster, controlled regular-file
ownership, bounded reads, atomic replacement and restart/version persistence.
The writer must publish membership and classes together; missing or invalid
input must never install an empty roster. This request does not implement it.

### Q07: Identity lifecycle — node owner, with NSD confirmation

2026-10-27 status: Registration/source and lifecycle handling are adopted in source; current matched enrollment corpus bytes, live confirmation and the Q07/Q11 owner answers remain open. See [adoption evidence](account-handoff.md#adoption-core).

Does the node contract agree that `MembershipIdentityVersion` advances within
one NSD membership, `RecordGeneration` advances only within one full identity
across all served realms, and `GrantIncarnation`/`ReporterIncarnation` are
opaque equality-only tokens? Identity replacement increases membership version,
replaces both I and K, rederives NodeId/N6/N4 and may restart generation;
K-only rotation preserves membership version, I and derived identifiers while
changing K and increasing generation. Existing same-generation record conflict
rules remain. Please specify when each transition is chosen and provide
independent vectors for both, stale generation and every fresh-incarnation regrant.

Please resolve the gateway consumer's three candidate mismatches: there is no
same-I/K record-refresh transition tag; NodeBinding has account record generation
but no separate K generation beside the existing signed NodeRecord generation;
and the candidate membership version is u64 while ordinary membership derivation
accepts u32 and advances by checked addition. How is the account binding joined
to the exact signed NodeRecord, and which counter advances for refresh versus
K rotation? No new tag or signed field is assumed here.

Confirm that a differing binding without a valid lifecycle from the accepted
binding is refused, including a rejected staged-version restart after an
unaccepted replacement; lower versions are refused too. Accepted registration
is the durable version boundary. Ordinary derivation yields one K per membership
version; stable-I rotation requires an explicit producer-profile authorization
and supplied K. Quick's K-per-generation derivation is a different profile.
Please provide independent vectors for these restart and authorization decisions.

The candidate registration profile now explicitly treats Lifecycle's final two
mandatory 16-byte positions as wire placeholders. The requesting Node sends
sixteen zero bytes in each even with no grants and no reporter. Receivers decode
structurally and ignore values, including historical nonzero fixtures; they must
not compare them with grants, reports or accepted registration or persist them
as lifecycle custody or retirement state. No NSD response, provisioning or token
acquisition produces them. They are not authority or transition inputs; nonzero
fixtures do not define a registration producer form.

NSD compares requested membership and authenticated presented I with provisioned
enrollment authority and its accepted binding. Lifecycle.before must equal that
complete accepted binding and Lifecycle.after the presented binding.
IdentityReplacement increases membership version and changes I and K, with
record generation allowed to restart under the new I. RecordRotation preserves
I and membership version, changes K and increases generation, and requires
explicit reviewed producer-profile RebindAuthorization. Initial enrollment still
has no lifecycle; Equal compares the complete binding; rollback, authentication
and scope checks remain. Ordinary stable-I self-initiated rebind remains disabled
without the reviewed profile, regardless of placeholder values.

The ns or gateway consumer compares its retained binding for the exact membership
and signing authority. Before commit it verifies authenticated acceptance against
staged membership, complete binding, profile, capabilities and locally computed
EnrollmentDecision, with response correlation, recipient and nodes-source checks.
Rejection or mismatch preserves committed identity. Accepted history and selected
acceptance remain custody; placeholders add no durable state.

Identity replacement fences old resources without transferring grants. NSD
produces fresh grant incarnations for newly authorized replacement-identity grants
under the existing signed grant/payer/resource-authority contracts and exact
resource/client/provider/protocol/payer and retirement-history comparisons.
K-only rotation alone changes no identity-keyed grant token; NSD publishes the
changed authenticated I-to-K binding through Node L3. The reporter produces and
durably retains its own lifecycle token, with fresh tokens for new reporter
lifecycles under the usage contract. Registration assigns or retires neither
token; pending rows and parts retain original attribution and settlement custody.

The independent zero-placeholder `enrollment_consumer_vectors` preserve
before/after mismatch and unauthorized-rotation refusals alongside valid identity
replacement and authorized rotation. These are candidate fixtures, not producer
confirmation. NSD N24/N26 and ns S17 live adoption confirmation and complete requested producer-owned vector coverage remain
outstanding; no response or approval is recorded. No schema, crate-source or
codec change, gateway source change or gateway repin is required by this delta.

### Q08: Complete replacement semantics — NSD and node owners

2026-10-27 status: Canonical realm/source publication production and ns recorded-byte consumption are adopted; complete owner confirmation, refusal coverage and live source retirement remain open. See [adoption evidence](account-handoff.md#adoption-publication).

For all eleven families, can the registry's publication/`clears` strings and
explicit issuer/recipient scopes be used as specified? Identify any missing
authority, revision, validity deadline or scope field needed in each detailed
payload. Confirm complete empty withdrawal, shared-peer contribution retention,
separate directory/roster scope and preservation of usage history/watermarks.
Provide scoped-empty, partial and malformed-publication producer cases.

The [signed publication event candidate](../spec/account/publication.md)
adds signed per-key complete/version/validity and typed ACL failure decisions.
Confirm the exact family/kind ownership table, separate stream versus snapshot
authority, complete empty withdrawal, absent retention and immediate denial for
authenticated `node-l3` fetch failure. Confirm durable versions including empty
and failure tombstones, actual exclusive expiry and whole-snapshot rejection
for one invalid event. Please supply independent NSD producer vectors for each
decision, including unrelated scopes and absent/empty/failure distinctions.

### Q09: Normalized Node L3 schema — NSD and node owners

2026-10-27 status: Canonical realm/source publication production and ns recorded-byte consumption are adopted; complete owner confirmation, refusal coverage and live source retirement remain open. See [adoption evidence](account-handoff.md#adoption-publication).

The delivered [complete Node L3 authority](../spec/account/node.md#normalized-node-l3-form)
is `[1, bindings, policy_bytes]`. Each binding is `[full_identity_I, authorized_WireGuard_K]`:
I is a validated full Ed25519 identity, K is a nonzero 32-byte string, bindings
are strictly ordered by I and distinct identities cannot share K. Every identity
in a policy scope requires a binding. Consumers join installed I/K only through
this explicit authority; a peer record or roster entry alone grants no access.

`policy_bytes` retains the existing canonical
`[1, issuer, recipient, revision, scopes, rules]` encoding. Authority-assigned
opaque namespaces, sorted full identity sets and sorted unique TCP/UDP allow
rules use inclusive nonzero ports, overlap as union and no implicit wildcard.
Missing membership or policy denies; selective namespace withdrawal preserves
independently authorized namespaces. Independent consumers cover these cases,
exact I/K bindings and namespace/protocol/port boundaries. Compilation and
direct N6/N4 identity resolution remain in consumers; mapped Subnet routes
resolve their exact resource and selection without a provider-wide Node rule. Confirm the 8,192-entry
bounds and 1 MiB wrapper limit.

Owner confirmation of NSD/ns producer mappings remains open: resolve current string machine/owner
identifiers and the NodeL3Config resource graph into full I/K authority,
opaque namespaces and explicit rules; encode peer keys as byte strings rather
than integer arrays. Please confirm this delivered wrapper and provide
independently owned accepted/refused producer vectors for empty authority,
missing/ambiguous bindings, missing membership/policy, cross-scope rules,
selective withdrawal, port ranges and bounds. Candidate fixture agreement is
not producer confirmation or live interoperability.

### Q10: Service byte unit — NSD owner

2026-10-27 status: NSD usage receipt/history handling and actual answer corpora are adopted; live completed-I/O capture, exclusion/repair, matching downstream corpus consumption and the retention seal remain open. See [adoption evidence](account-handoff.md#adoption-usage).

Will NSD explicitly accept Egress/Exit completed host-write/send layer-4 bytes,
partial completions only, zero for failures, and the unchanged public-ingress
boundary? Confirm explicit payer/direction/grant/reporter incarnation and the
exclusion of WireGuard overhead. Confirm `batch_loss_window: null` means unset,
distinct from measured `[0]`, with no invented duration. Identify producer
vectors for these units; relay DATA remains a separate unit.

`EchoReplySend` retains its completed-send meaning: completed synthetic ICMP
reply message bytes excluding IP headers, for a runtime that can observe
per-packet send completion. The current gateway candidate emits no `EchoReplySend`
rows: at frozen nsplane 0.16.0, synthetic replies are delivered but unbilled
because the normal outbound path provides no per-packet successful-send receipt.
Queue admission is never completion. `EchoProbeSend` is unchanged; an unmetered
or failed reply does not erase a completed probe. Reply billing remains deferred
until a released packet-runtime capability is adopted and qualified. This is an
outstanding runtime capability, not a contract change or recorded agreement.

### Q11: Enrollment payload — NSD owner

2026-10-27 status: Registration/source and lifecycle handling are adopted in source; current matched enrollment corpus bytes, live confirmation and the Q07/Q11 owner answers remain open. See [adoption evidence](account-handoff.md#adoption-core).

Confirm the [independent snapshot poll candidate](../spec/account/control.md): PublicationSnapshotRequest, config.snapshot on the existing confidential control endpoint, exact sorted scopes, retained active subscription boot nonce/attempt and signed response nonce correlation. The only response is a signed B43 Response with canonical `[1, [bstr(SourcePublication), ...]]` payload, request-derived Snapshot delivery and independently accepted exact source for each requested scope, retaining existing per-key versions. Plain and mixed entries reject the whole poll; snapshot entries have no SSE/Base64 framing limit. No predecessor kind selector exists; only snapshot-owned kinds are requested, and explicit stream selectors are refused as unknown fields. Confirm exact scope authorization, active subscription binding and response correlation echo. Independent publication-snapshot-request.vec fixtures are not real producer output; NSD confirmation remains outstanding.

Confirm the exact [publication subscription candidate](../spec/account/control.md): PublicationSubscriptionRequest, config.stream, /api/v1/config/stream, full issuer/recipient/realm/scope entries, enrollment capability syntax, family 7 public ingress indices and required nonzero boot nonce/positive u32 attempt counter. Confirm `request` as the subscription query parameter, `config-envelope.v1` as the single SourcePublication Base64 event, the shared inclusive 1,398,139-byte framing ceiling and independent decoded 1,048,576-byte ceiling. Confirm producer bytes and external scope authorization, confidential signed carrier use and unchanged publication versions/channel ownership. NSD confirmation remains outstanding; independent fixture vectors do not constitute producer agreement.

The [complete control exchange candidate](../spec/account/control.md) specifies
RegistrationRequest/RegistrationAcceptance, AuthenticationRequest/Response and
InformationRequest/Response and their exact tuple fields and constants. Confirm
the provisioned membership/credential join, accepted profile/capabilities and
I/K/version/generation comparison, including lifecycle refusal. Consumer vectors
are independently generated in `control-exchange.vec`, not NSD producer output.
Confirmation and complete requested producer-owned vector coverage remain outstanding; no agreement is recorded.


The [Enrollment section](../spec/account/node.md#enrollment) adds the
binding/capability publication and acceptance decisions beyond the published
candidate revision; the family table above retains that revision's state.

What exact schema, field widths, capability/profile identifiers and endpoint
forms will complete `enrollment`, including authenticated authority/recipient,
ordinary per-membership I/K registration and own-node binding? Name independent
NSD producer vectors for registration, replacement and invalid binding.

The enrollment candidate now defines `[1, binding, capabilities]`, with 0..64
opaque identifiers of 1..64 ASCII bytes matching `[a-z0-9._-]+`, strictly sorted
and duplicate-free. Which exact capability identifier values and profile meanings
should ordinary Nodes declare? Confirm these bounds and provide independent
vectors for empty, supported, unknown, duplicate and out-of-bounds sets. Confirm
Q07's restart refusal, separate account/signed K generation, missing refresh tag
and u64/u32 derivation width before live producer use. The endpoint and
authenticated envelope candidates below still need independent producer confirmation.

The [bootstrap and envelope trust candidate](../spec/account/control.md)
now details family 11 discovery as `[1, 1, https_origin, [1], endpoints,
noise_key_or_null, quic_spki_pins, envelope_pins]`. Endpoints retain preference
order and permit HTTPS/Noise/QUIC only. Confirm canonical origins, WebPKI source,
raw Noise key, full-SPKI pins and RFC 7638 signer pins, including local intersection.
Please provide independent NSD discovery producer vectors for accepted order,
missing trust, empty intersections, noncanonical/duplicate pins and downgrades.

### Q12: Realm and peer payload — NSD owner

2026-10-27 status: Canonical realm/source publication production and ns recorded-byte consumption are adopted; complete owner confirmation, refusal coverage and live source retirement remain open. See [adoption evidence](account-handoff.md#adoption-publication).

The [realm publication candidate](../spec/account/realm.md) now specifies
`[1, 2, contributions]`: complete served-realm collections with full NodeBinding
and signed NodeRecord I/K/generation checks, strict realm/member ordering, global
identity/key uniqueness and bounded sizes. Existing Node contracts derive NodeId
and N4/N6; membership grants no L3 permission. The signed snapshot publication's
exact issuer/recipient/served_realm/scope key establishes collection authority.
Independent candidate vectors cover two-realm installation, malformed refusal
without renewal, omitted-realm removal, empty withdrawal and older replay refusal
against a restored version tombstone. The field mapping explicitly retires gateway
device addresses, listen ports, arbitrary cryptokey routes and carrier tuning.

Family 11 policy-version is `[1, 11, counter]` on its existing signed stream kind:
an observation only, never applied-policy evidence or an authorization revision.
Its exact key and enclosing publication version control acceptance, including
counter decreases under a newer publication.

Please confirm these realm contribution, binding, withdrawal and diagnostic counter
schemas and supply independently owned NSD producer vectors. NSD/ns owner confirmation remains open for mapping string machine/owner identifiers and the NodeL3Config
resource graph to full identities. Candidate fixture success does not establish
producer confirmation; no producer reply has been received.

The [source authority candidate](../spec/account/publication.md) now adds signed
NSD/recipient/realm/scope/profile/source/contribution/epoch/generation binding and
exact subscription boot/attempt or poll context inside new source-publication
signed bytes. These are additional exact fences before existing full-key versions,
including complete-empty and authenticated failures; higher versions cannot revive
retired sources or sessions. Please confirm the authenticated control-response
provenance and durable NSD contribution generation, and provide independent
producer bytes. Labelled fixture success is not producer confirmation.

### Q13: Egress grant payload — NSD owner

2026-10-27 status: Protocol-qualified grant, payer and withdrawal projection is adopted in source; complete independent producer vectors, owner answers and live joins remain open. See [adoption evidence](account-handoff.md#adoption-grants).

What schema completes `egress` using M6 provider/resource and declaration
references, address view, protocol/virtual port, authorized client, paying realm
and subject, fresh grant incarnation and realm limits? Name NSD vectors for
valid grants, scope mismatch and withdrawn authority.

The [delivered pure candidate](../spec/account/grants.md) specifies
`[1, 3, issuer, provider_recipient, revision, grants]`, with canonical M6 resource,
full client/provider, exact local floor reference and projected name, concrete
protocol/virtual port, optional positive alias generation, one binary payer
realm/UserId pair, fresh incarnation and absolute expiry. Independent consumers
compare every context field and refuse absent/ambiguous payer and invalid fields.
NSD confirmation and complete requested producer-vector coverage remain outstanding, including conversion
from current string ULIDs to exact 16-byte unsigned big-endian UserId bytes.
No acceptance proof or local host binding is added to the payload.

### Q14: Exit grant and selection payload — NSD owner

2026-10-27 status: Select/clear production, immutable receipts and ns restart/replay consumption are adopted; live routing and matched default/nested Exit confirmation remain open. See [adoption evidence](account-handoff.md#adoption-routes).

What schema completes `exit-subnet` with stable route/resource identity,
family-neutral prefixes, actual IPv4 and mapped IPv6 range, exclusions,
bypasses, selection, client, payer, incarnation and limits? Local Exit enablement
and floor are provider-local and have no wire field. Egress wire floor is unchanged.
Name NSD vectors for nested default/specific routes, range ownership and empty
selection; preserve the existing M6 route/listener boundaries.

The [Subnet selection candidate](../spec/account/subnet.md)
uses standalone client-recipient `subnet-routes` snapshots with complete
`[1, 4, nsd_id, network_id, recipient, revision, routes]` payloads and canonical M6
ServiceRef bytes. This kind is separate from provider-recipient `exit-grants`;
both use the recipient's nodes source in the event Network. Each route names real/mapped
family/address/length, full provider/client identities, exact distinct exclusions
and bypasses and tagged default/explicit selection. IPv4 mapping is `/96+p`
with exact embedded real network bits. Selected destinations subtract exclusions;
bypasses stay distinct. Only a nonempty selected real IPv4 set advertises TCP,
UDP and echo; real IPv6 advertises none. No local host binding is carried.
Can NSD independently produce canonical accepted and typed-refused vectors for
nested default/specific routes, IPv6 without coverage, exact exclusions/bypasses,
empty selection and complete empty withdrawal, mismatched mapping, outside and
overlapping prefixes, noncanonical/misaligned prefixes, mixed selection, unknown
discriminants and malformed/nonminimal/trailing bytes? Grants, payer and
incarnation remain separate; this candidate does not change M6 listener semantics.

The delivered [Exit grant candidate](../spec/account/grants.md) wraps exactly
one validated Subnet route per grant, preserving all existing real/mapped,
exclusion/bypass and selection semantics. Resource/client/provider must agree
with the enclosing grant; the provider receives the grant publication, while
the embedded route publication retains its client recipient. Independent
consumer vectors compare every field and the independently computed selected
CIDR output. Payer is a binary realm/UserId pair and incarnation and expiry
are explicit. Local floor and Linux binding remain consumer facts. Outstanding:
NSD grant/route composition, payer assignment and independently owned vectors.

The [Node route command candidate](../spec/account/publication.md)
adds `node.route.select` and `node.route.clear` on the confidential signed control carrier,
with full provider I, stable M6 ServiceRef, existing default/explicit scope, exact
source/profile, request and selection identities. NSD-signed committed receipts
carry selection generation; clear targets that exact generation. Replay retrieves
the original immutable profile/source/request receipt without changing current
selection, including after source replacement and restart. Changed content under
one request identity conflicts. NSD transaction rechecks, all-receipt persistence and ns pending-journal handling
are adopted as recorded above; complete requested producer-vector coverage and
live route confirmation remain open; the
predecessor latest-clear-receipt-per-machine store cannot supply this ownership.

### Q15: Payer binding payload — NSD owner

2026-10-27 status: Protocol-qualified grant, payer and withdrawal projection is adopted in source; complete independent producer vectors, owner answers and live joins remain open. See [adoption evidence](account-handoff.md#adoption-grants).

What schema and resource scope complete `payer`, so each grant has an explicit
paying realm/subject and ambiguous cross-realm grants are withheld? Name NSD
vectors for explicit payer, ambiguity and payer change without packet-derived
realm inference.

The [delivered payer candidate](../spec/account/grants.md) defines complete
family-5 assignments keyed by full M6 resource, client and discriminator,
with the exact grant incarnation.
Each has exactly one `[payer_realm, payer_subject]` pair of 16-byte strings;
subject is the paying realm's local UserId ULID, never an IdentityKey. Zero
and multiple bindings (even equal values) are distinct typed refusals. NSD must
authenticate the resource proposal and the paying administrator's accepted exact
assignment before producing this pair. Producer vectors, accepted-assignment
integration and binary conversion from current string ULIDs remain outstanding.
The service usage candidate now carries the same realm/UserId pair; see Q19
for the incompatible predecessor and the exact candidate bytes.

### Q16: Withdrawal and regrant payload — NSD owner

2026-10-27 status: Protocol-qualified grant, payer and withdrawal projection is adopted in source; complete independent producer vectors, owner answers and live joins remain open. See [adoption evidence](account-handoff.md#adoption-grants).

What schema completes `withdrawal` with resource removal or empty authority,
current incarnation, real deadlines and payer/binding changes? Name NSD vectors
for immediate removal, expiry and identical-content regrant with a fresh token;
withdrawal must not wait behind relay snapshots.

The [delivered resource authority candidate](../spec/account/grants.md)
contains active claims and retained resource-scoped retired tokens. Pure
successor validation requires unchanged scope, increasing revision, preserved
history and retirement of removed/replaced claims. Independent consumers prove
selective removal preserves another resource, fresh identical-content regrant
succeeds and retired tokens fail. Equal or later deadline-only renewal may keep
the token at a strictly newer valid revision; every other content change requires
a fresh token.
Runtime fencing, durable history and actual expiry comparisons remain consumer
responsibilities. NSD complete requested producer-vector coverage and publication/history delivery remain
outstanding; candidate fixtures do not assert deployed interoperability.

### Q17: Public-edge payload — NSD owner

2026-10-27 status: NSD public-edge projection, anonymous/raw-name vectors and actual producer corpus are adopted; a matching downstream corpus reader, live policy/name enforcement and Q17 confirmation remain open. See [adoption evidence](account-handoff.md#adoption-edge).

The delivered [candidate specification](../spec/account/edge.md) defines
PublicEdge complete realm contributions under the existing signed family 7
stream scope, exact material generations and correlated installation ACKs,
embedded shared subject/JWT/header values and EdgeServiceRequest/Response using
unchanged M6 Declaration, ReportContent and ListenerIntent bytes and digests.
Please confirm names/aliases/domains/virtual ports, full Node identity backends,
explicit no-connector behavior, complete replacement/empty withdrawal, refusal
without renewal and dependency-before-route ordering. Review both independent
consumer acceptance tests public_edge_vectors and material_declaration_vectors
and supply NSD producer-owned vectors; Python fixture authority is not NSD output.

Service DNS labels resolve from the authenticated M6 Resource via ServiceRef.
Standalone labels remain excluded pending M01/M02 with the M6 contract owner.
The [confidential authentication contract](../spec/account/edge.md) closes
the provider/import, cookie, organization, template and redirect candidate carriers.
It retains actual verifier/secret values and exact realm/reference/generation
correlation in authenticated confidential envelopes only. Please review
confidential_auth_generation and supply NSD-owned positive and refusal vectors,
including current dependency changes and rotation. NSD producer confirmation
remains outstanding; no agreement, live interoperability or public-ingress usage
changes are claimed; Q17 was sent on 2026-10-25; its answer is outstanding.

### Q18: Relay directory and participant payload — NSD owner

2026-10-27 status: NSD signed roster/participant and directory production plus ns recorded directory consumption are adopted; local file-writer proof, live rollback/carrier transitions and complete unsettled-reference sealing remain open. See [adoption evidence](account-handoff.md#adoption-roster).

The owner choice is settled: use a shared participant credential and a separate
NSD-signed directory binding. The global directory, its entry identities and its
existing format remain unchanged. Relay clients, independent participants and
gateway Nodes retain distinct authority; directory hints or gateway Node
credentials do not establish participant authorization.

The shared [participant authority definition](../spec/account/relay.md)
and independent `participant-authority.vec` vectors deliver participant
enrollment, authentication, renewal, revocation and separate signed directory
bindings. Gateway runtime adoption remains pending. The source-binding and Node
route candidate only cross-references this boundary. The shared definition is
delivered at immutable revision `28bf972db2e1f434114adc324a26fabad545aed1`; producer
confirmation must name its immutable consumed revision.

NSD producer review, independently owned complete requested producer-vector coverage and NSD/ns live adoption confirmation
remain outstanding. The existing participant roster retains its signed
issuer/recipient scope; its concrete carriers remain reviewed in Q01–Q06.
Confirm Q03's retained complete authority and diagnostic degradation rule and
supply NSD producer vectors for enrollment/renewal, empty replacement, revocation,
realm eligibility withdrawal, class changes and the exact validity/degradation
boundaries. Candidate fixture vectors establish neither producer confirmation
nor live interoperability.

### Q19: Service and relay report schemas — NSD owner

2026-10-27 status: NSD usage receipt/history handling and actual answer corpora are adopted; live completed-I/O capture, exclusion/repair, matching downstream corpus consumption and the retention seal remain open. See [adoption evidence](account-handoff.md#adoption-usage).

What exact schemas complete `usage` reporter identity/sequence, report windows,
acknowledgements, durable watermarks and errors for both independent reporters?
Service reports attach resource/payer/incarnations. Relay reports attach source
NodeId, captured scope/epoch/class and whole accepted encoded DATA including
its header, counted once at accepting ingress. Name NSD vectors for delayed
history, duplicate delivery, repair and gateway-associated billing once against
gateway service usage, without converting relay bytes to the service unit.

The [usage candidate](../spec/account/usage.md) now defines service and relay
report parts and exact correlated ACK/conflict/permanent/unknown-mapping answers.
Independent fixture consumers are `service_usage_vectors`, `relay_usage_vectors`,
`usage_report_vectors` and `usage_answer_vectors`. The same UserId in two realms
retains distinct payer ownership and fails a mismatched historical grant join.
Historical relay comparison uses the captured issuer/participant/roster version
and both endpoint classes; either gateway endpoint is excluded in both directions.

This is an explicit incompatible candidate wire delta: the predecessor subject
was the CBOR byte string `5820` followed by 32 validated Ed25519 identity bytes
(for example `8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c`).
The revised subject is `50` followed by exactly 16 unsigned big-endian UserId
ULID bytes (the migrated account fixture uses `09090909090909090909090909090909`).
The version 1 nine-element tuple and every other field are unchanged. The exact
implementation revision is `05ee100f4eba547cd1e7025c92860a20f79fefc2`; predecessor integration
revision `c71148388636da72f3808623529e1946d1cee1ba` still uses the incompatible identity subject.
The immutable candidate handoff must include the implementation revision. There is no old-subject fallback or tagged union. NSD confirmation,
complete requested producer-owned vector coverage, historical ledgers and live exclusion remain outstanding;
fixture answers establish none of them. Current gateway echo message quantities
require completed-byte instrumentation before this profile can be adopted.

### Q20: Node-control vocabulary — node owner and NSD owner

2026-10-27 status: NSD usage/Node-control catalogue production and actual corpus are adopted; matching ns/gateway corpus consumption, live preserved state and Q19/Q20 answers remain open. See [adoption evidence](account-handoff.md#adoption-profiles).

The candidate now supplies `nsshared_proto::node_control` for ACK, ENDPOINTS,
RECORD, PROBE_REQUEST and PROBE_REPLY, with unchanged version 2 and port 47900.
ACK means at least accepted and permits persistence before ACK. The independent
Python producer `tools/vectors/nsvec/producers/node_control.py` reproduces all
nine pinned gateway fixtures and the node's known bytes and unkeyed ACK hash.
`tests/node_control.rs` ports the ten codec tests present at node revision
`50f8e3fd95fac8bbc72aea9b132459103c3b206a`; `tests/vectors_node_control.rs`
checks the independently generated bytes and refusals. See the
[codec specification](../spec/node-control.md).
Please confirm the delivered contract and supply independent producer/consumer
review results. This candidate does not claim live interoperability; transport,
persistence, retransmission and state machines remain in consumers.

### Q21: Complete v1 replacement map — NSD and node owners

2026-10-27 status: Exact shared control-report producer bytes, admin scope/subject/JWT/signed-URL/header review, unplaced carriers and any gateway audience decision remain open; partial family-7 implementation is recorded. See [adoption evidence](account-handoff.md#adoption-policy).

The [source/selection candidate](../spec/account/publication.md) records the
assigned `explicit-gateway-profile` vocabulary and mandatory source/profile
comparisons. New signed forms refuse retired gateway-ID selections, carrier
credentials and old-profile receipts without compatibility translation. The
`source_selection_fence` independent fixture sequence preserves I/K/addresses
while replacing source authority, refuses delayed higher-version A content and
keeps A's original clear receipt and B's selection intact across restart. NSD/ns
retained-cohort inventory and retirement decisions, producer review and live adoption confirmation
remain outstanding. This is candidate delivery, not approval or interoperability.

Confirm the exact [publication subscription candidate](../spec/account/control.md): PublicationSubscriptionRequest, config.stream, /api/v1/config/stream, full issuer/recipient/realm/scope entries, enrollment capability syntax, family 7 public ingress indices and required nonzero boot nonce/positive u32 attempt counter. Confirm `request` as the subscription query parameter, `config-envelope.v1` as the single SourcePublication Base64 event, the shared inclusive 1,398,139-byte framing ceiling and independent decoded 1,048,576-byte ceiling. Confirm producer bytes and external scope authorization, confidential signed carrier use and unchanged publication versions/channel ownership. NSD confirmation remains outstanding; independent fixture vectors do not constitute producer agreement.

The [control exchange delta](../spec/account/control.md)
maps all 264 pinned control-trust/enrollment inventory rows. Four internal
fixture records remain historical records, not migrated consumers. Confirm the
RS256 claims/JWK forms, key-use refusal, realm/address pin ownership, qualified
rotation, kid selection, 30-second gateway expiry leeway and 300-second refresh
window. `BootstrapEnvelope::signing_input` retains exact existing domain/content
bytes and is reused by senders and independently signed fixture responses.

Gateway machine bearer validation preserves its audience-agnostic predicate:
absent, unrelated single and array audiences keep their current outcome.
Wrong-audience refusal vectors are explicitly labelled as the distinct NSD
machine verifier boundary. Open owner-review item: should a later gateway
candidate require the expected machine audience? No such change is decided or
implemented here. NSD confirmation, independent complete requested producer-vector coverage and any later
policy agreement remain outstanding.


Which detailed family or explicit retirement covers every inventoried discovery,
envelope verification, admin claim, policy, signed URL, material declaration,
report, snapshot and event item? Supply the mapping and NSD vectors for retained
semantics and refusals; inventory ownership alone does not prove wire equivalence.

The family 11 [bootstrap and envelope trust candidate](../spec/account/control.md)
adds `[content_bytes, signature]`, with content `[1, direction, signer_I,
recipient_I_or_null, kind, unix_seconds, nonce_16, opaque_payload_bytes]`.
Confirm exact domains `ns.account.call.request.v1\0` and
`ns.account.call.response.v1\0` (each ending in one zero byte), required pinned
signature verification, optional-recipient matching and unchanged M6 message bytes.
Confirm bounds: discovery 256 KiB, call body 8 MiB, headers and encoded subscription
16 KiB each, Noise plaintext 65,519 and ciphertext 65,535 bytes excluding its
two-byte length prefix, inclusive 60-second skew and 120-second replay retention.
Please provide independent NSD carrier producer vectors for both domains,
issuer/recipient, kind, signature, local intersection, time/replay and byte-limit
boundaries, nonminimal/trailing encodings and every downgrade refusal. Candidate
Python vectors are fixtures, not producer output; these questions were sent on
2026-10-25 and their answers are outstanding.

The publication candidate reuses `[content_bytes, signature_64]` with distinct
`ns.account.publication.v1\0` signing domain and content
`[1, issuer, recipient, served_realm, scope, family, kind, channel, complete,
publication_version, issued_seconds, expires_seconds, outcome, payload_bytes]`.
Confirm the profile's owning-channel table and canonical ordered snapshot list.
Confirm the inclusive 1,048,576-byte limit on the measured complete signed event
as received before decoding/allocation: oversized stream input terminates and
reconnects without replacement; oversized snapshot events reject the whole poll.
Please supply independent NSD canonical signed producer vectors at exactly that
size and one byte over, malformed/truncated declared lengths, unknown kinds,
wrong channels, issuer/recipient/scope/signature/freshness refusals and atomic
snapshot rejection. Existing M6 payload bytes remain unchanged. These additions
were sent on 2026-10-25; candidate fixture signatures are not NSD output.

### Q22: Independent family producer vectors — NSD owner

2026-10-27 status: Named NSD producer corpora and bounded ns readers are adopted; the complete eleven-family refusal/limit inventory, matching remaining readers and Q22/Q23 owner answers remain open. See [adoption evidence](account-handoff.md#adoption-vectors).

Where will NSD publish its independently generated vectors for each of
`enrollment`, `realms-peers`, `egress`, `exit-subnet`, `payer`, `withdrawal`,
`public-edge`, `relay`, `usage`, `node-control` and `v1-replacement`?
For each family, identify schema revision, canonical bytes, expected validation
result and positive/empty/malformed/scope/limit cases. Candidate Python fixtures
cannot stand in for NSD's producer output. Identify unresolved schemas explicitly.

### Q23: M6 composition boundary — NSD and node owners

2026-10-27 status: NSD M6 carrier and ns recorded-byte adapters are adopted; Q23 composition agreement and real per-Network session/proposal/lease confirmation remain open. See [adoption evidence](account-handoff.md#adoption-m6).

Does each detailed family retain the exact types, message variants, codecs,
constants and vector domains in the reuse table? For any additional needed M6
change, identify the affected type, message or vector, family and concrete need
so the owner can forward it to the M6 contract owner. No additional M6 schema
change is established by this frame; standalone label validation is requested below.

### Q24: Gateway report ingress scopes — NSD owner

2026-10-27 status: Open: NSD must classify GatewayReport ingress values as publication scopes or report-only labels. No answer or stricter validation is inferred.

Are the `public_ingress_scopes` values of `GatewayReport` (see the
[gateway observations](../spec/account/control.md#gateway-observations)) publication
scopes, or report-only labels? They are validated as bounded data text, so
whitespace is accepted, and they authorize nothing. If they are publication scopes,
the scope text rule (1 to 256 UTF-8 bytes without whitespace or control characters)
would apply to them in a later revision, with refusal vectors; until then they keep
the data text rule.

## Requested M6 changes for agreement

The owner forwards M01 and M02 to the `nsshared-service-control` contract owner.
These are requests for agreement, not API or wire changes made here. Neither
consumer nor L8 introduces a parallel type, validator or M6 serializer.

### M01: Public standalone service-label validation

Affected API: private `valid_service_label(label: &str) -> bool` in
`crates/nsshared-service-control/src/snapshot.rs`, and `Resource::service_label`.
Need: Egress grants, withdrawal/snapshot composition and public-edge/declaration
families (inventory B39/B44/B46) can carry a supplied DNS service label outside
a complete `Resource` or `Snapshot`. Please expose the existing validation
through a public API with the same rule: 1–63 bytes, lowercase ASCII letters,
digits or hyphens, alphanumeric ends. Agree its exported name/signature with
the contract owner. Do not derive labels from display names or declaration keys
or construct artificial resources just to validate a label.

### M02: Independent vectors for standalone label validation

Affected vectors: `crates/nsshared-service-control/vectors/service-control-v1.json`
and `tests/vectors.rs`; affected API: the public validation requested in M01.
Need: the same Egress, snapshot/withdrawal and public-edge/declaration families
must prove standalone validation agrees with existing snapshot validation.
Please add independent accepted/rejected label vectors for lengths 1/63/64,
empty, uppercase, non-ASCII, interior hyphen and leading/trailing hyphen.
Retain all existing report/listener/snapshot/message bytes and digest domains;
new cases must not rename or copy the M6 fixture into the account vectors.

## Disposition

`prepared` means ready for forwarding. Record `sent` only when the owner reports
delivery, with its actual date. Record `answered` with the answer's durable
location. Use `outstanding` for an unresolved or unreceived answer after delivery;
retain the delivery date and any partial answer reference. Outstanding answers
do not block candidate preparation and do not imply approval. The owner reported
delivery of every row on 2026-10-25; no answer has been received.
These statuses track external producer review; Q18's owner design choice is
settled. Shared definitions and bounded upstream adoption are delivered; owner
answers and live confirmation remain open as detailed in the linked evidence.

| Reference | Addressee | Status | Sent date (reported by owner) | Answer location |
| --- | --- | --- | --- | --- |
| Q01 | NSD and node | sent; answer open | 2026-10-25 | No received owner answer; [adoption evidence](account-handoff.md#adoption-roster) |
| Q02 | NSD and node | sent; answer open | 2026-10-25 | No received owner answer; [adoption evidence](account-handoff.md#adoption-roster) |
| Q03 | NSD and node | sent; answer open | 2026-10-25 | No received owner answer; [adoption evidence](account-handoff.md#adoption-roster) |
| Q04 | NSD and node | sent; answer open | 2026-10-25 | No received owner answer; [adoption evidence](account-handoff.md#adoption-roster) |
| Q05 | NSD | sent; answer open | 2026-10-25 | No received owner answer; [adoption evidence](account-handoff.md#adoption-usage) |
| Q06 | NSD | sent; answer open | 2026-10-25 | No received owner answer; [adoption evidence](account-handoff.md#adoption-roster) |
| Q07 | Node, with NSD | sent; answer open | 2026-10-25 | No received owner answer; [adoption evidence](account-handoff.md#adoption-core) |
| Q08 | NSD and node | sent; answer open | 2026-10-25 | No received owner answer; [adoption evidence](account-handoff.md#adoption-publication) |
| Q09 | NSD and node | sent; answer open | 2026-10-25 | No received owner answer; [adoption evidence](account-handoff.md#adoption-publication) |
| Q10 | NSD | sent; answer open | 2026-10-25 | No received owner answer; [adoption evidence](account-handoff.md#adoption-usage) |
| Q11 | NSD | sent; answer open | 2026-10-25 | No received owner answer; [adoption evidence](account-handoff.md#adoption-core) |
| Q12 | NSD | sent; answer open | 2026-10-25 | No received owner answer; [adoption evidence](account-handoff.md#adoption-publication) |
| Q13 | NSD | sent; answer open | 2026-10-25 | No received owner answer; [adoption evidence](account-handoff.md#adoption-grants) |
| Q14 | NSD | sent; answer open | 2026-10-25 | No received owner answer; [adoption evidence](account-handoff.md#adoption-routes) |
| Q15 | NSD | sent; answer open | 2026-10-25 | No received owner answer; [adoption evidence](account-handoff.md#adoption-grants) |
| Q16 | NSD | sent; answer open | 2026-10-25 | No received owner answer; [adoption evidence](account-handoff.md#adoption-grants) |
| Q17 | NSD | sent; answer open | 2026-10-25 | No received owner answer; [adoption evidence](account-handoff.md#adoption-edge) |
| Q18 | NSD | sent; answer open | 2026-10-25 | No received owner answer; [adoption evidence](account-handoff.md#adoption-roster) |
| Q19 | NSD | sent; answer open | 2026-10-25 | No received owner answer; [adoption evidence](account-handoff.md#adoption-usage) |
| Q20 | Node and NSD | sent; answer open | 2026-10-25 | No received owner answer; [adoption evidence](account-handoff.md#adoption-profiles) |
| Q21 | NSD and node | sent; answer open | 2026-10-25 | No received owner answer; [adoption evidence](account-handoff.md#adoption-policy) |
| Q22 | NSD | sent; answer open | 2026-10-25 | No received owner answer; [adoption evidence](account-handoff.md#adoption-vectors) |
| Q23 | NSD and node | sent; answer open | 2026-10-25 | No received owner answer; [adoption evidence](account-handoff.md#adoption-m6) |
| Q24 | NSD | open, not sent | — | Need NSD scope-versus-label classification; not answered |
| M01 | M6 contract owner, through owner | sent; answer open | 2026-10-25 | Need explicit API agreement and independent label vectors; [adoption evidence](account-handoff.md#adoption-labels) |
| M02 | M6 contract owner, through owner | sent; answer open | 2026-10-25 | Need explicit API agreement and independent label vectors; [adoption evidence](account-handoff.md#adoption-labels) |

## Policy, subject and admin claim review delta

2026-10-27 status: Exact shared control-report producer bytes, admin scope/subject/JWT/signed-URL/header review, unplaced carriers and any gateway audience decision remain open; partial family-7 implementation is recorded. See [adoption evidence](account-handoff.md#adoption-policy).

Review the [pure policy and claim values](../spec/account/realm.md)
and independent [policy-claims vectors](../../crates/nsshared-control/tests/vectors/account/realm/claims.vec).
The Python producer is `tools/vectors/nsvec/producers/policy_claims.py`; the
independent Rust consumer is `tests/policy_claim_vectors.rs`. These are labelled
candidate fixture bytes, not NSD producer confirmation or live interoperability.
This addition was sent on 2026-10-25; no owner agreement is recorded.

The values add no publication kind. Existing NodeL3Authority retains full Node
L3 authority, public-edge/visitor/auth values embed in family 7 under its owner,
and admin scopes travel in authenticated admin-token claims. Machine-token
claims/key sets and the diagnostic policy-version counter remain separately
owned. Q21's aggregate policy aliases/self-tests and other unplaced rows stay
open carrier items; no new policy stream or implicit authority is introduced.

Please confirm these concrete producer deltas against NSD's current model:

- Human `Claims` carries UserId, realm, audience, organization/session and time
  claims but no admin scope. There is no NSD producer for the gateway's
  AdminClaims `scope`. Supply an explicit authenticated admin-token producer
  with read_only/read_write/super_admin, or retain the consumer's refusal;
  never derive scope from human login, API-token `full`/`read-only`, or roles.
- Candidate binary user subjects reuse the exact Payer realm/UserId pair.
  Symbolic user/group/machine/external labels remain explicit realm-local
  policy subjects, not identity keys, payer conversions or credential-derived
  principals. Confirm the NSD projection source and exact canonical bytes for
  each subject/binding, including malformed/missing/cross-realm refusals.
- Credential/consumer joins must preserve stable subject, enabled status,
  credential reference, actual expiry, exact JWT authority/claim name/value
  and opaque credential scopes. Confirm family 7's enclosing consumer and
  issuer/audience/key-source metadata; this value performs no key fetch or
  token verification and must not acquire that trust from unverified claims.
- Signed URL inputs preserve the current HMAC-SHA256 canonical text, duplicate
  query pairs, literal plus, default-port removal, exact raw path and realm/route
  scope. Supply producer vectors for these cases and malformed percent escapes.
  Existing account request/response domains and envelope bytes remain unchanged;
  response-domain signatures must fail request authentication.
- Confirm explicit signed subject-header names, keyset reference, validity and
  inbound stripping in family 7. This package carries no header signing key or
  credential verifier. Preserve evaluator and self-test behavior in gateway
  consumers, and identify an enclosing carrier for every still-open aggregate
  policy item before treating those items as delivered publications.

The required independent owner vectors include every admin scope and ordering
pair, insufficient/unknown scope, expired and wrong-subject/realm contexts,
missing/malformed subjects, exact binary UserId widths, duplicate/unsorted sets,
wrong signing domain and non-shortest/trailing CBOR. Consumer acceptance of the
candidate fixture cannot replace these outstanding producer review inputs.

### Exact JWT claim string data

The candidate distinguishes JWT `claim_name` and `claim_value` from subject
labels and authority/credential references. Both fields preserve the exact
original UTF-8 string within 256 bytes, including spaces, controls, empty strings
and Unicode normalization form. In particular `department` matching
`Platform Engineering` round-trips without trimming or encoding. Empty fields
remain distinct from missing/non-text fields; the latter still refuse, as do
invalid UTF-8, oversized fields and noncanonical encodings. No claim lookup or
token verifier is moved into the shared contract. Please include exact name/value
producer cases in family 7 review, independently of its reference/token syntax.

## Control exchange family state delta

2026-10-27 status: Registration/source and lifecycle handling are adopted in source; current matched enrollment corpus bytes, live confirmation and the Q07/Q11 owner answers remain open. See [adoption evidence](account-handoff.md#adoption-core).

Implementation revision: `1c9602c5e626e186ea6c8c0d85b42536c43c508e`.
Review the exact source, tuple specification and independent fixture bytes at
that revision; the earlier package revision does not include this delta.

| Family | Current candidate state | Review status |
| --- | --- | --- |
| Enrollment | Registration, explicit acceptance and lifecycle comparison implemented | Registration/source and lifecycle handling are adopted in source; current matched enrollment corpus bytes, live confirmation and the Q07/Q11 owner answers remain open. See [adoption evidence](account-handoff.md#adoption-core). |
| Bootstrap / v1 replacement | Information and authentication values reuse confidential signed envelopes and public signing input | Registration/source and lifecycle handling are adopted in source; current matched enrollment corpus bytes, live confirmation and the Q07/Q11 owner answers remain open. See [adoption evidence](account-handoff.md#adoption-core). |
| Machine claims / v1 replacement | RS256 public claims, JWK forms, pin qualification and distinct audience predicates implemented | Producer vectors and possible later gateway audience requirement open |

This delta accompanies the changed source and independent fixtures; the earlier
published revision above is historical and does not contain this delta.

## Control reports delta for Q11/Q21

2026-10-27 status: Exact shared control-report producer bytes, admin scope/subject/JWT/signed-URL/header review, unplaced carriers and any gateway audience decision remain open; partial family-7 implementation is recorded. See [adoption evidence](account-handoff.md#adoption-policy).

Implementation and independent fixture revision: `e8f03746d26ac26491ba644704a4357934f43bdd`.
The earlier package does not include this explicit candidate delta.

Review the exact report tuples in control-report-candidate.md and the independent
control-reports.vec and updated public-edge.vec. Heartbeat retains uptime, local
addresses and the observation-only policy counter. Gateway observations retain
software/revision, connection/termination intent, drain, capabilities, ingress
ports/scopes and every certificate observation; identity/endpoints belong to the
ordinary Node record and node-control. Legacy removed carrier fields have explicit
dispositions in the complete pinned consumer map.

The existing EdgeServiceRequest/Response kind 1 candidate changes incompatibly:
unchanged M6 service objects now carry complete capabilities/labels and local Exit
floor declarations with exact per-kind accepted/rejected-reference outcomes and
reasons. Missing, unknown or contradictory outcomes refuse; empty floor is explicit.
Its digest commits the complete floor. All other public-edge, material,
declaration and listener bytes remain unchanged.

Confirm the five signed operation identifiers on the existing confidential control
endpoint, heartbeat features/receipt correlation, observation-only metadata and
complete service floor semantics. Material status must correlate the exact reference,
contributing realm and generation; auth configuration also retains its separate
confidential request correlation. The private configuration request/response is not
defined by this report delta. Installed status follows actual installation only.
Service UnknownMapping answers fail correlation; historical mapping repair remains
relay-only and never acknowledges a service report.

NSD confirmation, producer-owned canonical/refusal vectors and real producer
interoperability remain outstanding. Fixture acceptance records no agreement.

## Exact floor text acceptance

2026-10-27 status: Exact shared control-report producer bytes, admin scope/subject/JWT/signed-URL/header review, unplaced carriers and any gateway audience decision remain open; partial family-7 implementation is recorded. See [adoption evidence](account-handoff.md#adoption-policy).

Source and independent fixture revision: `300e72c13c36c10cdb9374179913e0ea329aa9e3`.
The floor wrapper preserves valid unchanged M6 declaration keys, and nonempty
control-free Exit references and policy-label keys, including internal, leading
and trailing spaces and Unicode whitespace. Accepted and rejected references
use the same exact data-text contract. Capability token syntax, limits, strict
ordering/uniqueness and control-character refusals remain unchanged. Empty
policy-label values retain their separate existing meaning. No trimming, folding
or normalization is applied before serialization, digesting or correlation.
Independent floor-text.vec cases cover these accepted/refused boundaries and
exact matching acknowledgements. Tuple shapes and existing valid fixture bytes
are unchanged; NSD confirmation and complete requested producer-owned vector coverage remain outstanding.

## Confidential authentication family state delta

2026-10-27 status: NSD confidential acquisition/dispatch is adopted in source; independent material/auth producer corpora, JWT projection review and live installation remain open. See [adoption evidence](account-handoff.md#adoption-material).

| Family | Current candidate state | Review status |
| --- | --- | --- |
| Public edge | Public references unchanged; complete confidential catalog DTOs, pure codecs and exact pending/current dependency refusal implemented | NSD confidential acquisition/dispatch is adopted in source; independent material/auth producer corpora, JWT projection review and live installation remain open. See [adoption evidence](account-handoff.md#adoption-material). |
| Bootstrap / control exchange | Existing request/response envelopes carry edge.auth.config.get; no new transport or publication kind | Accepted authority/recipient binding and installation remain consumer-owned |

The pinned NSD projection supplies client secrets, cookie keys and API/Basic/
signed-URL/mTLS credentials, while management credentials remain NSD-only and JWT
issuer projection is absent. Confirm the candidate JWT key-source/binding
projection explicitly; the independent candidate fixture does not establish it.
Unsupported OAuth2/webhook reservations and presentation-only last4 are explicitly
retired in the mapping. Existing OIDC refresh, rotation, real expiry and configured
JWKS stale refusal remain unchanged in consumers.

## Protocol-qualified grant and renewal delta

2026-10-27 status: Protocol-qualified grant, payer and withdrawal projection is adopted in source; complete independent producer vectors, owner answers and live joins remain open. See [adoption evidence](account-handoff.md#adoption-grants).

The [grant authority specification](../spec/account/grants.md) changes family 5
bindings to `[resource_bytes, client, incarnation, payers, discriminator]` and
family 6 active claims to `[resource_bytes, client, incarnation, discriminator]`.
Discriminators are `[0, 6]`, `[0, 17]`, `[1]` for TCP, UDP, Exit. Ordering,
uniqueness and admission joins use the full resource/client/discriminator key,
exact token and payer pair, without fallback. Resource/token retirement stays
unchanged; tokens cannot be shared across independent keys within a resource.
Strictly newer valid grant publications allow equal or later deadlines with
all other fields unchanged, including embedded Subnet bytes. Any other reuse
refuses and retired lifetimes cannot renew. ServiceGrant and usage tuple bytes
are unchanged. `protocol_grant_renewal` provides independent fixture producer
and consumer coverage. NSD N06 protocol/token/deadline producer live adoption confirmation and
complete requested producer-owned vector coverage remain outstanding; this incompatible candidate delta
is not contained in the earlier published package revision.

## Signed source authority response delta

2026-10-27 status: Registration/source and lifecycle handling are adopted in source; current matched enrollment corpus bytes, live confirmation and the Q07/Q11 owner answers remain open. See [adoption evidence](account-handoff.md#adoption-core).

Successful registration now requires `[1, scope, bstr(Enrollment), profile,
decision, bstr(SignedSourceBinding)]`, including Equal. Successful authentication
requires `[1, token, bstr(SignedSourceBinding)]`. This incompatible candidate
extension retires standalone SourceAcceptance and refuses old response arities.
Existing operations, confidential carrier, field encodings and refusals remain.
The [control exchange](../spec/account/control.md) and
[source authority](../spec/account/publication.md) specify envelope trust, exact
pending nonce correlation, nested signature and independent enrollment comparisons.
Independent fixture vectors precede the pure codecs; fixtures are not NSD output.
NSD N04 live adoption confirmation, complete requested producer-owned vector coverage and real interoperability remain outstanding.
Prior delivered revisions retain their original attribution; consumers must name
the immutable revision containing this response extension when adopting it.

## Explicit authentication source selection

2026-10-27 status: Registration/source and lifecycle handling are adopted in source; current matched enrollment corpus bytes, live confirmation and the Q07/Q11 owner answers remain open. See [adoption evidence](account-handoff.md#adoption-core).

AuthenticationRequest is exactly `[1, membership_scope, NodeBinding, "control",
[served_realm, publication_scope]]`. The selector is required, with no default or
old-shape fallback. Realm text is canonical 26-character RealmId; scope uses the
existing nonempty, control-free UTF-8 encoding bounded to 256 bytes. This is an
incompatible candidate request delta. AuthenticationResponse and SignedSourceBinding
encodings and signing domains are unchanged. NSD N04 live adoption confirmation remains outstanding.

Registration, including pending gateway enrollment and Equal, returns nodes authority
in the accepted registration Network. Recipient and source_node equal the enrolled
identity. The contribution field is the NSD-allocated Node source record in this
scope; it grants no gateway contribution, service resource or M6 admission.

Nodes authentication selects the enrollment Network; egress selects an independently
accepted contribution Network, including home. Consumers retain the exact pending
realm/scope and nonce, compare returned authority against that pair and independently
accepted NSD, recipient, profile and source Node facts, and verify both signatures
and the normal token. Unknown or unauthorized selectors are refused, never replaced
with another binding. Retain each accepted scope independently. Fixture vectors
cover pending registration, Equal and nodes/egress authentication in one Network,
including swapped-scope and swapped-realm refusal.

## Usage and Node-control catalogue payload delivery

2026-10-27 status: NSD usage/Node-control catalogue production and actual corpus are adopted; matching ns/gateway corpus consumption, live preserved state and Q19/Q20 answers remain open. See [adoption evidence](account-handoff.md#adoption-profiles).

Review the new [profile payload specification](../spec/account/usage.md)
and independent `profile-publications.vec` producer/consumer fixtures. Family 9
now carries `[1, reporter, profiles]`; family 10 carries
`[1, membership_scope, 2, capabilities]`. These are explicit new candidate payloads,
with no registry family additions or changes to existing usage report/ACK or Node-control
control bytes. Earlier package revisions do not establish this payload delivery.

Confirm the configured reporter's exact identity, fixed quantity identifier
selection and exact accepted membership/capability projection. Review malformed
replacement refusal without reserving a version, exact-scope complete-empty
withdrawal and retained replay tombstones. Payloads are descriptive catalogues,
never authority, permission or runtime negotiation; captured usage and received
control state survive replacement and withdrawal. The source-bound fixture sequence
is available for gateway adoption using the same independent bytes.

NSD/ns review, producer-owned canonical/refusal vectors and producer live adoption confirmation
remain outstanding. This delta was sent on 2026-10-25; no answer or live
interoperability is recorded by candidate fixture acceptance.

## Inner publication producer addition

2026-10-27 status: Canonical realm/source publication production and ns recorded-byte consumption are adopted; complete owner confirmation, refusal coverage and live source retirement remain open. See [adoption evidence](account-handoff.md#adoption-publication).

The additive producer API keeps existing inner wire bytes unchanged:
`PublicationContent::canonical()` returns validated signed content bytes,
`PublicationContent::signing_input()` returns
`PUBLICATION_SIGNATURE_DOMAIN || content_bytes`, and
`encode_publication(content, signature64)` returns `[bstr(content_bytes), signature64]`.
`PublicationEvent::signing_input()` and `signature()` expose the exact received
signature inputs for independent producers. The crate holds no signing key.

The producer requires a registered family/kind and its owning signed channel,
nonempty scope/kind bounded to 256 UTF-8 bytes, positive version, issue before
expiry, and Data or FetchFailed outcome. FetchFailed requires family 11 node-l3
and nonempty payload. The complete encoded event must fit MAX_PUBLICATION_BYTES,
including CBOR and signature overhead. Structural and ownership refusals use
PublicationError::Fields; measured overflow uses PublicationError::Bounds.
Known-pair partial content is producer-valid. Family payload bytes remain opaque;
family codecs validate their typed content. Decoder and decision behavior stay
unchanged, including unknown-kind forward compatibility and incomplete refusal.
Independent fixtures round-trip producer-valid content and assert producer refusal
for decodable invalid content; they are not NSD output.

NSD adopted shared `95f1688` containing implementation revision
`2391ebd5e59574cb318fbc2c7b1ca3615426796a`; the producer evidence above
supersedes the request to adopt that older revision. Complete requested refusal
coverage, owner review and live confirmation remain open beyond the named corpora.

## Ordinary provider Subnet report review addition

2026-10-27 status: NSD report handling and ns report/custody adapters are adopted in source; matched actual producer report bytes and real provider activation remain open; gateway self-reporting stays deferred. See [adoption evidence](account-handoff.md#adoption-provider).

Review the additive `node.subnet.report` operation in both directions on the
confidential BootstrapEnvelope under the
[provider report specification](../spec/account/subnet.md).
NSD enrollment supplies exact signed nodes authority; committed mapping custody
supplies provider, Network and real-prefix eligibility. NSD supplies stable M6
references; the provider carries intent and retains the pending report/response.
Pure independent vectors cover complete replacement/withdrawal, retained
allocations and stale generation/source refusal. M6 declarations, Subnet
publications and select/clear bytes remain unchanged.

NSD N30 ingestion/allocation/persistence, N07/N08 selection/projection and ns
S11/S25 production/custody live adoption confirmation and producer-owned interoperability evidence
remain outstanding. Gateway self-reporting is deferred to later ordinary-provider
integration. Prepared shared contracts do not demonstrate external adoption.

## Exit grant and client route view review addition

2026-10-27 status: NSD grant/client-route production and ns recorded-byte consumers are adopted; live installation/replacement/withdrawal and default/nested Exit qualification remain open. See [adoption evidence](account-handoff.md#adoption-subnet).

Review the two family 4 snapshot kinds and their distinct payloads in the
[grant specification](../spec/account/grants.md).
Confirm provider exit-grants and client subnet-routes use their recipient's nodes
source, while Egress retains its egress contribution source. Confirm no Exit wire
floor is produced; Egress floor remains unchanged. Confirm independent membership,
recipient, served realm and revision comparisons and exact collection isolation.

The independent subnet_publication_views sequence is prepared for consumer reuse.
NSD N07/N08 projection, producer-owned canonical/refusal vectors and ns route
installation/live adoption confirmation remain outstanding; fixture acceptance is not interoperability.

## M6 carrier and subscription review delta

2026-10-27 status: NSD M6 carrier and ns recorded-byte adapters are adopted; Q23 composition agreement and real per-Network session/proposal/lease confirmation remain open. See [adoption evidence](account-handoff.md#adoption-m6).

Review the [canonical M6 carrier](../spec/account/control.md), its pure
`account::service_control` APIs and independent `service-control-carrier.vec`
fixtures. Confirm all legal unary pairs, signed empty receipts for snapshot.ack,
port.result, port.query.result and service.retry-port, Error/bootstrap runtime
and epoch shapes, singleton lease.acquire and exact per-service results. The
stream admits only SnapshotPush, PortCancel and PortQuery; reverse answers echo
the full proposal and M6 correlation, using their own unary nonce and receipt.
Confirm current contribution/session custody and persistent proposal comparisons,
not just successful decoding. No receipt is readiness or termination proof.

PublicationSubscriptionRequest is now exactly eight elements, appending null or
`[nsd_id, network_id, runtime_generation, runtime_id, authority_epoch, session_seq,
session_request_id]`. This is breaking for existing consumers; seven-element
requests are refused. Existing scope/capability/boot/attempt meanings remain.
The reference lifecycle is `ns/docs/plan/20261017-m6-service-contract.md` at
`0e5adc17c9b05ae7fa351de00a5184a57b92e584`, sections 1–6 and 10; its historical
carrier is replaced by the candidate mapping. M6 message and declaration bytes
are unchanged. No runtime or persistence is added to shared contracts.

| Family surface | Delivered shared candidate | Review/live adoption confirmation status |
| --- | --- | --- |
| Bootstrap / v1 replacement | Unary context, empty receipts, failures and bound M6 events with independent vectors | NSD M6 carrier and ns recorded-byte adapters are adopted; Q23 composition agreement and real per-Network session/proposal/lease confirmation remain open. See [adoption evidence](account-handoff.md#adoption-m6). |
| Public edge / service integration | Unchanged M6 bytes, singleton leases and exact reverse port result comparison | NSD M6 carrier and ns recorded-byte adapters are adopted; Q23 composition agreement and real per-Network session/proposal/lease confirmation remain open. See [adoption evidence](account-handoff.md#adoption-m6). |
| Subscription | Breaking optional typed M6 binding in eight-element request | NSD M6 carrier and ns recorded-byte adapters are adopted; Q23 composition agreement and real per-Network session/proposal/lease confirmation remain open. See [adoption evidence](account-handoff.md#adoption-m6). |

The `contribution_network_sessions` shared vector test establishes candidate
bytes and refusals across two Networks. It does not claim gateway lifecycle
execution or real NSD agreement. Request explicit producer review of the full
reverse-event, receipt and singleton-lease mapping before live interoperability.

## Confidential certificate and client-CA acquisition addition

2026-10-27 status: NSD confidential acquisition/dispatch is adopted in source; independent material/auth producer corpora, JWT projection review and live installation remain open. See [adoption evidence](account-handoff.md#adoption-material).

Review the [canonical material contract](../spec/account/edge.md) and
`confidential_edge_material_generation` consumer vectors for `edge.material.get`.
The seven-field acquisition request uses the existing encodings, permits only
Certificate/ClientCa, and is echoed in full canonical bytes. Successful values
carry nonempty PEM, permitted hostnames, an exclusive Unix-seconds deadline and,
for ClientCa, a trust domain. No private value is present in public publications.
The auth-only operation and installation ACK bytes remain unchanged; certificate
and client-CA ACK ids are independently minted installation-status ids.

Please confirm the adopted confidential production/dispatch against authenticated
custody and supply the complete independent producer-byte/refusal coverage. Current dependency validation, host coverage, trust-domain
comparison, X.509 parsing and installation stay with the gateway. The independent
Python candidate vectors do not establish NSD agreement or live interoperability.
NSD implementation and dispatch are adopted as recorded above. Complete independent
material producer vectors, the owner answer and live installation confirmation
remain open; this review request records no received agreement.

## R3 local Node naming and legacy registration retirement

2026-10-27 status: Local-name enrollment and ns authenticated commit/restart handling are adopted in source; live cutover and owner confirmation remain open; the portability follow-up is pending. See [adoption evidence](account-handoff.md#adoption-naming).

R3 enrollment declares `node_local_names.v1` using the public
`account::NODE_LOCAL_NAMES_V1` constant in the existing Enrollment.capabilities
set. Omission does not negotiate a legacy response or fallback. This declares
naming mode only, not service permission or permission to publish DNS.
NSD accepts the declaration through authenticated registration without allocating
or requiring a legacy Node label. Capability encoding and all existing exact
exchange tuples remain unchanged.

| Retired registration value | R3 disposition and retained meaning |
|---|---|
| `domain_base` | No R3 producer, carrier or pinned-value comparison. Retire its per-machine `.node.` root and derived `.svc.`/`.gw.` suffix selection from the R3 reader. The canonical Node name is the existing `node_dns_name(NodeId)` form `<node id>.n.ns.io`, with NodeId derived from the accepted NodeBinding identity, never from a hostname or machine-id prefix. Do not manufacture a replacement domain_base or service/gateway suffix by string substitution. |
| `dns_root` | No R3 registration producer, carrier or pinned-value comparison. The Node zone is the shared `NODE_DNS_ZONE` constant `n.ns.io`, not a remotely selected root. Existing Subnet and public-edge naming retain their own contracts; the Node zone does not replace their suffixes. |
| `network_token` | No R3 registration producer, carrier or pinned-value comparison. NSD's committed Network naming state retains this token internally for existing Subnet suffix consumers; it is not an enrollment identifier or new shared field. Any existing Subnet name remains owned by its own authenticated projection, not inferred from the Node name. |
| `node_name` | No R3 registration producer, carrier or pinned-value comparison. Retire the NSD-allocated immutable compact Node label. Manual nicknames remain local and never published as registration authority; they do not alter the identity-derived canonical Node name. |

RegistrationAcceptance, AuthenticationResponse and InformationResponse carry
none of `domain_base`, `dns_root`, `network_token` or `node_name`. There is no
substitute naming publication or shared legacy-value decoder. An R3 consumer
refuses any response or adapter supplying these values; it must not silently
accept them or compare an old pin. The legacy `dns_config.short_dns_v2`
tuple-bound snapshot supplies no R3 naming authority. Existing exact tuple
validation remains the shared boundary; adapter refusal belongs to consumers.

The staged Node Enrollment produces the capability set; authenticated registration
acceptance must carry the exact same bytes, binding and declared profile.
Consumers compare membership, full binding, capabilities, trusted authority and
source binding before committing. Missing capability or mismatched acceptance
never switches naming mode. After acceptance, `node_dns_name` derives
`<node id>.n.ns.io` from the accepted NodeBinding identity and `NODE_DNS_ZONE`.
Verified NodeRecord identity/name/address comparison remains discovery, not
authorization. M6 `Resource.service_label` remains the sole source of service
labels through the authenticated recipient/Network snapshot. Public domains
remain in authenticated public-edge publication with its existing ownership
checks. `InformationResponse.realm` remains a display hint.

The consumer owns old-pin cutover: at the authenticated R3 commit it removes all
four naming pins and tuple-bound Short DNS authority from active R3 state,
without feeding absent values through the legacy first-wins setter. Pins are
never compared, converted into identity or recovered after restart. Failure
before commit preserves the prior selected profile. Original-profile records
remain isolated and preserved under existing custody rules; no deletion,
deployment or re-enrollment is authorized here. Startup uses accepted binding
and mode. Registration history and lifecycle comparisons remain unchanged.
Retired compact Node names are not promised as aliases. Subnet names, service
labels, public-edge names and authorization retain their existing contracts.

The external R3 runtime consumer owns cutover and its commit/restart regression:
matching acceptance must drop every active old pin and Short DNS authority; mismatched acceptance or supplied legacy values must leave the prior
profile intact. NSD N04/N09 producer live adoption confirmation and ns S05/S06/S11 consumer/cutover
live adoption confirmation remain outstanding, including independent producer confirmation.
The review delta is a candidate, never agreement or interoperability evidence.
No new field, carrier, P-item or dependency edge is introduced; previous delivery
evidence does not establish this delta or release external cutover acceptance.

## Node L3 route admission and applied status review delta

2026-10-27 status: NSD issuance/digest/status persistence and ns recorded status adapters are adopted; live enforcement-to-Applied association remains open. See [adoption evidence](account-handoff.md#adoption-status).

The [status specification](../spec/account/control.md) defines the confidential
`node.l3.status` request, exact signed-inner-event digest, current issuance/source
comparisons and exact echoed receipt. Only enforcement application produces
Applied; complete-empty Applied proves removal. Independent shared vectors cover
route selection without ordinary host permission and the applied-status sequence.
NodeL3, NodeL3Authority, grant, Subnet and service-control bytes are unchanged.

NSD N08 producer and Node S03/S24 consumer live adoption confirmation remains outstanding:
NSD retains and correlates exact issuance/source, and the Node associates actual
collection application with status.
These are review requests, never recorded agreement or live interoperability.

Publication delivery source adoption and matched bytes are recorded in the
[delivery evidence](account-handoff.md#adoption-delivery); real NSD N09 / ns S23
delivery, disconnect and expiry confirmation remains open.


## Explicit anonymous public-edge selector delta

2026-10-27 status: NSD public-edge projection, anonymous/raw-name vectors and actual producer corpus are adopted; a matching downstream corpus reader, live policy/name enforcement and Q17 confirmation remain open. See [adoption evidence](account-handoff.md#adoption-edge).

SubjectRule now uses SubjectSelector: AnyVerified retains sole null, Subject
retains canonical PolicySubject bytes, and Anonymous is the byte string
`43 82 01 03` containing canonical `[1, 3]`. Anonymous can coexist with ordered
explicit subjects; null remains exclusive. Older consumers reject the extension.
See the [profile matching table](../spec/account/profile.md)
and [family 7 consumption rules](../spec/account/edge.md).
The independent `anonymous-public-edge.vec` fixtures distinguish anonymous,
verified user, Node and group matching, malformed selectors, and no-Auth
HTTP/TCP/UDP routes. They are consumer fixtures, not external producer evidence.

NSD producer live adoption confirmation of accepted service public-ingress policy and ACL remains
outstanding, including the separately tracked N20 producer live adoption confirmation. No producer
agreement, external interoperability or live promotion is recorded. PolicySubject,
credential bindings, group members, admin claims and confidential authentication
configuration remain unchanged. Consumers must preserve payload-free anonymous
classification, verified-only null semantics and required Auth dependencies.

## Protocol-specific public-edge names

2026-10-27 status: NSD public-edge projection, anonymous/raw-name vectors and actual producer corpus are adopted; a matching downstream corpus reader, live policy/name enforcement and Q17 confirmation remain open. See [adoption evidence](account-handoff.md#adoption-edge).

Family 7 retains version 1 and thirteen route positions, with `name_or_null`
at the existing name position. HTTP requires its canonical hostname and retains
its bytes and host ownership. TCP/UDP require null and empty aliases/domains,
claim no names, and retain realm-qualified route identity and gateway-wide
protocol/port listener ownership. Duplicate raw listeners and TCP/HTTP port
conflicts refuse; TCP/UDP may share a numeric port. Backend endpoint uniqueness
and all policy/material/source checks remain unchanged. No empty or inferred
hostname is accepted. The independent `public_edge_protocol_names` sequence
covers these shapes and conflicts; existing named raw fixtures are regenerated
to null, while HTTP-only bytes stay unchanged.

NSD N20 producer live adoption confirmation remains outstanding. Confirm NSD HTTP public_host
and raw protocol/port projection, with producer-owned accepted/refused vectors.
Independent candidate fixtures are not producer agreement.

## Provider mapping inventory

2026-10-27 status: The separate provider-mappings publication and authenticated ns activation remain open; report/selection implementations do not establish this inventory or its independent producer vectors. See [adoption evidence](account-handoff.md#adoption-mapping).

The [provider mapping specification](../spec/account/edge.md)
adds family 4 Snapshot kind `provider-mappings`, clears `mappings`, canonical
`[1, mappings]` with `[nonzero_u32_id, B40_SubnetPrefix]` entries strictly ascending
by id, at most 256, and a 1 MiB payload bound. It is the complete eligible inventory,
independent of grants and client routes. Decode alone or nodes enrollment alone
establishes no eligibility: exact current nodes source, provider recipient/source_node,
accepted issuer and Network, pending Snapshot context, signatures, version and
validity must all pass. Newer replacement, typed empty and authenticated withdrawal
operate only on that exact collection. Existing report/grant/route bytes are unchanged.

The independent `provider_mapping_replacement` consumer sequence proves populated,
changed/omitted and empty sets and authority/payload refusals with fixture authorities.
NSD N07/N09 publication and current-source handoff, and ns S25/S11 activation live adoption confirmation
remain outstanding requests; no agreement, producer delivery or external live adoption confirmation is
inferred. Gateway self-reporting/inventory consumption remains deferred to C06.
