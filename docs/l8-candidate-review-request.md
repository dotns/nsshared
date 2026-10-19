# L8 candidate review request for NSD and node owners

Status: prepared for the owner to forward. Addressed to the NSD owner as
producer and the node (`ns`) owner as consumer reviewer. No delivery, answer
or approval is recorded. Completion means this request is ready; NSD
independently owns producer vectors and implementation. Unreceived answers
remain outstanding and do not block the candidate. Review remains required
before merging the candidate into `main` or releasing it.

## Candidate package

The published candidate revision is
`41149fe1febf2ecee07f077d68a500e18822442c`. Review these files at that revision:

- [Specification](l8-account-payload-profile.md): schema 1 canonical CBOR and
  local admission JSON schema 2; replacement, lifecycle and byte-unit rules.
- [Family registry](../crates/nsshared-proto/src/account/registry.rs): all eleven
  identifiers, publication scopes, cleared kinds and M6 reuse groups.
- [Candidate vectors](../crates/nsshared-proto/tests/fixtures/vectors/account.vec):
  independent Python-generated fixtures, including `family-registry`,
  `identity-replacement`, `record-rotation`, `l3-scoped-rules`,
  `l3-empty-withdrawal`, `usage-unset`, `usage-measured-zero`, `signed-roster`,
  `local-roster`, `local-empty-withdrawal` and malformed-input refusals.
- [Lifecycle](../crates/nsshared-proto/src/account/lifecycle.rs),
  [normalized L3](../crates/nsshared-proto/src/account/l3.rs) and
  [roster carriers](../crates/nsshared-proto/src/account/roster.rs): typed
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

## Family state

Every registration has wire version 1 and candidate owner
`account-payload-profile`. “Frame only” means its identifier, replacement rule
and M6 references exist, not that its detailed payload is ready. The named
contract work below follows the gateway inventory; other payloads remain
explicitly frame only. NSD supplies producer vectors for every row.

| ID / family | State at the candidate revision | Detailed contract work / review question |
| --- | --- | --- |
| 1 `enrollment` | Binding/lifecycle specified; enrollment publication frame only | Identity contract B38; Q11 |
| 2 `realms-peers` | Registry frame only | Served-realm and peer payload; Q12 |
| 3 `egress` | Registry frame only | Grants contract B39; Q13 |
| 4 `exit-subnet` | Registry frame only | Grants B39 and selection B40; Q14 |
| 5 `payer` | Explicit-payer invariant specified; binding publication frame only | Grants B39; Q15 |
| 6 `withdrawal` | Incarnation invariant specified; authority publication frame only | Grants B39; Q16 |
| 7 `public-edge` | Registry frame only | Declaration integration B46; Q17 |
| 8 `relay` | Signed roster and local schema 2 specified; directory and participant credential frame only | Q01–Q06, Q18 |
| 9 `usage` | Service unit specified; service and relay report envelopes frame only | Usage contract B42; Q10, Q19 |
| 10 `node-control` | Registry frame only | Shared Node-control vocabulary; Q20 |
| 11 `v1-replacement` | Registry frame only | Complete surface mapping/retirement; Q21 |

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

For relay admission, can NSD produce and the node consume atomic `[I, class]`
entries with full validated 32-byte `IdentityKey`, class 0 `ordinary_node` or
1 `gateway_node`, sorted uniquely by identity? Please identify producer vectors
for both classes, empty withdrawal, duplicate identity and unknown class.

### Q02: Local schema 2 entry format — NSD and node owners

Can the local relay snapshot writer emit required object fields `identity`
(canonical full key text) and `class` (`ordinary_node` or `gateway_node`) in
every `identities` entry, with required root `schema_version: 2`,
`issued_at_unix_ms` and `roster_version`? Please identify vectors rejecting
missing/duplicate/unknown fields, positional arrays and non-string classes.

### Q03: Signed roster attribution epoch — NSD and node owners

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

Can local `roster_version` identify the same admission/class epoch rather than
the issue timestamp? Specify how the controlled file's configured issuer and
participant scope corresponds to the signed scope, and how its version sequence
is retained across restart and carrier changes. The JSON contains no issuer,
recipient or signature; consumer rollback persistence remains necessary.

### Q05: Historical report lookup — NSD owner

For delayed relay usage, can NSD resolve identity/class using the original roster
scope and version, even after reclassification, withdrawal or identity replacement?
Name the report fields that identify that original issuer/participant scope,
epoch and source NodeId, and the history retention/repair contract. Unknown
history requires repair rather than attribution using the current roster.
Provide delayed-report, changed-class and unavailable-history vectors.

### Q06: Delivery of writer fields — NSD owner

Which separately owned NSD/`ns` implementation work will deliver both `class`
and `roster_version` in the atomic local schema 2 file? Please name its delivery
reference, field source and mapping to the signed roster, controlled regular-file
ownership, bounded reads, atomic replacement and restart/version persistence.
The writer must publish membership and classes together; missing or invalid
input must never install an empty roster. This request does not implement it.

### Q07: Identity lifecycle — node owner, with NSD confirmation

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

### Q08: Complete replacement semantics — NSD and node owners

For all eleven families, can the registry's publication/`clears` strings and
explicit issuer/recipient scopes be used as specified? Identify any missing
authority, revision, validity deadline or scope field needed in each detailed
payload. Confirm complete empty withdrawal, shared-peer contribution retention,
separate directory/roster scope and preservation of usage history/watermarks.
Provide scoped-empty, partial and malformed-publication producer cases.

The [signed publication event candidate](l8-account-payload-profile.md#signed-publication-events)
adds signed per-key complete/version/validity and typed ACL failure decisions.
Confirm the exact family/kind ownership table, separate stream versus snapshot
authority, complete empty withdrawal, absent retention and immediate denial for
authenticated `node-l3` fetch failure. Confirm durable versions including empty
and failure tombstones, actual exclusive expiry and whole-snapshot rejection
for one invalid event. Please supply independent NSD producer vectors for each
decision, including unrelated scopes and absent/empty/failure distinctions.

### Q09: Normalized Node L3 schema — NSD and node owners

Does `[1, issuer, recipient, revision, scopes, rules]` cover the shared input:
authority-assigned opaque namespaces, sorted full identity sets, sorted unique
TCP/UDP allow rules with inclusive nonzero ports, overlap as union and no
implicit wildcard? Confirm resolution of N6/N4/provider ranges before policy
compilation, 8,192 bounds and 1 MiB byte limit. Provide empty, cross-scope,
duplicate, range and limit vectors; compilation stays in consumers.

### Q10: Service byte unit — NSD owner

Will NSD explicitly accept Egress/Exit completed host-write/send layer-4 bytes,
partial completions only, zero for failures, and the unchanged public-ingress
boundary? Confirm explicit payer/direction/grant/reporter incarnation and the
exclusion of WireGuard overhead. Confirm `batch_loss_window: null` means unset,
distinct from measured `[0]`, with no invented duration. Identify producer
vectors for these units; relay DATA remains a separate unit.

### Q11: Enrollment payload — NSD owner

The [Enrollment section](l8-account-payload-profile.md#enrollment) adds the
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

The [bootstrap and envelope trust candidate](l8-account-payload-profile.md#bootstrap-and-envelope-trust)
now details family 11 discovery as `[1, 1, https_origin, [1], endpoints,
noise_key_or_null, quic_spki_pins, envelope_pins]`. Endpoints retain preference
order and permit HTTPS/Noise/QUIC only. Confirm canonical origins, WebPKI source,
raw Noise key, full-SPKI pins and RFC 7638 signer pins, including local intersection.
Please provide independent NSD discovery producer vectors for accepted order,
missing trust, empty intersections, noncanonical/duplicate pins and downgrades.

### Q12: Realm and peer payload — NSD owner

What schema completes `realms-peers` with served realms, I, NodeId, authorized K,
exact N4/N6 ownership, provider ranges and shared-peer contribution provenance?
Name NSD vectors for contribution withdrawal, retained shared peers and invalid
or missing complete sets.

### Q13: Egress grant payload — NSD owner

What schema completes `egress` using M6 provider/resource and declaration
references, address view, protocol/virtual port, authorized client, paying realm
and subject, fresh grant incarnation and realm limits? Name NSD vectors for
valid grants, scope mismatch and withdrawn authority.

### Q14: Exit grant and selection payload — NSD owner

What schema completes `exit-subnet` with stable route/resource identity,
family-neutral prefixes, actual IPv4 and mapped IPv6 range, exclusions,
bypasses, selection, client, payer, incarnation, local enablement and limits?
Name NSD vectors for nested default/specific routes, range ownership and empty
selection; preserve the existing M6 route/listener boundaries.

The prepared [Subnet selection candidate](l8-account-payload-profile.md#subnet-selection)
uses complete `[1, 4, nsd_id, network_id, recipient, revision, routes]`
publications and canonical M6 ServiceRef bytes. Each route names real/mapped
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

### Q15: Payer binding payload — NSD owner

What schema and resource scope complete `payer`, so each grant has an explicit
paying realm/subject and ambiguous cross-realm grants are withheld? Name NSD
vectors for explicit payer, ambiguity and payer change without packet-derived
realm inference.

### Q16: Withdrawal and regrant payload — NSD owner

What schema completes `withdrawal` with resource removal or empty authority,
current incarnation, real deadlines and payer/binding changes? Name NSD vectors
for immediate removal, expiry and identical-content regrant with a fresh token;
withdrawal must not wait behind relay snapshots.

### Q17: Public-edge payload — NSD owner

What schema completes `public-edge`, preserving NodeId/node6 backends, names,
aliases, ports, domains, visitor subjects, authentication dependencies,
certificate/client-CA references and material generations? Name NSD vectors
for each preserved boundary and M6 declaration composition without changing
the existing public-ingress usage boundary.

### Q18: Relay directory and participant payload — NSD owner

What schemas complete relay directory capabilities and independent participant
credentials/authorized scope, keeping the relay client, participant and gateway
Node distinct? Name NSD vectors for separate complete directory/roster scopes,
the union of served-realm admission identities and removal. The concrete
roster carriers are reviewed separately in Q01–Q06.

The participant roster candidate uses only its existing signed issuer/recipient
pair as its own credential scope. What additional authorized scopes, if any,
require a separate agreed contract? This question remains open for those scopes;
none is inferred from directory or gateway Node authority. Confirm Q03's retained
complete authority and diagnostic degradation rule and supply NSD producer
vectors for renewal, empty replacement, revocation, class changes and the exact
validity/degradation boundaries. Candidate Python vectors are preparation only.

### Q19: Service and relay report schemas — NSD owner

What exact schemas complete `usage` reporter identity/sequence, report windows,
acknowledgements, durable watermarks and errors for both independent reporters?
Service reports attach resource/payer/incarnations. Relay reports attach source
NodeId, captured scope/epoch/class and whole accepted encoded DATA including
its header, counted once at accepting ingress. Name NSD vectors for delayed
history, duplicate delivery, repair and gateway-associated billing once against
gateway service usage, without converting relay bytes to the service unit.

### Q20: Node-control vocabulary — node owner and NSD owner

Which canonical shared codec, constants and vectors complete `node-control`
ACK, ENDPOINTS, RECORD, PROBE_REQUEST and PROBE_REPLY on the ordinary N6 UDP
tuple? Confirm ACK means at least accepted and permits persistence before ACK.
Name independent producer vectors and the node consumer checks; state machines
remain in consumers.

### Q21: Complete v1 replacement map — NSD and node owners

Which detailed family or explicit retirement covers every inventoried discovery,
envelope verification, admin claim, policy, signed URL, material declaration,
report, snapshot and event item? Supply the mapping and NSD vectors for retained
semantics and refusals; inventory ownership alone does not prove wire equivalence.

The family 11 [bootstrap and envelope trust candidate](l8-account-payload-profile.md#bootstrap-and-envelope-trust)
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
Python vectors remain preparation; these questions retain `prepared` disposition.

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
retain `prepared` disposition; candidate fixture signatures are not NSD output.

### Q22: Independent family producer vectors — NSD owner

Where will NSD publish its independently generated vectors for each of
`enrollment`, `realms-peers`, `egress`, `exit-subnet`, `payer`, `withdrawal`,
`public-edge`, `relay`, `usage`, `node-control` and `v1-replacement`?
For each family, identify schema revision, canonical bytes, expected validation
result and positive/empty/malformed/scope/limit cases. Candidate Python fixtures
cannot stand in for NSD's producer output. Identify unresolved schemas explicitly.

### Q23: M6 composition boundary — NSD and node owners

Does each detailed family retain the exact types, message variants, codecs,
constants and vector domains in the reuse table? For any additional needed M6
change, identify the affected type, message or vector, family and concrete need
so the owner can forward it to the M6 contract owner. No additional M6 schema
change is established by this frame; standalone label validation is requested below.

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
do not block candidate preparation and do not imply approval. All rows start
prepared because no delivery or answer has been received.

| Reference | Addressee | Status | Sent date (reported by owner) | Answer location |
| --- | --- | --- | --- | --- |
| Q01 | NSD and node | prepared | — | — |
| Q02 | NSD and node | prepared | — | — |
| Q03 | NSD and node | prepared | — | — |
| Q04 | NSD and node | prepared | — | — |
| Q05 | NSD | prepared | — | — |
| Q06 | NSD | prepared | — | — |
| Q07 | Node, with NSD | prepared | — | — |
| Q08 | NSD and node | prepared | — | — |
| Q09 | NSD and node | prepared | — | — |
| Q10 | NSD | prepared | — | — |
| Q11 | NSD | prepared | — | — |
| Q12 | NSD | prepared | — | — |
| Q13 | NSD | prepared | — | — |
| Q14 | NSD | prepared | — | — |
| Q15 | NSD | prepared | — | — |
| Q16 | NSD | prepared | — | — |
| Q17 | NSD | prepared | — | — |
| Q18 | NSD | prepared | — | — |
| Q19 | NSD | prepared | — | — |
| Q20 | Node and NSD | prepared | — | — |
| Q21 | NSD and node | prepared | — | — |
| Q22 | NSD | prepared | — | — |
| Q23 | NSD and node | prepared | — | — |
| M01 | M6 contract owner, through owner | prepared | — | — |
| M02 | M6 contract owner, through owner | prepared | — | — |
