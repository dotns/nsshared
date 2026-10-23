# L8 account payload profile candidate

Membership realm identities follow the [canonical RealmId contract](canonical-realm-identity.md).
Affected text positions retain text but require the exact uppercase 26-character
spelling and decode to RealmId; binary positions retain their exact 16 bytes.
This incompatible candidate delta refuses arbitrary realm labels without fallback.
NSD/ns producer and consumer updates, including the other active consumer delivery,
remain outstanding. Encoding equality is not authentication. Discovery realm hints,
external provider subject namespaces and opaque scopes retain their meanings.
Signed usage bytes and the historical payer pair remain unchanged.


Status: candidate, schema 1; local admission JSON schema 2. This pure contract
is an additive module of `nsshared-proto` at the workspace minor-release version.
It defines no runtime, transport session, policy compiler or v1 adapter.
The [account payload record](task/20261019-0029-l8-account-payload-profile.md)
owns every candidate registry entry; detailed family payloads follow separately.
The published candidate revision is
`41149fe1febf2ecee07f077d68a500e18822442c`. The
[NSD and node review request](l8-candidate-review-request.md) packages that
revision, family states, producer questions and requested M6 changes for the
owner to forward. Preparation does not imply delivery or approval.

## Placement and M6 reuse

The module uses `nsshared_proto::encoding::{CborReader, CborWriter}`: definite
arrays, shortest unsigned integers, bytes, UTF-8 text, booleans and null only.
All arrays below have exact arity; trailing bytes and unknown discriminants fail.
All counters are u64; identity keys are validated 32-byte Ed25519 keys; opaque
incarnations and namespaces are 16-byte strings. No conversion to M6 CBOR occurs.

Subnet and grant payloads embed M6 references through the existing one-way
dependency from proto to service-control. Service declarations and references,
listener intents, leases, snapshots, service labels and messages always use
`nsshared-service-control` itself. No reverse dependency or alternate M6 codec
is introduced.

M6 reuse groups in the registry are:

- `identities`: `Id`, `Identity`, `Digest`, `ServiceRef`.
- `declarations`: `Declaration`, `BackendHost`, `Protocols`, `PortMode`,
  `Declaration::canonical/decode`, `ReportContent::canonical/decode`.
- `listeners`: `ListenerIntent::canonical/decode`, `domain_digest`.
- `snapshots`: `Resource`, `Route`, `Grant`, `PublisherListener`, `Withdrawal`,
  `Snapshot::canonical/decode`, `snapshot_digest`, `Resource::service_label` and
  its existing validation. The publisher-only backend boundary stays intact.
- `messages`: `Message`, `MessageBody`, `MessageKind`, `Message::encode/decode`,
  `CAPABILITY`, `SCHEMA`, `LOCAL_SCHEMA`, `MAX_LEASE_MS`, `REFRESH_MS`,
  `ContractError`, `next_revision`, including every existing body variant.
- `vectors`: `crates/nsshared-service-control/vectors/service-control-v1.json`
  and its `tests/vectors.rs`. Reference these bytes and domains directly;
  never copy, rename or re-encode them as account vectors.

All families reuse `identities`, `messages` and `vectors` when carrying service
work. Additional groups are listed below. The registry's `m6` list contains
these exact group names in this order: identities, declarations, listeners,
snapshots, messages, vectors (omitting groups not applicable).

## Family registry and replacement

Registry CBOR is `[1, entries]`; each entry is
`[id, version, name, publication, clears, owner, m6]`, ordered by id.
`version` is 1; `owner` is `account-payload-profile` for the candidate record
linked above. `clears` names the kinds exclusively replaced within that
publication's authenticated issuer/recipient and explicitly named scope.
Only a validated **complete** publication replaces its listed kinds. A complete
empty set withdraws all of those kinds in that scope. Missing, partial, malformed
or unauthenticated content is an error, never an empty set. A family publication
never implicitly clears another family or an unnamed scope. Reports and control
vocabularies describe replacement of catalogue/configuration sets, not erasure
of usage history, durable watermarks or received control messages.

| ID / family | Complete publication / exact `clears` string / scope | Additional M6 reuse |
| --- | --- | --- |
| 1 `enrollment` — enrollment and own Node binding | `own-node` / `binding,capabilities,endpoints` / one membership | declarations |
| 2 `realms-peers` — [complete served realms and peers](realm-publication-candidate.md) | `realm-peers` / `realms,peer-contributions` / exact signed issuer/recipient/served_realm/scope collection; omitted contributions removed | snapshots |
| 3 `egress` — [Egress grants](grant-authority-candidate.md) | `egress-grants` / `resources,grants,payers` / one realm and recipient | declarations, listeners, snapshots |
| 4 `exit-subnet` — [Exit grants and client routes](grant-authority-candidate.md) | `exit-grants` / `routes,grants,exclusions,bypasses,selection` / provider nodes collection; `subnet-routes` / `routes,exclusions,bypasses,selection` / client nodes collection | listeners, snapshots |
| 5 `payer` — [binary realm/UserId bindings](grant-authority-candidate.md) | `payer-bindings` / `payers` / one resource scope; ambiguity withholds the resource | snapshots |
| 6 `withdrawal` — [resource authority and retired tokens](grant-authority-candidate.md) | `resource-authority` / `authority,incarnations` / current authority in one recipient/resource scope | snapshots |
| 7 `public-edge` — [public edge, material and service operations](l8-public-edge-candidate.md) | `public-edge` / `backends,names,aliases,ports,domains,subjects,auth,materials` / exact signed issuer/recipient/served_realm/scope, per-realm contributions; full Node identity backends, explicit no-connector and generation-qualified dependencies | declarations, listeners, snapshots |
| 8 `relay` — relay directory and participant | `relay-directory-roster` / `directory\|identity-classes` / a named directory or participant roster, separately scoped; neither clears the other | snapshots |
| 9 `usage` — [typed usage catalogue](profile-publications-candidate.md) and unchanged reports/units | `usage-profile` / `units,reporters,parameters` / one reporter; never clears metering history | none |
| 10 `node-control` — [typed membership catalogue](profile-publications-candidate.md) and unchanged Node-control channel | `node-control-profile` / `vocabulary,capabilities` / one membership; ACK means at least accepted, persistence may precede ACK | none |
| 11 `v1-replacement` — replacement of the v1 surface, [policy observation](realm-publication-candidate.md) and [exact Node L3 applied status](node-l3-status-candidate.md) | `surface-map` / `mappings,retirements` / discovery/envelope verification, admin claims, policy, signed URL, material, reports and snapshot/events vocabulary in one account profile | declarations, listeners, snapshots |

The backslash before the table cell's pipe is Markdown escaping; the wire
string contains only the pipe. Every row has version 1 and candidate owner
`account-payload-profile`, linked to the account payload record above. The
typed registry fixes these publication identifiers and cleared-kind strings.
Detailed schemas will define authority, deadlines and payload-specific validation;
this registry is not an alternate declaration or generic M6 message envelope.

## Enrollment

Family 1 enrolls one ordinary Node membership's external NSD key binding and
its declared capability set. Enrollment CBOR is `[1, binding, capabilities]`;
`binding` is the existing `[membership_version, I, K, record_generation]`
NodeBinding defined below. NodeId, N6 and N4 are not carried: they derive from I
using the existing identity derivation. The authenticated caller supplies the
membership scope and its previously accepted binding; these bytes do not prove
authority or acceptance and never authorize a different membership.

Capabilities are opaque identifiers, sorted in strictly increasing ASCII byte
order with no duplicates. There are 0..64 identifiers, each 1..64 bytes, matching
`[a-z0-9._-]+`. No normalization or sorting occurs during validation. Empty means
no declared optional capabilities. Values and their meanings require NSD's Q11
answer; fixture identifiers are examples only. Noncanonical sets, excessive
counts or lengths, non-minimal CBOR and trailing bytes are refused. Endpoints
and authenticated envelope forms remain Q11 questions; this binding/capability
payload does not complete the registry's endpoint contract or change its bytes.

`decide_enrollment` validates the presented publication and any accepted binding.
With no accepted binding, it accepts initial enrollment without a lifecycle.
With an accepted binding, an equal binding is accepted, including a new valid
capability declaration. A lower membership version is refused. Any differing
binding needs a valid Lifecycle whose before is exactly the accepted binding
and whose after is exactly the presented binding. Identity replacement then
returns its own acceptance decision; stable-I K-only rotation returns a distinct
decision and additionally requires explicit producer-profile rebind authorization.
An absent lifecycle refuses a differing binding, including a **rejected
staged-version restart**: restarting after staging an unaccepted replacement
cannot promote that version. A mismatched or invalid lifecycle is refused.
The accepted binding changes only after authenticated registration acceptance;
this pure decision performs no persistence or old-resource fencing.

Ordinary membership derivation produces one K per membership identity version.
Its stable-I K-only rotation is an explicitly authorized rebind using a K supplied
by the producer profile, never another ordinary per-version derivation. Quick's
stable quick identity with a K per generation is a different profile, outside
these vectors. Candidate membership versions remain u64; the ordinary derivation
uses positive u32 and checked increment. Consumers must reject out-of-range
versions before ordinary derivation, without truncation. Q07 requests agreement
on this width, the missing same-I/K refresh tag and the separate signed K generation.

## Service grants and payer authority

The [grant authority candidate](grant-authority-candidate.md) completes families
3, 4, 5 and 6 with provider-recipient publications, canonical M6 resources,
exact client/provider and selection facts, Egress wire floor references, explicit binary realm/UserId
payer pairs, hard Unix-millisecond deadlines and grant incarnations. Complete
empty replacement withdraws only its named scope. Resource authority successor
validation retains retired tokens and preserves unrelated claims. Independent
producer fixtures and `grant_authority_vectors` exercise accepted and typed
refused contracts, selective withdrawal and fresh regrant. These are fixture
producer observations; NSD producer vectors and owner confirmation remain
outstanding. Family registry bytes are unchanged.

Grant and service usage payer subjects are exactly 16 unsigned big-endian ULID
bytes, paired with the paying realm. The usage revision replaces its predecessor
IdentityKey bytes without a conversion, fallback or tagged union. See the
[usage contract](usage-contract-candidate.md) for the incompatible candidate delta.

## Subnet selection

Family 4 kind `subnet-routes` carries the standalone complete route view encoded as
`[1, 4, nsd_id, network_id, recipient, revision, routes]`. IDs use M6 `Id`,
recipient/provider/client use M6 `Identity` with validated full Ed25519 keys,
and revision is positive. Authority and authenticated recipient scope are
supplied by the caller; validation itself grants no authority. A complete empty
routes array withdraws all routes within this scope. Missing, partial or malformed
publications fail. Grants, payer and incarnation are separate contracts.

A route is `[resource_bytes, real, mapped, provider, client, exclusions,
bypasses, selection]`. `resource_bytes` embeds exactly the canonical M6
`ServiceRef::value` bytes, encoded/decoded by service-control's own codec;
no M6 serializer or reference type is duplicated. Its NSD/network must match
the publication; client must equal recipient. Routes are strictly ordered by
full `ServiceRef`, with no duplicates. This embedding adds the one-way proto
to service-control dependency described above; no reverse dependency exists.

A prefix is `[family, address_bytes, length]`, family 4 with exactly four
network-order octets and length 0..32, or family 6 with sixteen octets and
length 0..128. Host bits must be zero. Lists use strict lexicographic order
by family, address bytes, then length; duplicates and overlaps within a list
fail. Exclusions and bypasses must be contained in real and mutually disjoint,
including across the two lists. Explicit selections must be contained in real.
For real IPv4, mapped must be IPv6 with length `96 + real.length` and its
low 32 bits must equal the real network exactly. The high 96 bits name the
mapping namespace. For real IPv6, mapped equals real; this carries no native
IPv6 Internet Exit promise.

Selection is `[0, []]` for a logical default (real must have length zero), or
`[1, prefixes]` for explicit named prefixes, including an empty selection.
A default with named prefixes is refused as mixed selection. Different routes
may carry nested default and specific real prefixes: results remain associated
with their stable resources, without runtime priority or winner selection.
The selected destination set is the default real prefix or explicit set minus
exclusions, emitted as a sorted minimal disjoint CIDR cover. Bypasses remain
separate in the returned route; they are not silently converted to exclusions.
Coverage is explicit TCP, UDP and echo for a nonempty selected real IPv4 set;
all three are false for real IPv6 or empty selection. Payload and output contain
no interface, local source address, host port, host binding or runtime state.

Bounds are 256 routes and 256 prefixes per input list, 32,768 selected prefixes
per route and 1 MiB per publication. Validation never sorts or repairs inputs.
Typed refusals distinguish mapping mismatch, outside exclusion/bypass/selection,
overlap, ordering/duplicates, misalignment/length, mixed/default selection,
unknown family/selection/schema, scope/identity, bounds and strict CBOR errors
(including trailing and nonminimal encodings). The independent Python Subnet
producer computes CIDR subtraction and coverage using `ipaddress`; Rust consumers
read decisions, canonical bytes, every route field and expected outputs directly
from the shared fixture. These are candidate fixtures, not NSD producer output.

## Lifecycle

`MembershipIdentityVersion` is a monotonically increasing derivation version
within one NSD membership. `RecordGeneration` increases only within one full
identity, shared by every served realm; existing NodeRecord same-generation
ordering/conflict rules still apply. Comparing either counter across its scope
has no meaning. `GrantIncarnation` and `ReporterIncarnation` are opaque tokens:
only equality is meaningful. Every regrant, even with identical content, uses a
fresh grant incarnation; every new reporter lifecycle uses a fresh reporter
incarnation. Never use record generation or membership version as either token.

Binding CBOR is `[membership_version, I, K, record_generation]`, with positive
versions/generations and a nonzero 32-byte K. Lifecycle CBOR is
`[1, transition, before, after, grant_incarnation, reporter_incarnation]`.
Transition 0 replaces identity: membership version increases, both I and K
change, and NodeId/N6/N4 are rederived from the new I. Record generation belongs
to the new identity and may restart. Transition 1 rotates only K: membership
version and I stay fixed, K changes, record generation increases, NodeId/N6/N4
stay fixed. Validation distinguishes these transitions; the choice of transition
for a deployment remains a consumer policy.

## Normalized Node L3 form

The complete authority wrapper is `[1, bindings, policy_bytes]`, where
`policy_bytes` is the exact existing Node L3 encoding below. A binding is
`[full_identity, wg_key]`, sorted uniquely by identity; K is a nonzero 32-byte
string and distinct identities cannot share K. Every scoped identity requires
a binding. Membership without an explicit matching rule denies. Removing a
namespace in a complete replacement leaves other namespaces' rules intact.
The consumer joins installed I/K only through these bindings, never roster
membership or a peer record alone. Existing standalone policy vectors retain
their bytes; they are policy fragments, not complete transport authority.

L3 CBOR is `[1, issuer, recipient, revision, scopes, rules]`. The revision is
positive and complete replacement applies only to this issuer/recipient.
A scope is `[namespace, identities]`; namespaces are opaque identifiers assigned
by the authority, never host interface names or inferred from a packet. Scopes
are sorted by namespace; identity sets are sorted by full identity bytes.
A rule is `[namespace, source_identity, destination_identity, protocol,
first_port, last_port]`. Both identities must belong to that namespace's scope.
Protocol 6 is TCP and 17 is UDP; ports are inclusive, 1..65535 with first <= last.
Rules are sorted lexicographically by all six fields and duplicates fail.
An empty rule set permits no L4 traffic; a missing set fails. Rules are an
explicit allow set; overlapping ranges mean union. There are no implicit
wildcards, payer guesses or interface-dependent identities. Compilation and
address/range ownership enforcement stay in consumers. Ordinary Node-L3 rules
govern direct identity-derived N6/N4 destinations only. A Subnet mapped-prefix
destination resolves to its exact resource and selected route, never to a
Node-L3 destination rule naming the provider. Neither side creates or requires
a Node-L3 rule for this path. See [route admission and applied status](node-l3-status-candidate.md).
The candidate bounds scopes/rules/identities per scope to 8,192 and bytes to 1 MiB.

## Service usage unit

Usage CBOR is `[1, boundary, direction, payer_realm, payer_subject,
grant_incarnation, reporter_incarnation, completed_bytes, batch_loss_window]`.
`payer_realm` is a 16-byte realm identifier; `payer_subject` is the paying
realm-local UserId encoded as exactly 16 unsigned big-endian ULID bytes, never
an IdentityKey. `completed_bytes` is u64. Boundary 0 counts Egress/Exit layer-4
payload bytes successfully completed by host writes and sends: partial writes count only their completed bytes; failed
writes contribute zero. Echo probe and synthetic reply sends count completed
message bytes separately, excluding IP headers; a failed reply does not erase a
completed probe. Boundary 1 preserves the existing public-ingress byte
boundary and does not reinterpret it as WireGuard or host-write usage.
Direction 0 is client-to-provider, 1 provider-to-client. Payer is always explicit;
an ambiguous payer withholds a resource. WireGuard handshakes, keepalives,
encapsulation and overhead are excluded. The
[detailed usage family](usage-contract-candidate.md) defines M6 resource references, full client/provider identities, operation metadata, independent
reporter/profile/sequence/window/part/digest and correlated answers. It adds no
transport or retry logic.

`EchoReplySend` retains its completed-send meaning: completed synthetic ICMP
reply message bytes excluding IP headers, for a runtime that can observe
per-packet send completion. The current gateway candidate emits no `EchoReplySend`
rows: at frozen nsplane 0.16.0, synthetic replies are delivered but unbilled
because the normal outbound path provides no per-packet successful-send receipt.
Queue admission is never completion. `EchoProbeSend` is unchanged; an unmetered
or failed reply does not erase a completed probe. Reply billing remains deferred
until a released packet-runtime capability is adopted and qualified. This is an
outstanding runtime capability, not a contract change or recorded agreement.

`batch_loss_window` is `null` (`Unset`) until measured, or `[duration_ms]`
(`Measured`) after measurement. Unset is not zero, unlimited, or permission to
bill guessed bytes. No duration is invented by this candidate. The measurement
is the maximum time span of completed bytes vulnerable to loss before durable
batch custody; measured zero is distinct from unset.
Relay usage is a separate unit: whole accepted encoded DATA including its header,
counted once at accepting ingress, both endpoint NodeIds/classes and the captured
roster scope/version, direction and reporter incarnation.
Delayed reports use historical attribution; unknown mapping requires repair.
It is not converted to this service host-write unit.

## Atomic roster attribution

Every entry is `(full IdentityKey, class)`, where class is `ordinary_node` (CBOR
0) or `gateway_node` (CBOR 1). No class-only publication exists. Complete empty
entries withdraw the recipient's entire admission roster. Versions are positive
u64, strictly increasing per issuer/participant, and are the attribution epoch.
Membership and classes are captured together for relay accounting.

Signed roster content CBOR is `[1, issuer, recipient, roster_version,
issued_at_unix_ms, valid_until_unix_ms, entries]`; an entry is `[I, class]`, sorted
by identity. The lifetime must be at least 86,400,000 ms. The signature is
Ed25519 over `ns.account.roster.v1` plus one zero byte plus the canonical content.
The signed carrier is `[content_bytes, signature_64_bytes]`. Both content and
carrier obey the 1 MiB bound and there are at most 8,192 identities.
Verification takes the trusted issuer, expected participant, last accepted
version and current time. It rejects wrong issuer/recipient, stale version,
future issue time, expiration, a short lifetime, duplicates and bad signatures.
Persistence of the accepted version is the consumer's rollback boundary.
NSD renews while reachable; consumers never extend a signed deadline locally.

### Participant roster lifecycle

For participant rosters in registry family 8 `relay`, scope is exactly the signed
content's `(issuer, recipient)` pair: the relay participant's own credential
scope. No additional scope field is carried. The shared
[participant authority contract](participant-authority-candidate.md) defines
enrollment, session proof, renewal and revocation for exactly this pair.
Directory eligibility uses its separate NSD-signed binding. NSD producer review
and adoption remain outstanding.

`verify_participant_roster(bytes, issuer, recipient, last_version, now_ms)` returns
an accepted generation containing scope, roster version as the attribution epoch,
the complete identity/class mapping, issue time and exclusive validity deadline.
Typed refusals distinguish wrong issuer, wrong recipient, stale/replayed version,
future issue, expiry, short lifetime, bad signature, missing class, duplicate class,
unknown class and duplicate identity. Other malformed/noncanonical content retains
its contract error. The existing `SignedRoster::verify` keeps its error behavior.

`participant_roster_status(generation, last_authenticated_renewal_ms, now_ms)` is
pure and reads no clock. The consumer supplies the instant of its last successful
authenticated renewal. At the signed deadline and thereafter it returns `expired`.
Before that deadline it returns `degraded` at and after 86,400,000 ms since that
renewal, otherwise `valid`. Degraded is diagnostic and still admits the complete
mapping; outage alone never withdraws it and renewal never extends its signed
deadline. The supplied renewal instant is authenticated consumer state, not a
timestamp inferred from a failed fetch. A new accepted complete version replaces
the entire mapping: empty denies all membership, omission revokes an identity,
and a class-only change advances the same epoch with a new complete generation.

The independent `participant_roster` producer emits canonical signed carriers,
explicit decisions, expected complete mappings and supplied-clock lifecycle cases.
Its sequences carry each previous signed publication and verify new versions
against the previously accepted scope/epoch. They include retained authority after
a refused publication and reclassification without any separate class message.

The local candidate is strict JSON schema 2:

```json
{"schema_version":2,"issued_at_unix_ms":1000,"roster_version":7,"identities":[{"identity":"<canonical IdentityKey text>","class":"ordinary_node"}]}
```

All four root fields and both entry fields are required. Unknown or duplicate
JSON fields, non-string or unknown classes, invalid/noncanonical key text, duplicate identity,
wrong schema, zero version, more than 8,192 entries and input over 1,048,576 bytes
fail. `validate_snapshot(bytes, now_ms, max_age_ms)` also rejects future timestamps
and ages greater than max_age_ms; equality at the freshness boundary is valid.
The returned version is the epoch, not the issue timestamp. Local snapshots
have no issuer, recipient or signature: controlled regular-file ownership,
atomic replacement, bounded reading and rollback persistence remain consumer
responsibilities. Validation does no I/O or clock access. A reader never installs
an invalid/missing file as an empty roster.

## Independent conformance

`tools/vectors/nsvec/producers/account.py` implements this specification using
only Python's standard library. `just vectors` and `just vectors-check` include
its candidate fixture. Rust tests decode each candidate byte string and compare
canonical re-encoding, validated semantics and expected rejection outcomes.
Enrollment cases additionally use `nsvec/derive.py` for expected NodeId text,
N6 and N4 bytes. The consumer reads each decision and canonical publication from
the fixture, checks every presented/accepted identity against those independent
values, and exercises named typed refusals. Existing candidate vectors retain
their names and bytes.
M6's own generator and tests remain unchanged and continue to own their bytes.

## Bootstrap and envelope trust

This details only discovery/envelope verification in family 11 `v1-replacement`.
It changes neither the registry nor its bytes and does not complete the other
surface mappings. Enrollment remains a distinct membership binding publication.
The caller obtains discovery through HTTPS WebPKI, supplies the authenticated
HTTPS origin, clock and replay observations, and performs transport execution.
No legacy key field, JSON fallback, discovery age denial or plaintext is defined.

Discovery CBOR is `[1, 1, https_origin, [1], endpoints, noise_key_or_null,
quic_spki_pins, envelope_pins]`: schema, trust version, authenticated discovery
origin, supported envelope versions, ordered endpoints and trust material.
An endpoint is `[kind, origin]`, with kinds 0 HTTPS, 1 Noise, 2 QUIC only.
Origins are exact ASCII `scheme://host[:port]/`, without userinfo, path beyond
`/`, query or fragment. Hosts are lowercase DNS labels (1..63 alphanumeric or
interior hyphen, total at most 253 bytes, no terminal dot), canonical dotted
IPv4, or bracketed canonical compressed hexadecimal IPv6. DNS hosts whose final
label is an IPv4 number are refused unless already canonical dotted IPv4. HTTPS omits default port 443;
Noise/QUIC require an explicit nonzero decimal u16 port without leading zeroes.
Unicode hosts must already be canonical ASCII IDNA labels. DNS hosts must pass
UTS #46 ToASCII with URL forbidden-domain-code-point checking, and its ASCII result
must equal the supplied hostname exactly. Malformed Punycode, forbidden decoded
characters and noncanonical A-labels fail; validation never rewrites a hostname.
The same predicate applies to the HTTPS source and every endpoint kind.
Discovery itself requires HTTPS.
Endpoints are nonempty and duplicate-free, retaining advertised preference order;
validation never sorts, normalizes or attempts a fallback. A caller selects the
first supported endpoint in this validated order (`first_supported`); all three kinds are confidential.
Noise needs the optional raw 32-byte static X25519 key; QUIC needs nonempty SPKI
pins. Pins are canonical unpadded base64url SHA-256 values (43 ASCII bytes),
duplicate-free in advertised order. QUIC pins hash full DER SubjectPublicKeyInfo;
envelope pins are RFC 7638 Ed25519 JWK thumbprints: SHA-256 of exact UTF-8
`{"crv":"Ed25519","kty":"OKP","x":"<base64url public key>"}`.
Envelope pins are nonempty. Local pins are validated identically; when configured,
the effective set is their intersection with discovered pins, in discovery order.
An empty intersection is refused. Legacy fields cannot supply missing trust.

The authenticated carrier is `[content_bytes, signature_64_bytes]`. Content CBOR
is `[1, direction, signer_I, recipient_I_or_null, kind, unix_seconds, nonce_16,
payload_bytes]`; direction 0 is request and 1 response. The signature is Ed25519
over `ns.account.call.request.v1\0 || content_bytes` or
`ns.account.call.response.v1\0 || content_bytes`, where `\0` is one zero byte.
These are new candidate domains, not historical wire strings. The signer is the
issuer, validated as an identity key and against caller-established effective pins
in both directions (request verification uses pins for its authorized request
issuers). Every signature is verified; absence of a pin never bypasses verification.
Verification requires the expected direction and exact nonempty kind; an optional
recipient must equal the caller's expected identity. A response without a recipient
is permitted for bootstrap, but is still pinned and signed. Payload is opaque:
M6 Message::encode bytes remain unchanged inside it; no M6 message or raw M6
envelope is duplicated. Limits count encoded bytes, including CBOR overhead.

| Boundary | Maximum | Meaning |
| --- | ---: | --- |
| Discovery | 262,144 bytes | Complete discovery document |
| Call body | 8,388,608 bytes | Complete unary response body / signed carrier |
| Headers | 16,384 bytes | Complete HTTP response headers |
| Encoded subscription | 16,384 bytes | Subscription envelope before hex/base64 decoding |
| Noise payload | 65,519 bytes | Plaintext excluding authentication tag |
| Noise frame | 65,535 bytes | Ciphertext including 16-byte authentication tag, excluding two-byte length prefix |
| Clock skew | 60 seconds | Absolute difference between signed timestamp and supplied time, inclusive |
| Replay retention | 120 seconds | Previously accepted issuer/direction/nonce retained for this inclusive window |

`validate_control_input` checks the exact supplied boundary bytes before decoding
or handing them to a transport. Discovery and carrier decoders also enforce their
own total limits and nested declared lengths before allocation. Kind length is
1..256 UTF-8 bytes. Endpoint and pin counts are limited by the discovery byte
bound, not an invented small rotation limit. Typed errors distinguish version,
origin, endpoint kind, duplicate endpoints, missing Noise/QUIC trust, invalid pins,
empty pins/intersection, signer, recipient, kind, direction, skew, replay, signature,
bounds and canonical encoding errors. Unknown fields, nonminimal CBOR and trailing
data fail. Constructed values obey the same checks as decoded values.

Replay state remains external: the caller supplies the previous acceptance time
for this exact `(signer_I, direction, nonce)` after authentication. A previous
observation at most 120 seconds old (or in the future) refuses replay. The caller
must retain observations through that window and atomically record success;
`None` asserts no retained observation. This contract neither stores nonces nor
claims state-free replay prevention. Timestamp skew remains 60 seconds even when
a nonce observation has aged beyond replay retention. There is no older-JSON path.
Independent Python discovery/carrier vectors give bytes, signatures, expected
pins/order/payload/authority and explicit decisions. NSD producer confirmation
and independent producer vectors remain requested in Q11 and Q21.

## Signed publication events

This is the snapshot/events vocabulary of family 11, version 1. The family
registry and payload ownership remain unchanged. Membership realm text follows
the incompatible canonical identity delta above. A publication is
`[content_bytes, signature_64]`, reusing the bootstrap carrier's outer shape.
Its content is `[1, issuer_I, recipient_I, served_realm, scope, family, kind,
channel, complete, publication_version, issued_seconds, expires_seconds,
outcome, payload_bytes]`. Ed25519 signs
`ns.account.publication.v1\0 || content_bytes`, with one final zero byte in
the domain. The call carrier's content/domain cannot be reused: its timestamp
and nonce do not express complete per-kind versions or actual validity.

| Field | Producer and meaning |
| --- | --- |
| schema | NSD fixes version 1; labelled Python fixture fixes the candidate version |
| issuer / recipient | NSD signs its full validated identity and exact target Node identity; fixture signs its labelled identities |
| served realm / scope | NSD supplies the authorized served realm and opaque scope within it; fixture supplies canonical realm A / `scope-a` and explicit alternate scopes |
| family / kind | NSD supplies the owning family number and exact kind below; fixture supplies the same candidate identifiers |
| channel | NSD supplies 0 stream or 1 independently polled snapshot, according to the table; fixture supplies signed ownership and mismatch cases |
| complete | NSD explicitly marks complete replacement; fixture supplies complete and refused partial cases |
| publication version | NSD persists a positive monotonic u64 for each full key; fixture supplies explicit versions, never derived from time or arrival order |
| issue / expiry | NSD supplies Unix seconds with `issued < expires`; fixture supplies both and an independent consumer clock |
| outcome / payload | NSD supplies 0 complete data or 1 authenticated ACL fetch failure and exact opaque owning-family bytes; fixture supplies labelled data/failure bytes |
| signature | NSD signs all content fields; the independent Python fixture signer signs candidate bytes only |

Realm is canonical 26-character RealmId text. Scope and kind are nonempty UTF-8 strings of at most 256 bytes each.
Recipient is mandatory. The consumer supplies the trusted expected issuer,
recipient, authorized `(served_realm, scope)` pairs, actual receiving channel,
clock and last accepted version for each key. No signed field substitutes for
those independent authority inputs. A full key is `(issuer, recipient,
served_realm, scope, family, kind)`; a version never orders different keys.

| Family | Kind | Owning channel |
| --- | --- | --- |
| 1 enrollment | `own-node` | stream |
| 2 realms-peers | `realm-peers` | snapshot |
| 3 egress | `egress-grants` | snapshot |
| 4 exit-subnet | `exit-grants`, `subnet-routes` | snapshot |
| 5 payer | `payer-bindings` | snapshot |
| 6 withdrawal | `resource-authority` | stream |
| 7 public-edge | `public-edge` | stream |
| 8 relay | `directory` | snapshot |
| 8 relay | `identity-classes` | stream |
| 9 usage | `usage-profile` | stream |
| 10 node-control | `node-control-profile` | stream |
| 11 v1-replacement | `node-l3` | snapshot |
| 11 v1-replacement | `policy-version` | stream |

These are candidate publication identifiers, not copies of v1 transport tags.
Each named kind replaces its complete owning-family publication within the exact
key only. In particular directory and participant roster remain separate.
`node-l3` carries the existing normalized Node L3 policy candidate. Outcome 1
is legal only for that ACL kind, with a nonempty opaque failure payload; it is
an authenticated typed failure that denies immediately and advances the accepted
version. It is distinct from an outer poll/fetch failure, which retains the last
complete state. No parallel M6 Snapshot, SnapshotPush or SnapshotAck is defined:
when carried, their existing canonical bytes remain opaque and unchanged, and
the owning-family validator checks their contents before installation.

A valid, complete event with a newer version returns `Replace`. An empty payload
with outcome 0 returns `Withdraw`; it also advances the accepted version. Missing
input returns `Absent`, changing nothing, including an already absent kind.
An unknown `(family, kind)` returns `UnknownKind` and changes nothing. In a
snapshot poll it may accompany valid known updates without discarding them;
it must still declare the snapshot channel and pass all pending-request and
authentication checks. Only a known stream-owned pair is refused for registry
ownership at that boundary. A known
kind whose signed channel or actual receiving channel differs from its owner
returns `ChannelMismatch` and changes nothing. Authentication, authorized scope
and validity are checked even for ignored kinds. A known owning-channel event
must be complete and strictly newer than the retained version; lower/equal
versions refuse. Validity is `issued <= supplied_now < expires`, with no skew
or local renewal. Wrong issuer/recipient, scope, signature, schema, malformed
content, future issue or expiry refuse. Arrival time is never a version.
Consumers atomically persist versions for replacement, withdrawal and typed
failure, including tombstones, and retain other keys. This pure module stores
nothing, reads no clock and makes no transport calls.

The **1,048,576-byte inclusive ceiling** is measured on the complete encoded
signed event **as received**, including both CBOR byte-string heads, content
and signature, before decoding or allocation. It is not a payload length or an
SSE/base64/hex length. Over-ceiling stream input returns `TerminateStream`, with
no replacement; the consumer must terminate and reconnect, never drop and
continue. Over-ceiling polled events reject the whole snapshot. SSE framing and
encoded carrier assembly remain consumer responsibilities using the shared
publication event/query names and derived 1,398,139-byte inclusive framing ceiling
defined in the [control exchange specification](control-exchange-candidate.md#publication-stream-framing).
The event decoder borrows all variable data, checks each canonical length and
available input slice before use, and allocates no variable data on either success
or rejection. Thus truncated length heads and declared lengths beyond input fail
without allocating for their claimed size.

A `config.snapshot` response is a signed B43 Response whose payload is canonical
`[1, [bstr(SourcePublication), ...]]`,
not the M6 Snapshot type. Its total encoded bound is the existing 8,388,608-byte
call-body ceiling. Each event has its own measured signed-event ceiling and
signature. Keys must be strictly increasing in the tuple order above (numeric
family order, then UTF-8 byte order for strings), refusing duplicates. Empty lists
are valid and imply no withdrawals. The consumer validates every event, scope,
signature, freshness and ordering before exposing any decisions. One invalid
known event rejects the whole snapshot, including any preceding replacement or
typed failure. Authenticated unknown Snapshot kinds yield UnknownKind; wrong-channel entries
reject the complete poll. The low-level plain PublicationSnapshot codec is not
a config.snapshot response validator.
The response validator returns a collection of decisions borrowing the signed
event bytes only after validating the complete ordered container. The authenticated call envelope supplies outer completeness
and poll authentication; absence never synthesizes a signed empty event.

The independent Python producer supplies canonical event/snapshot bytes, signed
fields, prior scoped versions, supplied clocks and explicit expected decisions.
Vectors include exact/over 1 MiB encoded events and malformed outer and nested
lengths. Existing fixtures retain their names and bytes. These are candidate
fixtures; NSD production and independent producer confirmation remain requested.


## Node-control codec

Family 10 (`FamilyId::NodeControl`) uses `nsshared_proto::node_control` for
ordinary Node-control bytes. The registry publication remains version 1;
control wire `VERSION` is independently 2 and `CONTROL_PORT` is 47900 at both
ends. This is a pure codec: transport, acceptance ordering, persistence,
retransmission, sessions and probe correlation remain in consumers.

The canonical CBOR message is `[2, kind, body]`, at most 1200 encoded bytes.
Every array has exact arity and all integers use shortest unsigned encoding.

| Kind | Body |
| --- | --- |
| 0 ACK | `[type_in_u8, hash_16]` |
| 1 ENDPOINTS | `[revision_u64, candidates, relays]` |
| 2 RECORD | `[NodeRecord]`, embedding the canonical signed array directly |
| 3 PROBE_REQUEST | `[nonce_32]` |
| 4 PROBE_REPLY | `[nonce_32]` |

ACK means **at least accepted**. A receiver that persists before ACK conforms;
this codec adds no durability or retransmission requirement. The hash is the
unkeyed BLAKE2s digest configured for 16-byte output over the entire encoded
acknowledged message, not a truncated 32-byte digest. Every u8 `type_in` is
representable, including unknown message kinds.

ENDPOINTS contains at most eight candidates and four relay identifiers.
A candidate is `[ip_bytes, port, kind]`: exactly 4 or 16 IP bytes, port 1–65535,
and kind 0 local, 1 reflected, or 2 configured. Relay strings use the existing
canonical RelayId parser and at most 255 UTF-8 bytes. Revision zero and duplicate
or unsorted input entries remain wire-representable. `Endpoints::select` sorts
by IP byte length, IP bytes, port and kind, deduplicates candidates and relays,
places a listed home relay first, then other relays in byte order. It greedily
adds candidates before relays subject to count and total byte limits. Its omitted
count covers rejected unique entries, not duplicates.

Decode rejects oversize input first, then malformed/noncanonical CBOR, wrong
version, unknown kind, malformed bodies and trailing bytes in reading order.
Candidate/relay array-head errors map to TooMany. Candidate IP strings over
16 bytes produce Cbor string-length errors; other invalid IP lengths, ports or
kinds produce Candidate. ACK type overflow preserves Type(0). Invalid relay
syntax produces Relay; embedded signed record validation produces Record after
its structural CBOR is read. Encoding preserves the supplied order and rejects
excess counts, zero candidate ports and messages over 1200 bytes.

The byte contract is the node codec at
`50f8e3fd95fac8bbc72aea9b132459103c3b206a`. Independent Python vectors in
`tools/vectors/nsvec/producers/node_control.py` reproduce the nine gateway
fixtures (gateway source `a00e6d61b5f0f635e740337131eb35514adbc46f`, original shared
revision `019bb7250549f1040a813c599a2ac1b09bd620f3`), both known-byte examples
and the empty-input ACK hash. `tests/node_control.rs` ports all ten predecessor
test functions; `tests/vectors_node_control.rs` checks independent bytes and
rejections. No dependency or protocol version changes accompany this contract.

## Policy and claim values

These pure schema-1 values own no publication kind. All arrays use strict shortest
CBOR, definite lengths and no trailing bytes, with the existing 1 MiB account
limit. Text is nonempty UTF-8 of at most 256 bytes without whitespace/control
characters unless a field explicitly carries unrestricted string data. Collections have at most
256 entries. Consumers authenticate the enclosing carrier before interpreting
any value; decoding never authenticates a caller or evaluates a rule.

### Subjects and bindings

`PolicySubject` is `[1, tag, ...]`: tag 0 is `[1, 0, realm_16, local_name]`,
tag 1 is `[1, 1, realm_16, user_id_16]` using the existing `Payer` pair, and tag 2
is `[1, 2, full_Node_I_32]`. Local names have an explicit nonempty namespace and
suffix: `user:`, `group:`, `machine:` or `external:`. They are opaque, case-sensitive
labels, never inferred from addresses, credentials or display names. Symbolic
`user:alice` is not a binary UserId and is never converted into a payer. A group
is a policy selector, never a credential principal. The Node form uses the
existing full signing identity validation; it does not introduce I/K authority.

`SubjectBinding` is `[1, realm_16, anchor_tag, anchor, subject_bytes, enabled,
expires_seconds_or_null]`. Anchor 0 is a full Node identity; anchor 1 is a
realm-local credential reference. A realm-local subject must have exactly the
binding's realm; group subjects refuse. Node anchors/subjects use full I, not WG
keys. Activation, expiry and credential verification stay with consumers.

### Policy values

`SubjectPolicy` is `[1, realm_16, rules, groups]`. Rules retain order and encode
`[subjects, destinations, protocol_or_null]`; every subject is canonical subject
bytes, with null standing for any *verified* subject. Subject and destination
sets are nonempty, strictly ordered by their encoded bytes and UTF-8 bytes,
respectively; null cannot coexist with another subject. Destinations are
nonempty opaque gateway matcher strings (`host:ports`, CIDRs or aliases); syntax,
host resolution, protocol matching, default deny, group expansion and self-tests
remain in the gateway evaluator. Protocol 6 is TCP, 17 is UDP, null is both.
Groups encode `[group_subject_bytes, member_subject_bytes_array]` in strict group
byte order. Each group is a realm-local `group:` subject in the policy realm;
members are unique ordered non-group subjects qualified by that same realm or
full Node identity. References to groups require an explicit group entry.
Rules may name groups; membership does not grant permission without a rule.
Empty rules/groups are a valid deny-all *value*, not a publication withdrawal.

### Admin claims

`AdminScope` has exact JSON names `read_only`, `read_write`, `super_admin`, and
CBOR integers 0, 1, 2 in that order. Unknown names/integers refuse; no aliases or
default exist. `AdminTokenClaims` is `[1, subject_bytes, scope, realm_or_null,
expires_seconds]`. The subject must be a non-group principal. A present realm
must equal a realm-local subject's realm. A null realm does not grant cross-realm
authority; the endpoint must enforce its own realm policy. The supplied-input
`require_scope` predicate accepts only scopes at or above the required level.
The supplied-input context comparison checks exact subject, exact optional realm,
minimum scope and `now < expires`; it does not verify JWT signatures, issuer,
audience, key id or revocation. Those checks remain mandatory in token consumers
using their authenticated authority. Admin claims belong in authenticated admin
tokens; they are not account publications. Human JWTs without scope cannot be
silently promoted to admin claims. Machine-token claims and key sets remain
outside these values.

### Public-edge auth policy values

`JwtSubjectBinding` is `[1, binding_bytes, authority_ref, claim_name, claim_value,
scopes]`. It joins a previously verified exact authority/claim to a credential
binding; the anchor must be a credential reference. `claim_name` and `claim_value`
are exact UTF-8 string data, each zero to 256 bytes inclusive. Empty strings are
present data, distinct from a missing field. Preserve all original bytes,
including leading/trailing/internal whitespace, controls, case, and Unicode
normalization form. Never trim, percent-encode, case-fold or normalize these
fields: consumers look up the exact claim name and compare the exact string
value. Missing fields, null/non-text fields, invalid UTF-8, values over the byte
bound, non-shortest CBOR and trailing bytes refuse. References, subjects, HTTP
header names, destination matcher tokens, URL realm/route labels and scope tokens
retain their existing syntax restrictions. Scopes are opaque ordered unique
whitespace-free text and never become AdminScope. Family 7 supplies issuer/audience/public
key source metadata and material separately; this value neither fetches nor
verifies keys. `SignedSubjectHeaderPolicy` is `[1, enabled, header_name_or_null,
signature_header_name_or_null, keyset_ref_or_null, validity_seconds_or_null,
strip_inbound]`. Header names are lowercase HTTP tokens, distinct when present.
An enabled policy requires all four optional fields, positive validity and
inbound stripping. Disabled partial settings grant no header authority. Key
material and signed-header production remain in family 7 and gateway consumers.

### Signed request canonical inputs

Account requests reuse `BootstrapEnvelope` exactly, including the request domain
`ns.account.call.request.v1\0`, schema, signer, recipient, operation, timestamp,
nonce, payload and signature bytes. `signing_input` exposes the existing domain
followed by canonical content, for both request and response. `SignedAccountRequest`
accepts only request-direction envelopes and exposes their canonical carrier;
it defines no second signature format. Wrong direction and response-domain
signatures refuse in the existing envelope verifier. M6 message payloads remain
opaque and unchanged.

Signed URL request text retains the gateway's HMAC input algorithm without
implementing HMAC or credential verification. `SignedUrlScope` binds method
(GET/HEAD), http/https scheme, host, raw path, raw query, realm, route and absolute
expiry. Host, path and query are each bounded to 16,384 UTF-8 bytes and contain no controls; realm/route use the 256-byte label limit and cannot contain `/`. Path starts with `/` and excludes a separate query or fragment. Query pairs split at `&` and first `=`; percent decoding preserves `+`
and duplicate names. Percent-encode every byte except RFC3986 unreserved bytes,
using uppercase hex, remove decoded `X-Nsgw-Signature`, sort encoded name/value
pairs and join with `&`. Lowercase the trimmed host and remove only the scheme's
default port; preserve a nondefault port and raw path bytes without normalization.
Canonical request text is `METHOD\nPATH\nQUERY\nhost:HOST\n\nhost\nUNSIGNED-PAYLOAD`.
String-to-sign is `NSGW-HMAC-SHA256\nEXPIRY\nREALM/ROUTE/nsgw_signed_url\nHASH`,
where HASH is lowercase SHA-256 of that request. Control parameter parsing,
duplicate/missing control refusal, actual expiry, rotation, HMAC comparison and
transport admission stay in the gateway consumer. No secret or key enters this
API. Malformed percent escapes, non-GET/HEAD methods and multiline components
refuse rather than silently changing the signed request.

### Inventory disposition and carrier boundary

| Inventoried values | Canonical value or disposition | Carrier |
| --- | --- | --- |
| AclPolicy.rules, AclRule.action/subject/dst/proto | SubjectPolicy rules; accept is implicit, deny actions retired | Public-edge fragments embed in EdgeRoute.policy; other aggregate carriers open |
| AclPolicy.groups | Explicit qualified groups and members | EdgeRoute.policy for public-edge groups; other aggregates open |
| AclBindings.wg_peer | NodeL3Authority bindings retain I/K authority; address/key-derived subjects retired | Existing family 11 node-l3 |
| AclBindings.machine | SubjectBinding with explicit Node or credential anchor | Family 7 EdgeAuth.bindings for public-edge credentials; other aggregates open |
| AclPolicy.hosts, tests | Gateway destination alias resolution and self-test inputs remain evaluator-owned; no contract equivalence claimed | Open carrier item |
| AclPolicy.gateway_roster, service_floor | Not subject authority; roster classification and service-floor metadata stay in their existing contracts/local configuration | No policy carrier added |
| AdminClaims, AdminScope, require_admin_scope | AdminTokenClaims, AdminScope, require_scope | Authenticated admin token |
| MachineClaims, TokenAudience, verify_machine_claims | Machine token/key-set contract remains separately owned; no duplicate claims | Existing token owner |
| GatewayAuthConsumer.subject and credential-to-consumer joins | PolicySubject, SubjectBinding; enabled/expiry retained | Embedded family 7 EdgeAuth |
| GatewayAuthJwtConsumerBinding | JwtSubjectBinding plus existing subject binding; credential id is the anchor, consumer resolution belongs to the enclosing family | Embedded family 7 EdgeAuth |
| GatewayAuthJwtAuthority and legacy issuer metadata | Authority reference retained by JwtSubjectBinding; issuer/audience/key source remain family 7 values; no trust inferred | Family 7 EdgeJwtAuthority; NSD producer confirmation pending |
| SignedSubjectHeaderPolicy | Explicit typed header configuration | Embedded family 7 EdgeRoute.headers |
| SignedUrlScope and canonical request/query/string-to-sign | SignedUrlScope deterministic public signing input | Existing SignedUrlScope request input plus realm-qualified auth material reference |
| EnvelopeDirection, signed account requests | SignedAccountRequest reuses BootstrapEnvelope and its domains | Existing authenticated call carrier |
| OIDC claims, organization/role subject projection, provider/cookie configuration | OIDC token verification and label construction remain consumer-owned, referencing qualified PolicySubject | Confidential AuthConfiguration values; OIDC runtime and label construction remain external; NSD confirmation outstanding |
| Policy compilation, VerifiedSubjectSet, verifier readiness and admission results | Consumer state/evaluation, not new wire claims | No carrier added |

No evaluator moves into shared contracts. Existing NodeL3Authority is neither
wrapped nor duplicated. Family 7 owns complete replacement of embedded visitor,
auth and public-edge values. Service targets continue to use existing M6
ServiceRef and grant/Payer contracts rather than a policy-specific service claim.
Diagnostic `policy-version` remains an observation owned separately; it never
carries this policy or establishes an authorization revision. Unplaced inventory
items stay open until an enclosing family or a later design assigns a carrier;
no new kind or implicit policy publication is defined here.

## Complete realm publication content

[Realm publication candidate](realm-publication-candidate.md) defines family 2
`realm-peers` complete contributions with existing NodeBinding and signed NodeRecord
validation, and family 11 `policy-version` as an observation-only u64 counter.
The registry metadata remains unchanged; these are content schemas for the existing
snapshot and stream publication kinds. Producer confirmation remains outstanding.

## Complete candidate control exchange

[Control exchange](control-exchange-candidate.md) completes the existing enrollment,
bootstrap and machine-claim families with exact operation/path constants,
authenticated registration acceptance comparison, authentication/information
forms, RS256 public claims and pin-qualified JWK sets. Independent fixtures are
`control-exchange.vec`; the consumer is `control_exchange_vectors`.
Enrollment binding, lifecycle, capabilities, bootstrap carriers and signing input
are reused. No publication kind or family registry bytes change.

Gateway bearer verification deliberately ignores audience, preserving absent,
unrelated and array outcomes. Wrong-audience refusal belongs solely to the
labelled NSD machine-audience predicate. Possible later gateway enforcement is
an open owner-review item. Wrong key use, exact subject/self-binding, 30-second
gateway expiry leeway, 300-second refresh window, qualified key selection and
realm/address pin ownership are explicit. NSD producer confirmation remains
outstanding; candidate fixtures do not establish agreement or interoperability.
## Public-edge, material and declaration candidate

The [family 7 specification](l8-public-edge-candidate.md) defines PublicEdge,
EdgeAuth, EdgeMaterialAck and EdgeServiceRequest/Response. The separate
[confidential authentication contract](confidential-auth-candidate.md) supplies
AuthConfiguration and correlated AuthConfigRequest/Response as pure values.
Public hostname/alias/domain validation is independent of M6 service
labels. Service entries carry M6 ServiceRef; authenticated snapshot Resources
supply the validated DNS label. No standalone service-label codec or copied
validator is added. Standalone label inventory rows remain open pending M01/M02
with the M6 contract owner through owner-mediated review.

SubjectPolicy, SubjectBinding, JwtSubjectBinding and SignedSubjectHeaderPolicy
are embedded unchanged; SignedUrlScope remains the shared request signing input.
JWT issuer/audience/key-reference carriers are EdgeJwtAuthority. Confidential
AuthConfiguration retains explicit provider/import, cookie, organization, template,
redirect, verifier and key-source values. It travels only in authenticated control
envelopes under edge.auth.config.get. PublicEdge retains references only.
Certificate/client-CA bytes stay on their existing confidential material transport.
No defaults or predecessor wire equivalence are claimed; installation ACKs remain
correlated to the exact reference/generation. Routes require dependency
installation before exposure.

The independent Python public_edge producer and Rust public_edge_vectors tests
exercise complete replacement, valid empty withdrawal, malformed/noncanonical
refusal without renewal, names/aliases/ports/domains, full backend identity joins,
material generation mismatch and unchanged M6 object bytes/digests. These are
fixture-produced candidate observations; NSD confirmation and producer-owned
vectors remain outstanding under Q17.

## Complete candidate control reports

[Report exchanges](control-report-candidate.md) completes heartbeat, gateway
observations, service/Exit floors, usage answers and exact material installation
status operations on the existing confidential signed carrier. The constants stay
in control_exchange; signing uses the existing envelope signing-input API.
Kind 1 EdgeServiceRequest/Response is an explicit incompatible candidate delta:
unchanged M6 service objects gain complete local metadata/Exit declarations and
exact per-reference accepted/rejected outcomes. No other public-edge bytes change.
UnknownMapping remains relay-only and fails service-answer correlation. Auth
material status preserves the exact pending confidential configuration request id;
that separate private payload and authenticated acquisition exchange stay outside
the report contract. Installed means actual installation of the exact reference,
realm and generation, never mere receipt. Independent producer bytes are in
control-reports.vec and public-edge.vec; NSD confirmation remains outstanding.

The independent confidential-auth.vec fixture and confidential_auth_generation
consumer validate pending/current dependency correlation and private configuration
refusals. The candidate fixture is not NSD producer confirmation. Family 7 registry
metadata and public publication bytes are unchanged.

## Publication subscription request

The [control exchange subscription specification](control-exchange-candidate.md#authenticated-publication-subscription) defines PublicationSubscriptionRequest, config.stream and its endpoint. It carries exact issuer/recipient/realm/scope entries, understanding-only capabilities, family 7 public ingress indices and required boot nonce/checked attempt counter. Existing publication key versions and channel ownership remain authoritative. Independent consumer vectors precede the pure codec; matching NSD production and confirmation remain outstanding.

## Publication snapshot poll request

The [snapshot poll specification](control-exchange-candidate.md#independent-publication-snapshot-poll)
defines PublicationSnapshotRequest and config.snapshot on the existing confidential
control endpoint. Exact sorted issuer/recipient/realm/scope entries request only
snapshot-owned kinds. The predecessor has no kind selector; stream selectors are
unknown fields and refused. Required boot nonce/checked attempt retain the active
subscription association, while a separate nonzero poll correlation is echoed in
the signed response nonce. The only response payload is the source-bound container defined above;
entries use request-derived Snapshot delivery and have no SSE/Base64 framing limit;
pending-scope checks add no version domain or acceptance runtime. Independent
publication-snapshot-request.vec fixture bytes are candidate evidence. NSD
confirmation and real producer vectors remain outstanding.

## Source binding and Node route commands

The [source/selection candidate](source-selection-candidate.md) adds mandatory
signed SourceBinding authority and subscriber DeliveryContext to a new outer
source-publication signature domain. Existing full publication keys, versions,
channels, complete replacement, failure/empty events and deadlines retain their
meaning. An old unbound event is refused by the new form without fallback; a
higher version never revives a retired source or session. M6 bytes are unchanged.
The same source/profile fences apply to Node/ServiceRef select-clear operations
on the confidential signed control carrier. Clear targets exact selection and
generation; original immutable receipts survive replacement and restart with no
current mutation authority. NSD assigns `explicit-gateway-profile` in enrollment.
Retired gateway-ID and carrier-credential fields are refused. Independent vectors
are labelled fixture authority; NSD producer review and ns/NSD adoption remain open.

[Q18](l8-candidate-review-request.md) records the settled participant/directory
choice: a shared participant credential and a separate signed directory binding,
with the global directory unchanged. The shared
[definitions and independent vectors](participant-authority-candidate.md) are
delivered; gateway runtime adoption remains pending. This source/selection
candidate only cross-references those contracts. NSD producer review and NSD/ns
adoption remain outstanding.

## Shared participant credential and directory eligibility

The shared definition is delivered at immutable revision
`28bf972db2e1f434114adc324a26fabad545aed1`.

Family 8 now includes shared enrollment/authentication/renewal frames and the
separate signed directory binding defined in
[participant authority](participant-authority-candidate.md). The existing family
registry bytes and directory/roster replacement scopes remain unchanged. Binding
replacement orders independently per issuer/numeric relay id and never clears a
directory or roster. Empty binding realms withdraw eligibility, while a newer
complete-empty roster withdraws admission. Enrollment credentials never serve as
session bearer tokens. NSD producer review and adoption remain outstanding.

## Protocol-qualified grant and renewal delta

The [grant authority specification](grant-authority-candidate.md) changes family 5
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
and consumer coverage. NSD N06 protocol/token/deadline producer adoption and
producer-owned vectors remain outstanding; this incompatible candidate delta
is not contained in the earlier published package revision.

## Signed source authority response delta

Successful registration now requires `[1, scope, bstr(Enrollment), profile,
decision, bstr(SignedSourceBinding)]`, including Equal. Successful authentication
requires `[1, token, bstr(SignedSourceBinding)]`. This incompatible candidate
extension retires standalone SourceAcceptance and refuses old response arities.
Existing operations, confidential carrier, field encodings and refusals remain.
The [control exchange](control-exchange-candidate.md) and
[source authority](source-selection-candidate.md) specify envelope trust, exact
pending nonce correlation, nested signature and independent enrollment comparisons.
Independent fixture vectors precede the pure codecs; fixtures are not NSD output.
NSD N04 adoption, producer-owned vectors and real interoperability remain outstanding.
Prior delivered revisions retain their original attribution; consumers must name
the immutable revision containing this response extension when adopting it.

## Explicit authentication source selection

AuthenticationRequest is exactly `[1, membership_scope, NodeBinding, "control",
[served_realm, publication_scope]]`. The selector is required, with no default or
old-shape fallback. Realm text is canonical 26-character RealmId; scope uses the
existing nonempty, control-free UTF-8 encoding bounded to 256 bytes. This is an
incompatible candidate request delta. AuthenticationResponse and SignedSourceBinding
encodings and signing domains are unchanged. NSD N04 adoption remains outstanding.

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

## Usage and Node-control profile payload delivery

Families 9 and 10 now have explicit candidate payloads: `[1, reporter, profiles]`
and `[1, membership_scope, 2, capabilities]`. The [exact profile specification](profile-publications-candidate.md)
records public signatures, canonical independent bytes, refusal cases and the
source-bound replacement sequence. These scoped catalogues describe existing
usage quantities and Node-control kinds without changing reporting/control bytes, permissions
or runtime semantics. Complete-empty withdrawal remains an explicit publication outcome.
Consumers compare independent reporter/membership authority before installation.
NSD/ns review, producer-owned vectors and producer adoption remain outstanding;
this new delivery does not retroactively establish earlier payload support.

## Inner publication producer addition

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

NSD N06, N08 and N21 producers should adopt implementation revision
`2391ebd5e59574cb318fbc2c7b1ca3615426796a`;
earlier package revisions do not include it. Producer-owned vectors and adoption
remain outstanding.

## Ordinary provider Subnet route reports

The additive `node.subnet.report` request/response operation uses the existing
confidential BootstrapEnvelope and signed nodes authority. The
[provider report contract](provider-subnet-report-candidate.md) specifies exact
canonical bytes, complete generations and withdrawal, mapping qualification and
retained stable M6 allocation comparisons. M6, Subnet publication and select/clear bytes are unchanged.
Independent fixtures establish pure decisions only. NSD N30/N07/N08 and ns
S11/S25 adoption and producer-owned vectors remain outstanding; gateway
self-reporting belongs to later ordinary-provider integration.

## Exit grants and consumer Subnet route views

Family 4 has two snapshot kinds. `exit-grants` carries the existing
GrantPublication `[1, 4, issuer, recipient, revision, grants]`, with recipient equal
to the provider. Exit details `[1, subnet_publication_bytes]` contain exactly one
matching route; the embedded recipient equals the client, not the outer provider.
`subnet-routes` carries standalone B40 `[1, 4, nsd_id, network_id, recipient,
revision, routes]`, with recipient equal to the client and possibly several
providers. Kind selects the decoder; these payloads cannot substitute for each other.
Its exact clears rule is `routes,exclusions,bypasses,selection`.

Both Exit views use the recipient's current nodes binding in the event's Network,
with event scope `nodes`; recipient and source_node equal that Node. Egress grants
retain the provider's `egress` contribution binding. Nodes enrollment alone grants
no Exit resource. Exact retained binding and pending delivery context comparisons
remain mandatory. Client view validation compares independently accepted identity,
MembershipScope NSD/Network IDs, event served realm (the same Network bytes), and
payload revision against event version. M6 NSD ID is not the signing key.

Each complete view replaces only its exact issuer/recipient/Network/scope/family/kind
collection. Empty withdraws that collection and omission removes a route; neither
clears another provider or another kind, including when a Node is both client and
provider. Route views carry selection information, never provider grant, payer or
incarnation authority and never independently authorize traffic service.

There is no Exit floor on the wire. Provider-local enablement and Linux
source/interface/route bindings are independently validated before admission.
Egress retains its existing wire floor reference. B40 ordering, bounds, prefixes,
explicit/default selection, and grant/payer/incarnation/renewal bytes are unchanged.

The independent `subnet_publication_views` sequence accepts providers P/Q and
client C under their nodes bindings without an Exit floor; rejects kind, recipient,
source and membership mismatches; empties P without changing Q/C; omits P from C's
newer view; then empties C without clearing Q. Fixture acceptance proves pure
contracts only. NSD N07/N08 projection, producer-owned vectors, and ns route
installation/adoption remain outstanding. Select/clear receipts stay immutable
command outcomes, separate from replaceable route views.

## M6 service control carrier

The [canonical carrier specification](service-control-carrier-candidate.md)
adds the shared `service.control.v1` unary operation and bound signed stream
mapping to the existing confidential carrier. Payloads reuse exact M6 Message
bytes; four one-way operations receive signed zero-byte carrier receipts.
Pure comparisons cover legal pairs, bootstrap results and Error, exact pending
context, singleton consumer leases and reverse cancel/query answers. Stream
bodies are only SnapshotPush, PortCancel and PortQuery. Receipts, content ACKs
and cancel delivery never grant readiness, termination or lease authority.

The subscription request is now an incompatible eight-element tuple with an
appended null or exact M6 session binding. Seven-element inputs are refused.
Existing publication scope, capability, boot nonce, attempt and channel meanings
remain unchanged. Source contribution custody, persistence and content floors
stay external. Independent carrier and regenerated subscription vectors are
candidate evidence; NSD M6 carrier adoption and producer review are outstanding.

| Existing family surface | Candidate delta | External status |
| --- | --- | --- |
| Bootstrap / v1 replacement | Exact M6 unary, receipt and bound signed-event validation | NSD carrier adoption and real producer vectors outstanding |
| Public edge / service integration | Reuses unchanged declaration, snapshot, listener, lease and port messages | Consumer lifecycle and NSD interoperability remain separate |
| Publication subscription | Breaking eight-field tuple with optional exact per-Network M6 session | Producer and consumer adoption required; no old-arity fallback |

## Confidential certificate and client-CA acquisition

The [material acquisition contract](confidential-material-candidate.md) adds
`edge.material.get` on the existing authenticated confidential carrier. Its pure
request/response codecs and independent certificate/client-CA fixtures preserve
exact pending-request echo and kind/reference/generation scope. Host lists and
exclusive Unix-seconds deadlines constrain use; installation, current dependency
rechecks, route coverage, trust-domain comparison and X.509 parsing stay external.
Family 7 gains confidential value delivery without changing public references,
registry bytes, AuthConfigRequest's auth-only restriction or installation ACK bytes.
Certificate/client-CA ACK ids are separate installation-status ids, not acquisition
ids. NSD producer implementation, confidential dispatch adoption, confirmation and
producer-owned vectors remain outstanding; fixture delivery is not agreement.

## R3 local Node naming and legacy registration retirement

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
profile intact. NSD N04/N09 producer adoption and ns S05/S06/S11 consumer/cutover
adoption remain outstanding, including independent producer confirmation.
The review delta is a candidate, never agreement or interoperability evidence.
No new field, carrier, P-item or dependency edge is introduced; previous delivery
evidence does not establish this delta or release external cutover acceptance.

## Node L3 applied status

Family 11 snapshot `node-l3` retains its existing bytes and source ownership.
The confidential `node.l3.status` operation reports only actual application of
an exact signed inner event. See the [canonical status contract](node-l3-status-candidate.md)
for request/response bytes, digest, full source fencing and independent vectors.
An exact Applied empty withdrawal proves removal; rejection and authenticated
fetch-failure denial never provide permission evidence.
