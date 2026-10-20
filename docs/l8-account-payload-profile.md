# L8 account payload profile candidate

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
| 2 `realms-peers` — served realms and peers | `realm-peers` / `realms,peer-contributions` / one account; shared peers retain provenance from remaining contributions | snapshots |
| 3 `egress` — [Egress grants](grant-authority-candidate.md) | `egress-grants` / `resources,grants,payers` / one realm and recipient | declarations, listeners, snapshots |
| 4 `exit-subnet` — [Exit Subnet grants](grant-authority-candidate.md) | `exit-grants` / `routes,grants,exclusions,bypasses,selection` / one realm and recipient | listeners, snapshots |
| 5 `payer` — [binary realm/UserId bindings](grant-authority-candidate.md) | `payer-bindings` / `payers` / one resource scope; ambiguity withholds the resource | snapshots |
| 6 `withdrawal` — [resource authority and retired tokens](grant-authority-candidate.md) | `resource-authority` / `authority,incarnations` / current authority in one recipient/resource scope | snapshots |
| 7 `public-edge` — public edge | `public-edge` / `backends,names,aliases,ports,domains,subjects,auth,materials` / one account; NodeId/node6 backends and existing auth/certificate/client-CA references and material generations retain their meanings | declarations, snapshots |
| 8 `relay` — relay directory and participant | `relay-directory-roster` / `directory\|identity-classes` / a named directory or participant roster, separately scoped; neither clears the other | snapshots |
| 9 `usage` — usage reports and units | `usage-profile` / `units,reporters,parameters` / one reporter; never clears metering history | none |
| 10 `node-control` — Node-control channel | `node-control-profile` / `vocabulary,capabilities` / one membership; ACK means at least accepted, persistence may precede ACK | none |
| 11 `v1-replacement` — replacement of the v1 surface | `surface-map` / `mappings,retirements` / discovery/envelope verification, admin claims, policy, signed URL, material, reports and snapshot/events vocabulary in one account profile | declarations, listeners, snapshots |

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
exact client/provider/floor and selection facts, explicit binary realm/UserId
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

Family 4's route selection candidate is a complete publication encoded as
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
address/range ownership enforcement stay in consumers. Native N6, N4 and
provider-route address views must be resolved to these identities before use.
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
scope. No additional scope field is carried. Any authorized scope beyond this
pair remains unresolved in Q18; directory authority is separate.

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
registry and every family's payload bytes remain unchanged. A publication is
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
| served realm / scope | NSD supplies the authorized served realm and opaque scope within it; fixture supplies `realm-a` / `scope-a` and explicit alternate scopes |
| family / kind | NSD supplies the owning family number and exact kind below; fixture supplies the same candidate identifiers |
| channel | NSD supplies 0 stream or 1 independently polled snapshot, according to the table; fixture supplies signed ownership and mismatch cases |
| complete | NSD explicitly marks complete replacement; fixture supplies complete and refused partial cases |
| publication version | NSD persists a positive monotonic u64 for each full key; fixture supplies explicit versions, never derived from time or arrival order |
| issue / expiry | NSD supplies Unix seconds with `issued < expires`; fixture supplies both and an independent consumer clock |
| outcome / payload | NSD supplies 0 complete data or 1 authenticated ACL fetch failure and exact opaque owning-family bytes; fixture supplies labelled data/failure bytes |
| signature | NSD signs all content fields; the independent Python fixture signer signs candidate bytes only |

Realm, scope and kind are nonempty UTF-8 strings of at most 256 bytes each.
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
| 4 exit-subnet | `exit-grants` | snapshot |
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
An unknown `(family, kind)` returns `UnknownKind` and changes nothing. A known
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
encoded carrier assembly remain consumer responsibilities with their own bounds.
The event decoder borrows all variable data, checks each canonical length and
available input slice before use, and allocates no variable data on either success
or rejection. Thus truncated length heads and declared lengths beyond input fail
without allocating for their claimed size.

A polled publication snapshot is canonical `[1, [signed_event_bytes, ...]]`,
not the M6 Snapshot type. Its total encoded bound is the existing 8,388,608-byte
call-body ceiling. Each event has its own measured signed-event ceiling and
signature. Keys must be strictly increasing in the tuple order above (numeric
family order, then UTF-8 byte order for strings), refusing duplicates. Empty lists
are valid and imply no withdrawals. The consumer validates every event, scope,
signature, freshness and ordering before exposing any decisions. One invalid
known event rejects the whole snapshot, including any preceding replacement or
typed failure. Authenticated unknown kinds and wrong-channel kinds remain ignored.
The validated result borrows the container and exposes decisions without allocating
an event collection. The authenticated call envelope supplies outer completeness
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
