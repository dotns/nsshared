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

This frame contains no M6 object, so neither crate depends on the other. A
consumer composes the two pure crates. Service declarations and references,
listener intents, leases, snapshots, service labels and messages always use
`nsshared-service-control` itself. A later frame embedding those types must add
an explicit one-way dependency from proto to service-control, never the reverse.

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
| 3 `egress` — Egress grants | `egress-grants` / `resources,grants,payers` / one realm and recipient | declarations, listeners, snapshots |
| 4 `exit-subnet` — Exit Subnet grants | `exit-grants` / `routes,grants,exclusions,bypasses,selection` / one realm and recipient | listeners, snapshots |
| 5 `payer` — payer rule | `payer-bindings` / `payers` / one resource scope; ambiguity withholds the resource | snapshots |
| 6 `withdrawal` — withdrawal and regrant | `resource-authority` / `authority,incarnations` / current authority in one recipient/resource scope | snapshots |
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
`payer_realm` is a 16-byte realm identifier; `payer_subject` is a full validated
IdentityKey. `completed_bytes` is u64. Boundary 0 counts Egress/Exit layer-4 payload bytes successfully completed by
host writes and sends: partial writes count only their completed bytes; failed
writes contribute zero. Boundary 1 preserves the existing public-ingress byte
boundary and does not reinterpret it as WireGuard or host-write usage.
Direction 0 is client-to-provider, 1 provider-to-client. Payer is always explicit;
an ambiguous payer withholds a resource. WireGuard handshakes, keepalives,
encapsulation and overhead are excluded. Reports attach resource and reporter
identity, sequence/window, acknowledgement/watermark and errors in the detailed
usage family; existing service references use M6, not a new service ID here.

`batch_loss_window` is `null` (`Unset`) until measured, or `[duration_ms]`
(`Measured`) after measurement. Unset is not zero, unlimited, or permission to
bill guessed bytes. No duration is invented by this candidate. The measurement
is the maximum time span of completed bytes vulnerable to loss before durable
batch custody; measured zero is distinct from unset.
Relay usage is a separate unit: whole accepted encoded DATA including its header,
counted once at accepting ingress, source NodeId and captured roster epoch/class.
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
Unicode hosts must already be ASCII IDNA labels. Discovery itself requires HTTPS.
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
