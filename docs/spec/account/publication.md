# Account publications

## Purpose and contracts covered

This specification defines the publication layer of the account contracts: how
NSD delivers signed, per-kind authority to a Node and how the Node requests it.
It covers:

- signed publication events (`PublicationEvent`), their keys, channels, decisions
  and the plain snapshot container;
- the producer API for signed publication content;
- source bindings (`SourceBinding`, `SignedSourceBinding`), subscriber delivery
  context (`DeliveryContext`) and source-bound publications (`SourcePublication`);
- the authenticated publication subscription (`config.stream`) and its stream framing;
- the independent publication snapshot poll (`config.snapshot`).

Signed publication events are the snapshot and events vocabulary of family 11
(`v1-replacement`), version 1, in the family registry.

Related contracts are specified elsewhere:

- The family registry, publication names, cleared-kind strings and family
  ownership of each kind: [family registry](profile.md#family-registry-and-replacement).
- The signed control carrier (`control::BootstrapEnvelope`), discovery, confidential
  HTTPS/Noise/QUIC carriers and their byte limits, registration and authentication
  operations, explicit authentication source selection, Node route select and clear
  commands, receipts and responses, and the M6 service control carrier: [control](control.md).
- Ordinary provider Subnet route reports, exit grants and consumer Subnet route
  views, including which source binding each family 4 kind uses: [Subnet](subnet.md).
- Shared participant credentials, participant rosters and directory bindings:
  [relay](relay.md). This specification only cross-references them and defines no
  participant or directory-binding contract.
- Family payloads: the owning family specifications ([realm](realm.md),
  [grants](grants.md), [Subnet](subnet.md), [edge](edge.md), [relay](relay.md),
  [usage](usage.md), [node](node.md)).

### Common encoding rules

- All arrays are exact canonical CBOR with minimal integers, definite lengths,
  exact arity, no extra fields and no trailing bytes. Unknown fields, unknown
  discriminants and nonminimal encodings are refused. Integers are unsigned u64
  unless stated.
- Identity fields (written `_I`) are complete validated 32-byte Ed25519 public keys.
- Realm text is [canonical RealmId](../realm-id.md) text (26 characters).
- Scope text follows the [scope text rule](profile.md#scope-text) everywhere in
  this specification: publication keys, subscription and snapshot request scopes,
  and source bindings. A scope outside it is refused, never normalized.
- Opaque 16-byte identities (nonces, correlations, contributions) are nonzero.
- Every signature is Ed25519 over a domain from `nsshared_control::account::domains`
  followed by the canonical signed bytes; each domain ends with one zero byte (`\0`).
- The contracts are pure: they store nothing, read no clock, make no transport
  calls, perform no installation and hold no signing key. Callers supply clocks,
  retained versions, pending request state and independently accepted authority.

## Publication keys and channels

A full publication key (`PublicationKey`) is
`(issuer, recipient, served_realm, scope, family, kind)`. A publication version
orders events within one full key only; a version never orders different keys.
An authorized publication scope (`PublicationScope`) is the exact pair
`(served_realm, scope)`; neither component implies another scope.

Each kind is owned by exactly one channel. Channel 0 is the control stream; channel
1 is the independently polled snapshot. The family that owns each kind, the
publication name and the exact cleared-kind strings are fixed by the
[family registry](profile.md#family-registry-and-replacement);
`publication::publication_channel(family, kind)` returns the owning channel of a
registered pair.

| Family | Kind | Owning channel |
| --- | --- | --- |
| 1 enrollment | `own-node` | stream |
| 2 realms-peers | `realm-peers` | snapshot |
| 3 egress | `egress-grants` | snapshot |
| 4 exit-subnet | `exit-grants`, `subnet-routes`, `provider-mappings` | snapshot |
| 5 payer | `payer-bindings` | snapshot |
| 6 withdrawal | `resource-authority` | stream |
| 7 public-edge | `public-edge` | stream |
| 8 relay | `directory` | snapshot |
| 8 relay | `identity-classes` | stream |
| 9 usage | `usage-profile` | stream |
| 10 node-control | `node-control-profile` | stream |
| 11 v1-replacement | `node-l3` | snapshot |
| 11 v1-replacement | `policy-version` | stream |

These publication identifiers are not copies of v1 transport tags. Each named kind
replaces its complete owning-family publication within the exact full key only.
In particular `directory` and the participant roster remain separate. A
subscription never moves a snapshot-owned kind to the stream, and a snapshot poll
never requests a stream-owned kind.

## Publication content and signed events

### Wire form

A publication event is `[bstr(content_bytes), signature64]`, reusing the outer
shape of the signed control carrier. The content is the 14-element tuple:

`[1, issuer_I, recipient_I, served_realm, scope, family, kind, channel, complete,
publication_version, issued_seconds, expires_seconds, outcome, payload_bytes]`

Ed25519 signs `ns.account.publication.v1\0 || content_bytes`
(`domains::PUBLICATION_DOMAIN`), with one final zero byte in the domain. The
control carrier content and domains cannot be reused for publications: its
timestamp and nonce do not express complete per-kind versions or actual validity.

| Position | Field | Encoding and meaning |
| ---: | --- | --- |
| 1 | schema | Unsigned integer, fixed at 1 |
| 2 | issuer | NSD's full validated identity |
| 3 | recipient | Exact target Node identity; mandatory |
| 4 | served_realm | Canonical RealmId text of the authorized served realm |
| 5 | scope | Opaque scope text within the served realm |
| 6 | family | Owning family number |
| 7 | kind | Exact kind; nonempty UTF-8 text of at most 256 bytes |
| 8 | channel | 0 stream or 1 snapshot, according to the owning-channel table |
| 9 | complete | Boolean; explicitly marks complete replacement |
| 10 | publication_version | Positive u64 that NSD persists monotonically for each full key; never derived from time or arrival order |
| 11 | issued_seconds | Unix seconds |
| 12 | expires_seconds | Unix seconds; `issued_seconds < expires_seconds` |
| 13 | outcome | 0 complete data (`PublicationOutcome::Data`) or 1 authenticated ACL fetch failure (`PublicationOutcome::FetchFailed`) |
| 14 | payload_bytes | Exact opaque owning-family bytes |

NSD signs all content fields.

### Outcomes and payloads

Outcome 1 is legal only for family 11 `node-l3`, with a nonempty opaque failure
payload. It is an authenticated typed failure that denies immediately and advances
the accepted version. It is distinct from an outer poll or fetch failure, which
retains the last complete state and is never represented by this value.
`node-l3` carries the normalized Node L3 policy ([node](node.md)).

Payload bytes are opaque to this layer; the owning-family codec validates their
typed content before installation. No parallel M6 Snapshot, SnapshotPush or
SnapshotAck is defined: when carried, their canonical M6 bytes are opaque and
unmodified, and the owning-family validator checks their contents before
installation.

### Consumer inputs

The consumer supplies, independently of the event (`PublicationExpectation`,
`AcceptedPublication`):

- the trusted expected issuer and recipient;
- the authorized `(served_realm, scope)` pairs;
- the actual receiving channel;
- the clock (`now_seconds`);
- the last accepted version for each full key.

No signed field substitutes for these independent authority inputs.

### Decisions

`publication::decide_publication` returns one `PublicationDecision`. Only
replacement, withdrawal and typed failure advance state.

| Decision | Condition | Effect |
| --- | --- | --- |
| `Replace` | Valid, complete, owning-channel event of a known kind with a strictly newer version and outcome 0 with a nonempty payload | Atomically replace this exact key after owning-family validation |
| `Withdraw` | As for `Replace`, but outcome 0 with an empty payload | Explicit complete empty authority; advances the accepted version and retains it as a tombstone |
| `FetchFailed` | Valid outcome 1 `node-l3` event with a strictly newer version | Deny immediately; advances the accepted version |
| `Absent` | No input for the queried kind | Nothing changes, including an already absent kind |
| `UnknownKind` | Authenticated event of an unregistered `(family, kind)` | Nothing changes |
| `ChannelMismatch` | Known kind whose signed channel or actual receiving channel differs from its owning channel | Nothing changes |
| `Refused(PublicationError)` | Invalid event | Nothing changes |
| `TerminateStream` | Over-ceiling input on the stream channel | No replacement; the consumer terminates and reconnects |

Authentication, authorized scope and validity are checked even for kinds that are
ignored (`UnknownKind`, `ChannelMismatch`). A known owning-channel event must be
complete and strictly newer than the retained version; partial content and lower
or equal versions are refused. Validity is `issued_seconds <= now_seconds <
expires_seconds`, with no clock skew allowance and no local renewal. Wrong issuer,
wrong recipient, unauthorized scope, invalid signature, unsupported schema,
malformed content, a future issue time or an expired event are refused. Arrival
time is never a version.

Refusals are typed by `PublicationError`: `Contract` (invalid, truncated,
nonminimal or trailing CBOR), `Bounds` (measured byte ceiling exceeded), `Field`
(unsupported schema, discriminant or invalid required field), `Issuer`,
`Recipient`, `Scope`, `Validity`, `Signature`, `Incomplete` (known owned kind is
partial), `Stale` (equal or lower version within the exact key) and `Order`
(snapshot keys duplicated or not strictly increasing). An error never represents
empty authority.

Consumers atomically persist the accepted version for replacement, withdrawal and
typed failure, including withdrawal tombstones, and retain all other keys.

### Byte ceiling and decoding

The **1,048,576-byte inclusive ceiling** (`control::MAX_PUBLICATION_BYTES`) is
measured on the complete encoded signed event **as received**, including both CBOR
byte-string heads, content and signature, before decoding or allocation. It is not
a payload length or an SSE, Base64 or hex length. Over-ceiling stream input returns
`TerminateStream` with no replacement; the consumer must terminate and reconnect,
never drop the event and continue. An over-ceiling polled event rejects the whole
snapshot. SSE framing and encoded carrier assembly are consumer responsibilities
using the event and query names and the framing ceiling in
[stream framing](#stream-framing).

The event decoder borrows all variable data, checks each canonical length and the
available input slice before use, and allocates no variable data on success or
rejection. Truncated length heads and declared lengths beyond the input therefore
fail without allocating for their claimed size.

### Snapshot containers

A snapshot is a container `[1, [bstr(entry), ...]]` bounded by the complete
8,388,608-byte call-body ceiling (`control::MAX_CONTROL_BODY`). Each entry has its
own measured signed-event ceiling and signature. The following rules apply to every
snapshot container:

- Keys are strictly increasing in the full-key tuple order (numeric family order,
  UTF-8 byte order for strings); duplicates are refused.
- An empty list is valid and implies no withdrawals. Keys omitted from a snapshot
  retain their state; container omission cannot clear another authority scope.
  Absence never synthesizes a signed empty event; a signed empty payload withdraws
  only its exact key.
- Every entry's signature, scope, freshness and ordering is validated before any
  decision is exposed. One invalid known entry rejects the whole snapshot,
  including any preceding replacement or typed failure.

The low-level plain container of `PublicationEvent` entries
(`publication::PublicationSnapshot`, `publication::decide_publication_snapshot`)
validates these rules for snapshot-channel events. It is not a `config.snapshot`
response validator: the `config.snapshot` response carries source-bound entries
([source-bound snapshots](#source-bound-snapshots), [snapshot responses](#snapshot-responses)).

## Producer API

The producer API produces exactly the event bytes defined above:

- `PublicationContent::canonical()` returns the validated signed content bytes.
- `PublicationContent::signing_input()` returns `domains::PUBLICATION_DOMAIN || content_bytes`.
- `publication::encode_publication(content, signature64)` returns
  `[bstr(content_bytes), signature64]`.
- `PublicationEvent::signing_input()` and `PublicationEvent::signature()` expose the
  exact received signature inputs for independent producers.

The crate holds no signing key. The producer requires:

- a registered family and kind, and its owning signed channel;
- scope text per the scope text rule and a nonempty kind of at most 256 UTF-8 bytes;
- a positive version;
- `issued_seconds < expires_seconds`;
- outcome Data or FetchFailed, where FetchFailed requires family 11 `node-l3` and a
  nonempty payload;
- a complete encoded event within `MAX_PUBLICATION_BYTES`, including CBOR and
  signature overhead.

Structural and ownership refusals return `PublicationError::Field`; measured
overflow returns `PublicationError::Bounds`. Partial content of a known pair is
producer-valid (the consumer refuses it as `Incomplete`). Family payload bytes
remain opaque; family codecs validate their typed content. Decoder and decision
behavior are independent of the producer API, including unknown-kind forward
compatibility and refusal of incomplete known kinds.

## Source bindings and source-bound publications

Source bindings and the complete route command, receipt and response payloads that
carry them ([control](control.md)) are each bounded by 16,384 encoded bytes
(`publication::MAX_SOURCE_BYTES`).

### Source binding

`SourceBinding = [1, nsd, recipient, realm, scope, profile, source_node,
contribution, source_epoch, source_generation]`

| Field | Meaning |
| --- | --- |
| nsd | Issuing NSD identity |
| recipient | Node that receives the binding |
| realm, scope | Canonical RealmId text and scope text of the bound authority scope |
| profile | Assigned enrollment profile; the sole profile is the literal `explicit-gateway-profile` (`SourceProfile::ExplicitGateway`) |
| source_node | Full source Node identity |
| contribution | Nonzero 16-byte contribution identity allocated by NSD |
| source_epoch | Positive counter |
| source_generation | Positive counter |

NSD assigns the profile through authenticated enrollment; a caller cannot grant
itself a profile, and no other profile converts to it. NSD's durable committed
enrollment and contribution state allocates the contribution and advances the
generation on replacement or retirement, even when the Node's I, K and addresses
do not change. Neither `NodeBinding.generation` nor the M6 `authority_epoch`
supplies this fact; their bytes and meaning are unaffected. Comparing accepted
authority requires exact equality of every field: issuer, recipient, realm, scope,
profile, source, contribution, epoch and generation. A local attachment generation
is never encoded as the NSD source generation.

`SignedSourceBinding = [bstr(SourceBinding), signature64]`, signed over
`"ns.account.source-binding.v1\0" || SourceBinding bytes`
(`domains::SOURCE_BINDING_DOMAIN`). `SignedSourceBinding::verify` checks the
signature against a supplied NSD identity.

### Source authority in registration and authentication responses

Source authority is carried only in the successful responses of the confidential
`machine.register` and `machine.auth` operations (`control::MACHINE_REGISTER`,
`control::MACHINE_AUTH`; see [control](control.md)). These are their sole success
payloads:

- registration: `[1, scope, bstr(Enrollment), profile, decision, bstr(SignedSourceBinding)]`;
- authentication: `[1, token, bstr(SignedSourceBinding)]`.

Every accepted enrollment decision, including Equal, requires the binding. Refusal
payloads are defined by the operations themselves. There is no standalone source
acceptance message and no fallback to response shapes without a binding.

A consumer accepts source authority only after it has:

1. verified the response carrier against the expected enrolled NSD pin, response
   direction, explicit recipient, exact operation and freshness and replay rules,
   with the carrier nonce equal to the caller's pending request id (no duplicate
   request-id field is carried);
2. verified the nested binding signature against the independently enrolled NSD;
3. compared the binding's recipient, realm and scope, assigned profile and full
   source Node with independent expectations (`SourceEnrollmentExpectation`).

Registration also compares the staged scope, enrollment, capabilities, profile and
lifecycle with retained history. Authentication uses the selected accepted Node
binding; token signature, claims, verification and custody remain consumer duties,
and authentication never grants registration acceptance. Only a fully validated
response supplies source authority. The contribution and counters come from the
NSD binding, never from the token. Decoding alone never establishes authority.

The authentication request's required source selector, the nodes and egress
authority scopes and the meaning of the contribution for registration are defined
in [control](control.md) (explicit authentication source selection). Consumers
retain each accepted scope's binding independently.

### Delivery context

`DeliveryContext` identifies the subscriber context in which a publication is
received:

- stream: `[0, boot_nonce16, attempt_counter]`;
- snapshot: `[1, boot_nonce16, attempt_counter, correlation16]`.

The boot nonce and correlation are nonzero 16-byte values; `attempt_counter` is a
positive u32. They echo the subscriber's own subscription identity
([correlation fields](#correlation-fields)) and poll correlation
([snapshot poll requests](#snapshot-poll-requests)), never a producer-chosen
session or freshness counter. The delivery tag must match the actual receiving
channel (`DeliveryContext::channel`).

### Source-bound publication

`SourcePublicationContent = [1, bstr(SignedSourceBinding), bstr(DeliveryContext),
bstr(PublicationEvent)]`

`SourcePublication = [bstr(SourcePublicationContent), signature64]`, signed over
`"ns.account.source-publication.v1\0" || SourcePublicationContent bytes`
(`domains::SOURCE_PUBLICATION_DOMAIN`).

The nested `PublicationEvent` keeps its own independent signature and its complete
full key, channel, complete flag, version, issue and expiry, outcome and payload.
Its nested signature and every decision rule of [decisions](#decisions) are still
checked. The binding and delivery context are mandatory. A bare `PublicationEvent`
is never accepted by the source-bound decoder; there is no fallback or signature
reinterpretation.

RealmPeers, Node L3, grants, Subnet and public-edge publications use this form,
including complete-empty and authenticated-failure events. Participant rosters and
M6 messages keep their own carriers ([relay](relay.md), [control](control.md)).

### Source decisions

The caller supplies the pending delivery context and the currently accepted binding.
Before an inner event can yield a decision:

- the outer signature and the binding signature verify against that current NSD;
- every binding field and every delivery field equals the supplied values;
- the inner event's issuer, recipient, realm and scope match the binding.

This authorizes the collection; it does not require equality between the enclosing
realm and each contributing realm inside the payload. A higher per-key version
cannot rescue a replaced source or session: an event bound to a retired binding
or a different delivery context is refused even when its version is newer. Existing
full-key version and tombstone retention and deadlines survive source replacement.

The measured entire outer `SourcePublication` is bounded by `MAX_PUBLICATION_BYTES`.
Oversized stream input yields `TerminateStream`; invalid snapshot input rejects the
complete snapshot.

The consumer preserves the source and delivery context of each event through its
queues and compares the local attachment generation in the same serialized
source-owner operation as final installation. The decision APIs perform no
installation and read no clock or state themselves.

### Source-bound snapshots

A source-bound snapshot is `[1, [bstr(SourcePublication), ...]]`, bounded by
`MAX_CONTROL_BODY`, with strictly increasing full inner keys and the container
rules of [snapshot containers](#snapshot-containers). Entries have no SSE or Base64
framing limit. Every entry is validated before any decision is exposed; omitted
keys retain their state.

Channel rules for every entry:

- Every entry must declare the snapshot channel and use snapshot delivery.
- A known stream-owned pair is refused even if it declares the snapshot channel.
- An unknown registry pair that declares the stream channel is refused.
- An authenticated unknown pair that declares the snapshot channel yields
  `UnknownKind` without authority and preserves adjacent valid updates.
- One wrong-channel entry rejects the whole batch, whether valid replacements occur
  before or after it.

Multi-scope polls supply the accepted binding for each requested scope, bounded by
the 32-scope request ceiling. Each enclosing issuer, recipient, realm and scope may
have only one current binding; supplying both retired and replacement authority for
one scope is refused. Every returned event must match its scope's exact current
binding; a good event in another scope cannot hide one stale-source event.

The single-source and multi-scope snapshot APIs both enforce these rules without
changing the per-event decision contract.

### Source APIs

- `publication::source_publication_signing_input(binding, delivery, event)` returns
  the outer signing input after validating the binding, context, nested event and
  complete signed-event bound.
- `publication::encode_source_publication(binding, delivery, event, signature64)`
  encodes the outer form with a producer-supplied signature.
- `SourcePublication::decode` and its accessors (`event`, `binding`, `delivery`,
  `signing_input`, `signature`).
- `publication::decide_source_publication` checks source and pending context before
  the per-key decision.
- `publication::decide_source_snapshot` (one current binding) and
  `publication::decide_source_snapshot_scopes` (one current binding per scope)
  validate a complete source-bound snapshot before exposing decisions.

Refusals are typed by `publication::SourceError`; no error withdraws or renews
accepted authority.

### Related source-bound contracts

- Node route select and clear commands carry a `SignedSourceBinding` and use the
  same source and profile fences on the confidential signed control carrier; clear
  targets an exact selection and generation, and original immutable receipts
  survive replacement and restart with no current mutation authority. Gateway-ID
  and carrier-credential fields are refused. See [control](control.md).
- The provider Subnet report carries the signed nodes authority defined here. See
  [Subnet](subnet.md).
- Family 4 `exit-grants` and `subnet-routes` use the recipient's current nodes
  source, while family 3 `egress-grants` uses its egress contribution source. See
  [Subnet](subnet.md) and [grants](grants.md).

## Subscription requests and stream delivery

### Operation and endpoint

The operation is `config.stream` (`control::CONFIG_STREAM`) at the endpoint
`/api/v1/config/stream` (`control::CONFIG_STREAM_PATH`). The request is
`publication::PublicationSubscriptionRequest`.

### Request tuple

`[1, subscriber_I, scopes, capabilities, public_ingress, boot_nonce, attempt_counter, service_control]`

The request has exactly eight elements; requests of any other arity are refused.

| Field | Rule |
| --- | --- |
| subscriber_I | Subscribing Node identity |
| scopes | At most 32 (`publication::MAX_SUBSCRIPTION_SCOPES`) `SubscriptionScope` entries |
| capabilities | At most 64 sorted unique tokens, each 1 to 64 ASCII bytes matching `[a-z0-9._-]+` |
| public_ingress | Strictly increasing array of at most 32 zero-based indices into scopes |
| boot_nonce | Nonzero 16-byte restart identity |
| attempt_counter | Positive u32 logical stream attempt |
| service_control | Null, or the typed seven-element admitted-session tuple (`control::ServiceControlBinding`) defined in [control](control.md) |

### Scopes

Each scope is `[issuer_I, recipient_I, served_realm, scope]`: full identities,
canonical RealmId text and scope text. Entries are strictly sorted by those four
values and unique, and every recipient equals `subscriber_I`. They are exact
requested publication scopes bound to their issuer and recipient, never wildcards
or grants. The producer must compare them against externally provisioned and
accepted authority before sending publications.

### Capabilities and public ingress

Capabilities are understanding-only and follow the enrollment capability rule
([node](node.md)). Each public ingress index requests family 7 `public-edge` for
that exact issuer, recipient, realm and scope; because it is an index, it cannot
lose realm or issuer qualification. It grants no exposure or material readiness.
Empty arrays request no corresponding scopes or capabilities.

### Correlation fields

`boot_nonce` and `attempt_counter` are required. The caller supplies a fresh nonce
on each restart, begins the attempt counter at one, reuses the pair across endpoint
fallbacks and increments the counter without wrapping for each outer reconnect.
Exhaustion fails closed. The codec validates the parts but cannot prove restart
uniqueness. There is no optional or unbound subscription. The pair does not
establish a session runtime, acceptance state, replay exemption or version reset,
and does not replace per-key versions or withdrawal and failure tombstones.

### Service control field

`service_control` is null or the admitted-session tuple. Its `runtime_id` and
`session_request_id` are nonzero M6 IDs on construction, decoding and
authenticated ingress; NSD and Network zero-ID encoding semantics are unaffected.
The field does not change the meaning of scopes, capabilities, public ingress, boot
nonce or attempt counter. Stream events of `service.control.v1`
(`control::SERVICE_CONTROL`) and their validation are defined in [control](control.md).

### Bounds and carrier

The request payload is bounded to 8,192 bytes (`publication::MAX_SUBSCRIPTION_BYTES`)
before decoding. Fixed tuple arity, minimal CBOR, no trailing bytes and bounded
arrays reject unknown fields, noncanonical encodings and oversized declarations
before allocation.

The signed control carrier (`control::BootstrapEnvelope`) carries the exact payload
and operation in request direction; `BootstrapEnvelope::signing_input` supplies the
request domain plus canonical content bytes. The signer equals `subscriber_I`, and
the mandatory carrier recipient equals every requested issuer.
`PublicationSubscriptionRequest::from_envelope` verifies the carrier, subscriber
self-binding and issuer addressing. The authenticated ingress also checks the
configured subscriber and authority and the authorized exact scope set; decoding
alone confers no authority.

The confidential HTTPS, Noise and QUIC carriers and the encoded-subscription bound
of [control](control.md) apply. There is no plaintext, empty unsigned request or
JSON form. HTTP carries the complete signed subscription envelope as canonical
URL-safe unpadded Base64 in the `request` query parameter
(`control::CONFIG_STREAM_REQUEST_PARAM`); URL encoding and stream I/O are consumer
work.

### Stream framing

The stream is server-sent events. The publication event name is
`config-envelope.v1` (`control::CONFIG_PUBLICATION_EVENT`). Each event has one
`data: ` line containing canonical URL-safe unpadded Base64 of exactly one complete
`SourcePublication` with stream delivery, never a signed control carrier envelope.
Producers use LF line endings; consumers accept LF and CRLF.

| Bound | Constant | Value |
| --- | --- | ---: |
| Decoded event N | `control::MAX_PUBLICATION_BYTES` | 1,048,576 |
| Base64 length E(N) | `control::MAX_PUBLICATION_ENCODED_BYTES` | 1,398,102 |
| Framed event | `control::MAX_PUBLICATION_FRAMED_BYTES` | 1,398,139 |

E(N) = 4 * floor(N / 3) + (0 when N mod 3 = 0, otherwise N mod 3 + 1). The framed
bound is E(N) + len(`config-envelope.v1`) + 19, inclusive, accounting for `event: `,
`data: ` and three CRLF endings; with LF endings the same event is three bytes
shorter.

The consumer measures each complete event including framing, independently of
network reads, and retains bounded standalone keepalives. Exceeding the framed
bound or the independent decoded bound N terminates the stream without installing
that event; never drop and continue. Runtime parsing is consumer work. The separate
`service.control.v1` event keeps its own signed carrier and M6 encoding and limits
([control](control.md)).

## Snapshot poll requests

### Operation and endpoint

The operation is `config.snapshot` (`control::CONFIG_SNAPSHOT`). Its endpoint
aliases the confidential control endpoint `/api/v1/control`
(`control::CONFIG_SNAPSHOT_PATH`). HTTPS, Noise and QUIC keep their confidentiality
and trust requirements. The request is `publication::PublicationSnapshotRequest`.

### Request tuple

`[1, subscriber_I, scopes, boot_nonce, attempt_counter, correlation]`

- `scopes` has the subscription scope shape, ordering and uniqueness rules, at most
  32 entries (`publication::MAX_SNAPSHOT_SCOPES`); every recipient is the subscriber.
- `boot_nonce` and `correlation` are nonzero 16-byte strings; `attempt_counter` is a
  positive u32 with no wrapping.
- The canonical request ceiling is 8,192 bytes (`publication::MAX_SNAPSHOT_REQUEST_BYTES`).

A poll requests every snapshot-owned kind within each exact scope entry; stream-owned
kinds are never requested. There is no kind selector, scope wildcard, capability
grant or optional unbound session. Unknown fields (including a stream-kind
selector), unsorted or duplicate scopes, nonminimal CBOR and trailing input are
refused.

### Correlation

Callers retain the active subscription's `boot_nonce` and `attempt_counter` pair and
supply a distinct correlation for each poll. The pair identifies the active
subscription only; it cannot establish relay or publication authority, and relay
participant authority is the separate signed roster ([relay](relay.md)).

The signed control carrier signs the request through `signing_input`. Its signer is
the subscriber, its mandatory recipient is every requested issuer and its nonce
equals the correlation. `PublicationSnapshotRequest::from_envelope` authenticates
the subscriber, requested issuer and correlation; the authority separately checks
the requested exact scopes and the active subscription facts against its own state.
Gateway-only machine lookup and gateway-wide wildcard selection do not exist;
selection is by ordinary membership and externally authorized exact scopes.

### Pending boundaries

Response validation enforces the complete 8,192-byte pending-request ceiling even
for publicly constructed requests and for authenticated empty responses; individual
scope bounds do not replace it. Pending-scope checks add no version domain or
acceptance runtime, and pending requests never reset versions or tombstones.

### Snapshot responses

The response uses the same operation, response direction, the subscriber as
mandatory recipient and a nonce equal to the pending correlation. Its only payload
form is the source-bound snapshot `[1, [bstr(SourcePublication), ...]]`, not the M6
Snapshot type; plain `PublicationEvent` entries and mixed containers are refused,
with no fallback or second poll mode.

Every entry, including family 8 `directory` and authenticated unknown snapshot
kinds, uses snapshot delivery `[1, boot_nonce, attempt_counter, correlation]`
derived from the pending request. `PublicationSnapshotRequest::response`:

1. verifies carrier trust, operation, addressing and correlation;
2. checks the exact pending scope set against independently accepted current
   source bindings, requiring exactly one current binding per requested scope;
3. validates every entry with the request-derived delivery context, including each
   event's recipient, exact requested scope and declared snapshot channel, before
   exposing any decision;
4. returns the decisions, borrowing the signed event bytes, only after validating
   the complete ordered container.

One invalid entry rejects the complete poll. Each complete outer entry is bounded by
1,048,576 bytes; the container and signed carrier are bounded by `MAX_CONTROL_BODY`.
Snapshot entries have no SSE or Base64 framing limit. A known stream-owned pair is
refused even when it declares the snapshot channel. An unknown family and kind pair
is an extension, not known stream ownership: after the snapshot validator
authenticates its issuer, signature, recipient, scope and validity, it yields
`UnknownKind` without authority or state changes, and known valid updates in the
same ordered snapshot remain available. An unknown event with a bad signature, wrong
scope or recipient, or a declared stream channel still refuses the entire poll;
correlation checks apply to its carrier. Complete replacement and per-key version
decisions are those of [decisions](#decisions).

An empty snapshot retains state; signed empty event payloads withdraw only their
exact key. Complete `realm-peers` content within its authenticated scope
([realm](realm.md)) and per-key publications determine served realms; container
omission cannot remove a realm. The signed carrier supplies outer completeness and
poll authentication; absence never synthesizes a signed empty event. Directory
payloads, numeric registrations and the separate discovery binding and eligibility
are not affected by this contract ([relay](relay.md)).

Refusals are typed by `publication::SnapshotRequestError`: `Contract`, `Envelope`,
`Publication`, `Source`, `Correlation`, `Signer`, `Recipient`, `Scope` and `Channel`.

## Code and vectors

### Code

Public items are at `nsshared_control::account::publication`, with signature domains
at `nsshared_control::account::domains` and operation names and limits at
`nsshared_control::account::control`.

| Contract | Source file |
| --- | --- |
| Events, decisions, plain snapshots, producer API | `crates/nsshared-control/src/account/publication/envelope.rs` |
| Family registry and owning channels | `crates/nsshared-control/src/account/publication/registry.rs` |
| Source bindings and delivery context | `crates/nsshared-control/src/account/publication/source_binding.rs` |
| Source-bound publications and snapshots | `crates/nsshared-control/src/account/publication/source_publication.rs` |
| Subscription requests | `crates/nsshared-control/src/account/publication/subscription.rs` |
| Snapshot poll requests and responses | `crates/nsshared-control/src/account/publication/snapshot_request.rs` |
| Operation names, paths, stream bounds | `crates/nsshared-control/src/account/control/methods.rs` |
| Signature domains | `crates/nsshared-control/src/account/domains.rs` |

### Tests

| Test module | Coverage |
| --- | --- |
| `account::publication::envelope` | Event decoding, decisions and plain snapshots |
| `account::publication::envelope_producer` | Producer API round trips and refusals |
| `account::publication::delivery` | Stream framing and decoded bounds |
| `account::publication::subscription` | Subscription requests |
| `account::publication::subscription_identifiers` | Nonzero M6 identifiers in the service control field |
| `account::publication::snapshot_request` | Snapshot poll requests and responses |
| `account::publication::snapshot_request_bounds` | Pending request encoded bound |
| `account::publication::snapshot_request_plain` | Refusal of plain snapshot responses |
| `account::publication::snapshot_request_unknown` | Unknown snapshot kinds preserving known updates |
| `account::publication::snapshot_pending_boundaries` | Pending request byte boundaries |
| `account::publication::source_selection` | Source authority, source-bound publications and route receipts |
| `account::publication::source_snapshot` | Refusal of stream-owned snapshot entries |

### Vectors

All vectors are under `crates/nsshared-control/tests/vectors/account/publication/`
and are produced by an independent Python fixture producer; Rust consumes these
bytes without using Rust output as producer input. Fixture assertions are contract
evidence of the bytes defined here.

| Vector file | Content |
| --- | --- |
| `crates/nsshared-control/tests/vectors/account/publication/envelope.vec` | Canonical event and snapshot bytes, signed fields, prior scoped versions, supplied clocks and explicit expected decisions; events exactly at and over the 1 MiB ceiling; malformed outer and nested lengths; producer-valid content round trips and producer refusal of decodable invalid content |
| `crates/nsshared-control/tests/vectors/account/publication/delivery.vec` | LF and CRLF stream events at and over the decoded and framed ceilings |
| `crates/nsshared-control/tests/vectors/account/publication/subscription.vec` | Accepted empty and populated sets, exact bytes, capability and attempt boundaries, wrong recipient, duplicate and unsorted sets, oversized declarations, unknown fields and nonminimal bytes |
| `crates/nsshared-control/tests/vectors/account/publication/snapshot-request.vec` | Snapshot poll requests, signing inputs and responses, including unknown snapshot extensions |
| `crates/nsshared-control/tests/vectors/account/publication/snapshot-pending-boundaries.vec` | Pending requests at and over the encoded ceiling |
| `crates/nsshared-control/tests/vectors/account/publication/source-selection.vec` | Source authority, source-bound publications, explicit authentication source selection and immutable Node route receipts |

Fixture field conventions in `envelope.vec`: the fixture signs labelled issuer and
recipient identities; uses canonical realm A with scope `scope-a` and explicit
alternate scopes; supplies signed channel ownership and mismatch cases, complete and
refused partial cases, explicit versions never derived from time or arrival order,
both issue and expiry times with an independent consumer clock, and labelled data
and failure payload bytes.

`source-selection.vec` covers pending registration, Equal and nodes and egress
authentication in one Network, including swapped-scope and swapped-realm refusal.
Its `source_selection_fence` sequence uses a labelled authority with the same full
source I, K and derived addresses across sources A and B:

1. Register a pending gateway with no contribution and accept A as nodes authority
   in its enrollment Network; Equal retains that scope.
2. Authorize a contribution in that same Network, then authenticate independently
   for nodes and egress with the exact pending selector and nonce. Retain both
   bindings. Refuse swapped scope or realm and requests missing the selector.
   Refuse missing or mismatched bindings and wrong correlation for both operations.
3. Select and clear A's route; replace only contribution and generation with B and
   select B's route.
4. Deliver A's delayed signed success at a higher per-key version: refuse it.
5. Replay A's clear before and after restoring immutable receipts and the current
   selection from canonical bytes: the receipt stays A's and B remains intact.
6. Accept the current B publication.

Variants refuse a wrong request, wrong boot nonce or attempt, wrong poll context,
wrong profile, missing binding, gateway-ID fields and carrier-credential
fields.
