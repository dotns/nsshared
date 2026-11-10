# Usage

This specification defines the service usage unit, the relay usage unit, immutable
usage report parts and their correlated answers, and the scoped catalogue payloads of
registry family 9 `usage` (kind `usage-profile`) and family 10 `node-control` (kind
`node-control-profile`) of the [family
registry](profile.md#family-registry-and-replacement). Public items are at
`nsshared_control::account::usage`. Membership realm identities follow the [canonical
RealmId](../realm-id.md).

The usage contract carries M6 resource references, full client and provider
identities, operation metadata, an independent reporter, profile, sequence, window,
part and digest, and correlated answers. It is a pure contract and adds no transport,
persistence or retry logic. All CBOR uses definite-length arrays and strings,
shortest integer and length heads, no tags and no trailing bytes, following the
[account encoding rules](profile.md#encoding). Each unit, report and answer is
bounded to 1 MiB. Gateway and relay credential, sequence and spool custody are
independent.

## Service usage unit

The version-1 service usage unit (`ServiceUsage`) is the nine-field CBOR array

```text
[1, boundary, direction, payer_realm, payer_subject, grant_incarnation, reporter_incarnation, completed_bytes, batch_loss_window]
```

| Field | Encoding |
| --- | --- |
| `boundary` | unsigned, `ServiceBoundary` |
| `direction` | unsigned, `ServiceDirection` |
| `payer_realm` | 16-byte byte string, RealmId |
| `payer_subject` | 16-byte byte string: the paying realm-local UserId as exactly 16 unsigned big-endian ULID bytes, never an IdentityKey |
| `grant_incarnation` | 16-byte byte string (`node::GrantIncarnation`) |
| `reporter_incarnation` | 16-byte byte string (`node::ReporterIncarnation`) |
| `completed_bytes` | u64 |
| `batch_loss_window` | `null` or `[duration_ms]` |

`payer_subject` is always paired with `payer_realm`; there is no IdentityKey or
tagged fallback, and the same UserId in two realms names two distinct payers. The
payer is always explicit; an ambiguous payer withholds a resource. Unknown
boundaries and directions, an untyped window and wrong payer widths are refused.

### Boundary

| Value | `ServiceBoundary` | Meaning |
| --- | --- | --- |
| 0 | `CompletedHostWritesAndSends` | Egress/Exit layer-4 payload bytes successfully completed by host writes and sends |
| 1 | `PublicIngress` | The existing public-ingress byte boundary |

Boundary 0 counts completed TCP write lengths, including partial progress before an
error, completed UDP sends, and completed echo probe and reply sends excluding IP
headers. Partial writes count only their completed bytes. Failed operations and
queue admission contribute zero; queue admission is never completion. Echo probe and
synthetic reply sends count completed message bytes separately, excluding IP
headers; a failed or unmetered reply does not erase a completed probe.

`EchoReplySend` means completed synthetic ICMP reply message bytes excluding IP
headers, for a runtime that can observe per-packet send completion. A runtime
without a per-packet successful-send receipt emits no `EchoReplySend` rows.

Boundary 1 preserves the existing public-ingress byte boundary and is not
reinterpreted as WireGuard or host-write usage.

WireGuard handshakes, keepalives, encapsulation and overhead, and original IP packet
sizes are excluded. The quantity is always bytes: message counts must never be
copied into `completed_bytes`, and no implicit message-to-byte conversion is
authorized.

### Direction

| Value | `ServiceDirection` |
| --- | --- |
| 0 | `ClientToProvider` |
| 1 | `ProviderToClient` |

### Batch loss window

`batch_loss_window` (`BatchLossWindow`) is `null` (`Unset`) until measured, or
`[duration_ms]` (`Measured`) after measurement. The measurement is the maximum time
span of completed bytes vulnerable to loss before durable batch custody. Unset is
not zero, unlimited, or permission to bill guessed bytes, and no duration is
invented by this contract; measured zero (`[0]`) is distinct from unset.

## Relay usage

Relay usage is a separate unit and is never converted to the service host-write
unit. `RelayUsage` is the eleven-field CBOR array

```text
[1, source, destination, source_class, destination_class, issuer, participant, attribution_epoch, direction, reporter_incarnation, encoded_bytes]
```

Source and destination are existing 12-byte NodeIds. They name the fixed endpoints
for this observation. Both classes are `relay::IdentityClass` (0 ordinary, 1
gateway). Issuer and participant reuse `relay::ParticipantRosterScope`; participant
is the reporter's full identity. The attribution epoch is positive and is captured with
both classes. `reporter_incarnation` is a 16-byte byte string.

`encoded_bytes` is positive: the whole accepted encoded DATA including its relay
header, counted once at the accepting ingress. Regional destination processing
contributes no second observation. Endpoint context does not impose a
source/destination aggregation key. Rejected or replayed DATA contributes zero
observations.

### Direction

| Value | `RelayDirection` |
| --- | --- |
| 0 | `SourceToDestination` |
| 1 | `DestinationToSource` |

### Attribution

Relay attribution is historical: it records both endpoint NodeIds and classes, the
captured roster scope and attribution epoch (see [attribution](relay.md#attribution)), the
direction and the reporter incarnation. Delayed reports use historical attribution.

`RelayUsage::validate_history` compares the retained historical
`ParticipantRosterGeneration`, even after its expiry. Historical comparison requires
the original complete roster scope and attribution epoch and both exact endpoint classes. It
ignores present-day roles and current roster expiry, and performs no authentication
or history lookup on the caller's behalf.

### Billing

| Endpoint classes | `RelayBilling` |
| --- | --- |
| Either endpoint gateway, in both directions | `GatewayExcluded` |
| Ordinary and ordinary | `Billable` |

Missing history or a missing endpoint mapping is unknown mapping (`UsageError::UnknownMapping`)
and requires repair, never a guessed class or service conversion.

## Usage reports

### Immutable parts

`UsageReport` is the twelve-field CBOR array

```text
[1, 9, kind, reporter, incarnation, profile, sequence, [start_unix, end_unix], part_index, part_count, part_digest, rows]
```

- Sequence is positive within the independent reporter/incarnation/profile domain;
  each part has its own sequence. The part index and count describe the sealed
  window partition and do not share a sequence between parts.
- Windows are half-open Unix seconds with `start < end`.
- Part index is zero-based and less than a positive `part_count <= 8192`.
- Rows contains at most 8192 items, including zero for a sequence probe.
- Every embedded unit's reporter incarnation matches the envelope; a relay
  participant also matches the reporter; a service provider identity also matches
  the envelope reporter.

### Profiles

| Kind | `UsageProfile` | Profile | Rows |
| --- | --- | --- | --- |
| 0 | `Service` | `l8-completed-io-v1` | service rows |
| 1 | `Relay` | `l8-relay-data-v1` | byte strings of canonical `RelayUsage` |

Profiles are exact and never interchangeable (`UsageRows::Service`,
`UsageRows::Relay`). Each report part carries exactly one quantity family.

### Service rows

A service report row (`ServiceUsageRow`) is

```text
[resource, client, provider, operation, unit]
```

where resource is the existing canonical M6 `ServiceRef` (`nsshared_control::service`)
in a byte string, client and provider are full validated identities, and unit is the
canonical `ServiceUsage` in a byte string.

| Operation | `ServiceOperation` | Required boundary | Direction |
| --- | --- | --- | --- |
| 0 | `TcpWrite` | 0 | either |
| 1 | `UdpSend` | 0 | either |
| 2 | `EchoProbeSend` | 0 | client-to-provider |
| 3 | `EchoReplySend` | 0 | provider-to-client |
| 4 | `PublicIngress` | 1 | either |

Historical comparison (`ServiceUsageRow::validate_grant` against the retained
[service grant](grants.md#service-grants)) checks the exact resource, client,
provider, grant incarnation and realm/UserId pair, and refuses a mismatch with
`UsageError::HistoricalGrant`. Current expiry or current payer reassignment cannot
rewrite this retained ownership.

### Digest

`part_digest` is SHA-256 over `ns.account.usage.part.v1` followed by a zero byte and
the canonical eleven-field array obtained by omitting `part_digest` from the report
(`UsageReport::computed_digest`, using `nsshared_control::service::domain_digest`
with `domains::USAGE_PART_DIGEST_DOMAIN`). It therefore commits all ownership, profile,
sequence, window, partition metadata and rows. A changed payload must not reuse a
frozen digest; a digest that does not commit the supplied part is
`UsageError::Digest`.

### Duplicates

`UsageReport::validate_duplicate` validates the exact retained ownership key
(reporter, incarnation, profile, sequence, part index) and identical canonical
content, without storing state or advancing a watermark. A different ownership key
is `UsageError::Scope`; changed bytes reusing an ownership key are
`UsageError::Conflict`. The caller owns durable duplicate and sequence/window checks.

## Usage answers, watermarks and repair

`UsageAnswer` is the CBOR array

```text
[1, reporter, incarnation, profile, sequence, part_index, part_digest, outcome]
```

Correlation (`UsageAnswer::validate_for`) compares every field to the immutable
pending part. An answer from another reporter, lifecycle, profile, sequence, index
or digest is refused (`UsageError::Scope`). Outcomes (`UsageOutcome`) are:

| Outcome | Variant | Meaning |
| --- | --- | --- |
| `[0, accepted_through]` | `Accepted` | Durable contiguous acknowledgement, including an identical duplicate. `accepted_through` must cover this part's sequence. |
| `[1, watermark]` | `Conflict` | Conflict, never an acknowledgement. Watermark (`UsageWatermark`) is `null` (`Absent`), `[0]` (`Malformed`), or `[1, accepted_through]` (`Present`, including zero). |
| `[2, code]` | `Permanent` | Permanent rejection (`UsageRejection`): code 0 `Forbidden`, 1 `InvalidRequest`. |
| `[3, issuer, participant, attribution_epoch, node]` | `UnknownMapping` | Unknown historical relay mapping, requiring repair. The scope, attribution epoch and node must belong to this relay report, and cannot acknowledge service usage or another historical epoch. |

No error is an acknowledgement. Duplicate acceptance is the same ACK bytes; changed
duplicate content has a different digest and cannot correlate to that ACK.
An `UnknownMapping` answer to a service report fails `validate_for`, even if every
other correlation field matches. Authentication and transport of answers are
caller-owned; participant relays carry reports and answers in frames 5 and 6 (see
[frames](relay.md#frames)); the control report carrier reuses the same bytes
([control reports](control.md#usage)).

## Retention seals and acknowledgements

Recovery restores only future capture through a separately verified fresh signed
roster; EpochResult never changes historical report/seal bytes or acknowledges
usage. An interrupted epoch stays incomplete by absence of a seal, not an empty or
synthetic complete manifest. Normal clean shutdown durably persists its final cut
and leaves the current epoch open and reusable. See [epoch recovery](relay.md#epoch-recovery).

These pure contracts are part of the public account API from `v0.8.0` and carried
only by the confidential authenticated participant session: REPORT (5) contains
`RetentionSeal`, ANSWER (6) contains `RetentionSealAck`. They are distinct from
usage reports and answers; they are not control-report payloads or publications.

The canonical seal is an eight-element CBOR array:

```text
[1, 9, 2, issuer, recipient, owner_generation, epoch, parts]
parts = [[incarnation, profile, sequence, part_index, part_digest], ...]
```

The schema is 1, family is 9 and kind is 2 (usage reports use kinds 0 and 1).
Issuer and recipient are validated full 32-byte identity keys in
`ParticipantRosterScope`. Owner generation is a positive u64 from retained
participant custody, delivered by the pair-bound version 2 `Enrolled` or
`Authenticated` [session answer](relay.md#frames) and persisted with enrollment
completion and durable spool custody. Later authentication cannot relabel an old
manifest with a newer generation. Epoch is a positive `RosterVersion` from the captured
signed roster. A part contains the original 16-byte `ReporterIncarnation`, exact
`UsageProfile` text, positive u64 sequence, zero-based index less than 8,192,
and original 32-byte usage part digest. No field substitutes current attribution
for historical attribution. Parts are strictly increasing by the tuple
(incarnation bytes, profile UTF-8 bytes, sequence, part_index); duplicate keys are
refused even when their digests differ. Both existing quantity profile identifiers
are encoded unchanged; consumers verify each reference against historical receipts.

At most 8,192 parts and 1,048,576 total encoded bytes are accepted. Decoding checks
array bounds before collecting parts, requires exact widths and arities, rejects
nonminimal or indefinite CBOR and trailing data, and never sorts caller input.
An oversized manifest is refused; truncation or partial closure is not permitted.
An empty parts array explicitly declares that no part was captured.

The content digest is `domain_digest("ns.account.retention.seal.v1", canonical_seal)`
(`RETENTION_SEAL_DIGEST_DOMAIN`): SHA-256 over the ASCII domain, one zero byte,
and the complete canonical seal. The seal contains no self-referential digest.
Every identity field and part reference participates in the commitment.

`RetentionSeal::validate_for(authenticated_scope, expected_generation)` validates
the seal and refuses issuer, recipient or retained custody generation mismatch
with `RetentionError::{Issuer, Recipient, OwnerGeneration}` respectively.
`validate_duplicate(previous)` accepts exact replay, rejects another identity
(including `Epoch`), and returns `Conflict` for changed content under the same
identity. It does not persist or replace a receipt.

The acknowledgement is a nine-element CBOR array, distinct from the arity-eight
usage answer:

```text
[1, 9, 3, issuer, recipient, owner_generation, epoch, seal_digest, outcome]
```

Generation and epoch remain positive. The digest is exactly 32 bytes. Outcome is
one unsigned integer (`RetentionOutcome`):

| Value | Variant | Meaning |
| --- | --- | --- |
| 0 | `Committed` | The exact seal has committed to durable custody. |
| 1 | `Forbidden` | Participant scope or custody authority is forbidden. |
| 2 | `InvalidRequest` | The seal is permanently invalid. |
| 3 | `Conflict` | Different content already occupies this seal identity. |
| 4 | `UnknownMapping` | Retained custody or historical projection is missing; repair is required. |

Unknown values are refused. `RetentionSealAck::validate_for(seal)` compares every
echoed identity component and the computed digest, returning a typed outcome;
a mismatch yields the corresponding identity error or `Digest`. A successfully
correlated refusal is still a refusal. Only `Committed` acknowledges seal delivery,
and it does not assert settlement of every listed usage part.

The producer must durably stop capture under the epoch and finish all in-flight
aggregation before sealing. Its complete manifest includes predecessor incarnations
and already submitted parts, surviving restart and takeover. Retrying preserves
identical bytes. The receiver authenticates the scope, verifies retained ownership
and signed projection, and commits the seal before acknowledging. Cleanup separately
requires complete coverage of every issued recipient/custody and committed original
historical attribution for every referenced part. A missing seal, unknown history,
repair result, watermark or lost answer never establishes empty coverage or settlement.
The contract itself performs no authentication, storage, cleanup or consumer changes.

## Usage and Node-control profile publications

### Payloads

`UsageProfilePublication` is `[1, reporter, profiles]`. Reporter is the existing
validated full 32-byte IdentityKey. Profiles is a nonempty array of at most two
existing `UsageProfile` text identifiers, strictly increasing by UTF-8 bytes:
`l8-completed-io-v1`, `l8-relay-data-v1`. Each identifier references its entire
quantity, operation, direction and parameter definition in this specification and
introduces no overrides. No units, batching policies, incarnations, sequence
domains, custody or historical ownership change.

`NodeControlProfilePublication` is `[1, membership_scope, 2, capabilities]`.
`MembershipScope` (`nsshared_control::account::control::MembershipScope`) is exactly
`[nsd_id_bstr16, network_id_bstr16]`, reusing the [control
exchange](control.md#registration-and-authentication-exchanges) encoding and
validation (fixed widths, no additional nonzero predicate). Vocabulary 2 names the
existing [Node-control](../node-control.md) protocol. Capabilities is a nonempty,
strictly increasing array of at most five existing unsigned kind numbers: ACK 0,
ENDPOINTS 1, RECORD 2, PROBE_REQUEST 3, PROBE_REPLY 4. These are descriptions, never
permissions. Port 47900, the 1200-byte control ceiling, the codecs and the
at-least-accepted ACK meaning are unchanged by the catalogue.

Both payloads use shortest definite-length CBOR with exact tuple arity, no trailing
bytes and the existing inclusive 1,048,576-byte input bound before allocation. The
entire signed event, including the source wrapper, keeps the publication
encoded-event bound. Unsupported schemas, vocabulary, identifiers or kinds,
duplicates, unsorted or empty lists, malformed identity or membership and malformed
CBOR refuse. Encoding also refuses invalid constructed values.

```rust
pub struct UsageProfilePublication {
    pub reporter: IdentityKey,
    pub profiles: Vec<UsageProfile>,
}
impl UsageProfilePublication {
    pub fn canonical(&self) -> Result<Vec<u8>, AccountError>;
    pub fn decode(bytes: &[u8]) -> Result<Self, AccountError>;
    pub fn validate_reporter(&self, expected: IdentityKey) -> Result<(), AccountError>;
}
pub struct NodeControlProfilePublication {
    pub membership_scope: MembershipScope,
    pub capabilities: Vec<u8>,
}
impl NodeControlProfilePublication {
    pub fn canonical(&self) -> Result<Vec<u8>, AccountError>;
    pub fn decode(bytes: &[u8]) -> Result<Self, AccountError>;
    pub fn validate_membership(&self, accepted: &MembershipScope) -> Result<(), AccountError>;
}
pub enum ProfilePublicationPayload {
    Usage(UsageProfilePublication),
    NodeControl(NodeControlProfilePublication),
}
impl PublicationEvent<'_> {
    pub fn decode_profile_payload(&self) -> Result<Option<ProfilePublicationPayload>, AccountError>;
}
```

`PublicationEvent` is `nsshared_control::account::publication::PublicationEvent`;
`AccountError` is `nsshared_control::account::AccountError`.

### Catalogues

These scoped catalogues describe existing usage quantities and Node-control kinds
without changing reporting or control bytes, permissions or runtime semantics. Usage
report and answer bytes, Node-control bytes and the family registry are unaffected
by catalogue publications.

`PublicationEvent::decode_profile_payload` recognizes only the exact `(9,
"usage-profile")` and `(10, "node-control-profile")` family/kind pairs. It returns
`None` for other kinds and for empty payloads, preserving the
[publication](publication.md#outcomes-and-payloads) contract's explicit
complete-empty withdrawal. No empty identity or membership represents withdrawal.
Publication decisions reject malformed nonempty profile payloads before exposing
replacement.

Neither payload authenticates itself. Usage mapping also compares the reporter with
the signed recipient; callers must still supply the independent expected reporter
(`validate_reporter`). Node-control consumers must compare the accepted membership
(`validate_membership`) before committing the replacement. Consumers compare
independent reporter or membership authority before installation. Existing source
binding, issuer/recipient, scope, channel, signature, completeness, expiry and
durable per-key version checks of [publication](publication.md#decisions) and
[source-bound publication](publication.md#source-bindings-and-source-bound-publications)
remain necessary.

### Replacement

Replacement or withdrawal clears only the corresponding exact scope's catalogue:
usage `units,reporters,parameters`, control `vocabulary,capabilities`. It never
clears captured usage, pending reports, incarnations, batching or sequence/ACK
custody. Historical usage, pending reports, received control state and
independently accepted control authority remain consumer-owned. Complete-empty
withdrawal is an explicit publication outcome. Missing or rejected input cannot
reserve a version, renew validity or replace state.

## Code and vectors

| Contract | Source | Public items |
| --- | --- | --- |
| Service usage unit | `crates/nsshared-control/src/account/families/usage/service.rs` | `nsshared_control::account::usage::{ServiceUsage, ServiceBoundary, ServiceDirection, BatchLossWindow}` |
| Relay usage | `crates/nsshared-control/src/account/families/usage/relay.rs` | `nsshared_control::account::usage::{RelayUsage, RelayDirection, RelayBilling}` |
| Usage reports | `crates/nsshared-control/src/account/families/usage/report.rs` | `nsshared_control::account::usage::{UsageReport, UsageRows, UsageProfile, ServiceUsageRow, ServiceOperation, UsageError}` |
| Retention seals and acknowledgements | `crates/nsshared-control/src/account/families/usage/retention.rs` | `nsshared_control::account::usage::{RetentionSeal, RetentionPart, RetentionSealAck, RetentionOutcome, RetentionError}` |
| Retention digest domain | `crates/nsshared-control/src/account/domains.rs` | `nsshared_control::account::domains::RETENTION_SEAL_DIGEST_DOMAIN` |
| Usage answers | `crates/nsshared-control/src/account/families/usage/answer.rs` | `nsshared_control::account::usage::{UsageAnswer, UsageOutcome, UsageWatermark, UsageRejection}` |
| Profile publications | `crates/nsshared-control/src/account/families/usage/catalog.rs` | `nsshared_control::account::usage::{UsageProfilePublication, NodeControlProfilePublication, ProfilePublicationPayload}` |
| Publication payload mapping | `crates/nsshared-control/src/account/publication/payloads.rs` | `nsshared_control::account::publication::PublicationEvent::decode_profile_payload` |
| Part digest domain | `crates/nsshared-control/src/account/domains.rs` | `nsshared_control::account::domains::USAGE_PART_DIGEST_DOMAIN` |

| Vectors | Producer | Test module |
| --- | --- | --- |
| `crates/nsshared-control/tests/vectors/account/profile.vec` (kind `usage`) | `tools/vectors/nsvec/producers/control/account/profile.py` | `account::profile` |
| `crates/nsshared-control/tests/vectors/account/usage/reports.vec` | `tools/vectors/nsvec/producers/control/account/usage/reports.py` | `account::usage::reports` |
| `crates/nsshared-control/tests/vectors/account/usage/catalog.vec` | `tools/vectors/nsvec/producers/control/account/usage/catalog.py` | `account::usage::catalog` |
| `crates/nsshared-control/tests/vectors/account/usage/retention.vec` | `tools/vectors/nsvec/producers/control/account/usage/retention.py` | `account::usage::retention` |

The Python standard-library producers generate bytes without reading Rust output.
Every negative case records its exact input and refusal.

In `account::usage::reports`, `service_usage_vectors` checks completed write, send
and echo, malformed payer and canonical bytes, including the same UserId in two
realms and exact historical grant comparison. `relay_usage_vectors` checks both
endpoint classes, historical epochs, both directions, gateway exclusion and unknown
mapping repair. `usage_report_vectors` and `usage_answer_vectors` check the
immutable digest and reporter/part correlation, duplicate ACK, conflict and typed
errors.

In `account::usage::catalog`, `profile_payload_vectors` checks the payload bytes and
refusals, `profile_publication_context_refusals` the reporter and membership
comparisons, and `profile_publication_replacement` consumes install-usage,
install-control, malformed-replacement, withdraw-usage, then replay-usage. The
malformed version 2 must not reserve its version; the valid withdrawal at version 2
must succeed. Only the exact usage key is withdrawn, while control remains
installed. Retained version tombstones refuse the older install after a consumer
restart. Shared tests exercise pure decisions and externally retained versions only,
with no runtime or I/O.

The fixture issuer is Ed25519 seed `02` repeated 32 times, the recipient and
reporter seed `01` repeated 32 times, and the membership IDs are `03` repeated 16
times. Stream source binding and delivery use the exact source-selection encodings
([source binding](publication.md#source-binding),
[delivery context](publication.md#delivery-context)). Signature domains are
`ns.account.publication.v1\0`, `ns.account.source-binding.v1\0` and
`ns.account.source-publication.v1\0` (`domains::PUBLICATION_DOMAIN`,
`domains::SOURCE_BINDING_DOMAIN`, `domains::SOURCE_PUBLICATION_DOMAIN`), each with a
final zero separator. `catalog.vec` records inner and outer canonical bytes and exact
signatures; the fixed values are listed below and are identical to the
same-named entries of `catalog.vec`.

### usage-complete

```text
bytes = 830158208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c82726c382d636f6d706c657465642d696f2d7631706c382d72656c61792d646174612d7631
```

### control-complete

```text
bytes = 8401825003030303030303030303030303030303500303030303030303030303030303030302850001020304
```

### install-usage

```text
bytes = 8258ca8e0158208139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b39458208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c781a3033304331473630523330433147363052333043314736305233656e6f646573096d75736167652d70726f66696c6500f501186418c8005849830158208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c82726c382d636f6d706c657465642d696f2d7631706c382d72656c61792d646174612d7631584042d1d4f93e67bc416425e898dcd4602de8ff907fb04bc1afece16e2da67461f0535c7f95a02e7f503c6413e71ad1b9e61d5c9d2924507171a460fbeb94ee6e0d
signature = 42d1d4f93e67bc416425e898dcd4602de8ff907fb04bc1afece16e2da67461f0535c7f95a02e7f503c6413e71ad1b9e61d5c9d2924507171a460fbeb94ee6e0d
source_publication = 82590227840158fc8258b78a0158208139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b39458208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c781a3033304331473630523330433147363052333043314736305233656e6f64657378186578706c696369742d676174657761792d70726f66696c6558208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c500a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0101584090429d8d868a806cd1794a893a62aa58d7c1bc83eb05ec01c6253b3f91d36805a08be302e720479ca897605a2ce03817f4b14441dbd2a0ac58dc91834d73330354830050040404040404040404040404040404040159010f8258ca8e0158208139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b39458208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c781a3033304331473630523330433147363052333043314736305233656e6f646573096d75736167652d70726f66696c6500f501186418c8005849830158208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c82726c382d636f6d706c657465642d696f2d7631706c382d72656c61792d646174612d7631584042d1d4f93e67bc416425e898dcd4602de8ff907fb04bc1afece16e2da67461f0535c7f95a02e7f503c6413e71ad1b9e61d5c9d2924507171a460fbeb94ee6e0d5840517fe4606fd23306fec9f16c2ee899e17ec2f69be23265cd368cd36556007e90bde48b86c63309d399d989ea5751736dd07ef76a2e005f30156333248224780b
source_signature = 517fe4606fd23306fec9f16c2ee899e17ec2f69be23265cd368cd36556007e90bde48b86c63309d399d989ea5751736dd07ef76a2e005f30156333248224780b
```

### install-control

```text
bytes = 8258b48e0158208139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b39458208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c781a3033304331473630523330433147363052333043314736305233656e6f6465730a746e6f64652d636f6e74726f6c2d70726f66696c6500f501186418c800582c84018250030303030303030303030303030303035003030303030303030303030303030303028500010203045840e134dac7fa77aa61ce5e3aedc29f52690186faf6d112e401cd9c380ec18a46440518f81773315696e6532b4e2df04010b52bfe904f05a62aa50708a4f784420c
signature = e134dac7fa77aa61ce5e3aedc29f52690186faf6d112e401cd9c380ec18a46440518f81773315696e6532b4e2df04010b52bfe904f05a62aa50708a4f784420c
source_publication = 82590210840158fc8258b78a0158208139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b39458208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c781a3033304331473630523330433147363052333043314736305233656e6f64657378186578706c696369742d676174657761792d70726f66696c6558208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c500a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0101584090429d8d868a806cd1794a893a62aa58d7c1bc83eb05ec01c6253b3f91d36805a08be302e720479ca897605a2ce03817f4b14441dbd2a0ac58dc91834d73330354830050040404040404040404040404040404040158f98258b48e0158208139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b39458208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c781a3033304331473630523330433147363052333043314736305233656e6f6465730a746e6f64652d636f6e74726f6c2d70726f66696c6500f501186418c800582c84018250030303030303030303030303030303035003030303030303030303030303030303028500010203045840e134dac7fa77aa61ce5e3aedc29f52690186faf6d112e401cd9c380ec18a46440518f81773315696e6532b4e2df04010b52bfe904f05a62aa50708a4f784420c58401b990dc53ce7e5fce5dd5904ee96cfae023d2b2acf6bcacdd51931b2edf910b405b9b22b6060d885c596c1e363ddb3c19a526717d8ed03e91dcb514e8ebe2d02
source_signature = 1b990dc53ce7e5fce5dd5904ee96cfae023d2b2acf6bcacdd51931b2edf910b405b9b22b6060d885c596c1e363ddb3c19a526717d8ed03e91dcb514e8ebe2d02
```

### malformed-replacement

```text
bytes = 8258ca8e0158208139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b39458208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c781a3033304331473630523330433147363052333043314736305233656e6f646573096d75736167652d70726f66696c6500f502186418c8005849830158208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c82706c382d72656c61792d646174612d7631726c382d636f6d706c657465642d696f2d76315840de1bf163e5d1da50e540a85eaa0bb8f40f21d87df8c0d963a3736dc757381cb699cd549c610ffd1d4cc8ac6d01fb3181b1fb69c9bc0d53d871d1d09b86fe1f0c
signature = de1bf163e5d1da50e540a85eaa0bb8f40f21d87df8c0d963a3736dc757381cb699cd549c610ffd1d4cc8ac6d01fb3181b1fb69c9bc0d53d871d1d09b86fe1f0c
source_publication = 82590227840158fc8258b78a0158208139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b39458208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c781a3033304331473630523330433147363052333043314736305233656e6f64657378186578706c696369742d676174657761792d70726f66696c6558208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c500a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0101584090429d8d868a806cd1794a893a62aa58d7c1bc83eb05ec01c6253b3f91d36805a08be302e720479ca897605a2ce03817f4b14441dbd2a0ac58dc91834d73330354830050040404040404040404040404040404040159010f8258ca8e0158208139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b39458208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c781a3033304331473630523330433147363052333043314736305233656e6f646573096d75736167652d70726f66696c6500f502186418c8005849830158208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c82706c382d72656c61792d646174612d7631726c382d636f6d706c657465642d696f2d76315840de1bf163e5d1da50e540a85eaa0bb8f40f21d87df8c0d963a3736dc757381cb699cd549c610ffd1d4cc8ac6d01fb3181b1fb69c9bc0d53d871d1d09b86fe1f0c5840e31db478bdb0f62916b2392fb0573a7e4873ed5309d6e269da82b128dfe0f7c43fdc860a9721564d4c75f7c8aa28e3584cec1b355c413fe686a68a56fd454803
source_signature = e31db478bdb0f62916b2392fb0573a7e4873ed5309d6e269da82b128dfe0f7c43fdc860a9721564d4c75f7c8aa28e3584cec1b355c413fe686a68a56fd454803
```

### withdraw-usage

```text
bytes = 8258808e0158208139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b39458208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c781a3033304331473630523330433147363052333043314736305233656e6f646573096d75736167652d70726f66696c6500f502186418c80040584040e875e7a92b6e51bf2ef7207aadf77a32324078cdd343b4158833f845c477dbf538d0aab36d7ae947c1cf83b4c8ea460c08116577d78e32c2b1b18edcf2ec03
signature = 40e875e7a92b6e51bf2ef7207aadf77a32324078cdd343b4158833f845c477dbf538d0aab36d7ae947c1cf83b4c8ea460c08116577d78e32c2b1b18edcf2ec03
source_publication = 825901dc840158fc8258b78a0158208139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b39458208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c781a3033304331473630523330433147363052333043314736305233656e6f64657378186578706c696369742d676174657761792d70726f66696c6558208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c500a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0101584090429d8d868a806cd1794a893a62aa58d7c1bc83eb05ec01c6253b3f91d36805a08be302e720479ca897605a2ce03817f4b14441dbd2a0ac58dc91834d73330354830050040404040404040404040404040404040158c58258808e0158208139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b39458208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c781a3033304331473630523330433147363052333043314736305233656e6f646573096d75736167652d70726f66696c6500f502186418c80040584040e875e7a92b6e51bf2ef7207aadf77a32324078cdd343b4158833f845c477dbf538d0aab36d7ae947c1cf83b4c8ea460c08116577d78e32c2b1b18edcf2ec035840a4bf95e802106809ade8b38f28c604be398ab78c59f7d014b6d30bff4ccd6a95a844f81808429d4e61b500378ed3286f3d72a4603c94d3c953fbf0a4ce51b20a
source_signature = a4bf95e802106809ade8b38f28c604be398ab78c59f7d014b6d30bff4ccd6a95a844f81808429d4e61b500378ed3286f3d72a4603c94d3c953fbf0a4ce51b20a
```

### replay-usage

```text
bytes = 8258ca8e0158208139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b39458208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c781a3033304331473630523330433147363052333043314736305233656e6f646573096d75736167652d70726f66696c6500f501186418c8005849830158208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c82726c382d636f6d706c657465642d696f2d7631706c382d72656c61792d646174612d7631584042d1d4f93e67bc416425e898dcd4602de8ff907fb04bc1afece16e2da67461f0535c7f95a02e7f503c6413e71ad1b9e61d5c9d2924507171a460fbeb94ee6e0d
signature = 42d1d4f93e67bc416425e898dcd4602de8ff907fb04bc1afece16e2da67461f0535c7f95a02e7f503c6413e71ad1b9e61d5c9d2924507171a460fbeb94ee6e0d
source_publication = 82590227840158fc8258b78a0158208139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b39458208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c781a3033304331473630523330433147363052333043314736305233656e6f64657378186578706c696369742d676174657761792d70726f66696c6558208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c500a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0101584090429d8d868a806cd1794a893a62aa58d7c1bc83eb05ec01c6253b3f91d36805a08be302e720479ca897605a2ce03817f4b14441dbd2a0ac58dc91834d73330354830050040404040404040404040404040404040159010f8258ca8e0158208139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b39458208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c781a3033304331473630523330433147363052333043314736305233656e6f646573096d75736167652d70726f66696c6500f501186418c8005849830158208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c82726c382d636f6d706c657465642d696f2d7631706c382d72656c61792d646174612d7631584042d1d4f93e67bc416425e898dcd4602de8ff907fb04bc1afece16e2da67461f0535c7f95a02e7f503c6413e71ad1b9e61d5c9d2924507171a460fbeb94ee6e0d5840517fe4606fd23306fec9f16c2ee899e17ec2f69be23265cd368cd36556007e90bde48b86c63309d399d989ea5751736dd07ef76a2e005f30156333248224780b
source_signature = 517fe4606fd23306fec9f16c2ee899e17ec2f69be23265cd368cd36556007e90bde48b86c63309d399d989ea5751736dd07ef76a2e005f30156333248224780b
```

### Attribution epochs and publication refreshes

Relay usage and `UnknownMapping.epoch` carry the authenticated attribution epoch,
not the signed roster publication version. Historical validation compares
`ParticipantRosterGeneration.attribution_epoch` and the exact issuer/participant
scope, then both endpoint identities and classes. Refreshes with a repeated epoch
remain valid historical evidence even with a different publication version.
Pending report bytes, their original epochs and admission-start history remain
unchanged after renewal. NSD resolves the epoch against retained membership and
projection custody; missing history requires repair rather than a current-owner
lookup. See [roster attribution](relay.md#attribution).
