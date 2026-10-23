# feat: service and relay usage candidate

Membership realm identities follow the [canonical RealmId contract](canonical-realm-identity.md).
Affected text positions retain text but require the exact uppercase 26-character
spelling and decode to RealmId; binary positions retain their exact 16 bytes.
This incompatible candidate delta refuses arbitrary realm labels without fallback.
NSD/ns producer and consumer updates, including the other active consumer delivery,
remain outstanding. Encoding equality is not authentication. Discovery realm hints,
external provider subject namespaces and opaque scopes retain their meanings.
Signed usage bytes and the historical payer pair remain unchanged.


This is a pure candidate contract, not a released NSD producer profile. All CBOR
uses definite-length arrays and strings, shortest integer/length heads, no tags,
and no trailing bytes. Each unit, report and answer is bounded to 1 MiB.

## Service quantity and ownership

The nine-field version-1 ServiceUsage tuple is unchanged except that
payer_subject is now exactly 16 unsigned big-endian ULID bytes. It is always
paired with the 16-byte payer_realm. There is no IdentityKey or tagged fallback.
The public-ingress boundary retains its existing meaning.

Boundary 0 counts completed TCP write lengths (including partial progress before
an error), completed UDP sends, and completed echo probe/reply sends excluding
IP headers. Failed operations and queue admission add zero. Echo probe completion
survives failed reply delivery. Handshakes, WireGuard overhead and original IP
packet sizes are excluded. Operation metadata distinguishes TCP write (0), UDP
send (1), echo probe send (2), synthetic echo reply send (3), and preserved
public-ingress quantity (4). The quantity is always bytes; message counts must never be copied into completed_bytes.
Batch-loss window stays null until measured; [0] is measured zero.

`EchoReplySend` retains its completed-send meaning: completed synthetic ICMP
reply message bytes excluding IP headers, for a runtime that can observe
per-packet send completion. The current gateway candidate emits no `EchoReplySend`
rows: at frozen nsplane 0.16.0, synthetic replies are delivered but unbilled
because the normal outbound path provides no per-packet successful-send receipt.
Queue admission is never completion. `EchoProbeSend` is unchanged; an unmetered
or failed reply does not erase a completed probe. Reply billing remains deferred
until a released packet-runtime capability is adopted and qualified. This is an
outstanding runtime capability, not a contract change or recorded agreement.

A service report row is `[resource, client, provider, operation, unit]`, where
resource is the existing canonical M6 ServiceRef in a byte string, client and
provider are full validated identities, and unit is canonical ServiceUsage in
a byte string. Historical comparison checks the exact resource, client,
provider, grant incarnation and realm/UserId pair. Current expiry or current
payer reassignment cannot rewrite this retained ownership.

## Relay quantity and attribution

RelayUsage is `[1, source, destination, source_class, destination_class,
issuer, participant, roster_version, direction, reporter_incarnation,
encoded_bytes]`. Source and destination are existing 12-byte NodeIds. They name
the fixed endpoints for this observation; direction 0 is source-to-destination,
1 destination-to-source. Both classes are IdentityClass (0 ordinary, 1 gateway).
Issuer/participant reuse ParticipantRosterScope; participant is the reporter's
full identity. Roster version is positive and is captured with both classes.
encoded_bytes is positive whole accepted encoded DATA including its relay header,
counted once at the accepting ingress. Regional destination processing contributes
no second observation. Endpoint context does not impose a source/destination
aggregation key. Rejected or replayed DATA contributes zero observations.

Historical comparison requires the original complete roster scope and version
and both exact endpoint classes. It ignores present-day roles and current roster
expiry. Either gateway endpoint produces GatewayExcluded, in both directions;
ordinary/ordinary produces Billable. Missing history or an endpoint mapping is
UnknownMapping and requires repair, never a guessed class or service conversion.

## Immutable report part

UsageReport is `[1, 9, kind, reporter, incarnation, profile, sequence,
[start_unix, end_unix], part_index, part_count, part_digest, rows]`.
Kind 0/profile `l8-completed-io-v1` contains service rows. Kind 1/profile
`l8-relay-data-v1` contains byte strings of canonical RelayUsage. Profiles are
exact and never interchangeable. Sequence is positive within this independent
reporter/incarnation/profile domain; each part has its own sequence. The part
index/count describe the sealed window partition, and do not share a sequence
between parts. Windows are half-open Unix seconds with
start < end. Part index is zero-based and less than positive part_count <= 8192;
rows contains at most 8192 items, including zero for a sequence probe. Every
embedded unit's reporter incarnation matches the envelope; relay participant
also matches reporter. Service provider identity also matches the envelope
reporter. Echo operation directions are client-to-provider for probes and provider-to-client for replies;
operation 4 requires boundary 1, and operations 0–3 require boundary 0.
Gateway and relay credential, sequence and spool custody remain independent. No transport, persistence or retry behavior is implemented.

part_digest is SHA-256 over `ns.account.usage.part.v1` followed by a zero byte
and the canonical eleven-field array obtained by omitting part_digest from the
report. It therefore commits all ownership, profile, sequence, window, partition
metadata and rows. A changed payload must not reuse a frozen digest.

## Answer, watermark and repair

UsageAnswer is `[1, reporter, incarnation, profile, sequence, part_index,
part_digest, outcome]`. Correlation compares every field to the immutable pending
part. An answer from another reporter, lifecycle, profile, sequence, index or
digest is refused. Outcomes are:

- `[0, accepted_through]`: durable contiguous acknowledgement, including an
  identical duplicate. accepted_through must cover this part's sequence.
- `[1, watermark]`: conflict, never an acknowledgement. Watermark is null
  (absent), [0] (malformed), or [1, accepted_through] (present, including zero).
- `[2, code]`: permanent rejection; code 0 forbidden, 1 invalid request.
- `[3, issuer, participant, roster_version, node]`: unknown historical relay
  mapping, requiring repair. The scope/version/node must belong to this relay
  report, and cannot acknowledge service usage or another historical epoch.

No error is an acknowledgement. Duplicate comparison validates the exact
retained ownership key and identical canonical content, without storing state or advancing a watermark.
Duplicate acceptance is the same ACK bytes;
changed duplicate content has a different digest and cannot correlate to that
ACK. The caller owns durable duplicate and sequence/window checks.

## Independent consumers and migration

The Python usage producer generates bytes without reading Rust output.
`service_usage_vectors` checks completed write/send/echo, malformed payer and
canonical bytes, including the same UserId in two realms and exact historical
grant comparison. `relay_usage_vectors` checks both endpoint classes, historical
epochs, both directions, gateway exclusion and unknown mapping repair.
`usage_report_vectors` and `usage_answer_vectors` check immutable digest and
reporter/part correlation, duplicate ACK, conflict and typed errors.

The older account usage fixtures migrate from a 32-byte identity subject to a
16-byte ULID subject, with version and tuple arity unchanged. The review request
records the incompatible predecessor. These fixtures establish candidate
behavior only. NSD producer confirmation, historical ownership storage and real
producer vectors remain outstanding. The existing gateway neutral echo recorder
uses message quantities and needs explicit completed-byte instrumentation before
adopting this profile; no implicit message-to-byte conversion is authorized.

## Scoped quantity catalogue publication

The new family 9 `usage-profile` candidate payload is `[1, reporter, profiles]`,
with the full validated reporter identity and a nonempty strictly sorted subset
of the existing `l8-completed-io-v1` and `l8-relay-data-v1` identifiers. See the
[profile publication specification](profile-publications-candidate.md) for exact
signatures, independent canonical fixtures and context validation. These identifiers
reference the complete quantity and parameter definitions above; they introduce
no overrides. Replacement/withdrawal clears only the scoped catalogue, never
captured usage, pending reports, incarnations, batching or sequence/ACK custody.
Independent expected-reporter comparison remains mandatory. Existing usage report
and ACK bytes are unchanged. NSD/ns review, producer-owned vectors and producer
adoption for this new candidate payload remain outstanding.
