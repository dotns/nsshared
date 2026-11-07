# Default Exit floor profiles

The existing M6 `report.replace` complete-floor carrier supports configured Default Exit
profiles alongside explicit profiles. `FloorContent` retains `floor_version = 1`, the
`ns.service.floor.v1` digest domain and its existing fields. Empty extensions retain the
exact legacy report encoding and digest.

Each Exit profile remains the five-element tuple
`[reference, selection, enabled, capabilities, policy_labels]`. Its selection is exactly:

| Selection | Canonical CBOR value | Hex |
| --- | --- | --- |
| Default | `[0]` | `8100` |
| Explicit | `[1, prefixes]` | Existing encoding unchanged |

Default has no CIDR payload. Extra elements, empty selections, unknown tags, wrong tag types
and malformed tuples are refused. Explicit CIDRs retain their canonical spelling, strict
ordering, non-overlap and bounds checks. Default does not imply that IPv6 is offered;
address-family availability remains a property of the accepted gateway configuration and
existing selection scope. Explicit `/0` prefixes remain explicit selections, with distinct
canonical bytes and digest from Default.

The complete report, metadata and Exit profiles remain covered by one floor digest.
Authenticated requests and accepted replies retain their exact publisher, NSD, Network,
runtime, generation, authority epoch, request, revision, nonce and complete-digest
correlation. Replacing Default with Explicit, changing intent or removing profiles changes
the digest. Omission in the next complete floor withdraws the omitted profile; it is not a
partial patch. Metadata references, profile order, labels and collection limits remain
validated for both selections.

## Compatibility and immutable delivery

A Default-capable producer and every consumer on its path must use a verified immutable
nsshared revision containing this encoding and decoding contract. Consumer verification
must include the independent `default_floor_cbor`, `default_message_cbor` and
`signed_default` fixtures in `crates/nsshared-control/tests/vectors/service/floor.json`,
including malformed-selection refusal and authenticated acknowledgement correlation.
The existing explicit fixture bytes, digests and signed envelopes remain unchanged.

The explicit-only revisions `9969abd8507ea3de057b0b870492755908206e89` and
`e8ee4f3a00d4bb8b396eb889cc4a6fd2629954b6` refuse Default. The presence of the Rust enum
variant, `floor_version = 1`, or support for explicit `/0` prefixes does not establish
Default compatibility. Legacy `ReportContent` and `Message` decoders also refuse the extended
floor and its complete message. The existing `DefaultExitUnsupported` error code remains
valid for explicit-only consumer refusals.

Deliver the verified source through a pushed immutable commit, and pin that exact full
revision in each consuming manifest and lockfile. From `v0.8.0`, the account
carrier is available without feature flags. Record the actual gateway producer, NSD admission/selection consumer and client
consumer revisions together with that shared revision. A matching shared pin establishes
schema compatibility only; each component must also implement its existing Default path.
An unverified or unsupported producer/consumer tuple stays unavailable. Do not publish a
Default floor to an explicit-only consumer, silently drop the profile, retry with rewritten
prefixes, or fall back to a legacy digest. A rollback must withdraw Default through the
compatible complete-floor path before restoring explicit-only consumers.

## Authority boundary

An enabled profile is configured intent, capabilities are observations, and policy labels
are data. Encoding, authenticating or accepting the report supplies no grant. No capability
bit, enrollment authority, policy store or alternate authority carrier is added.

NSD still compares approved enrollment, current reporter runtime and contribution custody,
provider, mapping ownership and Network before deriving an existing Exit candidate and
canonical resource. Selection still requires the client's authenticated choice, current
policy and mapping/use authority, payer consent, a correlated receipt and the existing
scoped signed grant. The client and gateway retain their existing resource, scope, identity,
provider, payer and incarnation comparisons. Schema support alone does not qualify gateway
enrollment, grant issuance, route ownership, endpoint continuity, NAT or Internet delivery.
