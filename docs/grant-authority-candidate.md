# Service grant authority candidate

Membership realm identities follow the [canonical RealmId contract](canonical-realm-identity.md).
Affected text positions retain text but require the exact uppercase 26-character
spelling and decode to RealmId; binary positions retain their exact 16 bytes.
This incompatible candidate delta refuses arbitrary realm labels without fallback.
NSD/ns producer and consumer updates, including the other active consumer delivery,
remain outstanding. Encoding equality is not authentication. Discovery realm hints,
external provider subject namespaces and opaque scopes retain their meanings.
Signed usage bytes and the historical payer pair remain unchanged.


These pure candidate payloads use strict shortest-form definite-length CBOR,
schema 1, at most 1 MiB and at most 8,192 entries per collection. Existing M6
ServiceRef values are embedded as canonical byte strings using the M6 codec.
Identity fields are full validated Ed25519 keys. Authentication, current time,
installed peers, local floor and persistence remain consumer responsibilities.
The existing authenticated publication kinds carry these payloads: family 3
`egress-grants`, family 4 `exit-grants` and family 5 `payer-bindings` use the
snapshot channel; family 6 `resource-authority` uses the stream channel. Complete
Node L3 authority is family 11 `node-l3` on the snapshot channel. Transport,
signature verification, outer realm/scope and version ownership are unchanged.

Grant publication: `[1, family, issuer, recipient, revision, grants]`, family
3 for Egress or 4 for Exit. Recipient is the provider, revision is positive.
Entries are strictly ordered by `(resource, client, discriminator)` and must
match family and provider recipient. A complete empty set withdraws this named publication;
missing or malformed input never means empty. Authenticated publication scope
must match every resource's NSD/network and the exact issuer and recipient.

Grant: `[resource_bytes, client, provider, payers, incarnation, expires_at_unix_ms,
details]`. Expiry is positive, absolute Unix milliseconds; consumers deny at
actual expiry. Incarnation is an opaque 16-byte token. Exactly one payer is
required, including when multiple supplied values are equal. Zero and multiple
entries have distinct typed refusals. Payer is `[payer_realm, payer_subject]`:
both exactly 16 bytes, subject the paying realm's local UserId ULID in unsigned
big-endian order. Text, tags, IdentityKey, hashes and padding are refused.
No payer is inferred from client identity, resource realm or packet addresses.
NSD authenticates resource proposal and paying administrator acceptance before
emitting authority; no additional acceptance proof is introduced here.

Egress details: `[0, floor, name, protocol, virtual_port, alias_generation]`.
Floor is the exact local declaration reference string (1..256 UTF-8 bytes),
name the exact projected listener name (1..256 bytes), protocol 6 or 17,
port 1..65535. Alias generation is null for a non-alias or `[positive_u64]`;
consumer admission compares it with local alias ownership without guessing.

Exit details: `[1, subnet_publication_bytes]`. The embedded existing Subnet
publication must contain exactly one route matching resource/client/provider.
Its real/mapped prefixes, exclusions, bypasses and default/explicit selection
retain the existing selection contract and independently computed CIDR output.
No local source address, interface or route binding is sent by NSD.

Payer publication: `[1, 5, issuer, recipient, revision, bindings]`. Each binding
is `[resource_bytes, client, incarnation, payers, discriminator]`, strictly ordered by
`(resource, client, discriminator)`, with exactly one payer as above. A service admission joins
the entire resource/client/discriminator/incarnation context and both payer components;
the payer publication alone grants no service permission.

Resource authority: `[1, 6, issuer, recipient, revision, active, retired]`.
Active claims are `[resource_bytes, client, incarnation, discriminator]` sorted
by resource, client and discriminator. Retired entries are
`[resource_bytes, incarnation]` sorted by both fields.
Any active token retired for that full resource is refused, across clients.
Successor validation requires matching issuer/recipient, increasing revision,
preserved retirement history and retirement of every removed/replaced claim.
This is validation of caller-owned snapshots, not a runtime state machine.
The caller retains history durably. An identical-content regrant after removal
needs a fresh token. A strictly newer valid publication may keep a token only when every grant field
except the deadline is unchanged and the deadline is equal or later. Earlier
deadlines and all other changes are ReusedIncarnation, including embedded Subnet
changes. Renewal never revives retired tokens and remains subject to actual expiry
and enclosing authority validity. Unchanged claims
and independently authorized resources survive selective removal unchanged.
`ResourceAuthority::validate_grants` joins the exact issuer, recipient and every
resource/client/discriminator/incarnation against current active claims; decoding either
payload alone does not perform that admission join. Consumers also compare
the exact payer assignment and local floor and deny at actual expiry.

Node authority is the wrapper in the account profile. The legacy policy fragment
bytes are unchanged. Complete bindings, scopes and rules are supplied atomically.
Candidate fixtures supply authority; they do not establish live interoperability.
NSD's current producer uses string ULIDs, integer-array peer keys and its
NodeL3Config resource graph. Outstanding producer work must map authenticated
machine identities to full I/K bindings, authority namespaces and explicit rules,
emit binary payer UserId/realm pairs, Egress floor and exact service references,
incarnations and deadlines. Service usage retains its existing binary payer
realm/UserId pair and historical attribution; this grant delta changes no usage
bytes.

## Protocol-qualified identity and renewal

Derive the discriminator from GrantDetails: `[0, 6]` for Egress TCP, `[0, 17]`
for Egress UDP and `[1]` for Exit. Compare numeric components, TCP before UDP.
The seven-field ServiceGrant tuple is unchanged. Duplicate full keys refuse.
Families 5 and 6 require the new tuple arities with no old-tuple fallback.
Every admission joins the exact full key, incarnation and historical payer pair;
no field is inferred from arrival order or an unqualified resource/client lookup.
Within a resource, independent grant keys must have distinct lifetime tokens;
reusing a token across keys refuses, including across successor publications.
Retirement stays keyed by resource/incarnation, with retained history.

The independent `protocol_grant_renewal` sequence covers dual protocols,
deadline-only renewal, content refusal, selective withdrawal, fresh regrant
and Exit renewal. Continuing usage attribution keeps the same tokens and payer
pairs; usage wire bytes are unchanged. NSD N06 producer adoption remains
outstanding: enabled protocols supply distinct tokens and discriminators, the
grant publication supplies the deadline, and signed source binding remains
mandatory. Candidate fixture acceptance does not establish producer adoption.

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

Consumer API sequence: authenticate with `decide_source_publication` (or the
source snapshot API), then call `PublicationEvent::validate_routing_context`
with the independently retained identity and `control_exchange::MembershipScope`
before installation. `decode_grant_payload` and `decode_subnet_payload` select
by exact kind, compare payload envelope facts and expose the existing owning types.
The generic publication decision refuses malformed routing payloads before any
version can advance. Source decisions enforce nodes versus egress ownership.
`FamilyRegistry::replacement(4, "subnet-routes")` exposes the additional exact
replacement rule; canonical family registry bytes retain the primary family row.

## Mapped-route admission and direct host authority

Ordinary Node-L3 rules govern direct identity-derived N6/N4 destinations only.
A Subnet mapped-prefix destination resolves to its exact resource and selected
route, never to a Node-L3 rule naming the provider. Neither provider nor client
creates or requires such a rule. Route withdrawal, exclusion or missing coverage
never falls back to a provider-wide Node rule.

Provider admission joins the current Exit owner's exact resource, authenticated
client/provider, grant incarnation, payer and expiry, embedded validated route's
real/mapped selection minus exclusions and SubnetProxyCoverage, and independently
validated local enablement/binding. Preserve resource-authority/payer joins and
retirement; a client view alone cannot authorize service.

The client selects only the named resource's selected mapped destinations and
covered TCP/UDP/echo for that route's provider, comparing client with self and
provider with the independently installed peer identity/key within the accepted
source and Network. This grants route selection only; the client receives no
provider payer/incarnation facts. Bypasses retain their existing routing semantics;
source/destination and reverse-flow ownership remain unchanged. Direct N6/N4
requires independent authority. Native IPv6 forwarding and live default Exit
remain outside this contract. See [applied status](node-l3-status-candidate.md).
