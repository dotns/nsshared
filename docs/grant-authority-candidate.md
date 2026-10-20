# Service grant authority candidate

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
Entries are strictly ordered by `(resource, client)` and must match family and
provider recipient. A complete empty set withdraws this named publication;
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
is `[resource_bytes, client, incarnation, payers]`, strictly ordered by
`(resource, client)`, with exactly one payer as above. A service admission joins
the entire resource/client/incarnation context and both payer components;
the payer publication alone grants no service permission.

Resource authority: `[1, 6, issuer, recipient, revision, active, retired]`.
Active claims are `[resource_bytes, client, incarnation]` sorted by resource and
client. Retired entries are `[resource_bytes, incarnation]` sorted by both fields.
Any active token retired for that full resource is refused, across clients.
Successor validation requires matching issuer/recipient, increasing revision,
preserved retirement history and retirement of every removed/replaced claim.
This is validation of caller-owned snapshots, not a runtime state machine.
The caller retains history durably. An identical-content regrant after removal
needs a fresh token. Changed grant content also requires a fresh token; the
grant successor validator compares the complete prior entry. Unchanged claims
and independently authorized resources survive selective removal unchanged.
`ResourceAuthority::validate_grants` joins the exact issuer, recipient and every
resource/client/incarnation against current active claims; decoding either
payload alone does not perform that admission join. Consumers also compare
the exact payer assignment and local floor and deny at actual expiry.

Node authority is the wrapper in the account profile. The legacy policy fragment
bytes are unchanged. Complete bindings, scopes and rules are supplied atomically.
Candidate fixtures supply authority; they do not establish live interoperability.
NSD's current producer uses string ULIDs, integer-array peer keys and its
NodeL3Config resource graph. Outstanding producer work must map authenticated
machine identities to full I/K bindings, authority namespaces and explicit rules,
emit binary payer UserId/realm pairs, exact floor and service references,
incarnations and deadlines. Service usage retains its predecessor subject until
its separate coordinated wire revision; it is not interchangeable with this payer.
