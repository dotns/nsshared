# Service grants, payers and resource authority

## Purpose

This specification defines the provider-recipient service authority payloads
of the account payload profile (see [profile.md](profile.md) for the family
registry):

| Family | Kind | Channel | Payload |
| --- | --- | --- | --- |
| 3 | `egress-grants` | snapshot | `GrantPublication` with Egress grants |
| 4 | `exit-grants` | snapshot | `GrantPublication` with Exit grants |
| 5 | `payer-bindings` | snapshot | `PayerBindings` |
| 6 | `resource-authority` | stream | `ResourceAuthority` |

Family 4 also has the `subnet-routes` kind, the consumer route view, which is
specified with the Exit route views in [subnet.md](subnet.md). Complete Node L3
authority is family 11 `node-l3` on the snapshot channel and is specified in
[node.md](node.md); its complete bindings, scopes and rules are supplied
atomically.

The existing authenticated signed publication carries these payloads (see
[publication.md](publication.md)). Transport, signature verification, outer
realm and scope, and version ownership are those of that carrier.

### Common encoding

All payloads are schema 1 and use strict shortest-form, definite-length CBOR
with no trailing bytes. Each payload is at most 1 MiB and each collection has at
most 8,192 entries.

- Resources are existing M6 `ServiceRef` values embedded as canonical byte
  strings using the M6 codec (`resource_bytes`).
- Identity fields (issuer, recipient, client, provider) are full validated
  Ed25519 keys.
- Realm identities are the [canonical RealmId](../realm-id.md) in its 16-byte
  binary form.

Authentication, current time, installed peers, the local floor and persistence
remain consumer responsibilities.

## Payers

A `Payer` is `[payer_realm, payer_subject]`. Both components are exactly 16
bytes: `payer_realm` is the paying realm's binary RealmId and `payer_subject` is
that realm's local UserId ULID in unsigned big-endian byte order. Text, tags,
IdentityKey bytes, hashes and padding are refused; there is no conversion,
fallback or tagged union.

Grant payers and service usage payers are the same binary realm/UserId pair
(see [usage.md](usage.md)). Service usage keeps that pair for historical
attribution; grant payloads define no usage bytes.

Every grant and payer binding carries a `payers` array that must contain exactly
one payer, including when several supplied values are equal. Zero entries and
multiple entries are distinct typed refusals (`MissingPayer` and
`AmbiguousPayer`).

No payer is inferred from client identity, resource realm or packet addresses.
NSD authenticates the resource proposal and the paying administrator's
acceptance before emitting authority; no additional acceptance proof is part of
these payloads.

## Service grants

### Grant tuple

`ServiceGrant` is the seven-field tuple `[resource_bytes, client, provider,
payers, incarnation, expires_at_unix_ms, details]`:

- `resource_bytes` is the canonical M6 `ServiceRef`.
- `client` and `provider` are full identities.
- `payers` contains exactly one `Payer`.
- `incarnation` is an opaque 16-byte lifetime token.
- `expires_at_unix_ms` is a positive, absolute Unix-millisecond hard deadline.
  Consumers deny at actual expiry.
- `details` are the family-specific grant details.

### Details

Egress details (family 3) are `[0, floor, name, protocol, virtual_port,
alias_generation]`:

- `floor` is the exact local declaration reference string, 1 to 256 UTF-8 bytes.
- `name` is the exact projected listener name, 1 to 256 bytes.
- `protocol` is 6 (TCP) or 17 (UDP).
- `virtual_port` is 1 to 65535.
- `alias_generation` is null for a non-alias or `[positive_u64]`. Consumer
  admission compares it with local alias ownership without guessing.

Exit details (family 4) are `[1, subnet_publication_bytes]`. The embedded
existing Subnet publication must contain exactly one route matching the grant's
resource, client and provider. Its real and mapped prefixes, exclusions,
bypasses and default or explicit selection follow the existing Subnet selection
contract and its independently computed CIDR output. NSD sends no local source
address, interface or route binding, and Exit grants carry no floor; see
[subnet.md](subnet.md) for the embedded route rules and provider-local
enablement.

### Discriminators

Every grant has a discriminator derived from its details:

| Grant | Discriminator |
| --- | --- |
| Egress TCP | `[0, 6]` |
| Egress UDP | `[0, 17]` |
| Exit | `[1]` |

Discriminators compare by numeric components, so Egress TCP orders before
Egress UDP, which orders before Exit.

### Protocol-qualified identity

The full grant key is `(resource, client, discriminator)`. Ordering, uniqueness
and admission joins use the full key, the exact token and the payer pair,
without fallback. Duplicate full keys refuse.

Each enabled protocol of a resource has its own grant, with a distinct token and
discriminator. Within a resource, independent grant keys must have distinct
lifetime tokens: reusing a token across keys refuses, including across
successor publications.

Every admission joins the exact full key, the incarnation and the payer pair.
No field is inferred from arrival order or from an unqualified resource/client
lookup.

## Grant publications

### Layout

`GrantPublication` is `[1, family, issuer, recipient, revision, grants]`:

- `family` is 3 for Egress or 4 for Exit, and every grant's details must match
  it.
- `recipient` is the provider, and every grant's `provider` must equal it.
- `revision` is positive.
- `grants` are strictly ordered by `(resource, client, discriminator)`.

The authenticated publication scope must match every resource's NSD and network
and the exact issuer and recipient.

### Replacement and withdrawal

Each publication is a complete replacement of its named scope. A complete empty
grant set withdraws only that named publication. Missing or malformed input
never means empty.

### Renewal

A successor publication must have the same family, issuer and recipient and a
strictly greater revision. In a successor:

- A token retired for the grant's resource refuses (`RetiredIncarnation`).
- A token present in the previous publication for the same resource may be kept
  only when every grant field except the deadline is unchanged, including the
  embedded Subnet bytes, and the deadline is equal or later.
- An earlier deadline and every other change under a kept token refuse
  (`ReusedIncarnation`).

The grant publication supplies the deadline. Renewal never revives retired
tokens and remains subject to actual expiry and to the validity of the
enclosing authority. Usage attribution across a renewal keeps the same tokens
and payer pairs. Signed source binding remains mandatory (see
[publication.md](publication.md)).

## Payer bindings

`PayerBindings` (family 5) is `[1, 5, issuer, recipient, revision, bindings]`,
with a positive revision. Each binding is the five-field tuple
`[resource_bytes, client, incarnation, payers, discriminator]`, with exactly one
payer as in [Payers](#payers). Bindings are strictly ordered by
`(resource, client, discriminator)`. Any other binding arity refuses, with no
fallback.

A service admission joins the entire resource, client, discriminator and
incarnation context and both payer components. The payer publication alone
grants no service permission.

## Resource authority

### Layout

`ResourceAuthority` (family 6) is `[1, 6, issuer, recipient, revision, active,
retired]`:

- Active claims are the four-field tuples `[resource_bytes, client,
  incarnation, discriminator]`, strictly ordered by resource, client and
  discriminator. Any other claim arity refuses, with no fallback.
- Retired entries are `[resource_bytes, incarnation]`, strictly ordered by both
  fields.

Any active token that is retired for its full resource is refused, across all
clients. Tokens cannot be shared across independent keys within a resource.

### Admission join

`ResourceAuthority::validate_grants` joins the exact issuer, the exact recipient
and every grant's resource, client, discriminator and incarnation against the
current active claims. Decoding either payload alone does not perform that
admission join. Consumers also compare the exact payer assignment and the local
floor, and deny at actual expiry.

### Retirement

Retirement is keyed by resource and incarnation, with retained history.
Successor validation requires:

- matching issuer and recipient;
- a strictly increasing revision;
- preserved retirement history;
- retirement of every removed or replaced claim.

This is validation of caller-owned snapshots, not a runtime state machine. The
caller retains history durably.

### Withdrawal and regrant

Removing a claim retires its token. Unchanged claims and independently
authorized resources survive a selective removal unchanged. An
identical-content regrant after removal needs a fresh token; retired lifetimes
cannot renew.

### Related admission contracts

Exit route views carry route selection information only, never grant, payer or
incarnation authority; see [subnet.md](subnet.md). Provider admission of
mapped Subnet routes joins this authority with the selected route and local
enablement; see [node.md](node.md).

## Code and vectors

Code lives in `crates/nsshared-control/src/account/families/grants/`, with public
items at `nsshared_control::account::grants`:

| File | Public items |
| --- | --- |
| `grant.rs` | `ServiceGrant`, `GrantDetails`, `GrantDiscriminator`, `GrantPublication` (including `validate_successor`), `GrantError` |
| `payer.rs` | `Payer`, `PayerBinding`, `PayerBindings` (including `validate_grants`) |
| `authority.rs` | `GrantClaim`, `RetiredGrant`, `ResourceAuthority` (including `validate_grants` and `validate_successor`) |

The grant lifetime token type is `nsshared_control::account::node::GrantIncarnation`.

The test module `account::grants::grant_authority`
(`crates/nsshared-control/tests/account/grants/grant_authority.rs`) with the
independent vectors `crates/nsshared-control/tests/vectors/account/grants/grant-authority.vec`
exercises accepted and typed refused contracts, selective withdrawal and fresh
regrant. Its `protocol_grant_renewal` sequence covers dual protocols,
deadline-only renewal, content refusal, selective withdrawal, fresh regrant and
Exit renewal.
