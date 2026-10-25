# Subnet routes, Exit grants and provider mappings

## Purpose

This specification defines family 4 of the account payload profile: Subnet
prefixes and selection, the standalone Subnet publication that a client
receives as its route view, Exit grants that a provider receives, ordinary
provider Subnet route reports with their stable M6 allocations, and the
provider mapping inventory that establishes report eligibility.

Membership realm identities follow the [canonical RealmId](../realm-id.md)
contract. Shared encoding rules and the family registry are in
[profile.md](profile.md); publication delivery, source bindings and source
decisions are in [publication.md](publication.md); the confidential carrier,
route commands and applied status are in [control.md](control.md); grant,
payer, resource authority and renewal rules are in [grants.md](grants.md);
Node L3 and its boundary with mapped routes are in [node.md](node.md).

Family 4 has three snapshot kinds, each with its own decoder. The payloads
cannot substitute for each other.

| Kind | Recipient | Payload | Replacement clears |
| --- | --- | --- | --- |
| `exit-grants` | provider | GrantPublication with Exit details | `routes,grants,exclusions,bypasses,selection` (primary family row) |
| `subnet-routes` | client | standalone Subnet publication | `routes,exclusions,bypasses,selection` |
| `provider-mappings` | provider | complete eligible mapping inventory | `mappings` |

Authority and authenticated recipient scope are always supplied by the caller;
validation and decoding grant no authority. The contracts are pure: they
perform no persistence, interface binding or route installation.

## Prefixes and Subnet selection

### Prefixes and sets

A prefix (`SubnetPrefix`) is `[family, address_bytes, length]`: family 4 with
exactly four network-order octets and length 0..32, or family 6 with sixteen
octets and length 0..128. Host bits must be zero. Prefix lists use strict
lexicographic order by family, address bytes, then length; duplicates and
overlaps within a list fail.

### Real and mapped prefixes

For real IPv4, mapped must be IPv6 with length `96 + real.length` and its low
32 bits must equal the real network exactly. The high 96 bits name the mapping
namespace. For real IPv6, mapped equals real; this carries no native IPv6
Internet Exit promise.

### Exclusions and bypasses

Exclusions and bypasses must be contained in real and mutually disjoint,
including across the two lists. Bypasses remain separate in the returned route;
they are not silently converted to exclusions.

### Selection and defaults

Selection (`SubnetSelection`) is `[0, []]` for a logical default, which requires
real to have length zero, or `[1, prefixes]` for explicit named prefixes,
including an empty selection. Explicit selections must be contained in real. A
default with named prefixes is refused as mixed selection. Different routes may
carry nested default and specific real prefixes: results remain associated with
their stable resources, without runtime priority or winner selection.

The selected destination set is the default real prefix or the explicit set
minus exclusions, emitted as a sorted minimal disjoint CIDR cover
(`SelectedSubnetRoute`).

### Coverage

Coverage (`SubnetProxyCoverage`) is explicit TCP, UDP and echo for a nonempty
selected real IPv4 set; all three are false for real IPv6 or an empty
selection. Payload and output contain no interface, local source address, host
port, host binding or runtime state.

## Subnet publications and route views

### Publication

Kind `subnet-routes` carries the standalone complete route view
(`SubnetPublication`) encoded as
`[1, 4, nsd_id, network_id, recipient, revision, routes]`. IDs use M6 `Id`;
recipient, provider and client use M6 `Identity` with validated full Ed25519
keys; revision is positive. A complete empty routes array withdraws all routes
within this scope. Missing, partial or malformed publications fail. Grants,
payer and incarnation are separate contracts ([grants.md](grants.md)).

### Routes

A route (`SubnetRoute`) is `[resource_bytes, real, mapped, provider, client,
exclusions, bypasses, selection]`. `resource_bytes` embeds exactly the canonical
M6 `ServiceRef::value` bytes, encoded and decoded by the M6 service-control
codec (`nsshared_control::service`); no M6 serializer or reference type is
duplicated. The embedding uses the one-way dependency from the account payloads
to the M6 contract; no reverse dependency exists. The reference NSD and Network
must match the publication; client must equal recipient. Routes are strictly
ordered by full `ServiceRef`, with no duplicates.

### Bounds and refusals

Bounds are 256 routes (`MAX_SUBNET_ROUTES`) and 256 prefixes per input list
(`MAX_SUBNET_PREFIXES`), 32,768 selected prefixes per route
(`MAX_SELECTED_PREFIXES`) and 1 MiB per publication. Validation never sorts or
repairs inputs. Typed `SubnetError` refusals distinguish mapping mismatch,
outside exclusion, bypass or selection, overlap, ordering and duplicates,
misalignment and length, mixed and default selection, unknown family, selection
or schema, scope and identity, bounds, and strict CBOR errors (including
trailing and nonminimal encodings).

### Client route views

The `subnet-routes` recipient equals the client, and one view may contain routes
from several providers. Route views carry selection information, never provider
grant, payer or incarnation authority, and never independently authorize
traffic service. Select and clear receipts ([route commands](control.md#route-commands-and-receipts)) are
immutable command outcomes, separate from replaceable route views.

## Exit grants and client route views

### Exit grants

Kind `exit-grants` carries the GrantPublication
`[1, 4, issuer, recipient, revision, grants]` ([grant publications](grants.md#grant-publications)), with
recipient equal to the provider. Exit details are `[1, subnet_publication_bytes]`:
the embedded Subnet publication contains exactly one route matching the grant's
resource, client and provider, and its embedded recipient equals the client,
not the outer provider. Its real and mapped prefixes, exclusions, bypasses and
default or explicit selection follow [Prefixes and Subnet selection](#prefixes-and-subnet-selection)
with the independently computed CIDR output. NSD sends no local source address,
interface or route binding.

There is no Exit floor on the wire. Provider-local enablement and Linux source,
interface and route bindings are independently validated before admission.
Egress carries its wire floor reference under its own contract
([grant details](grants.md#details)).

### Source and membership

Both views, provider `exit-grants` and client `subnet-routes`, use the
recipient's current nodes binding in the event's Network, with event scope
`nodes`; recipient and source_node equal that Node. Family 3 `egress-grants`
keeps its independent provider `egress` contribution binding; a nodes binding
cannot substitute. Nodes enrollment alone grants no Exit resource. Source
decision APIs enforce these scopes, including for complete-empty withdrawals.
Exact retained binding and pending delivery context comparisons are mandatory.

Client view validation compares independently accepted identity,
`MembershipScope` NSD and Network IDs, the event served realm (the same Network
bytes), and payload revision against event version. The M6 NSD ID is not the
signing key.

### Replacement and withdrawal

Each complete view replaces only its exact
issuer/recipient/Network/scope/family/kind collection. Empty withdraws that
collection and omission removes a route; neither clears another provider or
another kind, including when a Node is both client and provider.

### Admission

Provider admission and client route selection are defined in
[node.md](node.md#mapped-route-admission): a mapped-prefix destination resolves
to its exact resource and selected route, never to a Node L3 rule, and a client
view alone cannot authorize service.

### Consumer sequence

1. Authenticate with `nsshared_control::account::publication::decide_source_publication`
   (or the source snapshot API `decide_source_snapshot`).
2. Call `PublicationEvent::validate_routing_context` with the independently
   retained identity and `nsshared_control::account::control::MembershipScope`
   before installation.
3. `PublicationEvent::decode_grant_payload` and
   `PublicationEvent::decode_subnet_payload` select by exact kind, compare
   payload envelope facts and expose the owning types.

The generic publication decision refuses malformed routing payloads before any
version can advance. Source decisions enforce nodes versus egress ownership.
`FamilyRegistry::replacement(4, "subnet-routes")` exposes the per-kind exact
replacement rule; canonical family registry bytes retain the primary family row.

## Provider Subnet route reports

### Wire

`node.subnet.report` (`nsshared_control::account::control::NODE_SUBNET_REPORT`)
is a request and response operation using the authenticated confidential
BootstrapEnvelope in both directions ([signed confidential carrier](control.md#signed-confidential-carrier))
and the signed nodes source authority ([source binding](publication.md#source-binding)).

- `NodeSubnetRouteReport` payload is
  `[1, bstr(SignedSourceBinding), report_generation, offers]`, with each offer
  (`SubnetRouteOffer`) `[subnet_id, selection]`.
- `NodeSubnetRouteReportResponse` payload is
  `[1, bstr(SignedSourceBinding), report_generation, allocations]`, with each
  allocation (`SubnetRouteAllocation`) `[subnet_id, bstr(canonical_M6_ServiceRef)]`.

Arrays have exact arity, definite lengths and shortest unsigned integers; extra
fields and trailing bytes are refused. Generation is a positive u64. Mapping ids
are nonzero u32, ascending and unique. Each list has at most 256 entries
(`MAX_SUBNET_OFFERS`). Payloads have an inclusive 1 MiB encoded limit,
independent of the route command ceiling and applying alongside carrier and
transport limits.

Selection is the exact `SubnetSelection` representation: `[0, []]` explicitly
offers the logical default; `[1, prefixes]` offers strictly ordered
nonoverlapping network-aligned prefixes, at most 256 per offer. Empty explicit
offers no destinations. Named destinations must fit the mapping's committed real
prefix, with the same family; default requires a real /0. No absent-field
default, chunking, truncation or repair exists. M6 supplies the reference
encoding directly. Reports are separate from M6 declarations, Subnet
publications and route commands, whose bytes are defined by their own
contracts.

### Authority

NSD enrollment and source custody supplies the full signed nodes binding,
including the assigned profile, full Node identity, source record, epoch and
generation. The only defined profile is `explicit-gateway-profile`; no other
profile is inferred. The caller supplies its exact current committed binding
and authenticated caller identity (`SubnetReportAuthority`). The nested
signature and every binding field must match; an egress binding cannot
substitute. A retired binding is refused even when replaying identical report
content.

NSD mapping custody supplies mapping id, Network, real and mapped prefix,
provider membership and active provider authority. Pure input
(`SubnetMappingAuthority`) exposes the owning Network, full provider identity,
active eligibility and real prefix needed for report qualification. The caller
resolves those facts transactionally, including membership and mapped-prefix
validity. Offered ids and configured prefixes are intent, never authority.
Report acceptance grants no membership, consumer permission, selection or
applied routing.

The caller supplies the identity-bound M6 NSD id separately from the NSD signing
identity, and the exact Network id. Network equals the binding's served RealmId
bytes. Reference NSD and Network components must equal these independently
committed facts. NSD alone allocates unique service ids in its existing
namespace; no mapping number conversion or private-service reference
substitution is defined.

The request carrier authenticates Node, NSD recipient, request direction,
operation, freshness, signature and a fresh nonzero nonce. A retry keeps
generation and content but uses a fresh carrier nonce. The response carrier
authenticates trusted NSD, explicit reporting Node recipient, response
direction, operation and pending nonce.

### Generations and allocation history

A newer generation replaces the complete source-owned offer set. Omission
withdraws a live offer and an empty set withdraws all. Equal generation with
exact content returns the retained allocation result; changed content at an
equal generation conflicts; older generations are refused. Accepted generation,
content and allocations are retained after withdrawal and restart
(`RetainedSubnetReport`).

Allocation custody (`SubnetAllocationHistory`) is keyed by
`(NSD, Network, full signed source binding, subnet_id)`. Retained allocations
include withdrawn ids. Updates and reoffers must reuse them; a response cannot
replace an already assigned reference. Other sources have independent history
and remain usable.

### Decisions and comparisons

`decide_subnet_report` qualifies the current source, mappings and complete
generation against retained custody and returns `SubnetReportDecision::Replace`
(atomically replace the complete offered set, retaining prior allocation
custody) or `SubnetReportDecision::Retry` (return the exact retained allocation
response without reapplying mutation). Pure functions return decisions and
validate proposed results without mutating caller state or assigning ids.
Callers commit all facts atomically and preserve history. Current authority is
checked before a retry.

The provider retains the exact pending report and compares the response's
binding, generation, mapping ids and order, current source, and each reference's
NSD, Network and prior assignment (`NodeSubnetRouteReportResponse::from_envelope`
and `compare`). It also compares against the last accepted report: older
generations and changed equal-generation content are refused, even when an old
pending request remains in custody. Delayed responses of a retired source
cannot restore offers. Refusals are typed by `SubnetReportError`.

## Provider mappings

### Inventory

Kind `provider-mappings` (`ProviderMappings`) is a Snapshot-only complete
replacement with clears `mappings`. Its canonical CBOR is `[1, mappings]`, with
entries (`ProviderMapping`) `[subnet_id, real_cidr]`. Ids are nonzero u32,
strictly ascending without duplicates, at most 256 entries
(`MAX_PROVIDER_MAPPINGS`). The payload ceiling is 1 MiB. `real_cidr` is exactly
the Subnet prefix `[4, bstr(4), length]` or `[6, bstr(16), length]`, with
network alignment. Malformed, noncanonical and oversized input is refused
without repair.

The inventory is the complete eligible set, independent of grants and client
routes. It carries no ServiceRef, mapped prefix, selection, grant, payer or
permission, and is separate from report, allocation, grant and client route
bytes.

### Eligibility

The signed outer event supplies version and validity. Independently accepted
issuer, provider identity, Network membership, current nodes source, pending
Snapshot context, retained versions and clock establish authority. Binding
recipient and source_node both equal the provider; event scope is `nodes`. Both
actual and signed channels must be Snapshot and replacement must be complete.
Decoding alone, or an accepted nodes binding or nodes enrollment alone,
establishes no mapping eligibility; the exact current nodes source, provider
recipient and source_node, accepted issuer and Network, pending Snapshot
context, signatures, version and validity must all pass.

NSD committed mapping and provider custody produces eligibility independently
of reports, selection and grants; Node custody supplies the current nodes
binding, and the publication owner persists versions and validity. Providers
compare configured mapping id and real prefix before offering; explicit
destinations stay within the real prefix and default requires /0. NSD rechecks
committed authority on reports.

### Replacement and withdrawal

A newer valid set replaces only its exact
issuer/recipient/Network/scope/family/kind inventory. Omission removes
eligibility. Typed `[1, []]` and authenticated empty payload withdrawal clear
only this inventory, preserving grants, client routes and other providers.
Transport failure does not clear still-valid state. Expiry, source retirement,
authenticated failure and replay rules of the publication contract apply
([publication.md](publication.md)).

## Code and vectors

Code (crate `nsshared-control`, public items at `nsshared_control::account::subnet`):

| Area | Source | Public items |
| --- | --- | --- |
| Prefixes, selection, publications | `crates/nsshared-control/src/account/families/subnet/views.rs` | `SubnetPrefix`, `SubnetSelection`, `SubnetRoute`, `SubnetPublication`, `SubnetProxyCoverage`, `SelectedSubnetRoute`, `SubnetError`, `MAX_SUBNET_ROUTES`, `MAX_SUBNET_PREFIXES`, `MAX_SELECTED_PREFIXES` |
| Provider reports | `crates/nsshared-control/src/account/families/subnet/report.rs` | `NodeSubnetRouteReport`, `NodeSubnetRouteReportResponse`, `SubnetRouteOffer`, `SubnetRouteAllocation`, `SubnetReportAuthority`, `SubnetMappingAuthority`, `SubnetAllocationHistory`, `RetainedSubnetReport`, `SubnetReportDecision`, `SubnetReportError`, `decide_subnet_report`, `MAX_SUBNET_OFFERS` |
| Provider mappings | `crates/nsshared-control/src/account/families/subnet/mapping.rs` | `ProviderMapping`, `ProviderMappings`, `MAX_PROVIDER_MAPPINGS` |

Routing payload decoding is at `nsshared_control::account::publication::PublicationEvent`
(`decode_grant_payload`, `decode_subnet_payload`,
`decode_provider_mapping_payload`, `validate_routing_context`); replacement
rules are at `nsshared_control::account::publication::FamilyRegistry::replacement`.

Tests and vectors:

| Contract | Test module | Vectors |
| --- | --- | --- |
| Prefixes, selection, coverage | `account::subnet::selection` | `crates/nsshared-control/tests/vectors/account/subnet/selection.vec` |
| Exit grants and client route views | `account::subnet::views` | `crates/nsshared-control/tests/vectors/account/subnet/views.vec` |
| Provider reports | `account::subnet::report` | `crates/nsshared-control/tests/vectors/account/subnet/report.vec` |
| Provider mapping replacement | `account::subnet::mapping` | `crates/nsshared-control/tests/vectors/account/subnet/mapping.vec` |
| Mapping inventory well-formedness | `account::subnet::mapping_inventory` | `crates/nsshared-control/tests/vectors/account/subnet/mapping.vec` |
| Mapping snapshot actions | `account::subnet::mapping_actions` | `crates/nsshared-control/tests/vectors/account/subnet/mapping-actions.vec` |

The independent Python Subnet producer computes CIDR subtraction and coverage
using `ipaddress`; Rust consumers read decisions, canonical bytes, every route
field and expected outputs directly from the shared vectors.

The `subnet_publication_views` sequence in `account::subnet::views` accepts
providers P and Q and client C under their nodes bindings without an Exit floor;
rejects kind, recipient, source and membership mismatches; empties P without
changing Q or C; omits P from C's newer view; then empties C without clearing Q.

The `provider_subnet_report` sequence in `account::subnet::report` consumes
Python-produced bytes independent of Rust. It accepts A's explicit and default
offers, retries and updates without reference changes, withdraws one then all
offers, reconstructs retained state, refuses stale restoration, reoffers using
retained allocations, retires A and refuses delayed reports and responses while
B remains usable. Wrong source, profile and mapping association must refuse
without mutation. Further malformed wire, carrier, bounds and reference
variants exercise the same contract.

The `provider_mapping_replacement` sequence in `account::subnet::mapping`
covers populated, changed or omitted and empty sets, and authority and payload
refusals with vector authorities.
