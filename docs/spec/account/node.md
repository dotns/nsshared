# Node enrollment, identity lifecycle and Node L3

## Purpose

This specification defines the node layer of the account payload profile:
family 1 enrollment of one ordinary Node membership, the identity lifecycle
that links successive bindings of that membership, local Node naming declared
at enrollment, the normalized Node L3 form and its complete authority wrapper,
and the boundary between Node L3 authority and Subnet mapped routes.

Membership realm identities follow the [canonical RealmId](../realm-id.md)
contract. Shared encoding rules, the family registry and replacement rules are
in [profile.md](profile.md); registration, authentication and information
exchanges are in [control.md](control.md#registration-and-authentication-exchanges); publication delivery and source
authority are in [publication.md](publication.md); grants, payers and resource
authority are in [grants.md](grants.md); Subnet routes, Exit grants and provider
mappings are in [subnet.md](subnet.md).

These are pure contracts. They define no runtime, transport session, policy
compiler, persistence or old-resource fencing.

## Enrollment

### Payload

Family 1 enrolls one ordinary Node membership's external NSD key binding and
its declared capability set. Enrollment CBOR is `[1, binding, capabilities]`;
`binding` is the `[membership_version, I, K, record_generation]` NodeBinding
defined in [Bindings](#bindings). NodeId, N6 and N4 are not carried: they derive
from I using the existing identity derivation. The authenticated caller supplies
the membership scope and its accepted binding; these bytes do not
prove authority or acceptance and never authorize a different membership.

### Capabilities

Capabilities are opaque identifiers, sorted in strictly increasing ASCII byte
order with no duplicates. There are 0..64 identifiers (`MAX_CAPABILITIES`),
each 1..64 bytes (`MAX_CAPABILITY_BYTES`), matching `[a-z0-9._-]+`. No
normalization or sorting occurs during validation. Empty means no declared
optional capabilities. Capability identifiers in the vectors other than
`node_local_names.v1` are examples only. Noncanonical sets, excessive counts or
lengths, non-minimal CBOR and trailing bytes are refused. This binding and
capability payload does not define the registry's endpoint contract or
authenticated envelope forms, and does not change the registry bytes.

### Local Node naming

Enrollment declares local Node naming with the capability `node_local_names.v1`,
the public constant `nsshared_control::account::node::NODE_LOCAL_NAMES_V1`, in
the Enrollment capability set. Omission does not negotiate a naming response or
fallback. The capability declares naming mode only; it grants no service
permission and no permission to publish DNS. NSD accepts the declaration through
authenticated registration without allocating or requiring a Node label.
Capability encoding and the exact exchange tuples in [control.md](control.md) are
not affected by the declaration.

The staged Node Enrollment produces the capability set; authenticated
registration acceptance must carry the exact same bytes, binding and declared
profile. Consumers compare membership, full binding, capabilities, trusted
authority and source binding before committing. A missing capability or a
mismatched acceptance never switches naming mode.

After acceptance the canonical Node name is `node_dns_name(NodeId)`, of the form
`<node id>.n.ns.io`, with NodeId derived from the accepted NodeBinding identity
and the Node zone given by the shared `NODE_DNS_ZONE` constant `n.ns.io`
(`nsshared_identity::discovery`). NodeId is never derived from a hostname or a
machine-id prefix, and the Node zone is never a remotely selected root. No
per-machine domain root, service or gateway suffix is derived from the Node
name, and none may be manufactured by string substitution. Manual nicknames
remain local, are never published as registration authority and do not alter
the identity-derived canonical Node name. Compact Node labels allocated by NSD
are not part of this contract and are not promised as aliases.

Registration carries no naming values:

- RegistrationAcceptance, AuthenticationResponse and InformationResponse carry
  none of `domain_base`, `dns_root`, `network_token` or `node_name`, and no
  registration producer, carrier or pinned-value comparison exists for them.
- There is no substitute naming publication and no shared decoder for these
  values. A consumer declaring local Node naming refuses any response or adapter
  supplying them; it must not silently accept them or compare a
  pinned naming value. The `dns_config.short_dns_v2` tuple-bound snapshot supplies no
  naming authority.
- Exact tuple validation is the shared boundary; adapter refusal belongs to
  consumers.
- `network_token` is retained only inside NSD's committed Network naming state
  for Subnet suffix consumers; it is not an enrollment identifier or a shared
  field. Any Subnet name is owned by its own authenticated projection and is
  not inferred from the Node name.

Naming sources other than the Node name keep their own contracts: verified
NodeRecord identity, name and address comparison is discovery, not
authorization; M6 `Resource.service_label` is the sole source of service labels
through the authenticated recipient and Network snapshot; public domains are in
the authenticated public-edge publication with its ownership checks
([edge.md](edge.md)); Subnet and public-edge naming keep their own suffixes,
which the Node zone does not replace; `InformationResponse.realm` is a display
hint.

Consumer commit of the naming mode:

- At the authenticated commit of local Node naming, the consumer removes all
  four naming pins and tuple-bound Short DNS authority from active state,
  without feeding absent values through a first-wins setter. Pins are never
  compared, converted into identity or recovered after restart.
- Matching acceptance drops every active pinned naming value and Short DNS
  authority; mismatched acceptance or supplied naming values leave the prior
  profile intact. Failure before commit preserves the prior selected profile.
- Records of the original profile remain isolated and preserved under existing
  custody rules; no deletion, deployment or re-enrollment is authorized by this
  contract. Startup uses the accepted binding and mode. Registration history
  and lifecycle comparisons are not affected.

### Enrollment decisions

`decide_enrollment` validates the presented publication and any accepted
binding and returns an `EnrollmentDecision`:

| Accepted binding | Presented binding | Result |
| --- | --- | --- |
| none | valid | `Initial`, without a lifecycle |
| present | equal binding, including a new valid capability declaration | `Equal` |
| present | lower membership version | refused (`LowerVersion`) |
| present | differing, no lifecycle | refused (`LifecycleRequired`) |
| present | differing, lifecycle before/after not exactly accepted/presented, or invalid lifecycle | refused (`LifecycleMismatch` or contract error) |
| present | differing, valid identity-replacement lifecycle | `IdentityReplacement` |
| present | differing, valid K-only rotation lifecycle with `RebindAuthorization::Authorized` | `RecordRotation` |
| present | differing, valid K-only rotation lifecycle without authorization | refused (`RebindUnauthorized`) |

Any differing binding needs a valid Lifecycle whose before is exactly the
accepted binding and whose after is exactly the presented binding. An absent
lifecycle refuses a differing binding, including a **rejected staged-version
restart**: restarting after staging an unaccepted replacement cannot promote
that version. Equal compares the complete binding. The accepted binding changes
only after authenticated registration acceptance; this pure decision performs no
persistence or old-resource fencing.

### Rebind authorization

Ordinary membership derivation produces one K per membership identity version.
Its stable-I K-only rotation is an explicitly authorized rebind using a K
supplied by the producer profile, never another ordinary per-version
derivation. The producer profile supplies `RebindAuthorization`; ordinary
stable-I self-initiated rebind stays disabled without that profile. Quick's
stable quick identity with a K per generation is a different profile, outside
these vectors.

Membership versions are u64 on the wire; the ordinary derivation uses positive
u32 and checked increment. Consumers must reject out-of-range versions before
ordinary derivation, without truncation.

## Identity lifecycle

### Bindings

`MembershipIdentityVersion` is a monotonically increasing derivation version
within one NSD membership. `RecordGeneration` increases only within one full
identity, shared by every served realm; existing NodeRecord same-generation
ordering and conflict rules still apply. Comparing either counter across its
scope has no meaning.

Binding CBOR is `[membership_version, I, K, record_generation]`, with positive
versions and generations and a nonzero 32-byte K.

### Transitions

Lifecycle CBOR is
`[1, transition, before, after, grant_incarnation, reporter_incarnation]`.

- Transition 0 (`IdentityReplacement`) replaces identity: membership version
  increases, both I and K change, and NodeId, N6 and N4 are rederived from the
  new I. Record generation belongs to the new identity and may restart.
- Transition 1 (`RecordRotation`) rotates only K: membership version and I stay
  fixed, K changes, record generation increases, and NodeId, N6 and N4 stay
  fixed.

Validation distinguishes these transitions; the choice of transition for a
deployment is consumer policy.

NSD compares the requested membership and authenticated presented I with
provisioned enrollment authority and the accepted binding for that membership.
For a differing binding, Lifecycle.before must equal the complete accepted
binding and Lifecycle.after the complete presented enrollment binding.
IdentityReplacement requires a higher membership identity version and different
I and K; generation belongs to the new I and may restart. RecordRotation
requires unchanged I and membership version, changed K, increased record
generation and explicit producer-profile `RebindAuthorization`. Initial
enrollment has no lifecycle, Equal compares the complete binding, and rollback,
authentication and scope checks apply.

The ns or gateway consumer makes the same comparison against its retained
binding for the exact membership and signing authority. Before committing, it
verifies authenticated acceptance against staged membership, complete binding,
profile, capabilities and the locally computed `EnrollmentDecision`, plus
response correlation, recipient and nodes-source checks. Rejection or mismatch
preserves the committed identity. Accepted history and selected-acceptance
custody are the transition state; placeholders add no durable state.

### Incarnation domains

`GrantIncarnation` and `ReporterIncarnation` are opaque 16-byte tokens: only
equality is meaningful. Every regrant, even with identical content, uses a
fresh grant incarnation; every new reporter lifecycle uses a fresh reporter
incarnation. Never use record generation or membership version as either token.

Identity replacement fences old identity resources without transferring grants
to the new I. NSD produces fresh incarnations for newly authorized grants naming
the replacement identity, carried by the signed grant, payer and resource
authority families ([grants.md](grants.md)) and compared against exact
resource, client, provider, protocol, payer and retained retirement history.
K-only rotation does not itself change identity-keyed grants or their
incarnations; NSD publishes the authenticated I-to-K change through Node L3.
Independent withdrawal, expiry and content-change rules apply.

The reporter produces and durably retains its own lifecycle token, carried with
original attribution in usage rows, reports and correlated answers; a new
reporter lifecycle uses a fresh token under the usage contract
([usage.md](usage.md)). Registration assigns or retires neither token. Pending
rows and parts keep their original reporter and grant attribution and
settlement custody.

### Registration-only placeholders

For RegistrationRequest, the last two Lifecycle positions are mandatory 16-byte
wire placeholders. The requesting Node emits sixteen zero bytes in each
position, including when it has no grants and no reporter. No NSD response,
provisioning operation or token acquisition supplies them. Receivers
structurally decode both positions and ignore their values, including nonzero
values. They are not grant or reporter authority, transition inputs or
lifecycle custody; receivers neither compare them with grants, reports or
accepted registration nor store them as retirement state. Placeholders
authorize neither transition. Nonzero placeholder vectors test receiver
structure only and do not define a registration producer form.

## Normalized Node L3 form

### Policy

L3 CBOR is `[1, issuer, recipient, revision, scopes, rules]`. The revision is
positive and complete replacement applies only to this issuer and recipient.

### Scopes

A scope is `[namespace, identities]`; namespaces are opaque identifiers
assigned by the authority, never host interface names or inferred from a
packet. Scopes are sorted by namespace; identity sets are sorted by full
identity bytes.

### Rules

A rule is `[namespace, source_identity, destination_identity, protocol,
first_port, last_port]`. Both identities must belong to that namespace's scope.
The Node-only `L3Protocol` selects the following forms:

| Protocol | Meaning | Port slots | Request | Reply |
| --- | --- | --- | --- | --- |
| 1 (`EchoV4`) | IPv4 Echo only | both zero | type 8, code 0 | type 0, code 0 |
| 6 (`Tcp`) | TCP | inclusive 1..65535, first <= last | existing TCP semantics | existing flow state |
| 17 (`Udp`) | UDP | inclusive 1..65535, first <= last | existing UDP semantics | existing flow state |
| 58 (`EchoV6`) | IPv6 Echo only | both zero | type 128, code 0 | type 129, code 0 |

TCP/UDP retain their exact existing canonical bytes. Echo's zero slots mean no
ports; they are neither wildcards nor configurable type/code ranges. Either
nonzero slot on Echo, a zero or reversed TCP/UDP range, an unknown protocol,
additional selector positions or malformed/noncanonical CBOR fails the entire
payload. Rules are sorted lexicographically by all six fields and duplicates
fail. The shared `TransportProtocol` used by non-Node families remains TCP/UDP
only; Service grants, public-edge routes and Realm rules gain no Echo authority.

Source and destination specify the Echo request direction, within the exact
Network namespace and authenticated full identity/key scope. Only the matching
reply to an admitted request may use existing reverse-flow state. An unsolicited
reply or a request in the opposite direction is not authorized. Consumers must
compare actual IP family, type and code before granting or reusing state,
including on the reply path. Existing state ownership, retirement and bounds
remain. Other ICMP types, nonzero codes, arbitrary ICMP errors and all-ICMP
permission are excluded; existing unrelated error/PMTU handling is unchanged.

An empty rule set permits no traffic; a missing set fails. Rules are an
explicit allow set; overlapping ranges mean union. There are no implicit
wildcards, payer guesses or interface-dependent identities. Compilation and
address and range ownership enforcement stay in consumers.

Bounds: scopes, rules and identities per scope are each at most 8,192, and the
encoding is at most 1 MiB.

### Runtime support and mixed versions

`node_l3_echo.v1` is an additional feature in the existing authenticated runtime
capability mechanism, alongside `node_l3_acl.v1`. A runtime may declare it only
when it can decode and enforce both exact Echo forms above. Its existing runtime
authentication request carries the feature; NSD's existing fenced authentication
transaction commits and compares the declaration for the exact current Node
custody: accepted membership, full identity and WireGuard key, Network and
current runtime fence. Registration/enrollment metadata, heartbeat observations and
runtime-less authentication cannot assert runtime Echo support. This requirement
adds no registration capability or control channel and does not change the
shared authentication tuple arities.

Before issuing Echo in a recipient publication, NSD must verify committed support
for both participating source and destination runtimes and the recipient of the
extended payload, retaining the existing `node_l3_acl.v1` requirement. Absent or unknown support omits Echo and preserves the complete
existing TCP/UDP projection. A current runtime authentication lacking the feature
removes it from that runtime's committed support and triggers the existing
affected Node L3 reprojection. Registration-owned capabilities and enrollment
approval remain independent.

New decoders accept old TCP/UDP-only publications. Old decoders refuse protocols
1 and 58; no claim is made that an old binary accepts extended payloads. Never
send Echo to an unsupported recipient, silently discard an unknown rule while
accepting its enclosing payload, reinterpret it as TCP/UDP or use a permissive
fallback. Old producers supply no Echo authority. Unverified mixed versions stay
Echo-unqualified. Authenticated withdrawal, complete replacement and actual
authority deadlines still apply.

NSD extends both existing same-owner implicit production and explicit Node policy
compilation within their accepted membership, owner and policy scope. It carries
the selector and zero slots in the canonical signed Node L3 authority, bound to
the exact source and revision. No cross-owner or non-Node authority is introduced.
Consumers compare issuer, recipient, independently authenticated installed peer
identity and WireGuard key, current Network and request direction; packet
addresses and roster membership alone grant no permission.

### Consumer enablement prerequisite

Contract decoding does not advertise runtime support or establish packet
enforcement. Consumer enablement and `node_l3_echo.v1` advertisement require a
compatible immutable released nsplane path enforcing code zero for the selected
Echo request and reply **before granting or reusing flow state**, while retaining
existing unrelated error/PMTU behavior. A type-only matcher is insufficient,
including for replies admitted through existing state. Until that path is
supplied and verified, consumers retain the complete TCP/UDP-only projection and
refuse Echo enablement. No dependency change is implied by this shared contract.

Producer and consumer handoffs must pin the verified immutable shared revision
without feature flags from `v0.8.0`; manifests and lockfiles must identify the compatible
producer, consumer and released enforcement revisions. A floating branch or a
sibling path dependency supplies no immutable contract input. Contract tests
qualify construction, canonical decoding and scope validation only. Packet
request/reply delivery and type/code enforcement require verification on the
compatible consumer tuple; retained diagnosis is input evidence, not proof of
current runtime behavior or deployment equivalence.

### Withdrawal and replacement

Membership without an explicit matching rule denies. Removing a namespace in a
complete replacement leaves other namespaces' rules intact.

## Node L3 authority

### Bindings

Complete Node L3 authority is family 11 `node-l3` on the snapshot channel. The
complete authority wrapper is `[1, bindings, policy_bytes]`, where
`policy_bytes` is the exact Node L3 encoding above. A binding is
`[full_identity, wg_key]`, sorted uniquely by identity; K is a nonzero 32-byte
string and distinct identities cannot share K. Every scoped identity requires a
binding. Complete bindings, scopes and rules are supplied atomically.

The consumer joins installed I and K only through these bindings, never roster
membership or a peer record alone. Standalone policy vectors are policy
fragments, not complete transport authority; their bytes are the Node L3 form
above.

Refusals are typed by `L3AuthorityError`: strict CBOR (`Encoding`), invalid
full identity or Node L3 policy (`Contract`), unsupported schema (`Field`), too
many bindings (`Bounds`), bindings not in strict identity order (`Ordering`),
and a zero or repeated key or a scoped identity without a binding (`Binding`).

### Mapped-route admission

Ordinary Node L3 rules govern direct identity-derived N6 and N4 destinations
only. A Subnet mapped-prefix destination resolves to its exact resource and
selected route, never to a Node L3 rule naming the provider. Neither provider
nor client creates or requires such a rule. Route withdrawal, exclusion or
missing coverage never falls back to a provider-wide Node rule.

Provider admission joins the current Exit owner's exact resource, authenticated
client and provider, grant incarnation, payer and expiry, the embedded validated
route's real and mapped selection minus exclusions and `SubnetProxyCoverage`,
and independently validated local enablement and binding. Resource-authority and
payer joins and retirement are preserved; a client view alone cannot authorize
service. See [Exit grants and client route views](subnet.md#exit-grants-and-client-route-views).

The client selects only the named resource's selected mapped destinations and
covered TCP, UDP and echo for that route's provider, comparing client with self
and provider with the independently installed peer identity and key within the
accepted source and Network. This grants route selection only; the client
receives no provider payer or incarnation facts. Bypasses keep their routing
semantics; source and destination and reverse-flow ownership are unaffected.

Route admission and applied status reports are specified in
[Node L3 status](control.md#node-l3-status).

### Direct host authority

Direct identity-derived N6 and N4 destinations require independent authority,
governed by ordinary Node L3 rules. A Subnet mapped route grants no direct host
authority, and direct host authority grants no mapped route. Native IPv6
forwarding and live default Exit are outside this contract.

## Code and vectors

Code (crate `nsshared-control`, public items at `nsshared_control::account::node`):

| Area | Source | Public items |
| --- | --- | --- |
| Enrollment | `crates/nsshared-control/src/account/node/enrollment.rs` | `Enrollment`, `EnrollmentDecision`, `EnrollmentError`, `RebindAuthorization`, `decide_enrollment`, `NODE_LOCAL_NAMES_V1`, `MAX_CAPABILITIES`, `MAX_CAPABILITY_BYTES` |
| Lifecycle | `crates/nsshared-control/src/account/node/lifecycle.rs` | `NodeBinding`, `Lifecycle`, `Transition`, `MembershipIdentityVersion`, `RecordGeneration`, `GrantIncarnation`, `ReporterIncarnation` |
| Node L3 form | `crates/nsshared-control/src/account/node/l3.rs` | `NodeL3`, `L3Scope`, `L3Rule`, `L3Protocol`, `TransportProtocol` |
| Node L3 authority | `crates/nsshared-control/src/account/node/l3_authority.rs` | `NodeL3Authority`, `L3Binding`, `L3AuthorityError` |

`node_dns_name` and `NODE_DNS_ZONE` are in `nsshared_identity::discovery`.

Tests and vectors:

| Contract | Test module | Vectors |
| --- | --- | --- |
| Enrollment, decisions, placeholders, rebind authorization | `account::node::enrollment` | `crates/nsshared-control/tests/vectors/account/node/enrollment.vec` |
| Lifecycle and Node L3 form | `account::profile` | `crates/nsshared-control/tests/vectors/account/profile.vec` |
| Node L3 authority wrapper | `account::grants::grant_authority` | `crates/nsshared-control/tests/vectors/account/grants/grant-authority.vec` |
| Mapped-route admission | `account::control::node_l3_route_admission` | `crates/nsshared-control/tests/vectors/account/control/node-l3-route-admission.vec` |

The `enrollment_consumer_vectors` cases in `account::node::enrollment` cover an
ordinary Node with no grants or reporter, zero-placeholder identity replacement
and authorized K rotation, mismatched before and after bindings, and
unauthorized rotation.

The focused `ordinary_node_echo_*` cases in the profile, grant-authority and
route-admission tests exercise actual canonical codecs and scope validation,
including fixed zero slots, unknown/malformed selectors, exact identity and
Network boundaries, request direction, missing rules, key binding refusal,
non-Node protocol refusal and unchanged TCP/UDP vectors. They do not implement
or qualify packet enforcement or state-correlated reply delivery.
