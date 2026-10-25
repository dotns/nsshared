# Account profile

The account contracts (`nsshared_control::account`) carry the account-plane payloads
between NSD, Nodes and gateways: enrollment, publications of every family, the control
exchanges and reports, and their local admission state. This profile holds the rules
they share: encoding, placement and M6 reuse, scope text, signature domains and the
family registry. The account contracts are a candidate: the module is built only with
the `unstable-account` feature of `nsshared-control`, is not covered by semver and may
change incompatibly before the gate is removed and a release is made. Each layer and
family is specified separately:

| Specification | Contracts |
| --- | --- |
| [Node](node.md) | Enrollment, identity lifecycle, normalized Node L3 form and authority, local Node naming |
| [Control](control.md) | Bootstrap discovery, signed confidential carriers, control exchanges and reports, machine tokens, signed URL requests, route commands, Node L3 status, the M6 carrier |
| [Publication](publication.md) | Signed publication events and snapshots, source bindings and source-bound publications, subscriptions and snapshot polls |
| [Realm](realm.md) | Family 2: served realms and peers, policy subjects, subject rules, admin and JWT claims |
| [Grants](grants.md) | Families 3, 5 and 6: service grants, payers and payer bindings, resource authority |
| [Subnet](subnet.md) | Family 4: Subnet selection, Exit grants and client route views, provider reports and mappings |
| [Edge](edge.md) | Family 7: public-edge routes, authentication policy, material, confidential configuration, service declarations |
| [Relay](relay.md) | Family 8: admission and participant rosters, participant sessions, directory bindings |
| [Usage](usage.md) | Families 9 and 10: service and relay usage, reports and answers, profile publications |

Contracts use schema 1 (`SCHEMA`); local admission JSON uses schema 2. They are pure:
no runtime, transport session, policy compiler or v1 adapter, and no clock or file
access. Membership realm identities follow the [canonical RealmId](../realm-id.md).

## Encoding

Contracts use the NS array profile of `nsshared_codec::cbor` (`CborReader`,
`CborWriter`): definite arrays, shortest unsigned integers, bytes, UTF-8 text,
booleans and null only. All arrays have exact arity; trailing bytes and unknown
discriminants fail. All counters are u64; identity keys are validated 32-byte Ed25519
keys; opaque incarnations and namespaces are 16-byte strings. An encoded contract or
local snapshot is at most `MAX_BYTES` (1,048,576) bytes; a complete admission roster
holds at most `MAX_IDENTITIES` (8,192) identities. No conversion to M6 CBOR occurs.

Every refusal is typed. Errors never represent withdrawal: invalid content is an
error, never an empty set.

## Placement and M6 reuse

Subnet and grant payloads embed M6 references as their unchanged canonical M6 bytes
(`ServiceRef::canonical` and `ServiceRef::decode`). Service declarations and
references, listener intents, leases, snapshots, service labels and messages always
use the M6 contract, `nsshared_control::service` on the M6 value profile of
`nsshared_codec::cbor::value`; no alternate M6 codec exists.

M6 reuse groups in the registry are:

- `identities`: `Id`, `Identity`, `Digest`, `ServiceRef`.
- `declarations`: `Declaration`, `BackendHost`, `Protocols`, `PortMode`,
  `Declaration::canonical/decode`, `ReportContent::canonical/decode`.
- `listeners`: `ListenerIntent::canonical/decode`, `domain_digest`.
- `snapshots`: `Resource`, `Route`, `Grant`, `PublisherListener`, `Withdrawal`,
  `Snapshot::canonical/decode`, `snapshot_digest`, `Resource::service_label` and
  its validation. The publisher-only backend boundary stays intact.
- `messages`: `Message`, `MessageBody`, `MessageKind`, `Message::encode/decode`,
  `CAPABILITY`, `SCHEMA`, `LOCAL_SCHEMA`, `MAX_LEASE_MS`, `REFRESH_MS`,
  `ContractError`, `next_revision`, including every body variant.
- `vectors`: `crates/nsshared-control/tests/vectors/service/canonical.json` and the
  `service::canonical` tests. Reference these bytes and domains directly; never copy,
  rename or re-encode them as account vectors.

All families reuse `identities`, `messages` and `vectors` when carrying service work.
The registry's `m6` list contains these exact group names in this order: identities,
declarations, listeners, snapshots, messages, vectors (omitting groups not
applicable).

## Scope text

Every opaque authority scope text (publication keys, subscription and snapshot
request scopes, source bindings, authentication source selection, public-edge,
material and confidential configuration requests) is 1 to 256 UTF-8 bytes and
contains no whitespace and no control characters. Encoders and decoders apply the
same rule; a scope outside it is refused, never normalized. Policy labels follow the
same token rule.

## Signatures and domains

Every signed contract signs the domain followed by the canonical signed bytes with
Ed25519 and verifies strictly (`verify_strict`). Every domain ends with a zero
separator; `nsshared_control::account::domains` holds them all:

| Domain | Bytes | Signed contract |
| --- | --- | --- |
| `ACCOUNT_REQUEST_DOMAIN` | `ns.account.call.request.v1\0` | confidential carrier request ([control](control.md)) |
| `ACCOUNT_RESPONSE_DOMAIN` | `ns.account.call.response.v1\0` | confidential carrier response ([control](control.md)) |
| `PUBLICATION_DOMAIN` | `ns.account.publication.v1\0` | publication event ([publication](publication.md)) |
| `SOURCE_BINDING_DOMAIN` | `ns.account.source-binding.v1\0` | source binding ([publication](publication.md)) |
| `SOURCE_PUBLICATION_DOMAIN` | `ns.account.source-publication.v1\0` | source-bound publication ([publication](publication.md)) |
| `ROSTER_DOMAIN` | `ns.account.roster.v1\0` | admission roster ([relay](relay.md)) |
| `DIRECTORY_BINDING_DOMAIN` | `ns.account.directory-binding.v1\0` | directory binding ([relay](relay.md)) |
| `PARTICIPANT_PROOF_DOMAIN` | `nsgw-participant-candidate-v1\0` | participant connection proof ([relay](relay.md)) |

`USAGE_PART_DIGEST_DOMAIN` (`ns.account.usage.part.v1`) is the digest domain of usage report
parts, digested with `service::domain_digest`, which appends the zero separator
([usage](usage.md)). `PARTICIPANT_EXPORTER_LABEL`
(`EXPORTER-nsgw-participant-candidate-v1`) is the TLS exporter label of participant
connections.

## Family registry and replacement

Registry CBOR is `[1, entries]`; each entry is
`[id, version, name, publication, clears, owner, m6]`, ordered by id
(`nsshared_control::account::publication::FamilyRegistry`, `FAMILIES`). `version` is
1 and `owner` is `account-payload-profile` for every family. `clears` names the kinds
exclusively replaced within that publication's authenticated issuer/recipient and
explicitly named scope. Only a validated **complete** publication replaces its listed
kinds. A complete empty set withdraws all of those kinds in that scope. Missing,
partial, malformed or unauthenticated content is an error, never an empty set. A
family publication never implicitly clears another family or an unnamed scope.
Reports and control vocabularies describe replacement of catalogue and configuration
sets, not erasure of usage history, durable watermarks or received control messages.

| ID / family | Complete publication / exact `clears` string / scope | Additional M6 reuse |
| --- | --- | --- |
| 1 `enrollment` — [enrollment and own Node binding](node.md) | `own-node` / `binding,capabilities,endpoints` / one membership | declarations |
| 2 `realms-peers` — [complete served realms and peers](realm.md) | `realm-peers` / `realms,peer-contributions` / exact signed issuer/recipient/served_realm/scope collection; omitted contributions removed | snapshots |
| 3 `egress` — [Egress grants](grants.md) | `egress-grants` / `resources,grants,payers` / one realm and recipient | declarations, listeners, snapshots |
| 4 `exit-subnet` — [Exit grants and client routes](subnet.md) | `exit-grants` / `routes,grants,exclusions,bypasses,selection` / provider nodes collection; `subnet-routes` / `routes,exclusions,bypasses,selection` / client nodes collection; `provider-mappings` / `mappings` / provider nodes inventory | listeners, snapshots |
| 5 `payer` — [binary realm/UserId bindings](grants.md) | `payer-bindings` / `payers` / one resource scope; ambiguity withholds the resource | snapshots |
| 6 `withdrawal` — [resource authority and retired tokens](grants.md) | `resource-authority` / `authority,incarnations` / current authority in one recipient/resource scope | snapshots |
| 7 `public-edge` — [public edge, material and service operations](edge.md) | `public-edge` / `backends,names,aliases,ports,domains,subjects,auth,materials` / exact signed issuer/recipient/served_realm/scope, per-realm contributions; full Node identity backends, explicit no-connector and generation-qualified dependencies | declarations, listeners, snapshots |
| 8 `relay` — [relay directory and participant](relay.md) | `relay-directory-roster` / `directory\|identity-classes` / a named directory or participant roster, separately scoped; neither clears the other | snapshots |
| 9 `usage` — [typed usage catalogue](usage.md) and unchanged reports and units | `usage-profile` / `units,reporters,parameters` / one reporter; never clears metering history | none |
| 10 `node-control` — [typed membership catalogue](usage.md) and the unchanged [Node-control channel](../node-control.md) | `node-control-profile` / `vocabulary,capabilities` / one membership; ACK means at least accepted, persistence may precede ACK | none |
| 11 `v1-replacement` — replacement of the v1 surface, [policy observation](realm.md) and [exact Node L3 applied status](control.md) | `surface-map` / `mappings,retirements` / discovery/envelope verification, admin claims, policy, signed URL, material, reports and snapshot/events vocabulary in one account profile | declarations, listeners, snapshots |

The backslash before the table cell's pipe is Markdown escaping; the wire string
contains only the pipe. The typed registry fixes these publication identifiers and
cleared-kind strings; the family specifications define authority, deadlines and
payload-specific validation. The registry is not an alternate declaration or a
generic M6 message envelope. Which delivery channel (stream or snapshot) owns each
kind is `publication_channel` ([publication](publication.md)).

## Conformance

`tools/vectors/nsvec/producers/control/account/` implements these specifications
using only Python's standard library, one producer per vector file;
`account/profile.py` writes `crates/nsshared-control/tests/vectors/account/profile.vec`
(registry, lifecycle, Node L3, usage unit, admission rosters and local snapshots).
`just vectors` and `just vectors-check` include every producer. The tests of the
`account` binary decode each byte string and compare canonical re-encoding, validated
semantics and expected refusal outcomes. Enrollment cases additionally use
`nsvec/derive.py` for expected NodeId text, N6 and N4 bytes. Consumers read each
decision and canonical publication from the fixture, check every presented and
accepted identity against those independent values, and exercise named typed
refusals. The M6 producer and tests own the M6 bytes.
