# Realm publication candidate

## Canonical content

The candidate fixture authority is not NSD producer confirmation. CBOR uses exact
array arity, minimal unsigned integers, definite lengths and no trailing bytes.

Family 2 `realm-peers` content is `[1, 2, contributions]`. Each contribution is
`[realm, members]`, with a nonempty UTF-8 realm of at most 256 bytes. Contributions
are strictly ordered by realm UTF-8 bytes. Each member is `[binding, record]`:
`binding` is the existing NodeBinding array `[identity_version, I, K, generation]`,
and `record` is a byte string containing the existing signed NodeRecord v2.
Members are strictly ordered by full signing identity bytes. Identity version and
record generation are positive; K is nonzero. The record must verify and match I,
K and generation exactly. Its validity remains caller-time dependent: consumers
check each record at their supplied current time before installation. NodeId and
N6/N4 derive from the existing Node identity contracts; no address is carried.

There are at most 256 contributing realms and 8192 members across the collection,
with at most 1 MiB encoded content. No full identity or K may occur twice anywhere
in one collection, including across realms. Distinct authenticated collections
retain their own source provenance; cross-collection conflicts fail closed in the
consumer. A realm with no members is still served. Membership grants no L3 or
service permission. Existing M6 service identities, declarations and snapshots
remain unchanged and are not wrapped or cloned in this payload.

Family 11 `policy-version` content is `[1, 11, counter]`, with a u64 counter
including zero and at most 13 encoded bytes. It is a last-seen observation only,
never applied-policy evidence or an authorization revision. A smaller observed
counter under a newer valid publication is legal: only the enclosing publication
version determines replay acceptance.

## Publication and replacement

The sole carrier is the existing signed publication: realm-peers uses family 2
and snapshot channel; policy-version uses family 11 and stream channel. Neither
payload carries issuer, recipient, served_realm, scope or a publication revision.
These come exclusively from the exact authenticated enclosing key and independent
provisioned/accepted authority. The collection's realm names describe contributions,
not a claim to its enclosing authority. No wildcard gateway scope is introduced.

Validate the entire collection before atomically committing content, provenance,
expiry and the accepted publication version. Replace the complete collection in
that key only: omitted realms and their contributions disappear; never union with
previous content. `[1, 2, []]` is a valid empty withdrawal; the carrier's existing
empty byte payload also withdraws. Retain the version tombstone for either form.
Missing or malformed input preserves the previous content and its original
freshness, without advancing its version. Actual expiry remains unchanged.
Authenticated Node L3 FetchFailed remains a separate publication rule.

The consumer owns persistence of exact per-key versions and restores tombstones
before accepting input after restart. An older signed publication cannot restore
removed members. Observation counters also require an exact authenticated key and
publication version; the numeric counter is never used as that version.

## Predecessor field mapping

| Predecessor field | Candidate disposition |
| --- | --- |
| WgConfig.ip_address | Retired gateway device address; NodeId/N6/N4 derive from I |
| WgConfig.listen_port | Retired gateway device port; no membership authority meaning |
| WgConfig.peers | Complete realm contributions with full I, authorized K and signed NodeRecord |
| PeerConfig.public_key | NodeBinding.K, checked against NodeRecord |
| PeerConfig.endpoint | Retired direct gateway carrier endpoint; existing NodeRecord relay discovery applies |
| PeerConfig.allowed_ips | Retired arbitrary device routes; Node addressing derives from I; routing and grants remain separate |
| PeerConfig.persistent_keepalive | Retired gateway device tuning; no membership field |
| GatewayConfig.gateways | Retired gateway-specific endpoint collection; ordinary NodeRecord relay contract applies |
| last_seen_policy | Observation-only policy-version counter under its exact publication key |

Independent `realm-publication.vec` fixtures and `realm_publication_vectors` cover
canonical content, refusals and `realm_membership_replacement`. Producer-owned NSD
vectors and confirmation of the realm contribution and binding model remain
outstanding; fixture success is not agreement.
