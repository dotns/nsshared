# Realm peers, policy subjects, rules and claims

## Purpose

This specification defines account payload family 2 (see [profile.md](profile.md)
for the family registry): the complete `realm-peers` membership content, the
`policy-version` observation counter carried by family 11, and the pure policy
and claim values that other families embed: qualified policy subjects, subject
bindings, subject rules and groups, and admin token claims.

Realm identities in these payloads are the [canonical RealmId](../realm-id.md):
text positions use the exact canonical text spelling and binary positions use
the exact 16 bytes.

### Common encoding

All values are schema 1 and use strict shortest-form CBOR: exact array arity,
minimal unsigned integers, definite lengths and no trailing bytes. Every value
is bounded by the account limit of 1 MiB encoded bytes.

In the policy and claim values, text is nonempty UTF-8 of at most 256 bytes
without whitespace or control characters, unless a field explicitly carries
unrestricted string data. Policy and claim collections have at most 256 entries.

Consumers authenticate the enclosing carrier before interpreting any value.
Decoding never authenticates a caller or evaluates a rule.

### Carrier boundary

The policy and claim values own no publication kind, and this specification
defines no policy publication, implicit or otherwise. They are carried as
follows:

- Public-edge policy fragments, including their groups, embed `SubjectPolicy`
  in family 7 `EdgeRoute.policy`. Public-edge credential bindings embed
  `SubjectBinding` in family 7 `EdgeAuth.bindings`, `JwtSubjectBinding` is
  embedded in family 7 `EdgeAuth`, and `SignedSubjectHeaderPolicy` is embedded
  in family 7 `EdgeRoute.headers`. Family 7 owns complete replacement of its
  embedded visitor, auth and public-edge values; see [edge.md](edge.md).
- Admin token claims belong in authenticated admin tokens.
- Node I/K authority is the existing `NodeL3Authority` (family 11 `node-l3`,
  see [node.md](node.md)). It is neither wrapped nor duplicated here, and no
  subject is derived from an address or a key.
- Service targets use the existing M6 `ServiceRef` and the grant and `Payer`
  contracts ([grants.md](grants.md)); there is no policy-specific service claim.
- Machine-token claims, token audiences and key sets are owned by the machine
  token contract ([control.md](control.md)); these values do not duplicate them.
- Signed account request and signed URL canonical inputs are specified in
  [control.md](control.md).
- OIDC token verification and subject label construction are consumer-owned;
  the resulting labels reference a qualified `PolicySubject`.
- Gateway roster classification and service-floor metadata are not subject
  authority and stay in their own contracts or local configuration.

No evaluator moves into shared contracts. Policy compilation, verified subject
sets, verifier readiness, admission results, destination alias resolution and
gateway self-tests are consumer state and evaluation, not wire claims. Policy
inputs without an assigned carrier have none until an enclosing family assigns
one.

## Realm peers publication

### Carrier

The sole carrier is the existing signed publication (see
[publication.md](publication.md)): `realm-peers` uses family 2 and the snapshot
channel; `policy-version` uses family 11 and the stream channel. These are
content schemas for those registered kinds; the family registry metadata is
defined in [profile.md](profile.md).

Neither payload carries issuer, recipient, served realm, scope or a publication
revision. These come exclusively from the exact authenticated enclosing key and
independently provisioned or accepted authority. The realm names inside a
collection describe its contributions; they are not a claim to its enclosing
authority. There is no wildcard gateway scope.

### Content

Family 2 `realm-peers` content is `[1, 2, contributions]`.

Each contribution is `[realm, members]`, where `realm` is the canonical
26-character RealmId text. Contributions are strictly ordered by RealmId bytes
(equivalently, by canonical text). A realm with no members is still served.

### Members

Each member is `[binding, record]`:

- `binding` is the existing NodeBinding array `[identity_version, I, K, generation]`.
- `record` is a byte string containing the existing signed NodeRecord v2.

Members within a contribution are strictly ordered by full signing identity
bytes. Identity version and record generation are positive; K is nonzero. The
record must verify and match I, K and generation exactly. Record validity is
caller-time dependent: consumers check each record at their supplied current
time before installation.

NodeId and the N6/N4 addresses derive from I through the existing Node identity
contracts; no address, device port, endpoint, allowed-IP route or keepalive is
carried. Relay discovery uses the ordinary NodeRecord relay contract.

### Collection bounds and uniqueness

A collection has at most 256 contributing realms, at most 8192 members across
all contributions, and at most 1 MiB of encoded content. No full identity and no
K may occur twice anywhere in one collection, including across realms.

Distinct authenticated collections retain their own source provenance;
cross-collection conflicts fail closed in the consumer.

Membership grants no L3 or service permission. Existing M6 service identities,
declarations and snapshots are not wrapped or cloned in this payload.

### Policy version observation

Family 11 `policy-version` content is `[1, 11, counter]`, where `counter` is a
u64 (including zero) and the content is at most 13 encoded bytes.

The counter is a last-seen observation only. It is never applied-policy
evidence or an authorization revision, and it never carries policy. A smaller
counter under a newer valid publication is legal: only the enclosing
publication version determines replay acceptance. Observation counters require
an exact authenticated key and publication version; the numeric counter is never
used as that version.

### Replacement

Validate the entire collection before atomically committing content,
provenance, expiry and the accepted publication version. Replace the complete
collection in that key only: omitted realms and their contributions disappear,
and content is never unioned with previous content.

`[1, 2, []]` is a valid empty withdrawal; the carrier's empty byte payload also
withdraws. Retain the version tombstone for either form.

Missing or malformed input preserves the previous content and its original
freshness without advancing its version. Actual expiry is unaffected.
Authenticated Node L3 FetchFailed is a separate publication rule (see
[publication.md](publication.md)).

The consumer owns persistence of exact per-key versions and restores tombstones
before accepting input after restart. An older signed publication cannot restore
removed members.

## Policy subjects and bindings

### PolicySubject

`PolicySubject` is `[1, tag, ...]`:

| Tag | Form | Meaning |
| --- | --- | --- |
| 0 | `[1, 0, realm_16, local_name]` | Realm-local name |
| 1 | `[1, 1, realm_16, user_id_16]` | Realm and binary UserId, the same pair as [`Payer`](grants.md#payers) |
| 2 | `[1, 2, full_Node_I_32]` | Full Node signing identity |

Local names have an explicit nonempty namespace and suffix: `user:`, `group:`,
`machine:` or `external:`. They are opaque, case-sensitive labels, never
inferred from addresses, credentials or display names. Symbolic `user:alice` is
not a binary UserId and is never converted into a payer. A group is a policy
selector, never a credential principal.

The Node form uses the existing full signing identity validation; it does not
introduce I/K authority.

### SubjectBinding

`SubjectBinding` is `[1, realm_16, anchor_tag, anchor, subject_bytes, enabled,
expires_seconds_or_null]`, where `subject_bytes` are canonical `PolicySubject`
bytes.

- Anchor tag 0 is a full Node identity; anchor tag 1 is a realm-local credential
  reference.
- A realm-local subject must have exactly the binding's realm.
- Group subjects refuse.
- Node anchors and Node subjects use full I, not WireGuard keys.

Activation, expiry and credential verification stay with consumers.

## Subject rules and groups

`SubjectPolicy` is `[1, realm_16, rules, groups]`.

### Rules

Rules retain their order. Each rule encodes `[subjects, destinations,
protocol_or_null]`. A rule carries no action: a matching rule allows, and deny
actions do not exist.

### Selectors

Rule subjects are typed `SubjectSelector` values:

| Selector | Encoding |
| --- | --- |
| `AnyVerified` | The sole CBOR null |
| `Subject(PolicySubject)` | The canonical subject byte string |
| `Anonymous` | A byte string containing canonical CBOR `[1, 3]` (`82 01 03`; outer byte string `43 82 01 03`) |

`Anonymous` is a rule selector, never a `PolicySubject` namespace. How consumers
match selectors against anonymous and verified visitors is specified with the public
edge in [anonymous selectors and verified-only matching](edge.md#anonymous-selectors-and-verified-only-matching).

The subject set is nonempty and strictly ordered by encoded selector payload
bytes. Null cannot coexist with another selector. `Anonymous` may coexist with
explicit subjects in strict selector payload-byte order.

### Destinations and protocol

Destinations are a nonempty set strictly ordered by UTF-8 bytes. Each is an
opaque gateway matcher string (`host:ports`, CIDRs or aliases). Matcher syntax,
host resolution, protocol matching, default deny, group expansion and
self-tests remain in the gateway evaluator.

Protocol 6 is TCP, 17 is UDP and null is both.

### Groups

Groups encode `[group_subject_bytes, member_subject_bytes_array]`, strictly
ordered by group bytes. Each group is a realm-local `group:` subject in the
policy realm. Members are unique, ordered non-group subjects qualified by that
same realm or by full Node identity.

A reference to a group requires an explicit group entry. Rules may name groups;
membership does not grant permission without a rule.

### Empty policy

Empty rules and groups are a valid deny-all value, not a publication withdrawal.

## Admin token claims and JWT subject bindings

### AdminScope

`AdminScope` has the exact JSON names `read_only`, `read_write` and
`super_admin`, and the CBOR integers 0, 1 and 2, in that order. Unknown names
and integers refuse; there are no aliases and no default.

### AdminTokenClaims

`AdminTokenClaims` is `[1, subject_bytes, scope, realm_or_null,
expires_seconds]`.

- The subject must be a non-group principal.
- A present realm must equal a realm-local subject's realm.
- A null realm does not grant cross-realm authority; the endpoint must enforce
  its own realm policy.

The supplied-input `require_scope` predicate accepts only scopes at or above the
required level. The supplied-input context comparison checks the exact subject,
the exact optional realm, the minimum scope and `now < expires`.

Neither check verifies JWT signatures, issuer, audience, key id or revocation.
Those checks remain mandatory in token consumers using their authenticated
authority. Admin claims belong in authenticated admin tokens; they are not
account publications. Human JWTs without scope cannot be silently promoted to
admin claims. Machine-token claims and key sets are outside these values.

### JWT subject bindings

`JwtSubjectBinding` joins an already verified exact authority and claim to a
`SubjectBinding` whose anchor is a credential reference. Its scopes are opaque
tokens and never become `AdminScope`. `JwtSubjectBinding` and
`SignedSubjectHeaderPolicy` are family 2 types embedded by family 7; their
encodings, exact claim-string rules and header policy rules are specified in
[edge.md](edge.md).

## Code and vectors

Code lives in `crates/nsshared-control/src/account/families/realm/`, with public
items at `nsshared_control::account::realm`:

| File | Public items |
| --- | --- |
| `peers.rs` | `RealmPeers`, `RealmContribution`, `RealmMember`, `PolicyVersion`, `MAX_PEER_REALMS`, `MAX_POLICY_VERSION_BYTES` |
| `subject.rs` | `PolicySubject`, `SubjectAnchor`, `SubjectBinding` |
| `rules.rs` | `SubjectPolicy`, `SubjectRule`, `SubjectGroup`, `SubjectSelector` |
| `claims.rs` | `AdminScope`, `AdminTokenClaims`, `JwtSubjectBinding`, `SignedSubjectHeaderPolicy` |

Tests and independent vectors:

| Test module | Vectors | Coverage |
| --- | --- | --- |
| `account::realm::peers` | `crates/nsshared-control/tests/vectors/account/realm/peers.vec` | Canonical realm-peers and policy-version content, refusals, and the `realm_membership_replacement` sequence |
| `account::realm::membership` | `crates/nsshared-control/tests/vectors/account/realm/membership.vec` | Canonical RealmId use in membership positions |
| `account::realm::claims` | `crates/nsshared-control/tests/vectors/account/realm/claims.vec` | Policy subjects, bindings, rules, groups and admin claims, plus the signed URL inputs specified in [control.md](control.md) |
| `account::realm::claim_strings` | | Exact JWT claim name and value preservation |
