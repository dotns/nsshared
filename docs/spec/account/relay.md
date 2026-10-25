# Relay

Registry family 8 `relay` carries the relay authority contracts: signed admission
rosters and the local admission snapshot, participant rosters and their supplied-clock
lifecycle, participant credentials and bounded session frames, and the separate
signed directory binding. Public items are at `nsshared_control::account::relay`;
signature domains are at `nsshared_control::account::domains`. Membership realm
identities follow the [canonical RealmId](../realm-id.md).

This is a pure contract with CBOR content schema 1 and local admission JSON schema 2.
It defines no runtime or transport session. TLS, provisioning, custody, storage and
installation are consumer responsibilities. CBOR follows the [account encoding
rules](profile.md#encoding). The family registry bytes and the directory and roster
replacement scopes are those of the [family
registry](profile.md#family-registry-and-replacement): a directory and a participant
roster are separately scoped and neither clears the other. Signed publication events
carrying these contracts follow
[publication](publication.md#publication-content-and-signed-events).

## Admission rosters

### Signed roster

Every entry is `(full IdentityKey, class)`, where class is `ordinary_node` (CBOR 0,
`IdentityClass::OrdinaryNode`) or `gateway_node` (CBOR 1,
`IdentityClass::GatewayNode`). No class-only publication exists. Complete empty
entries withdraw the recipient's entire admission roster.

Signed roster content (`Roster`) is the CBOR array

```text
[1, issuer, recipient, roster_version, issued_at_unix_ms, valid_until_unix_ms, entries]
```

An entry is `[I, class]`, and entries are sorted by identity. The signature is
Ed25519 over `ns.account.roster.v1` plus one zero byte plus the canonical content
(`domains::ROSTER_DOMAIN`). The signed carrier (`SignedRoster`) is
`[content_bytes, signature_64_bytes]`. Both content and carrier obey the 1 MiB bound,
and there are at most 8,192 identities.

### Attribution

Versions (`RosterVersion`) are the attribution epoch. Membership and classes are
captured together for relay accounting: a relay usage observation records the
roster scope and version together with both endpoint classes (see
[relay usage](usage.md#relay-usage)).

### Version and validity

Versions are positive u64, strictly increasing per issuer/participant. The lifetime
from `issued_at_unix_ms` to `valid_until_unix_ms` must be at least 86,400,000 ms
(`MIN_ROSTER_VALIDITY_MS`).

`SignedRoster::verify` takes the trusted issuer, the expected participant, the last
accepted version and the current time. It rejects a wrong issuer or recipient, a
stale version, a future issue time, expiration, a short lifetime, duplicates and bad
signatures. Persistence of the accepted version is the consumer's rollback boundary.
NSD, the issuer, renews while reachable; consumers never extend a signed deadline
locally.

### Local admission snapshot

The local admission snapshot (`AdmissionSnapshot`) is strict JSON schema 2:

```json
{"schema_version":2,"issued_at_unix_ms":1000,"roster_version":7,"identities":[{"identity":"<canonical IdentityKey text>","class":"ordinary_node"}]}
```

All four root fields and both entry fields are required. Unknown or duplicate JSON
fields, non-string or unknown classes, invalid or noncanonical key text, a duplicate
identity, a wrong schema, version zero, more than 8,192 entries and input over
1,048,576 bytes fail.

`validate_admission_snapshot(bytes, now_ms, max_age_ms)` also rejects future
timestamps and ages greater than `max_age_ms`; equality at the freshness boundary is
valid. The returned version is the epoch, not the issue timestamp. Validation does
no I/O or clock access.

Local snapshots have no issuer, recipient or signature: controlled regular-file
ownership, atomic replacement, bounded reading and rollback persistence are consumer
responsibilities. A reader never installs an invalid or missing file as an empty
roster.

## Participant rosters

### Lifecycle

A participant roster is the signed roster above, published in family 8 `relay`. Its
scope (`ParticipantRosterScope`) is exactly the signed content's
`(issuer, recipient)` pair: the relay participant's own credential scope. No
additional scope field is carried. Enrollment, session proof, renewal and revocation
for exactly this pair are defined under
[participant credentials and sessions](#participant-credentials-and-sessions).
Directory eligibility uses the separate signed
[directory binding](#directory-bindings).

A new accepted complete version replaces the entire mapping: empty denies all
membership, omission revokes an identity, and a class-only change advances the same
epoch with a new complete generation. A refused publication is never withdrawal;
the last accepted generation is retained.

### Classes

Each identity entry carries exactly one class, `ordinary_node` (0) or `gateway_node`
(1). An entry lacking its class, an entry carrying more than one class, an undefined
class value and an identity assigned more than once are each refused with a typed
error.

### Verification

`verify_participant_roster(bytes, issuer, recipient, last_version, now_ms)` decodes
and authenticates the signed carrier and returns an accepted
`ParticipantRosterGeneration` containing the scope, the roster version as the
attribution epoch, the complete identity/class mapping, the issue time and the
exclusive validity deadline.

`ParticipantRosterError` distinguishes:

| Variant | Refusal |
| --- | --- |
| `Issuer` | Wrong issuer |
| `Recipient` | Wrong recipient |
| `Stale` | Stale or replayed version (below or equal to the accepted epoch) |
| `FutureIssue` | Signed issue time later than the supplied clock |
| `Expired` | Supplied clock at or beyond the exclusive deadline |
| `ShortLifetime` | Signed lifetime below 24 hours, or ending before issue |
| `Signature` | Bad signature over the canonical domain and content |
| `MissingClass` | Entry lacks its class |
| `DuplicateClass` | Entry carries more than one class |
| `UnknownClass` | Undefined class value |
| `DuplicateIdentity` | Identity assigned more than once |
| `Contract` | Other malformed or noncanonical content, with its contract error |

`SignedRoster::verify` keeps its own error behavior.

### Status

`participant_roster_status(generation, last_authenticated_renewal_ms, now_ms)` is
pure and reads no clock. The consumer supplies the instant of its last successful
authenticated renewal. It returns `ParticipantRosterStatus`:

- `Expired` at the signed deadline and thereafter;
- before that deadline, `Degraded` at and after 86,400,000 ms since that renewal;
- otherwise `Valid`.

Degraded is diagnostic and still admits the complete mapping. Outage alone never
withdraws it, and renewal never extends its signed deadline. The supplied renewal
instant is authenticated consumer state, not a timestamp inferred from a failed
fetch.

## Participant credentials and sessions

### Credentials

The participant generates its own Ed25519 key; its public identity is exactly the
roster recipient. Confidential out-of-band provisioning supplies a dedicated 32-byte
enrollment credential for one trusted issuer/recipient pair, plus server trust and
the expected issuer (`EnrollmentProvision`). A self-presented key is not enrollment
authority. The credential is enrollment-only and never serves as a session bearer
token. A key change requires new enrollment and explicit directory binding updates;
old roster floors and immutable report attribution are not reinterpreted.

### Exporter context and proof

A participant connection uses verified TLS 1.3 and the regular completed-handshake
exporter, also after resumption, with:

| Input | Value |
| --- | --- |
| Label | `EXPORTER-nsgw-participant-candidate-v1` (`domains::PARTICIPANT_EXPORTER_LABEL`) |
| Context | 64 bytes `issuer_32 \|\| recipient_32` (`exporter_context`) |
| Output | 32 exported bytes |

The connection proof is Ed25519 over `nsgw-participant-candidate-v1\0 || exporter_32`
(`domains::PARTICIPANT_PROOF_DOMAIN`, `proof_input`). Every connection requires a
fresh proof. Exporter input is supplied by the TLS owner; these codecs cannot prove
that a caller supplied real TLS material.

### Frames

A frame (`Frame`) is `length_u32_be || kind_u8 || body`. Participant frame kinds are
the `FrameKind` enum; each discriminant is the wire kind byte (`FrameKind::byte`,
`FrameKind::from_byte`).

| Byte | `FrameKind` | Operation | Body and exact byte length |
| --- | --- | --- | --- |
| 1 | `Authenticate` | authenticate | issuer32, recipient32, proof64: 128 |
| 2 | `Authenticated` | authenticated | optional deadline: 1 or 9 |
| 3 | `Refused` | refused | empty: 0 |
| 4 | `Roster` | complete roster | unchanged signed roster: 1..=1,048,576 |
| 5 | `Report` | usage report | unchanged report: 1..=1,048,576 |
| 6 | `Answer` | usage answer | unchanged answer: 1..=1,048,576 |
| 7 | `Enroll` | enroll | issuer32, recipient32, correlation16, enrollment credential32, proof64: 176 |
| 8 | `Enrolled` | enrolled | issuer32, recipient32, correlation16, optional deadline: 81 or 89 |
| 9 | `Renew` | renew | issuer32, recipient32, correlation16: 80 |
| 10 | `Renewed` | renewed | issuer32, recipient32, correlation16, optional deadline: 81 or 89 |

All concatenations are in table order; identity keys undergo strict existing key
validation. Correlations are nonzero 16-byte values. An optional deadline is tag 0
alone for absent, or tag 1 followed by a u64 big-endian Unix milliseconds value
(`credential_deadline`). Zero is a finite expired deadline; absence does not erase a
retained finite bound (`retained_credential_deadline`).

Roster, report and answer frames carry the signed roster, the
[usage report](usage.md#usage-reports) and the
[usage answer](usage.md#usage-answers-watermarks-and-repair) bytes unchanged, and the
signed roster domain applies unchanged.

### Bounds

The length includes the kind byte and is in 1..=1,048,577; the body is at most 1 MiB
(`MAX_FRAME_BODY`). Unknown kinds, trailing data, wrong lengths and premature EOF are
rejected before granting authority. Header validation is exposed separately
(`validate_header(length, kind)`) so a runtime can refuse lengths before allocating
bodies.

### Authorization

An enrolled authorization (`Authorization`: issuer, participant, enabled state,
optional deadline) is checked against the exact pair, the enabled state and the
exclusive optional deadline before authentication, renewal and report acceptance.
Enrollment additionally requires exact comparison against the separately provisioned
credential and pair.

`SessionError` distinguishes `Contract` (invalid keys or contract fields), `Frame`
(unknown kind, invalid length, malformed field or trailing bytes), `Unauthorized`
(pair not provisioned, enabled or currently valid), `Proof` (proof does not match
this connection's exporter) and `Correlation` (response differs from the exact
pending operation, pair or request). Refusal never supplies signed withdrawal or a
renewed deadline.

### Enrollment and renewal

Enrollment sends its connection proof only after completed verified TLS. NSD
compares the independently provisioned credential and pair, verifies possession and
records authorization before returning enrolled. The authenticated TLS response must
echo the exact pair and the pending correlation and carry NSD's actual
deadline. Pure response validation (`Frame::validate_response` against a
`PendingResponse`) compares kind, pair, correlation and the supplied clock.

Renewal requires an already authenticated session for the same pair, a new pending
correlation and current enabled authorization. It returns renewed with the resulting
actual deadline. Authentication success alone never implies renewal. The runtime
rejects out-of-order frames; pure shape decoding grants no session.

Only a newly accepted complete roster with authenticated credential metadata renews
retained authority. Omitted bounds retain earlier finite bounds. Refusal,
cancellation and transport failure neither replace generations nor extend time.

### Revocation

Revocation disables authorization for subsequent authentication, renewal and report
acceptance. NSD also publishes a newer signed complete-empty roster to
existing sessions and newer empty bindings for all owned directory ids. Consumers
persist these floors before publishing withdrawal.

Refusal or disconnection alone is not signed withdrawal; disconnected consumers
retain only independently valid authority until its existing credential, roster or
binding deadline. No new revocation latency or relay realm ACL is defined. Original
immutable reports retain historical custody.

## Directory bindings

### Signed binding

Directory binding content (`DirectoryBinding`) is the canonical CBOR array

```text
[1, issuer32, relay_id_u16, participant32, realms, version_u64, issued_at_unix_ms, expires_at_unix_ms]
```

The relay id is positive and is exactly the numeric `RelayEntry.id`, never the
host:port `RelayId`. The version is positive, expiry strictly exceeds issue, and
realms is a complete set of at most 8,192 canonical uppercase RealmId text values,
strictly increasing by their 128-bit value. Empty is valid withdrawal.

Content and the signed carrier each obey the 1 MiB bound. The signature input is
`ns.account.directory-binding.v1\0` followed by the canonical content
(`domains::DIRECTORY_BINDING_DOMAIN`, `SignedDirectoryBinding::signing_input`); the
carrier (`SignedDirectoryBinding`) is `[content_bytes, ed25519_signature64]`. Every
field is signed. Nonminimal CBOR, extra fields, invalid keys, duplicate or unordered
realms, noncanonical realm text, bad domains or signatures and bound violations are
rejected.

### Replacement

`SignedDirectoryBinding::verify(issuer, relay_id, floor, previous, now_ms)` takes the
trusted issuer, the selected numeric directory id, the persisted version floor, the
retained accepted record if restored, and the clock. It checks the exact issuer
and id, the signature, and `issued_at_unix_ms <= now_ms < expires_at_unix_ms`,
and returns a `BindingDecision`.

Bindings are ordered independently per issuer and numeric relay id, regardless of
directory or roster versions, and binding replacement never clears a directory or
roster:

- A newer binding completely replaces the owner and the eligible realms, including
  empty (`BindingDecision::Replace`).
- An equal version is idempotent only with an identical retained accepted signed
  record and the matching floor; it retains the original deadlines
  (`BindingDecision::Idempotent`).
- Lower versions and changed equal versions fail.
- On restart a floor alone grants nothing: equal replay is refused unless the exact
  accepted content was also restored and verified.

The consumer persists the floor, including empty withdrawal, before exposing the
replacement. Ownership replacement uses a newer version of the same id.

`BindingError` distinguishes `Contract` (invalid canonical fields, CBOR or bounds),
`Authority` (wrong issuer, selected directory id, owner or supplied retained state),
`Stale` (lower version or changed equal version, including replay after restart),
`Time` (future issue or expired exclusive deadline) and `Signature`.

### Eligibility

`SignedDirectoryBinding::eligible(issuer, relay_id, participant, realm, now_ms)`
answers an eligibility query for a binding first accepted with `verify` and its
persisted floor. It requires the trusted current binding, the selected directory id,
the signed participant owner and the requested authenticated RealmId; absent realms
return false. Endpoint or key equality alone never supplies this association.

Missing or invalid bindings grant no new eligibility; retained valid bindings last
only until signed expiry or newer replacement. Empty binding realms withdraw
eligibility, while a newer complete-empty roster withdraws admission. Directory
entries, codes, update rules and Quick behavior are not changed by bindings.

## Code and vectors

| Contract | Source | Public items |
| --- | --- | --- |
| Admission rosters and local snapshot | `crates/nsshared-control/src/account/families/relay/roster.rs` | `nsshared_control::account::relay::{Roster, SignedRoster, RosterEntry, RosterVersion, IdentityClass, AdmissionSnapshot, MIN_ROSTER_VALIDITY_MS, validate_admission_snapshot}` |
| Participant rosters | `crates/nsshared-control/src/account/families/relay/participant_roster.rs` | `nsshared_control::account::relay::{ParticipantRosterScope, ParticipantRosterGeneration, ParticipantRosterError, ParticipantRosterStatus, verify_participant_roster, participant_roster_status}` |
| Participant sessions | `crates/nsshared-control/src/account/families/relay/session.rs` | `nsshared_control::account::relay::{Frame, FrameKind, MAX_FRAME_BODY, Authorization, EnrollmentProvision, PendingResponse, SessionError, exporter_context, proof_input, validate_header, credential_deadline, retained_credential_deadline}` |
| Directory bindings | `crates/nsshared-control/src/account/families/relay/directory.rs` | `nsshared_control::account::relay::{DirectoryBinding, SignedDirectoryBinding, BindingDecision, BindingError}` |
| Signature domains | `crates/nsshared-control/src/account/domains.rs` | `nsshared_control::account::domains::{ROSTER_DOMAIN, DIRECTORY_BINDING_DOMAIN, PARTICIPANT_PROOF_DOMAIN, PARTICIPANT_EXPORTER_LABEL}` |

| Vectors | Producer | Test module |
| --- | --- | --- |
| `crates/nsshared-control/tests/vectors/account/profile.vec` (kinds `signed-roster`, `snapshot`) | `tools/vectors/nsvec/producers/control/account/profile.py` | `account::profile` |
| none (named snapshot fields) | none | `account::relay::roster_fields` |
| `crates/nsshared-control/tests/vectors/account/relay/participant-roster.vec` | `tools/vectors/nsvec/producers/control/account/relay/participant_roster.py` | `account::relay::participant_roster` |
| `crates/nsshared-control/tests/vectors/account/relay/session.vec` | `tools/vectors/nsvec/producers/control/account/relay/session.py` | `account::relay::session` |

The independent participant roster producer emits canonical signed carriers,
explicit decisions, expected complete mappings and supplied-clock lifecycle cases.
Its sequences carry each previous signed publication and verify new versions against
the last accepted scope and epoch. They include retained authority after a
refused publication and reclassification without any separate class message.

The `participant_auth_transport` sequence of `session.vec` supplies fixed fixture
keys and exporter material: authorized enrollment and unprovisioned-key refusal;
authentication with a fresh proof and refusal of a prior proof on another
connection; an initial signed nonempty roster, correlated renewal, a canonical
unchanged report and a correlated ACK; binding A/B; replacement removing A with an
identical directory; disabled reauthentication, renewal and report acceptance plus a
newer complete-empty roster and empty binding; and old binding replay after floor
restoration refused. Independent malformed and noncanonical cases exercise both the
session and the binding contracts.
