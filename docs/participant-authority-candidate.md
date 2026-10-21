# Participant authority and directory binding candidate

Status: shared definition delivered; NSD producer review and adoption outstanding.
This is a pure contract. TLS, provisioning, custody, storage and installation are
consumer responsibilities. Independent vectors are fixture authority, not live NSD
qualification. See `participant_auth_transport` in `participant-authority.vec`.

## Credentials and session proof

The participant generates its own Ed25519 key; its public identity is exactly the
roster recipient. Confidential out-of-band provisioning supplies a dedicated
32-byte enrollment credential for one trusted issuer/recipient pair, plus server
trust and expected issuer. A self-presented key is not enrollment authority.
The credential is enrollment-only, never a session bearer token. A key change
requires new enrollment and explicit directory binding updates; old roster floors
and immutable report attribution are not reinterpreted.

Use verified TLS 1.3, the regular completed-handshake exporter (also after
resumption), label `EXPORTER-nsgw-participant-candidate-v1`, 64-byte context
`issuer_32 || recipient_32`, and 32 exported bytes. Ed25519 signs
`nsgw-participant-candidate-v1\0 || exporter_32`. Every connection requires a
fresh proof. Exporter input is supplied by the TLS owner; these codecs cannot
prove that a caller supplied real TLS material. An enrolled authorization is
checked against the exact pair, enabled state and exclusive optional deadline
before authentication, renewal and report acceptance. Enrollment additionally
requires exact comparison against separately provisioned credential and pair.

## Bounded frames

A frame is `length_u32_be || kind_u8 || body`. Length includes kind and is in
1..=1,048,577; body is at most 1 MiB. Reject unknown kinds, trailing data, wrong
lengths and premature EOF before granting authority. Header validation is exposed
separately so a runtime can refuse lengths before allocating bodies.

| Kind | Operation | Body and exact byte length |
| --- | --- | --- |
| 1 | authenticate | issuer32, recipient32, proof64: 128 |
| 2 | authenticated | optional deadline: 1 or 9 |
| 3 | refused | empty: 0 |
| 4 | complete roster | unchanged signed roster: 1..=1,048,576 |
| 5 | usage report | unchanged report: 1..=1,048,576 |
| 6 | usage answer | unchanged answer: 1..=1,048,576 |
| 7 | enroll | issuer32, recipient32, correlation16, enrollment credential32, proof64: 176 |
| 8 | enrolled | issuer32, recipient32, correlation16, optional deadline: 81 or 89 |
| 9 | renew | issuer32, recipient32, correlation16: 80 |
| 10 | renewed | issuer32, recipient32, correlation16, optional deadline: 81 or 89 |

All concatenations are in table order; identity keys undergo strict existing key
validation. Correlations are nonzero 16-byte values. Optional deadline is tag 0
alone for absent, or tag 1 followed by u64 big-endian Unix milliseconds. Zero is
a finite expired deadline; absence does not erase a retained finite bound.

Enrollment sends its connection proof only after completed verified TLS. NSD
compares independently provisioned credential/pair, verifies possession and
records authorization before returning enrolled. The authenticated TLS response
must echo exact pair and pending correlation and carry NSD's actual deadline.
Pure response validation compares kind, pair, correlation and supplied clock.
Renewal requires an already authenticated session for the same pair, a new pending
correlation, and current enabled authorization. It returns renewed with the
resulting actual deadline. Authentication success alone never implies renewal.
The runtime rejects out-of-order frames; pure shape decoding grants no session.

Only a newly accepted complete roster with authenticated credential metadata
renews retained authority. Omitted bounds retain earlier finite bounds. Refusal,
cancellation and transport failure neither replace generations nor extend time.
Roster and report/answer bytes and the signed roster domain are unchanged.

## Revocation

Disable authorization for subsequent authentication, renewal and report acceptance.
Also publish a newer signed complete-empty roster to existing sessions and newer
empty bindings for all owned directory ids. Consumers persist these floors before
publishing withdrawal. Refusal or disconnection alone is not signed withdrawal;
disconnected consumers retain only independently valid authority until its
existing credential/roster/binding deadline. No new revocation latency or relay
realm ACL is defined. Original immutable reports retain historical custody.

## Separate signed directory binding

Canonical CBOR content is `[1, issuer32, relay_id_u16, participant32, realms,
version_u64, issued_at_unix_ms, expires_at_unix_ms]`. Relay id is positive and
is exactly the numeric `RelayEntry.id`, never host:port `RelayId`. Version is
positive, expiry strictly exceeds issue, and realms is a complete set of at most
8,192 canonical uppercase RealmId text values, strictly increasing by their
128-bit value. Empty is valid withdrawal. Content and signed carrier each obey
the 1 MiB bound. Signature input is `ns.account.directory-binding.v1\0` followed
by canonical content; carrier is `[content_bytes, ed25519_signature64]`. Every
field is signed. Reject nonminimal CBOR, extra fields, invalid keys, duplicate or
unordered realms, noncanonical realm text, bad domains/signatures and bounds.

The node supplies trusted issuer, selected numeric directory id, persisted
version floor and clock. Check exact issuer/id, signature, `issue <= now < expiry`.
Order independently per issuer/id, regardless of directory/roster versions.
A newer binding completely replaces owner and eligible realms, including empty.
An equal version is idempotent only with an identical previously accepted signed
record and the matching floor; it retains original deadlines. Lower versions and
changed equal versions fail. On restart a floor alone grants nothing: equal
replay is refused unless exact accepted content was also restored and verified.
Persist the floor, including empty withdrawal, before exposing replacement.

Eligibility queries require trusted current binding, the selected directory id,
the signed participant owner and the requested authenticated RealmId. Endpoint or
key equality alone never supplies this association. Missing/invalid bindings
grant no new eligibility; retained valid bindings last only until signed expiry
or newer replacement. Ownership replacement uses a newer version of the same id.
Directory entries, codes, update rules and Quick behavior remain unchanged.

## Independent sequence

`participant_auth_transport` supplies fixed fixture keys and exporter material:
authorized enrollment and unprovisioned-key refusal; authentication with fresh
proof and refusal of a prior proof on another connection; an initial signed
nonempty roster, correlated renewal, canonical unchanged report and correlated ACK;
binding A/B; replacement removing A with identical directory; disabled
reauthentication/renewal/report acceptance plus newer complete-empty roster and
empty binding; old binding replay after floor restoration refused. Independent
malformed and noncanonical cases exercise both contracts. The gateway executes
TLS/lifecycle/discovery adoption separately. NSD producer review and ns/NSD
interoperability remain outstanding.
