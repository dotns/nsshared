# Canonical RealmId

`RealmId` (`nsshared_identity::realm::RealmId`) identifies a membership realm.

## Encoding

A RealmId is exactly 16 unsigned big-endian ULID bytes, without timestamp
interpretation. Every 128-bit value, including zero and the maximum, is valid.
Text is exactly 26 ASCII characters using `0123456789ABCDEFGHJKMNPQRSTVWXYZ`, with
first character 0–7. Lowercase, I/L/O/U, whitespace, separators, padding, alternate
spellings and overflow are refused. Text order and byte order agree. Encoding
equality is not authentication.

## Positions

Text positions stay CBOR text (MachineClaims stays JSON text) and decode to RealmId
with the exact uppercase 26-character spelling: PublicationScope/PublicationKey
served_realm and authorized inputs; SubscriptionScope in stream and snapshot
requests; RealmContribution.realm; MachineClaims.realm and KeySetOwner.realm;
PublicEdge.served_realm; EdgeMaterialAck.served_realm; AuthConfigRequest.served_realm.
Arbitrary realm labels such as `realm-a` are refused, with no fallback or
name-to-id map. Provisioning must independently supply typed expected identities;
no received claim supplies its own trusted owner.

Binary positions expose the same RealmId and keep their exact 16-byte CBOR byte
strings: grant payers, usage payer_realm, policy subjects, bindings and admin
constraints, EdgeRealm, EdgeAuth, the material acknowledgement realm and the
confidential configuration and request realm. Signed usage bytes and the
`(payer_realm, payer_subject)` pair are unchanged by this encoding.

Opaque scope strings and SignedUrlScope keep their own meanings;
InformationResponse.realm is a discovery hint; AuthProvider.subject_realm is an
external identity provider namespace. None of them is a RealmId.

## Membership consumption

`crates/nsshared-control/tests/vectors/account/realm/membership.vec` defines A as
text `030C1G60R30C1G60R30C1G60R3` and bytes `03030303030303030303030303030303`, and B
as text `09144GJ289144GJ289144GJ289` and bytes `09090909090909090909090909090909`.
Independent fixed pairs, zero, maximum and bit-pattern cases establish the
bijection. Negative text is embedded in each owning decoder's actual wire
position, before any authority replacement.

The sequence supplies signed membership serving only A and a separately valid
signed public-edge publication with otherwise valid routes in A and B under the
same enclosing key. Consumers admit A and refuse B; a valid membership
replacement removes A while the public-edge publication stays valid, so A is
then refused. The enclosing key never implies membership of every contributing
realm. Membership provenance, complete replacement, current validity, policy
matching and independent authentication are consumer obligations. The test
module `account::realm::membership` compares decoded membership identities and
route identities without a runtime admission implementation.
