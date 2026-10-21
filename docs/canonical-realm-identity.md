# Canonical candidate realm identity

RealmId is exactly 16 unsigned big-endian ULID bytes, without timestamp interpretation. Every 128-bit value, including zero and the maximum, is valid. Text is exactly 26 ASCII characters using `0123456789ABCDEFGHJKMNPQRSTVWXYZ`, with first character 0–7. Lowercase, I/L/O/U, whitespace, separators, padding, alternate spellings and overflow are refused. Text order and byte order agree. Encoding equality is not authentication.

## Candidate delta

The following existing text positions stay CBOR text (MachineClaims stays JSON text), but decode to RealmId: PublicationScope/PublicationKey served_realm and authorized inputs; SubscriptionScope in stream and snapshot requests; RealmContribution.realm; MachineClaims.realm and KeySetOwner.realm; PublicEdge.served_realm; EdgeMaterialAck.served_realm; AuthConfigRequest.served_realm. Provisioning must independently supply typed expected identities. No received claim supplies its own trusted owner.

Existing binary grant payer, usage payer_realm, policy subjects/bindings/admin constraints, EdgeRealm, EdgeAuth, material acknowledgement realm and confidential configuration/request realm expose the same RealmId and retain exact 16-byte CBOR byte strings. Signed usage bytes and the historical `(payer_realm, payer_subject)` pair are unchanged. Opaque scope strings and SignedUrlScope retain their meanings; InformationResponse.realm remains a discovery hint; AuthProvider.subject_realm remains an external IdP namespace.

This is incompatible candidate acceptance: arbitrary labels such as `realm-a` are refused, with no fallback or name-to-id map. NSD and ns producer and consumer updates remain outstanding, including the other active consumer delivery. Prior evidence applies only to its recorded revision. Original-profile persisted state remains isolated.

## Independent consumer vectors

`realm-identity-membership.vec` defines A as text `030C1G60R30C1G60R30C1G60R3` and bytes `03030303030303030303030303030303`, and B as text `09144GJ289144GJ289144GJ289` and bytes `09090909090909090909090909090909`. Independent fixed pairs, zero, maximum and bit-pattern cases establish the bijection. Negative text is embedded in each owning decoder's actual wire position, before any authority replacement.

The sequence supplies signed membership serving only A and a separately valid signed public-edge publication with otherwise valid routes in A and B under the same enclosing key. Consumers admit A and refuse B; valid membership replacement removes A while the public-edge publication remains valid, so A is then refused. The enclosing key never implies membership of every contributing realm. Membership provenance, complete replacement, current validity, policy matching and independent authentication remain consumer obligations. The shared test compares decoded membership identities and route identities without introducing a runtime admission implementation.
