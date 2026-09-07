# Mesh v1 Wire Vectors

`vectors.json` contains 29 fixed synthetic vectors. `oracle.rs` constructs integer
maps and signature inputs independently of the production `control` module.
It uses only ciborium, ed25519-dalek, blake2, sha2, serde_json and hex. The golden-vector
test compiles it and compares its independent output to the checked-in bytes;
tests never rewrite or regenerate the fixture file.

All payloads and nested structures use integer field `0 = 1` for the schema.
The following ordered lists assign field numbers starting at 1. `key` is a
32-byte string, `id` a 20-byte string, `nonce`/`op` a 16-byte string, `sig` a
64-byte string, `digest` a 32-byte string, `u` an unsigned u64, `text` UTF-8,
`bytes` an opaque byte string, and `?` explicit CBOR null or the indicated type.
Exact bounds and validation live in the named production types and are exercised
by `mesh_mailbox_wire`, `mesh_recovery_wire`, `mesh_transport` and `mesh_handshake`.

| Type/API suffix | Numbered fields in order |
| --- | --- |
| register | network_pub:key, wg_pub:key, member_incarnation:u, allocate_pin:PinRequest?, network_proof:sig?, vouch:bytes? |
| registered | nonce:nonce, status:u, network_pub:key, pin:PinInfo?, admins:bytes, admins_revision:u, latest_seq:u, observed_addr:ObservedEndpoint, relay_key:key, ttl_secs:u, slot_status:u, anchor:AnchorChallenge?, creation_receipt:bytes? |
| cookie | nonce:nonce, cookie:16 bytes |
| join | pin:text, joiner_wg:key, capabilities:u, expires_at:u, cookie:16 bytes?, request_id:nonce |
| accept | network_pub:key, network_name:text, relay_origin:text, approver_wg:key, joiner_id:id, joiner_wg:key, request_id:nonce, member_incarnation:u, capabilities:u, joiner_addrs:OverlayAddresses, approver_addrs:OverlayAddresses, added_at:u, expires_at:u, network_sig:sig, joiner_pub:key |
| resolved | network_pub:key, request_id:nonce, joiner_id:id, approver_id:id, seq:u |
| deny | request_id:nonce, joiner_id:id, reason:text |
| vouch | network_pub:key, member_id:id, member_wg:key, incarnation:u, register_nonce:nonce, issued_at:u, expires_at:u, signature:sig |
| unbind | network_pub:key |
| sequenced | network_pub:key, seq:u, record:bytes |
| Eviction body | member_id:id, incarnation:u, reason:text, member_pub:key |
| Admins body | admins:bytes, admins_revision:u |
| SignedManagementRecord | kind:u, network_pub:key, op_id:op, author_pub:key, issued_at:u, expires_at:u, body:bytes, signature:sig |
| addr (peer-only) | network_pub:key, member_incarnation:u, v4_salt:u (0..u32::MAX) |
| capability (peer-only) | network_pub:key, member_incarnation:u, capabilities:u (exit bit only) |
| commit.query | network_pub:key, op_id:op, record_digest:digest |
| commit.ack | network_pub:key, op_id:op, record_digest:digest, seq:u |
| CommitReceipt | network_pub:key, op_id:op, author_pub:key, seq:u, record_digest:digest, signature:sig |
| commit.result | network_pub:key, op_id:op, author_pub:key, status:u, seq:u?, record_digest:digest, receipt:CommitReceipt? |
| restore.begin | network_pub:key, request_id:nonce, anchor_seq:u, state_digest:digest, format_version:u, total_bytes:u, chunk_count:u, network_proof:sig |
| restore.chunk | network_pub:key, request_id:nonce, anchor_seq:u, state_digest:digest, index:u, bytes:bytes |
| restore.finish | network_pub:key, request_id:nonce, anchor_seq:u, state_digest:digest |
| WssHello | challenge:32 bytes, origin:text, signer_pub:key, wg_pub:key, signature:sig |
| OverlayAddresses | v4:4 bytes, v4_salt:u (0..u32::MAX), v6:16 bytes |
| ObservedEndpoint | ip:4 or 16 bytes, port:u |
| PinRequest | ttl_secs:u |
| PinInfo | value:text, expires_in_secs:u |
| AnchorChallenge | anchor_seq:u, state_digest:digest, format_version:u |

`mesh.evict` and `mesh.admins` carry a SignedManagementRecord with kind 0/1;
fresh outer envelopes do not replace the original signed record. Other entries
with capitalized names are nested data, not additional relay endpoints.
The cookie variant is unsigned and decoded separately from ControlEnvelope.
The WSS hello is a pre-authentication payload, not a managed JWT endpoint.
`mesh.addr` and `mesh.capability` are owner-signed records exchanged over member
WG streams, not relay mailbox endpoints. Their request-domain signatures and
original-byte digests survive historical sync; membership and incarnation are
checked separately by `mesh_owner_records` before comparing timestamp/digest.

Fixed-width signature fields are raw bytes, unsigned integers are BE u64, and
dynamic fields have BE u32 byte lengths. Option uses 0/1 then the present value;
nested address inputs concatenate their fields, without CBOR map headers.
Envelope signatures cover the original payload hash, never a re-encoding.
The oracle contains each exact domain and field order. Cookie uses the domain
`nsmesh-cookie-v1` followed by NUL, IP family byte 4/6 and IP bytes, BE u16 source
port, joiner key, request ID, BE u64 initial expiry and time bucket. With key
`07` repeated 32 times, source `192.0.2.1:51900`, joiner key `01` repeated 32,
request ID `02` repeated 16, expiry 120 and bucket 2, its truncated HMAC-SHA256 is
`99c7390cfd81c669a09ce81c0732d8a3`, independently checked with OpenSSL.

Cross-repository consumers copy these same bytes and run semantic assertions,
signature checks and transport bounds. A successful fixture check is protocol
evidence only; it does not establish native networking or runtime readiness.
