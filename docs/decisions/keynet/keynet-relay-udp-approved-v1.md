[design-review keynet-relay-udp v1]
campaignId: cmp-202609130355
recommendation: change; accept option C with the following exact text and defaults.

basis:
- Proposal /workspace/nsiod/.local/keynet-campaign/keynet-relay-udp-proposal.md:1-161; design /workspace/nsiod/docs/docs/ns/keynet.md:171-202,273-278,430-452,473-502,516-595, verified SHA-256 7c99ffb2e03c0728128da7270754aa065148e263fdc7c3aef233ff9696fa8a9f.
- Engine /workspace/nsiod/keynet/nsgw/crates/nsgw-wg/src/relay.rs at a81fe20:737-847,1419-1450,1557-1570,2453-2541 supports batching/bucket reuse and confirms linear scanning; it does not implement keynet.
- WireGuard cookies depend on a changing responder secret; relay and endpoint cookies can differ and cause alternating challenges. Fully padded 1380-byte inner packets plus IPv6/UDP/WireGuard/relay overhead reach 1509 bytes. These conclusions follow from the [WireGuard protocol](https://www.wireguard.com/protocol/). Reject all-zero DH as specified in [RFC 7748 §6.1](https://www.rfc-editor.org/rfc/rfc7748#section-6.1).

verdicts:
Exact replacements for every change and accepted text follow under recommended_text.
- 5.1 change: confirmed source registration, UDP-only reflection and path-specific MTU.
- 5.2 change: tentative registration, retained marks, fixed-source controls, authenticated replies and bounded queues. Relay-minted cookies are deferred because matching cookie-reply encryption does not match the endpoint's cookie secret.
- 5.3 change: datagram carrier semantics and separation from peer authorization.
- 5.4 change: INTRO contents are visible; direct success can be inferred; UDP has no relay-name authentication.
- 13.5 change: replace in full with the schemas, transcripts and rules below.
- 13.2 REGISTER signature row accept, reproduced below.
- 13.2 Relay control MAC replacement change: bind both header ids and nested unsigned body, and add a separate reply context.
- 13.2 session HKDF addition change: bind the complete signed registration digest.
- 13.2 nonce sentence change, necessary consistency edit: retain 32-byte introduction nonces; separately define 16-byte reflection nonces.
- 13.4 slot-id addition change: unchanged digest construction plus zero reservation and full-owner collision checks.
- 13.6 proposed datagram/header/DATA/control/slot/timestamp rows accept, reproduced below.
- 13.6 ephemeral/sk and TTL rows change: complete widths and accepted TTL range below.
- 13.6 removal of old frame/DATA caps accept.
- 13.6 old Nonce and secret/PSK/MAC/proof rows change: replace by the complete table below, including new pending/sequence/retention/text bounds.
- Part 5 §6.6 MTU change: entire replacement bullet below, per-path 1376 plus measured-PMTU bounds.
- Part 5 §8 model change: separate active, tentative and retained state below.
- Part 5 §9 relay bullet accept, reproduced below.
- Part 5 §11 row 9 change: reject unbounded mac1 scanning, not all future bounded kernel demultiplexing.
- Part 5 §11 deferred list change: retain kernel deferral and include relay-minted cookies.
- Part 5 §12 relay row change: full replacement below includes possession confirmation and UDP reflection.
- Part 5 §7.5 step 2 change: full replacement below requires confirmed PRESENCE; retain approved CLI timing semantics.

open_points:
1. Slot width. default: 16-byte BLAKE2s slot id, 37-byte header; zero reserved, full owners compared, collisions fail without changing the incumbent.
2. Registration. default: Signed six-field REGISTER without a long-term relay key; tentative REGISTERED, node PRESENCE proof, then a positive REGISTERED acknowledgment before use. This proves possession of the authorized ephemeral, not K. Immediate occupation on a signed datagram is rejected because signatures do not prove source reachability or private-key possession.
3. DATA authentication. default: No per-DATA MAC; accept source-spoofing/on-path availability risks explicitly, enforce fixed-source sessions and budgets, retain end-to-end WireGuard. Reject the claim that a MAC gains nothing: it would limit injection, but cost is a deliberate tradeoff. Defer relay-minted cookies and reuse hard buckets.
4. MTU. default: Per-path enforcement, existing interface MTUs, default relayed ceiling 1376 and actual-PMTU/padding checks; no silent encrypted-datagram splitting or false IPv6 MTU below 1280.
5. WSS convention. default: Same host/port, /keynet/v1, keynet-relay-v1, normal TLS verification, bounded binary messages, no UDP candidate from WSS. Migration requires confirmation; failed UDP probes retain active WSS.
6. Roadmap. default: Substantive deviation affects=[5,6]; phases 2-4 implementation/contracts/vector payloads remain unchanged. Full-design re-pinning also changes campaign acceptance metadata: combined bookkeeping deviation affects=[1,2,3,4,5,6], with 1-4 metadata only, matching the CLI-review distinction.

roadmap_impact:
- Phase 5 replaces the stream/header schemas with pure exact-datagram/header/control codecs, slot derivation, REGISTER sign/verify, X25519/HKDF and directional MACs; caller-supplied state supports freshness/correlation/replay decisions. Fixtures cover all types/directions, canonicalization, complete preimages, all-zero DH, tentative/committed decisions, timestamp/generation/incarnation/sequence edges, collisions, UDP/WSS observations and encoded bounds.
- Phase 6 seals independent literal vectors and the final design pin, replacing stream expectations while preserving earlier payloads and inventory defenses.
- Dependencies/path scope are unchanged. No sockets, async runtime, gateway dependency, relay service, cookie engine or old-crate edits. Pure-Rust X25519 support remains within the approved phase 5 helper boundary.
- Phase 2 continues on the current digest. No phase 5 spec or re-pin before the gate and owner-reported revision.

recommended_text:

## 5. Relay and Transport Adapter

The relay carries encrypted WireGuard datagrams and pairing introductions. It holds no overlay private key or overlay address/name and cannot authorize peers at endpoints. It authenticates registrations and enforces transport admission and limits.

### 5.1 Model

| Function | Mechanism |
| --- | --- |
| Carrier | UDP, with a 37-byte addressed header and unchanged WireGuard DATA body; one identical datagram per binary TLS WebSocket message as fallback (§13.5). |
| Rendezvous | At the token's home relay, signed REGISTER authorizes a fresh ephemeral session; REGISTERED and a confirmed PRESENCE establish the slot. Its 16-byte id derives from (network_id,I); retain the full owner tuple. |
| Introduction | The joiner confirms its slot at the issuer's relay before sending INTRO. INTRO_ACK returns there. Either introduction may also use a known direct UDP endpoint under §13.5. |
| Forwarding | Check active sender source, look up explicit destination, apply budgets and forward the complete datagram unchanged; no all-target mac1 scan. |
| Reflection | Return only an active node's own observed UDP endpoint. A WebSocket source is not a UDP candidate. |
| Path selection | The adapter owns direct/relay paths, maintains a stable virtual WireGuard endpoint and enforces per-path MTU (§6.6). |
| Endpoint exchange | Exchange candidates inside an established WireGuard session. A relay path can bootstrap this; reflection does not guarantee traversal of every NAT. |
| Scaling | Issuers select relays; no global identity-to-relay directory. Nodes register at required peer relays within local limits. |

The user-space socket adapter adds/strips headers and maps slots to configured full identities. Direct WireGuard packets have no relay header. Kernel integration is deferred. Each relay slot has one active source; NAT/carrier migration requires a new confirmed registration.

### 5.2 Authentication and limits

- **Registration.** I signs a current KeyBinding, incarnation, timestamp, fresh ephemeral and exact relay name. A bounded tentative session cannot route traffic or replace a live source until a session-key PRESENCE returns from that source. REGISTERED acknowledges tentative setup and later PRESENCE. This proves possession of the ephemeral authorized by I, not K; the binding authorizes K.
- **Freshness.** Apply §13.3 generation/conflict/revocation rules and §13.5 incarnation ordering across carriers. Reject zero slot ids and full-owner collisions. Retain security marks after route expiry or REVOKE; captured or unconfirmed requests cannot move a source.
- **Source binding.** The confirmed source is an exact UDP IP/port tuple or WebSocket connection. Controls must use it. DATA, introductions, observations and incoming packets never change it; migration requires a new signed incarnation and confirmation.
- **Peer authorization.** Relay access grants no peer permission. Endpoints validate token proofs/bindings or WireGuard authentication, allowlist and PSK. The adapter checks local dst and installed src peers before decrypting DATA. Slot headers are not cryptographic identity.
- **Budgets.** Before cryptography, bound REGISTER work per source IP and globally. Bound tentative/active slots, retained marks, per-connection slots, queued bytes/age and replies. Limit controls/INTRO and DATA packets/bytes by sender, destination and globally; separately bucket handshake initiations per destination. Offline delivery is not buffered. On capacity exhaustion reject new work rather than evicting security marks early.
- **DATA and cookies.** No extra DATA MAC is used; UDP source spoofing and on-path injection remain availability risks. WireGuard authenticates and rejects replays end to end. Forward endpoint-generated cookies unchanged. Relay-minted cookies are deferred: independent relay/endpoint secrets are not interchangeable.
- **Replies.** REGISTERED/REFLECTED are session-authenticated and correlated. STATUS is advisory, not delivery, liveness, revocation or pairing-denial proof. Unconfirmed UDP replies cannot exceed the triggering datagram; output queues are bounded.
- **Trust.** UDP authenticates the node to the relay but not the advertised relay name to the node. An active path attacker can impersonate/disrupt it. WSS verifies normal server certificates. Neither grants the relay endpoint secrets or authority.

### 5.3 Messages and the in-band control channel

REGISTER, REGISTERED, PRESENCE, REFLECT, REFLECTED, INTRO, INTRO_ACK, DATA, STATUS and REVOKE use §13.5. Each UDP datagram or complete binary WebSocket message contains one relay datagram; there is no length-framed byte-stream profile.

The in-band control channel is a fixed UDP port inside the tunnel, reachable only at N6(self), carrying signed endpoint candidates, KeyBinding updates/cutover times, recovery statements, optional name records and revocations between peers. It exists only after WireGuard establishment and is authenticated by that session. Relay controls and peer admission are separate.

### 5.4 What the relay sees

The relay sees registered identities/bindings/ephemerals, sources, presence, introduction bodies/timing, and encrypted packet sizes and slot relationships. INTRO/INTRO_ACK are authenticated but not encrypted at this layer. Token secrets and end-to-end private keys are not sent to the relay.

In-band endpoint candidates are encrypted, but observed UDP addresses are known and traffic changes can reveal likely direct-path success. A relay can misreport observations, inject unauthenticated traffic and deny service; it cannot forge endpoint-authenticated records or decrypt WireGuard payloads. These metadata/availability limits also apply to an authenticated malicious WSS relay.

### 13.5 Relay datagrams

This replaces the length-framed stream profile. Exactly one UDP datagram or complete binary WebSocket message contains one relay datagram. Maximum length is 2048 bytes including header; non-DATA types also have a 1200-byte limit. Reject over-limit/truncated transport messages before body parsing or allocation. These are codec bounds, not path MTUs.

| Offset | Width | Field |
| --- | --- | --- |
| 0 | 4 | ASCII magic KNR1 |
| 4 | 1 | type u8 |
| 5 | 16 | src slot id |
| 21 | 16 | dst slot id |
| 37 | remainder | body |

KNR1 identifies this version. There is no length or generation field. Inputs shorter than 37 bytes or with different magic are invalid. Zero slot id means relay. Types 1,3,4,10 require nonzero src and zero dst; types 2,5,9 require zero src and nonzero dst; types 6,7,8 require both nonzero.

Except DATA, each body is exactly one canonical fixed-length §13.1 array, with no trailing bytes. Enforce all byte widths, unsigned ranges, nested shapes and UTF-8 before authentication. binding means the complete signed eight-field KeyBinding. Do not normalize received bytes.

| Type | Name | Direction | Body |
| --- | --- | --- | --- |
| 1 | REGISTER | node to relay | [binding, incarnation u64, ts u64, node_ephemeral bytes32, relay_name text, sig bytes64] |
| 2 | REGISTERED | relay to node | [incarnation u64, relay_ephemeral bytes32, presence_ttl_s u32, observed_addr, ack_seq u64, mac bytes32] |
| 3 | PRESENCE | node to relay | [incarnation u64, seq u64, mac bytes32] |
| 4 | REFLECT | node to relay | [incarnation u64, seq u64, nonce bytes16, mac bytes32] |
| 5 | REFLECTED | relay to node | [incarnation u64, seq u64, nonce bytes16, observed_addr, mac bytes32] |
| 6 | INTRO | through relay or direct | [network_id bytes32, I_recipient bytes32, binding_recipient, nonce bytes32, mac bytes32] |
| 7 | INTRO_ACK | through relay or direct | [network_id bytes32, I_issuer bytes32, binding_issuer, nonce bytes32, mac bytes32] |
| 8 | DATA | node through relay to node | One unchanged WireGuard datagram, 1..2011 bytes, opaque to this codec, not CBOR |
| 9 | STATUS | relay to node | [type_in u8, destination bytes16, status u8] |
| 10 | REVOKE | node to relay | [incarnation u64, seq u64, reason u8, mac bytes32] |

relay_name is 1..255 UTF-8 bytes and matches an advertised relay identifier byte-for-byte. No case folding or URI normalization occurs in the codec. A token host:port selects both carriers; a short id resolves through explicit local configuration, not a new registry. Resolution does not change signed relay_name.

observed_addr is [ip bytes4 or bytes16, port u16 in 1..65535]. IPv4 uses four bytes, never mapped IPv6. REGISTERED on WSS uses null; UDP REGISTERED and REFLECTED use an address. Reject UDP registration from scoped IPv6 sources whose zone cannot be represented. Observations are advisory candidates requiring reachability testing, not peer assertions or guarantees about NAT behavior.

REGISTERED ack_seq=0 is tentative; positive ack_seq acknowledges PRESENCE and an active slot. TTL is 30..3600 seconds, default 90. REFLECTED echoes its request's seq and nonce. REVOKE reason is 0 rotation or 1 shutdown; others are malformed. STATUS destination echoes input dst; status is 1 no destination, 2 rate limited, 3 too large, 4 stale generation/incarnation, 5 unsupported type, 6 sender unregistered/source mismatch. Other values are malformed. STATUS has no success/delivery or pairing-denial meaning.

Signature and key/MAC transcripts:

- REGISTER uses ordinary Ed25519 by binding.I over ASCII "keynet/relay-register/v1" || CBOR([binding,incarnation,ts,node_ephemeral,relay_name]). The nested binding includes its signature.
- R is the canonical six-field signed REGISTER body; reg_hash=SHA256(R). ss is X25519 of the local ephemeral private key and the other side's public ephemeral. Reject all-zero ss. Fresh attempts use fresh private ephemerals; exact retransmissions reuse the attempt.
- sk is HKDF-SHA256, absent salt, IKM ss, info ASCII "keynet/relay-session/v1" || src_slot || incarnation_be64 || node_ephemeral || relay_ephemeral || reg_hash, output 32 bytes. src_slot is REGISTER.src. Concatenated fields are fixed-width; incarnation is eight-byte big-endian.
- Node controls 3,4,10 use HMAC-SHA256(sk, ASCII "keynet/relay-ctl/v1" || CBOR([magic_bytes4,type,src,dst,U])). Relay replies 2,5 use "keynet/relay-reply/v1" with the same five-field array. U is the nested body array without its final mac, not flattened or wrapped in a byte string. magic_bytes4 contains KNR1. Verify canonicality/schema before constant-time MAC verification.
- INTRO/INTRO_ACK keep their §13.2 token-secret MACs unchanged; no relay header enters those preimages. After authenticating a body, an endpoint requires dst equal its local slot, a matching local network, src equal the slot derived from the body's sender/network, and a binding naming that sender/network. The header cannot authorize or substitute identity.

Registration and controls:

1. Before cryptography enforce lengths, magic, direction, canonical schema, budgets, derived REGISTER.src, relay_name and inclusive abs(now-ts)<=120 seconds without overflow. Verify the binding signature/current validity and REGISTER signature before tentative state. Apply §13.3 marks; a same-generation different-K candidate may be staged for possession confirmation but never installs a route or clears conflict. Invalid input never commits state.
2. A tentative record is keyed by relay service, full owner, exact signed REGISTER and exact source. Give it a fresh relay ephemeral and a 10-second maximum lifetime. Identical same-source retransmissions resend the same tentative REGISTERED without extending its lifetime. Another source may receive a separately bounded challenge with a different ephemeral; it cannot move the existing tentative/active source or reserve the active slot merely by arriving first.
3. The node verifies tentative REGISTERED's MAC, current attempt, source/connection, TTL and observation, then sends a positive-sequence PRESENCE under sk. The relay verifies its MAC and exact tentative source and rechecks pending expiry, timestamp, binding current validity and current marks before committing. Unconfirmed slots cannot forward.
4. Confirmation atomically commits binding/marks, source, incarnation, sk and seq, retires the old session, and sends REGISTERED acknowledging that seq. The node uses the slot only after a matching positive acknowledgment. If it is lost, another PRESENCE with a new seq obtains a fresh acknowledgment from the now-active session.
5. Lower or revoked generations fail. A valid possession-confirmed same-generation different-K claim latches §13.3 conflict and disables that generation until a higher acceptable generation; it never chooses the latest K. Within an unconflicted generation/K, a new session needs a greater incarnation. Higher generation may reset incarnation. Equal generation/incarnation is idempotent only for the exact REGISTER/source while that session lives; it cannot recreate an expired/revoked session.
6. Reject different-full-owner slot collisions without changing the incumbent. Persist generation/revocation/conflict marks under §13.3; retain current-generation incarnation marks after expiry/REVOKE until a higher generation supersedes them. Nodes persist increasing incarnation per relay/generation across carriers. Bound mark storage and refuse new identities rather than discard security marks to admit them. Counter exhaustion requires a higher valid generation, never wraparound.
7. Node seq starts at 1 and increases by one per new control transmission. Receivers accept any authenticated seq above the high-water mark, permitting gaps under loss/reordering. Lower/equal values are dropped without reply, TTL refresh or state change. Invalid MACs never advance marks. Exhausted seq requires a new confirmed incarnation.
8. Only accepted node controls from the exact active source refresh TTL. Data, introductions, duplicate REGISTER/control, STATUS and replies do not. Expiry is exclusive at the earlier of last-control-plus-TTL or binding.not_after. REVOKE removes this session, preserving marks; it does not revoke tokens or peer allowlists.
9. PRESENCE confirms setup and then runs at most min(TTL/3,25 seconds) apart. Each accepted request receives REGISTERED with matching ack_seq. Nodes accept replies only for current-session outstanding requests; replay does not refresh liveness. Two intervals without a fresh authenticated matching response initiate recovery, not a conclusion about issuer denial/offline status.
10. REFLECT requires an active UDP source and increasing authenticated seq. Accept REFLECTED only for the current session's outstanding seq/nonce. WSS REFLECT is unsupported, may return STATUS 5, and produces no UDP candidate.
11. NAT rebinding/new connection/carrier migration needs a fresh signed ephemeral and greater incarnation, then confirmation. Keep an otherwise-valid old source while replacement is tentative. Queued output is tied to its committed session; retirement drops that session's queued sends instead of redirecting them to the new source.

Forwarding and errors:

Require live src with exact source and live dst in the same network for DATA/INTRO/INTRO_ACK; apply sender/destination/global budgets and forward bytes unchanged. Lookup uses slot ids and stored full owners. Validate introduction body/nested binding shape, but leave end-to-end MAC/signature validation to endpoints.

The receiver checks local dst and installed full-peer mapping of src before feeding stripped DATA to its stable WireGuard endpoint. WireGuard validates the opaque body, current key and replay window; the header authenticates neither sender nor generation. Direct WireGuard uses raw datagrams. Only direct INTRO/INTRO_ACK use KNR1, with full bounds/token/body/header checks even from unknown sources. Do not treat arbitrary header-wrapped direct DATA as relay traffic. Forward endpoint cookies unchanged; do not mint relay cookies using a forged peer slot.

Malformed known types are silent on UDP. Unknown types under KNR1 may receive STATUS 5. STATUS 1-5 require a registered matching source. STATUS 6 may answer an unregistered/mismatched source except REGISTER/STATUS; never reply to STATUS with STATUS. All STATUS replies must fit the triggering datagram and source/global reply budgets. Tentative REGISTERED cannot exceed its REGISTER request. Otherwise drop silently. Unauthenticated STATUS never moves/deletes a session or confirms liveness.

The decoder does not wait for more bytes or consume concatenated records. Non-DATA ends exactly at its canonical array; DATA consumes the bounded remainder. Preserve UDP truncation detection and bounded WebSocket assembly before passing a slice to it.

WebSocket carrier:

Use wss://host:port/keynet/v1 and subprotocol keynet-relay-v1 at the UDP host/port. Verify normal TLS certificates; UDP failure does not waive validation. Short identifiers resolve through explicit local host/port/trust configuration.

One binary message contains one datagram. WebSocket fragmentation is permitted with aggregate assembly bounded to 2048 and the 1200 control cap enforced when type is known. No compression extension, text, concatenated records or length prefix. Text/oversize/bad-magic/malformed known-type messages close the connection. Standard WebSocket control frames do not refresh keynet presence.

Confirm at least one registration within 10 seconds of connection opening. Additional slots have independent sessions and configured per-connection/global bounds. Expire slots individually; close a connection with neither active slots nor unexpired tentative registrations. Closing retires its slots without erasing marks. UDP/WSS slots can forward through the same table.

Default UDP startup retransmits the same REGISTER at 0,1,2 seconds; no usable tentative response by 3 seconds permits WSS fallback. Failure to confirm by the 10-second attempt deadline also permits fallback. Confirm fallback before replacing a working source. Retry UDP after 60 seconds with bounded back-off and hysteresis; intervals are configurable. Only a confirmed newer incarnation changes the active source; failed probes retain working WSS.

13.2 edits:

Preserve all existing KeyBinding, PairingToken, NameRecord, INTRO/ACK schemas and contexts. Add the signature row:

| Relay REGISTER | keynet/relay-register/v1 | [binding, incarnation, ts, node_ephemeral, relay_name] | the same five fields followed by sig (six fields) |

Replace the MAC introductory sentence:

MACs are HMAC-SHA256 over an ASCII context followed immediately by the canonical array below. INTRO/INTRO_ACK use the token secret; relay controls/replies use sk.

Replace Relay auth with:

| Relay control | keynet/relay-ctl/v1 | [magic_bytes4,type,src,dst,unsigned_body_array], types 3,4,10, key sk (§13.5) |
| Relay reply | keynet/relay-reply/v1 | [magic_bytes4,type,src,dst,unsigned_body_array], types 2,5, key sk (§13.5) |

Replace only the nonce sentence; preserve the following pair-PSK sentence:

INTRO/INTRO_ACK nonce is 32 bytes, generated by the INTRO sender from a cryptographic random source and echoed by INTRO_ACK; relay reflection nonce is separately 16 bytes.

Append after the PSK paragraph:

Relay sk is HKDF-SHA256 with absent salt, IKM ss from ephemeral X25519, info ASCII "keynet/relay-session/v1" || src_slot || incarnation_be64 || node_ephemeral || relay_ephemeral || reg_hash, output 32 bytes. reg_hash is SHA256 of the canonical signed six-field REGISTER. Reject all-zero ss. Section 13.5 fixes all header/nested-array transcripts; pair PSK and introduction MACs are unchanged.

13.4 addition:

- Slot id: BLAKE2s with a 16-byte digest and key "keynet-relay-slot-v1" over network_id || I, using the complete two 32-byte inputs. It identifies a relay slot, is not secret, and is not an overlay address. The all-zero value is reserved for the relay; a node whose derived id is zero cannot register using this profile. Relays retain and compare the full (network_id, I) owner alongside the hash and reject a different-owner collision without altering the incumbent slot or its security marks. Do not remap a colliding/zero digest, truncate the owner check or silently regenerate identity.

13.6 edits:

Remove the Frame body cap and DATA payload cap rows. Replace the Nonce and secret/PSK/MAC/proof rows and add the relay rows so that the resulting limits table is:

| Item | Value |
| --- | --- |
| Address format version ver | 1 |
| KeyBinding, PairingToken, NameRecord, INTRO record versions | 1 |
| Token text form maximum | 1024 bytes |
| issuer_name, net_name, relay, endpoint text fields | at most 255 bytes each, valid UTF-8 |
| Label | 1-63 bytes after normalization |
| INTRO/INTRO_ACK nonce | 32 bytes |
| secret, PSK, MAC | 32 bytes |
| Relay datagram maximum | 2048 bytes, header included |
| Relay header | 37 bytes: magic KNR1, type, src, dst |
| DATA body maximum | 2011 bytes; nonempty, opaque to the relay codec |
| Control datagram maximum, types 1-7,9,10 | 1200 bytes, header included |
| Slot id | 16 bytes; zero reserved for relay |
| Relay ephemeral public keys, ss, sk, reg_hash | 32 bytes; all-zero ss rejected |
| Relay REGISTER relay_name | 1-255 UTF-8 bytes; exact advertised-name match |
| Relay reflection nonce | 16 bytes |
| REGISTER ts | Unix seconds u64; inclusive +/-120-second window; overflow-safe comparison |
| presence_ttl_s | u32 in 30..3600; default 90 seconds |
| PRESENCE interval | At most min(presence_ttl_s/3,25 seconds); each accepted request has a matching authenticated REGISTERED reply |
| Tentative registration lifetime | At most 10 seconds; duplicate REGISTER does not extend it |
| Presence expiry | Exclusive, additionally bounded by KeyBinding not_after; only accepted node controls refresh it |
| Relay incarnation | u64; strictly increases within generation for new sessions, across carriers; never wraps |
| Relay control sequence | u64 starting at 1 per session; sender increments, receiver allows gaps and rejects lower/equal values; never wraps |
| Relay reply correlation | REGISTERED ack_seq=0 tentative, positive ack_seq matches PRESENCE; REFLECTED matches current-session seq and nonce |
| Retained relay marks | Generation/revocation/conflict marks follow section 13.3; current-generation incarnation marks survive slot expiry and REVOKE |
| Default relayed inner MTU ceiling | 1376 bytes, further bounded by actual path MTU (§6.6) |

Consistency replacements:

Section 6.6: replace the entire MTU bullet with:

- **MTU.** The WireGuard interface MTU is 1420; the IPv4 side advertises 1400. The default relayed inner ceiling is 1376 (1356 for ordinary IPv4 with 20-byte translation expansion). Enforce the selected path ceiling before encryption; generate validated, rate-limited ICMPv6 Packet Too Big and translate it to IPv4 Fragmentation Needed under existing fragment/ICMP rules. Reverse translation adds 20 and never advertises IPv6 MTU below 1280. UDP relay adds 37 bytes to IP/UDP and WireGuard's 32-byte data overhead plus padding. A safe ceiling with 16-byte padding is 16*floor((outer_path_mtu-outer_ip_header_bytes-8-37-32)/16), further capped by 1376 and actual encapsulation limits. Count outer options/extension headers. The 2048-byte codec cap is not a path MTU. Cache/revalidate MTU on path switches; do not silently send larger direct packets through relay. If actual encapsulation cannot carry inner IPv6 MTU 1280, select another viable carrier or report failure; no application fragmentation of encrypted datagrams is defined. WSS lets TCP segment message bytes but uses the same relayed inner ceiling. The adapter handles outer ICMP errors.

Section 8: replace the Relay model block and append its explanatory sentence:

Relay:
Slot { network_id, I, slot_id, binding, K, gen, incarnation, source, sk, seq_high_water, presence_ttl_s, last_control, registration_hash, budgets }
PendingRegistration { owner, slot_id, signed_register, source, node_ephemeral, relay_ephemeral, sk, created_at, deadline }
RelayMarks { network_id, I, committed_gen, committed_K, conflicted, revoked_through, incarnation_high_water }

source is a UDP IP/port tuple or a WebSocket connection identifier. These are runtime data-model sketches, not additional wire records. Pending state is bounded and cannot route traffic; dropping a Slot or PendingRegistration does not erase RelayMarks.

Section 9: replace the Relay bullet with:

- **Relay.** Encrypted datagrams travel behind the 37-byte relay header when the adapter selects the relayed path; addresses, sessions, and translation are unaffected.

Section 11: add decision row 9:

| 9 | Relay carries raw WireGuard datagrams over UDP behind an addressed 37-byte header, with identical datagrams in TLS WebSocket messages as fallback (§5, §13.5) | A length-framed stream as the only carrier; unbounded all-slot mac1 scans for destination discovery |

Section 11: replace the Deferred paragraph with:

Deferred: kernel WireGuard (§6.8), lossless key rotation, unlinkable per-network identities (which require per-network I and K), application-layer gateways, service publication, exit nodes, a well-known public relay list, relay load-shedding lists, and relay-minted WireGuard cookies with an explicitly interoperable endpoint admission profile.

Section 12: replace the complete Relay row with:

| Relay | Slot keyed by public key; endpoint exchange on request | Authenticated slot keyed by (network_id, I), registered by a signed datagram and confirmed by possession of its authorized ephemeral session key; explicit-slot forwarding of WireGuard datagrams, INTRO and INTRO_ACK over UDP or TLS WebSocket; reflection of the node's own UDP endpoint only; peer endpoints exchanged in-band | Captured registrations must not occupy or move a live slot; the relay remains outside peer authorization and is not an endpoint directory |

Approved CLI section 7.5: replace only step 2 with:

2. **Introduce.** The recipient constructs the INTRO and MAC exactly as specified in §13.2 and §13.5, using a runtime-generated 32-byte nonce associated with the live attempt. It sends to the issuer's reachable direct endpoint or home relay. When relayed, the recipient first completes REGISTER/REGISTERED and confirms its own slot using a session-authenticated PRESENCE and matching positive REGISTERED acknowledgment, so INTRO_ACK has an active return destination. The runtime retries with bounded back-off and jitter until token expiry or local cancellation. The CLI observation budget does not stop retries.

application:
- Bare go accepts this text, six defaults and roadmap impact. Only the owner applies text and reports the new digest. Preserve approved CLI text except the explicit step 2 clarification.
- No files, specs, pins, branches or phase execution changed. This follow-up retains the review.
[/design-review]