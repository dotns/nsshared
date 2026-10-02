## 2026-10-02 [feat]

Replace `quick-wire` with `ns-wire`, the NS protocol v2 wire layer (docs
`ns/quick-v2.md`): identity derivations (node ID, address group, `lan6`, alias
candidates), node records and the §3.3 ordering state, relay packets v2 with
REGISTER admission, session key and MACs, the region member protocol v2 and the
in-tunnel control messages. There is no v1 compatibility: KeyBinding,
INTRO / INTRO_ACK, `revoked_through` and the region QUICK frames are gone. The
consumers, the nsgw quick relay and ns, switch to `ns-wire` in migration
milestone M5 (plan P2). See [ns-wire spec coverage](spec-coverage/ns-wire.md)
and [ns-wire protocol crate](task/20261002-1516-quick-wire.md).

## 2026-10-02 [refactor]

Rebuild ns-shared on `next` around the Quick protocol. The workspace starts
with `quick-wire` (from `keynet-proto`) and `quick-rendezvous` (from
`keynet-quick`) on the pma-rust baseline: workspace lints that also deny
`unwrap`, `expect` and `panic` outside tests, rustfmt 2024 style, latest stable
dependencies (`ed25519-dalek` and `x25519-dalek` 3, `blake2` 0.11, `getrandom`
0.4 instead of `rand_core`'s removed OS RNG), cargo-shear with
`--deny-warnings`, doctests, the vector checks in `just qa`, and a Gitea QA
workflow. The previous workspace is archived at tag `archive/v1-20261002`.
Consumers move to Cargo git dependencies pinned by tag. See
[next workspace baseline](task/20261002-1516-next-workspace-baseline.md).

## 2026-09-29 [feat]

Add the gateway probe set. `GatewayWgRelayConfig` gains an optional
`probe_set` of `GatewayWgRelayProbeEntry { machine_id, machine_key_pub,
wg_pubkey }`, encoded like `GatewayWgRelayPair.nsn_machine_id`,
`nsn_machine_key_pub` and `nsn_pubkey`. It lists the machines of the realm
whose probe roster names the gateway, so the gateway can answer their
measurement-only reflexive probes; it is leased and fenced with the relay
table. The field is absent when empty and decodes to empty when missing, so
payloads without it keep their exact bytes. See
[Gateway probe-set projection type](task/20260929-2150-relay-placement-probe-set.md).

## 2026-09-27 [feat]

Add the region quick owner agreement decision. `decide_region_quick_owner`
classifies a control link as agreed (same owner and epoch on both sides),
inactive (neither side has an owner) or mismatched (anything else, including a
legacy HELLO read by a member with an owner), and records the peer's claim in
the in-memory `RegionQuickOwnerState`. A member may serve a broker only while no
peer has presented a higher epoch or its own epoch with a different owner; the
fence is lifted by a local epoch above the highest observed, by one equal to it
whose owner every peer at that epoch presented, or by a new state at restart.
The peer input is the HELLO extension itself, so an extension is never read as
the legacy HELLO; one with an out-of-range owner or epoch 0 is mismatched and
fences the member until its local epoch exceeds the presented one.
The 32 decision vectors join the sealed `keynet-region-quick-v1` set. See
[Region quick owner agreement decision](task/20260927-2212-region-quick-owner-decision.md).

## 2026-09-27 [feat]

Add the region quick frames and the extended region HELLO. `RegionHello`
gains an optional control-only sixth element `[capabilities, quick_owner,
quick_owner_epoch]`; without it the five-element body is unchanged. The
control-only QUICK_REQUEST (type 11) and QUICK_RESPONSE (type 12) frames carry
opaque quick pairing messages of at most 16384 bytes and an opaque actor of at
most 1024 bytes. They have their own body limit, `MAX_REGION_QUICK_FRAME_BYTES`
(17478, the largest valid QUICK_REQUEST), and their own prefix decoder; every
other frame type keeps 4096 bytes. The
frame version stays 1 and the existing fixture set is unchanged; the new
vectors form the sealed `keynet-region-quick-v1` set. See
[Region quick frames](task/20260927-2148-region-quick-frames.md).

## 2026-09-26 [fix]

Stop snapshot completion from replacing a local member's session without
retiring it. `RegionSnapshotCompletionInput` names the local member; when a
staged record wins the shared selection over one of its sessions (a higher
incarnation, or the equal-state tie-break for a lower remote member id), the
completion keeps both tables and the stage, returns
`LocalRetirementRequired` and one `RetireLocalPresence` effect per superseded
session. The caller retires those sessions with a mesh-only GONE reason 2 in
its local publication order and repeats the completion. The event decision is
unchanged. See
[Snapshot completion local supersession](task/20260926-0649-region-snapshot-local-supersession.md).

## 2026-09-25 [feat]

Add the control-only region SETTLED frame (type 10). It carries a data
connection generation and a cumulative forward id, and tells an entry member
that the exit has finally decided every forward on that generation up to the
id, so no MISS for them follows. It uses the strict fixed-arity CBOR rules of
MISS, is illegal on data, and rejects a zero generation or forward id. The
frame version stays 1; the sealed region frame fixture declares the new cases.
See [Region SETTLED frame](task/20260925-1655-region-settled-frame.md).

## 2026-09-24 [progress]

Remove URI invitation parsing and formatting. Keep default directory-prefixed
codes and accept eight-digit PINs whose relay must be supplied by the caller.
Keep signed identities, transcript binding and encrypted credential delivery
unchanged; legacy URI inputs are rejected rather than silently translated.

## 2026-09-23 [progress]

Add `keynet-quick`: immutable relay-directory identifiers, ten-character short
invitation locators, signed session identities and transcript-bound encrypted
recipient-token delivery. A code locates an invitation, never authorizes access.
Keep existing account and Keynet data-plane contracts unchanged.

## 2026-09-16 [decision]

Remove the standalone Mesh v1/v2 shared protocol, its dedicated tests/fixtures,
current design document, and unused control-envelope signing helpers. Account
registration, authentication, relay leases, gateway index schemes, DNS,
subnet-route contracts, and existing transports remain unchanged. No Keynet
code is integrated. Historical records and the original tree are preserved in
`archive/main-before-mesh-removal-20260916` and the existing feature branches.

Verification: 709 workspace tests passed with zero skips; Clippy, formatting,
shear, and changed-file spelling checks passed. The offline advisory check
still fails on unchanged `rustls 0.23.41` (RUSTSEC-2026-0285); this removal does
not claim a full-QA pass or upgrade dependencies.

## 2026-09-13 [fix]

Reject authenticated Mesh v2 allocations whose complete label and DNS root
exceed 253 characters. Cover the exact accepted boundary and longer roots or
labels with a focused contract test.

## 2026-09-13 [feat]

Add short-lived registration challenges and WG private-key possession proofs
before permanent Mesh v2 allocation. Bind the authenticated registry realm,
complete node identity, operation and deadline; retain stable retries and the
existing allocation response. Document the UDP cookie and WSS identity gates.
The full workspace gate passed 820 tests with no skips, formatting, Clippy,
dependency checks, shear and typos; existing advisory warnings remain reported.

## 2026-09-13 [feat]

Add closed Mesh v2 node-pair credentials and directed pairing messages. Both
endpoint signatures bind one registry realm, complete signing/WG identities,
operation and independent revocation generations. Fresh bilateral session
proofs bind WG possession and capabilities; PIN debug output is redacted.
The [pair contract](design/mesh-v2-pair-contract.md) records consumer persistence,
revocation and runtime obligations; codec validation does not grant access.
## 2026-09-16 [feature]

Define the public default wire context for Keynet clients without shared network
keys or owner permissions. Preserve the v1 codecs and sealed conformance suite;
add separately generated address/slot vectors and device-signed pairing checks.
Record the coordinated client profile and its remaining integration obligations.
Update rustls to 0.23.45 and rustls-webpki to 0.103.15 to clear
RUSTSEC-2026-0285 without weakening the advisory gate. The full shared QA passes
with 795 tests.

## 2026-09-13 13:03 [progress]

Sealed the complete keynet v0.7 interoperability fixture release. The manifest
now carries the full design pin and exact file, case, and field inventories;
an implementation-independent test pins its final digest and rejects filesystem
or locally rehashed drift. All twelve normative vector files remain unchanged.

## 2026-09-13 06:58 [progress]

Complete `20260913-0657-clean-keynet-campaign-worktrees`. Remove eleven retired keynet worktrees and fifteen
temporary branch refs after feature consolidation. Preserve `feat/keynet`, all
`main` refs, unrelated worktrees and branches, and the fourteen canonical diagrams
in the external diagram repository's `mermaid/keynet/` directory. Keep a verified standalone history bundle
and the before-cleanup inventory in `tmp/20260913-0657-clean-keynet-campaign-worktrees/`. Dedicated primary checkouts
now use `feat/keynet`. Source, fixtures and approved design text are unchanged;
this cleanup does not change the implementation's paused status or phase acceptance.

## 2026-09-13 06:13 [decision]

Relocate the Keynet approved design archive from
`crates/keynet-proto/docs/design/` to `docs/decisions/keynet/`.
CLI interaction and relay transport are project-level approved decisions, not
crate implementation tracking. Preserve both approved records byte for byte.
The architecture document links to the new decision index. Mark the former
"Keynet approved design archive" plan-index entry deleted while retaining its
original title and path as history. Design authority, fixture pins and phase
execution are unchanged.

## 2026-09-06 [fix]

Add an explicit gateway relay index scheme (COMPAT-001). Preserve the omitted
address-derived default and carry the device-key scheme in JSON and CBOR for
coordinated NSD/NSGW compatibility with current NS nodes.

## 2026-09-01 13:30 [fix]

Separated the SSE transport's TCP socket authority from its TLS server name.

- Bracketed IPv6 endpoints such as `[2001:db8::1]:443` remain intact for
  `TcpStream::connect`, while TLS certificate verification receives the
  unbracketed IP literal required by rustls.
- DNS and IPv4 endpoint behavior is unchanged; focused tests pin both IPv6 and
  DNS server-name derivation.

## 2026-08-29 06:05 [fix]

Gave address-shaped control-message fields one wire encoding (SHARED-002).

- `ControlMessage` is internally tagged, so serde re-deserializes a variant
  through a `ContentDeserializer` that always reports human-readable while
  `ciborium` reports the opposite and wrote the binary form. Every bare
  `SocketAddr`, `IpAddr`, `Ipv4Addr` and `IpNet` was therefore undecodable over
  a natively encoded CBOR config stream, and the failure tears the stream down
  rather than skipping the message. Measured: 10 of the 24 variants, including
  `wg_config`.
- `serde_wire_addr` writes the human-readable string in every format and reads
  either that or the legacy non-human-readable form, so bytes an un-upgraded
  producer already wrote keep decoding. Applied to all 27 previously bare
  fields; `serde_ipnet_vec`'s three fields fold into the same family.
- JSON is unchanged, byte for byte. The config stream is unchanged too: NSD's
  producer serializes through `serde_json::Value` before encoding CBOR, so it
  already emitted these fields as strings.
- **One wire shape moves, and the cutover is ordered: NSD before the node.**
  `P2pCandidate` also rides `peer_candidates.report`, which is raw `ciborium`
  on both ends and where the binary form is the working shape today; a new
  producer's string form is rejected by a consumer that predates this change.
  The tolerant reader covers the opposite direction. Merge with the `nsd`
  consumer arm ahead of any `ns` producer rollout.
- `subnet_route.rs` and the raw envelope payloads in `api.rs` keep their
  existing encodings deliberately — see `docs/task/SHARED-002.md`.

## 2026-08-24 06:07 [fix]

Defined one shared 1360-byte WireGuard plaintext-MTU default (MTU-001 / ns
PLAN-129).

- Export the conservative local data-plane default from `common::tunnel` for
  both NS and NSGW consumers.
- Keep the value outside every serialized control contract; NSD does not
  project or negotiate it.

## 2026-08-17 09:40 [feat]

Carried the control plane's overlay address assignment to the node (NODE-003).

- `MachineState` gains `overlay_address`, persisted in the per-realm
  registration file, so a registered node can find out which overlay address the
  control plane holds for it instead of configuring one itself.
- `AuthClient`'s registration decode carries `wg_tunnel_ip` on both the envelope
  and the legacy JSON path. The field was already on `api::RegisterResponse`;
  the client's own decode struct dropped it, so the value never reached the
  node.
- `set_overlay_address` is separate from `set_registered` rather than a new
  parameter on it: that call is shared by every client binary, and only the
  unified node has anything to say about an overlay address.
- Backward compatible in both directions. A registration file written before
  this change loads with no address, a machine with no assignment serializes the
  key away, and a response that omits `wg_tunnel_ip` registers exactly as
  before. No wire type, field, or bound changes.
- Merges with the `nsd` projection arm and the `ns` consumer arm in one window;
  this repository must not merge ahead of them.

## 2026-08-16 23:20 [feat]

Gave the approved-subnet-route projection a consumer channel (NODE-002).

- `ControlPlane` gains an optional `subnet_route_tx` and `set_subnet_route_tx`,
  so a node that accepts subnet routes can receive the `subnet_route_config.v1`
  projection NODE-001 previously decoded and dropped. Route admission, lease
  binding, and installation stay in the node.
- The sender is optional and set by the consumer rather than returned from
  `ControlPlane::new`, copying `status_tx`. A mandatory receiver in
  `ControlPlaneInit` would have to be drained by every node that never accepts
  subnet routes, because a dropped receiver is a shutdown in this dispatch
  loop.
- With no consumer attached the arm keeps NODE-001's decode-and-ignore
  behaviour exactly, so `nsc`, `nsn`, `nsd`, and `nsgw` are unchanged.
- No wire change: no message type, enum variant, field, or bound moves.

## 2026-08-16 12:05 [feat]

Added the unified node capability and subnet-route wire contracts.

- Added the versioned node capability vocabulary in `common::node_capability`
  with a single owner for the four wire tokens; unrecognized tokens resolve to
  nothing and can never activate a role or authorize a route.
- Added `control::subnet_route` with the intent-only `NodeSubnetRouteReport`
  (envelope api `node.subnet_routes.report.v1`) and the authoritative
  `SubnetRouteConfig` projection (control message `subnet_route_config.v1`)
  as separate types, so an advertisement can never authorize itself.
- Added deterministic bounds: canonical IPv4 prefixes, rejection of default
  routes, loopback, link-local, and multicast, route-count and encoded-size
  limits enforced during decoding, duplicate ids, duplicate prefixes,
  conflicting owners, overlapping prefixes, realm mismatch, and stale
  generations.
- Overlay-reserved range rejection takes the control plane's effective
  `vip_pool` / `tunnel_ip_pool` as an `OverlayReservedRanges` input instead of
  pinning NSD's documented defaults, which would otherwise accept a prefix
  that swallows the overlay's own address space in any deployment that
  overrides either pool.
- Added `AuthPayload::leg_role` with the `WssLegRole` request input so one
  identity can request separately scoped `client` and `relay` WSS legs. NSD
  remains the sole granting authority.
- Added cross-repository fixtures plus byte-for-byte compatibility coverage
  proving existing service, capture, GatewayExit, GatewayEgress, direct-P2P,
  and relay payloads are unchanged when the new fields are absent.

## 2026-07-25 [fix]

Made framed WebSocket tunnel child-task ownership structural.

- One tunnel-local task set now owns the WebSocket writer and every framed
  TCP/UDP relay.
- Added cooperative shutdown that aborts and joins all owned children before
  the tunnel runner returns; parent cancellation still aborts the complete set
  through structured drop ownership.
- Close lifecycle events now use a drop guard, so cancellation cannot leave
  an opened stream recorded without a matching close.
- Added a real WebSocket-to-TCP regression proving active backend EOF and
  lifecycle closure on cooperative shutdown.

## 2026-07-17 [feat]

Activated non-future V1 WgRelay leases immediately at receipt.

- `translate_wg_relay_lease_deadlines` now maps a not-before barrier at or
  before the authenticated signed timestamp to activation exactly at the
  monotonic receipt anchor, with no added guard.
- A future barrier keeps the existing guarded calculation and bound for old
  producer compatibility, and hard expiry stays receipt-anchored behind the
  conservative guard (a 300-second lease still expires at receipt plus 235
  seconds).
- All typed failures remain, including `NoUsableWindow` for legacy
  future-barrier leases and degenerate short leases; wire types, constants,
  and function signatures are unchanged.
- Consumer-local widening: a non-future lease now has a usable window once
  its signed interval exceeds the 65-second guard, where the always-guarded
  translation required more than twice the guard. Production leases keep the
  fixed 300-second interval, so only the activation instant changes there.

## 2026-07-13 [feat]

Added the causal scoped WgRelay roster and forwarding-lease contract.

- Added restart-unique checked control-stream sessions to config-stream and
  realm-snapshot requests, with one session shared across endpoint fallbacks.
- Added optional per-scope rosters, optional per-realm forwarding leases, and a
  default-false durable fleet-cutover attestation.
- Exposed authenticated envelope timestamps from config-event and unary
  verification together with receipt-time monotonic anchors, preserving both
  through scoped gateway delivery.
- Exported the fixed causal lease timing constants and one checked monotonic
  deadline translator that rejects invalid bounds, ordering, and overflow.
- Added scope/session-specific transport status and endpoint-confined
  `MultiControlPlane` children without synthetic config-arrival success.
- Added JSON/CBOR round-trip, omission-default, old/new compatibility, session,
  signed-timestamp, timing-bound, queued-anchor, three-transport fallback, and
  real A/B endpoint-confinement coverage.

## 2026-07-11 [feat]

Added shared control support for reliable direct-P2P candidate reporting.

- HTTP 429 responses now map to a typed `RateLimited` error with optional
  `current_epoch` and `retry_after_ms` data. The shared unary status mapper
  covers SSE, Noise, and QUIC, while older or malformed response bodies remain
  compatible with absent optional fields.
- Verification passed with `just qa` and `cargo test --doc --workspace
  --locked`.

## 2026-07-10 [feat]

Added the public-edge upstream authority wire contract.

- Added an optional `GatewayHttpRoute.upstream_authority` field that affects
  only the upstream HTTP virtual host.
- Kept public listener, certificate, authentication, OIDC, and ACL identity on
  `GatewayHttpRoute.host`; upstream TLS SNI is derived from the explicit
  authority when present.
- Added JSON/CBOR round-trip and legacy-decode compatibility coverage.

## 2026-07-01 15:29 [feat]

Added the public-edge upstream TLS re-encryption wire contract.

- Add an optional `GatewayHttpRoute.upstream_tls` policy for HTTPS NSN-backed
  backends.
- Added the gateway capability scope used to gate b-lite support during rollout.
- Added serde compatibility coverage proving old payloads without
  `upstream_tls` default to plaintext behavior.
- Verification passed with `just qa`.

## 2026-06-30 19:10 [feat]

Added the GatewayEgress selected-owner route hint.

- `ServiceBackendKind::GatewayEgress` now carries an optional
  `selected_gateway_id` field so NSD can project the gateway owner selected for
  a gateway-owned service VIP.
- The field is byte-additive: legacy payloads without the field deserialize to
  `None`, and routes without an owner omit the field when serialized.
- Verification passed with `just qa`.
## 2026-09-13 06:45 [progress]

Consolidated paused Keynet work onto canonical feature branches. The canonical
ns-shared feature branch preserves the complete Phase 2 rework tree and
project decision archive; the canonical documentation feature branch preserves
approved records, historical proposals, and diagrams. Dedicated ns-shared main
was restored with four additive reverts and has the same tracked tree as
`d02a29c`. Migration QA passed with 732 tests and no skipped tests. Phase 2
remains paused and unreviewed.

## 2026-09-21 05:08 [feat]

Added the strict inter-member region frame codec and sealed v0.9 fixture.

- Added canonical encoding and decoding for all nine region frame types and
  their nested snapshot schemas.
- Enforced frame, datagram, entry, channel, connection-generation, and
  canonical-CBOR validation at the codec boundary.
- Added sealed fixture vectors, independent inventory witnesses, and focused
  regression coverage while preserving every prior vector byte.

## 2026-09-21 06:18 [feat]

Added the pure retained-marks join and its sealed fixture family.

- Joined revocation floors independently of generation while resetting
  generation-specific key, conflict, and incarnation state on advancement.
- Made equal-generation conflicts deterministic, associative, commutative,
  and idempotent with exact directional change reporting.
- Rejected cross-owner joins and sealed the exact marks cases through
  independent fixture inventories while preserving prior vector bytes.

## 2026-09-21 08:10 [feat]

Added the pure region-presence decision and its sealed fixture family.

- Selected presence by generation and incarnation before route eligibility,
  with durable generation marks, channel pairs, and member identity applied at
  their defined boundaries.
- Preserved exact revision, epoch-replacement, capacity, retirement, and
  grace-channel behavior without mutating durable floors.
- Added strict fixture inventory witnesses and regression coverage for
  generation marks, capacity resynchronization, stale channels, and retirement
  failures while preserving all prior vector bytes.

## 2026-09-21 14:00 [feat]

Added bounded region snapshot staging and closed the sealed v0.9 fixture release.

- Kept partial presence unpublished until contiguous staging, exact owner
  validation, durable mark acknowledgments, and a scoped complete-cut receipt
  all succeed.
- Separated replay fences from active staging capacity and retained exact
  cross-batch duplicate detection without accumulating the whole owner cut.
- Preserved the existing batch and owner limits while adding positive and
  adversarial coverage for durable evidence, capacity recovery, and replay.
