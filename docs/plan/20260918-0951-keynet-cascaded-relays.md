# 20260918-0951-keynet-cascaded-relays Keynet cascaded relays: multi-member relay regions

- **status**: approved
- **createdAt**: 2026-09-18 09:51
- **approvedAt**: 2026-09-21 (campaign start; C0 delivered, D1 to D8 settled)
- **relatedTask**: 20260918-0951-keynet-cascaded-relays
- **baseBranch**: `main` after the keynet v1 merge of 2026-09-18 (ns-shared `58c48c7`, nsgw `b12fb24`, ns-remote `94d3274` after its re-cut from `main` on 2026-09-20)
- **integrationBranch**: `feat/keynet-cascaded-relays` in ns-shared, nsgw and ns-remote, re-cut from those `main` heads on 2026-09-18
- **designRevision**: keynet v0.9, documentation repository `main` `abb1dad`, `docs/ns/keynet.md` SHA-256 `a763e6db341b429361558df9ae81ca7d130cda7fb63ae912c2cf1f77638e27f2` (C0 delivered and independently reviewed on 2026-09-20; base was v0.8 `a8a3022`, SHA-256 `798916db…`). The revision adds section 13.8 and the edits listed below; node datagram encodings and `keynet-wire` are unchanged, while the consistency and failure semantics of section 13.5.1 and the runtime's registration policy (D5) do change. Where this plan's section 13.8 draft and the design text differ, the design text is normative: the review resolved the nested SNAPSHOT entry schemas and the PRESENT carrier values, the connection-generation and counter lifecycle, a `data_conn_gen` field in MISS, the resource defaults of section 13.6, and a `marks_revision` field in SNAPSHOT with the bootstrap cut rules.
- **updatedAt**: 2026-09-20, revised after the first independent review (findings F1 to F20 applied; D3 and D6 adopted at their defaults)
- **prerequisite**: keynet v1 code on `main`. Satisfied on 2026-09-18: ns-shared `main` 58c48c7 carries `keynet-proto`, nsgw `main` b12fb24 carries `nsgw-keynet-relay`, and ns-remote `main` already had the runtime.

## Context

A keynet v1 relay is one advertised authority (`dns-name:port`, `ip:port` or a
short id, design section 13.5.1) served by one machine. Capacity, availability
and maintenance need several machines behind one name. Section 13.5.1 already
permits "different termination machines only with one atomic slot/mark
namespace and section 13.5 migration behavior" but defines no mechanism, so
today a second machine is a second authority with separate slots.

Tailscale's DERP solves the same problem with a region mesh: the servers of one
region hold authenticated connections to each other, exchange client presence,
and forward a packet once to the server that holds its destination. Forwarding
is never more than one hop and never crosses regions; a client that wants to
reach a peer connects to the peer's home region. This plan specifies the keynet
equivalent, a **relay region**: `user -> member 1 -> member 2 -> user 2` inside
one advertised authority.

Synchronizing a "who is where" table between members is the core of the
mechanism, but it is not sufficient on its own. The plan therefore also fixes
the inter-member authentication and framing, the region-wide marks and the
limits of their convergence, two-stage budgets, reply attribution, loop
prevention, channel liveness, capacity and failure behavior.

## Goals

- One advertised authority served by 2..16 members; nodes register at any
  member and are reachable from every member.
- No change to the node datagram encodings (sections 13.5, 13.6, 13.7), to
  the authority forms of section 13.5.1, or to `keynet-wire`. Tokens that name
  a region authority keep working unchanged. What changes on the node side is
  behavior, not encoding: the runtime's registration policy (D5) and the
  consistency a node can observe from a region (stale sessions and delayed
  retirement during a partition, section 13.5.1 revision below).
- One forwarding hop inside a region; a member never forwards a datagram it
  received from another member.
- The section 13.5 security floors hold per member exactly as in v1: an
  unconfirmed REGISTER changes no retained mark and no active session on any
  honest member, including when it is replayed at another member before
  synchronization. Generation, conflict, revocation and incarnation marks
  converge across members after communication resumes; section 13.8 states
  the limits of that convergence instead of claiming atomic region-wide
  admission.
- Graceful degradation: a lost member or a partitioned mesh reduces the region
  to smaller independent relays without corrupting marks, and every accepted
  datagram is enqueued to the mesh at most once.

## Non-goals

- Inter-region transit (region X forwarding to region Y) and federation
  between operators. A node reaches a peer in another region by registering
  there, within its relay session limit (section 5.1, default 8) and the
  ordered endpoint list's four relay names.
- Relay-side peer authorization, offline buffering, kernel WireGuard, and any
  change to translation, pairing or naming.
- Region membership discovery beyond the authority forms of section 13.5.1: a
  DNS name that resolves to several member addresses, or a short id mapped to
  such a name. A literal `ip:port` authority keeps one address and gains no
  client-discovered failover from this plan; anycast or load balancing in
  front of it is outside this implementation and must preserve carrier and
  session affinity.
- Individual certificate revocation (CRL or OCSP) inside the region;
  membership is withdrawn by removing the member id everywhere or rotating
  the region CA.
- Global exactly-once delivery. The region promises at most one mesh enqueue
  per accepted datagram; WireGuard's endpoint replay rejection remains the
  end-to-end guarantee.
- A user or operator preference for keeping the relayed path when a direct
  cross-site path is usable but worse; path selection stays as in v0.8 and
  the preference is deferred. Acceptance tests that prove mesh forwarding
  suppress direct reachability deliberately.

## Architecture

| Element | Definition |
| --- | --- |
| Region | Exactly one canonical advertised identifier (section 13.5.1) configured identically on every member, and one retained mark namespace converged by the section 13.8 rules. For a DNS authority the host publishes every member address at the signed port; a short id keeps its explicit `{identifier, host, port, trust}` mapping (a mapped DNS host supplies several addresses, a mapped literal one). Each member terminates UDP and WSS on the same public port. Members may sit in different networks and jurisdictions (for example one member in mainland China and one in Hong Kong joined by a private line); the cross-site leg is then the single mesh hop. |
| Member | One relay process with a stable member id (1..16), a certificate issued by the region CA that names that id, a fresh `boot_epoch` on every process start, its own durable store, and the full v1 relay core. |
| Mesh | A full mesh between members over TCP only: two mutually authenticated TLS connections per unordered member pair, one control channel and one data channel, distinguished by the channel kind carried in HELLO, so a saturated data stream never delays presence or marks. Mesh endpoints are configured separately from the public authority and may be private addresses on an operator link; they never appear in tokens, ENDPOINTS, ORDERED_ENDPOINTS or any node-visible record. |
| Presence table | Origin-owned: each member publishes only its own active sessions, identified by `(member_id, boot_epoch, owner, gen, incarnation)` and ordered by a per-epoch event revision. Other members cache these entries; a cached entry never authorizes delivery while either channel to its origin is down. |
| Marks | The section 5.2.2 durable marks (`committed_gen`, `committed_K`, `conflicted`, `revoked_through`, `incarnation_high_water`), replicated by a monotonic join; every member stores the full retained-owner union. |
| Entry member | The member that received a datagram from a node. It performs every v1 sender check, charges the sender scopes and its forwarding-global scopes, and is the only member that ever sends STATUS to a node. |
| Exit member | The member that holds the destination slot. It charges the destination scopes, the handshake-initiation subset and its forwarding-global scopes, and delivers on the destination's exact committed session. |

## Node registration policy (D5)

Node behavior changes only in how a member is chosen. The runtime rules that
C3a implements in `keynet-runtime::relay_client`:

1. One logical relay session per signed authority, and one current UDP round
   per session. A round uses up to 3 deduplicated addresses taken from the
   existing resolution (bounded at 8 addresses, rotated fairly, refreshed
   after exhaustion or recovery; truncation is reported, and probing all
   members of a large region from one resolution is not promised).
2. Before every round the runtime durably allocates a fresh incarnation and a
   fresh node ephemeral. Every address in the round receives byte-identical
   REGISTER datagrams on the existing 0, 1, 2 s retransmission schedule.
3. Each tentative REGISTERED reply is validated against its exact attempted
   source address, the current round, the incarnation, the MAC, the TTL and
   the observation, using a candidate key derived separately per address; the
   selected relay ephemeral is pinned so that a later tentative reply cannot
   replace the selected challenge.
4. The first valid candidate is chosen atomically before PRESENCE is
   enqueued; PRESENCE goes only to that candidate (fresh sequence numbers on
   retry), and the session becomes active only on that candidate's correlated
   positive REGISTERED. One confirmation means one target, not one
   transmitted datagram. The losing candidates' queued REGISTER and PRESENCE
   actions are cancelled, their late replies are ignored, and the runtime
   never emits a confirmation under a losing candidate's key. The winner is
   never switched under the same incarnation once confirmation was attempted;
   a failed selected candidate ends the round, and the next round rotates
   addresses with fresh material.
5. The active session retains its exact source address or connection, key,
   incarnation and control correlations; DATA, keepalives and REFLECT use
   that source and never the first resolved address. Re-registration after a
   lost member is a new round with a greater incarnation (the section 13.5
   migration rule), not a control sent to the first DNS address.
6. WSS fallback keeps its existing trigger (3 s without a usable UDP tentative
   reply). Starting the fallback ends the failed UDP round and allocates a
   fresh incarnation and ephemeral; late confirmations from obsolete attempts
   are cancelled. A selected UDP candidate keeps the existing 10 s
   confirmation deadline. A WSS session binds to its exact connection with
   the original authority's host and trust validation; a healthy active WSS
   session is retained during a fresh UDP probe and replaced only after a
   confirmation.
7. Three addresses may reach the same member (aliases). The member's local
   per-owner tentative limit of 2 still applies, and a refusal is an ordinary
   failed candidate; the limit is not raised for this plan.
8. "First usable reply" selects the fastest sampled response, which is not
   guaranteed to be the geographically nearest or globally lowest-latency
   member. "One session per authority" is a node-side selection rule: a
   partitioned member may retain an old session of the same node until its
   TTL expires or the marks converge.

## Design deltas for keynet v0.9

Edits to existing text (documentation repository, `docs/ns/keynet.md`):

- Section 5.1, Rendezvous and Scaling rows: an authority may be a region; the
  node registers at any member; forwarding inside the region is one hop.
- Section 5.2, Registration: a member commits a registration against its own
  durable floors, then publishes MARKS and PRESENT; no member ever waits for
  another.
- Section 5.2.1: entry and exit admission stages with per-member global
  resource scopes and the mesh queue constants; the text must adopt the two
  stages explicitly and must not imply unchanged single-process aggregate
  accounting.
- Section 5.2.2: the join rule of section 13.8 rule 2 and the limits of
  convergence during a partition.
- Section 5.4: members see the same metadata as one relay; the presence table
  replicates the identity-to-member mapping inside the region; the trust
  statement of the security notes below.
- Section 8, relay model: `RegionMember`, `PresenceEntry` (with origin epoch
  and revision), mesh queue state, MISS correlation state.
- Section 11: decision rows "relay regions with one-hop mesh forwarding"
  versus rejected "multi-hop relay routing" and "one machine per authority",
  and "asynchronous convergence" versus rejected "synchronous member
  agreement".
- Section 12: the Relay row gains "multi-member regions".
- Section 13.5, forwarding rule: "live dst in the same network" becomes "live
  dst on this member, or present at another member of the same region";
  STATUS is produced only by the entry member under section 13.8 rule 3;
  frames received over the mesh are never forwarded again.
- Section 13.5.1: replace the sentence "different termination machines only
  with one atomic slot/mark namespace and section 13.5 migration behavior"
  with: "Several termination machines for one advertised identifier use the
  section 13.8 region profile: each member atomically commits its local slot
  and retained marks, asynchronously joins the regional marks, and applies
  deterministic presence convergence; this is not a single atomic
  region-wide namespace. During a partition, stale local sessions and delayed
  retirement may coexist within the limits stated there. UDP and WSS on a
  member share its local core, and migration keeps the fresh-incarnation and
  positive-confirmation rules of section 13.5." Add: a region has exactly one
  canonical advertised identifier; a signed relay name is never rewritten to
  an address; member ids never appear in tokens or endpoint announcements;
  separate advertised identifiers remain separate authorities and sessions.
- Section 13.6: the constants listed at the end of section 13.8 below. The
  existing constants stand: 2048-byte datagram maximum, 2011-byte DATA
  maximum, 1376-byte inner ceiling, per-owner tentative limit 2,
  `presence_ttl_s` default 90.
- Section 13.7: unchanged; member addresses never enter ORDERED_ENDPOINTS, and
  in-band records stay end to end.

New section 13.8, inter-member profile (draft for the design revision):

Transport: TCP only, two connections per unordered member pair.

- Both connections are TLS 1.3 with mutual authentication. Every member holds
  a certificate issued by the region CA whose subject names its member id in
  an unambiguous configured field; a peer is accepted only when its
  certificate chains to the region CA, is within its validity period, has the
  expected key usage, and names a member id in the configured member list,
  which is therefore the allowlist. The lower member id initiates both
  connections; connect, TLS and HELLO share a 10 s deadline.
- Each frame is a 4-byte big-endian length followed by one canonical CBOR
  array `[ver u8 = 1, type u8, body]` (section 13.1 rules). The length counts
  the complete encoded array, excludes the prefix, and is at most 4096.
- The control connection carries HELLO, SNAPSHOT, PRESENT, GONE, MARKS, MISS,
  PING and PONG. The data connection carries HELLO once as the setup
  exception and then FORWARD only. Separating them isolates backpressure: a
  saturated data stream never delays presence or marks.
- Head-of-line blocking on the data connection is accepted: a lost segment
  delays every forwarded datagram of that pair by one retransmission, the
  property the node-side WSS fallback already has. TCP loss can therefore
  surface as jitter, a stall timeout and a reconnection, not only as latency.
  The relay never retransmits forwarded datagrams itself; WireGuard end to
  end and the applications handle loss.
- Mesh endpoints may be private addresses on an operator link between sites.
  The lower-id initiator needs routability to every higher-id listener
  independently of the public node addresses, and TLS validates the member
  identity, not the private IP or the public WSS certificate name. TCP
  streams impose no mesh MTU: a forwarded datagram of the full 2048-byte
  relay maximum crosses the mesh intact, and the node-side relayed ceiling of
  1376 is unchanged.

| Type | Name | Body |
| --- | --- | --- |
| 1 | HELLO | `[region_name text, member_id u8, boot_epoch u64, channel_kind u8, conn_gen u32]` with `channel_kind` `0` control, `1` data; first frame in both directions on both connections; a different region name, a member id that does not match the certificate or the expected peer, a duplicate member id or an unknown channel kind closes the connection |
| 2 | SNAPSHOT | `[snapshot_id u64, base_revision u64, chunk_index u32, presence_entries, mark_entries, more bool]`; the sender's own active presence and its entire retained mark union, chunked by encoded size |
| 3 | PRESENT | `[slot bytes16, network_id bytes32, I bytes32, gen u64, incarnation u64, carrier u8, boot_epoch u64, revision u64]`; sent when a slot becomes active on the sender or its generation or incarnation changes |
| 4 | GONE | `[slot bytes16, network_id bytes32, I bytes32, gen u64, incarnation u64, reason u8, boot_epoch u64, revision u64]` with reason `0` expired, `1` revoked, `2` superseded, `3` shutdown |
| 5 | MARKS | `[network_id bytes32, I bytes32, committed_gen u64, committed_K bytes32, conflicted bool, revoked_through (null or u64), incarnation_high_water u64]`; sent on every local mark commit and on every changed join, with equality suppression |
| 6 | FORWARD | `[forward_id u64, source_owner [network_id bytes32, I bytes32], datagram bytes]`; the complete original relay datagram, header included, at most 2048 bytes; INTRO, INTRO_ACK and DATA only; data connection only |
| 7 | MISS | `[forward_id u64, status u8]`; the exit member could not deliver: `1` no eligible local destination, `2` destination admission or output exhaustion; control connection |
| 8 | PING | `[nonce u64, data_conn_gen u32, consumed_forward_id u64]` every 5 seconds on the control connection; three unanswered pings close both connections |
| 9 | PONG | `[nonce u64, data_conn_gen u32, consumed_forward_id u64]` |

Rules:

1. Presence. Each origin publishes only its own active sessions, identified
   by `(member_id, boot_epoch, owner, gen, incarnation)`, and serializes its
   presence changes with a monotonically increasing revision within the
   epoch. `boot_epoch` is fresh on every process start and is a process
   identity, not the store revision; reconnects within one process keep it,
   and both connections of a pair must present the same epoch. A receiver
   accepts events only from the origin's current authenticated stream and
   discards events of an older stream. A higher generation wins regardless of
   incarnation; within a generation a higher incarnation wins; both are
   subject to the joined marks (a PRESENT never overrides a higher floor). The
   equal-state case (same owner, generation, compatible key and incarnation
   confirmed on two members) is resolved after those checks by the lower
   member id keeping the session. That tie-break may retire the session the
   node is actually using; it is an availability trade-off, not evidence of
   node intent. The losing member stops authenticated acknowledgments and
   forwarding for that session, drops its queued output and publishes GONE
   reason 2; the node recovers through the ordinary missed-PRESENCE rule
   (about two intervals, 50 s at the default TTL) with a fresh, higher
   incarnation. GONE reason 2 is mesh-only: it is never sent as a node
   datagram and never becomes a new STATUS code, and STATUS stays advisory and
   cannot trigger authenticated retirement. GONE removes only the exact
   originating session and its revision is recorded so an older PRESENT
   cannot restore it. A changed `boot_epoch` invalidates the old origin's
   routes immediately and requires a new completed snapshot. A retired slot
   does not close a WSS connection that still serves other live slots.
2. Marks. The join is monotonic. `revoked_through` is null or u64 and joins
   by maximum over present values, independently of `committed_gen`. The
   greater `committed_gen` wins together with its generation-specific key,
   conflict and incarnation fields; an older generation's incarnation is
   never carried into a newer generation. At equal generation the incarnation
   high water takes the maximum, `conflicted` is or-ed and is latched when
   the keys differ, and the lexicographically smaller key is kept only as the
   deterministic serialized representative, never as an authorized winner. A
   member persists the joined state before it applies route changes or
   publishes it, then re-evaluates its local sessions and pending
   confirmations: lower generations, revoked or conflicted generations and
   same-generation lower incarnations are retired; equal current marks alone
   never retire the exact live session. A member commits a registration
   against the floors it currently holds and publishes MARKS and PRESENT
   afterwards; it never waits for other members. A restart joins the intact
   persisted floors and restores no sessions or keys. Limits of this rule:
   among honest members an unconfirmed REGISTER changes no retained mark or
   active session, including when replayed before synchronization, because
   activation needs the PRESENCE proof under the node's ephemeral private key;
   each member enforces its own durable floors; region-wide floors converge
   after communication resumes, with no convergence bound during a
   partition; an owner that possesses the required ephemeral can confirm
   stale state at an uninformed member, and equal-generation confirmations
   with different keys can latch a durable conflict that requires a higher
   acceptable generation. Asynchronous publication is the chosen design (D4);
   it provides neither atomic region-wide admission nor a guarantee that
   every stale-state effect is only a transient missing path.
3. Forwarding. The entry member performs every section 13.5 sender check
   (live src, exact source, same context, sender and global scopes). FORWARD
   admits only validated INTRO, INTRO_ACK and DATA, carries their original
   bytes, and never carries member-local controls (REGISTER, PRESENCE,
   REVOKE, REFLECT, REFLECTED). If dst is active locally the entry delivers
   and charges each applicable scope once; otherwise it looks up the presence
   table, charges the sender scopes and its forwarding-global scopes, and
   sends FORWARD over the data connection. `forward_id` is unique within the
   pair's connection generation and allocated monotonically in wire-send
   order; the entry keeps a bounded, expiring correlation (original header,
   input length, exact source, committed session identity). The exit member
   checks that `source_owner` derives the datagram's src and that its context
   equals the live destination owner's context (`source_owner` is an
   authenticated member assertion, not possession evidence), validates the
   destination full owner against its live slot record, charges the
   destination scopes, the handshake-initiation subset and its
   forwarding-global scopes before enqueue, and binds the queued output to
   that exact committed session, so that retirement drops it. Per-member
   global limits bound physical work on that member and are not a region-wide
   aggregate quota. A member never forwards a datagram that arrived over the
   mesh, so the path is loop-free by construction. A miss at the exit returns
   MISS with status 1 or 2; malformed mesh input is dropped silently. The
   entry emits at most one correlated STATUS per MISS, only while that exact
   sender session is still live, using the original input length and the
   source-IP and global reply budgets; unknown, expired or repeated MISS is
   ignored. When the pair's data queue is full the entry drops the datagram
   and answers STATUS 2 under the reply budgets; when the data channel is
   declared unavailable, or the connection is lost with no exit answer, it
   answers STATUS 1 under the same rules. Only the entry member ever sends
   STATUS to a node.
4. Sessions and reflection stay per member: tentative registrations,
   PRESENCE, the session key and REFLECT observations belong to the member the
   node is connected to. WSS output remains one bounded binary message on the
   exit's exact committed connection, WSS REFLECT stays unsupported with a
   null observation, and direct INTRO and INTRO_ACK are unaffected.
5. Channel identification and liveness. HELLO carries the channel kind and a
   connection generation in addition to region, member id and boot epoch; a
   member validates the expected peer, channel and epoch, keeps one current
   connection per kind and rejects stale duplicates deterministically. A
   member is forwardable only while both its control and its data connection
   are up under the same boot epoch. PING and PONG run on the control
   connection every 5 s with three misses closing the pair, and they report
   the current data-connection generation and the highest fully consumed
   `forward_id`. With outstanding data, 15 s without receive-progress
   advancement closes only the stalled data connection and marks the pair
   non-forwardable; TCP keepalive (5 s probes, three failures) and an
   unacknowledged-write timeout of 15 s are enabled where the platform
   supports them. Recovery of a data connection resets its correlations and
   never replays uncertain sends. Reconnect back-off per failed channel starts
   at 1 s, doubles to 60 s with 25 percent jitter, and resets after 30 s of
   healthy operation. While a pair's data connection is down, forwards to
   that member fail with STATUS 1 at the entry and presence and marks keep
   flowing on the control connection.
6. Snapshot and resynchronization. On connect, and after any invalidation,
   the sender streams a SNAPSHOT of its own current active presence and its
   entire retained mark union, chunked by encoded size under the 4096-byte
   frame cap with at most 256 combined entries per chunk and no entry split
   across chunks; `chunk_index` is contiguous from zero, and `more = false`
   terminates the snapshot even when it is empty. The presence view is frozen
   at `base_revision`; subsequent presence events follow in revision order
   after the final chunk, with bounded buffering, and a buffer overflow
   restarts the synchronization. The receiver streams the marks into bounded
   durable storage as they arrive and stages the presence within explicit
   table limits, publishing it only after complete receipt and mark
   validation; completion replaces only that origin's presence and deletes
   the routes it no longer lists, never marks. A disconnect or an invalid
   chunk discards the partial presence, keeps the marks already joined, and
   requires a new snapshot. When a channel to a member is lost, that member's
   entries are kept for a grace period of twice `presence_ttl_s` (180 s at
   the default), measured monotonically from the loss, but the grace never
   authorizes delivery while either required channel is unavailable;
   reconnection requires a completed synchronization before cached routes
   become eligible again, except that a data-only recovery within the same
   epoch may reuse the continuously synchronized control state. Marks are
   never garbage-collected with presence. A restart loads the intact marks
   and starts with no sessions, tentative keys or output. A new member with
   no prior store remains registration-closed until an explicitly selected
   intact peer has supplied a complete durable mark snapshot; this is
   bootstrap, not synchronous agreement on registrations. Each accepted input
   chooses one exit and is enqueued at most once, and data queues are never
   replayed after a reconnect.
7. Queues. Per-pair data output is bounded to 64 frames and 128 KiB with a
   maximum queued age of 1 s; all mesh and node output together stays under
   8192 queued datagrams and 16 MiB per process; the committed-destination
   limits of section 5.2.1 still apply at the exit. Control output has a
   separate bounded reserve (256 frames and 1 MiB per pair, 16 MiB per
   process) with priority for liveness and MARKS; presence events keep the
   snapshot-cut ordering, and an overflow closes the synchronization and
   forces a fresh snapshot rather than losing state silently. Ingress,
   in-flight MISS correlations and TLS and socket buffers are bounded
   separately. A data enqueue never blocks while holding the state owner or
   the control writer, and storage work never blocks the liveness scheduler.
   The age bound covers local pending output, not delivery time inside TCP.
8. Capacity. The default bounds are 160000 active origin-presence records
   across the region (10000 per member) plus bounded snapshot staging and
   event revisions. Every member stores the full retained-owner union under
   the existing limits of section 13.6 (1000000 owners, 512 MiB logical, 4
   GiB on disk), which apply to the union on every member and are not
   additive regional capacity. A member validates its effective limits and
   storage headroom at bootstrap. If a received floor cannot be persisted, the
   member marks its synchronization and admission failed and suppresses the
   routes and confirmations that would rely on unapplied state; it never
   evicts floors and never reports a successful synchronization. Independent
   admissions during a partition do not guarantee that the merged union fits;
   that capacity failure is reported explicitly. Snapshot marks are applied
   in bounded durable batches or through an incremental durable store,
   unchanged joins are skipped, and initial synchronization with concurrent
   local commits is benchmarked at the supported size before any capacity
   claim; the current whole-store clone and rewrite per received mark is not
   acceptable for this path.
9. Membership and certificates. Both roles validate the TLS 1.3 chain, the
   validity times, the key usage and the member-id field, and require the
   HELLO identity to match the certificate and the expected peer. Existing
   connections are closed when their certificate expires or their member is
   removed at a configuration reload; an implementation without reload
   documents a rolling restart of all accepting members instead. Replacing a
   certificate with the same allowed id does not revoke the old one before
   its expiry. An emergency response removes the id everywhere or rotates the
   trusted CA; issuance, rotation and expiry monitoring are documented
   operator procedures, and the CA private key stays offline.
10. Operations. `/readyz` stays local safe-admission readiness: a partition
    alone does not make a healthy local relay unready. Mesh degradation is
    reported separately in a bounded `/status` with region name, member id,
    boot epoch, local durable revision, per-peer channel and synchronization
    state, presence count, queue pressure and certificate expiry; the status
    response bound is sized and tested for 16 members.

Constants (for section 13.6; the numeric liveness, queue and capacity
defaults are proposals to be validated in C0 before implementation): members
per region 2..16; mesh frame cap 4096 bytes for the encoded array with the
forwarded datagram at most 2048 bytes; SNAPSHOT chunks bounded by encoded size
and at most 256 combined entries, never splitting an entry; presence grace `2 *
presence_ttl_s` (180 s at the default); PING interval 5 s with 3 misses; data
stall 15 s without receive progress while data is outstanding; TCP keepalive 5
s probes with 3 failures and a 15 s unacknowledged-write timeout where
supported; connect, TLS and HELLO deadline 10 s; reconnect back-off 1 s
doubling to 60 s with 25 percent jitter, reset after 30 s healthy; per-pair
data queue 64 frames, 128 KiB, age 1 s; process-wide output 8192 datagrams and
16 MiB; control reserve 256 frames and 1 MiB per pair, 16 MiB per process;
region presence 160000 records (10000 per member); retained-owner union under
the existing owner, logical and disk limits; MISS correlations bounded per pair
and expiring with the reply window.

## Repository placement

| Repository | Change |
| --- | --- |
| ns-shared `crates/keynet-proto` | New `region` module: section 13.8 frame codecs, the pure marks join, the pure presence decision (table snapshot plus event to new table plus effects) and the pure snapshot staging decision; fixture files `region_frames.vec`, `region_marks.vec` and `region_presence.vec` sealed against the approved C0 digest, including malformed frames, encoded-size boundaries, join permutations, event ordering, snapshot interruption and restart; the fixture inventory, file digests, metadata, inventory-test constants and every consuming repository's fixture pin are updated together, and the existing node-wire vectors are preserved byte for byte. |
| nsgw `crates/nsgw-keynet-relay` | New `region/` module (configuration and validation, mesh TLS transport with two channels per pair, connection manager with boot epochs and channel generations, presence table, marks join with batched durable application, entry and exit forwarding, MISS correlation and STATUS mapping, bounded queues) wired into `core.rs` and `store.rs`; `/readyz` and `/status` fields; an in-process three-member test harness; an operator runbook for CA issuance, identity encoding, offline CA storage, rotation, expiry, membership removal, bootstrap and intact-store recovery. Configuration: a `[region]` table with the region name, the local member id, the region CA path, the member certificate and key paths, and the member list `{id, mesh address}`; the same template serves every member, with member-local identity, listeners, store and certificate contents differing. Validation before serving: one canonical advertised identifier, unique member ids and endpoints, the local member in the list, certificate and key identity, CA trust and validity, a consistent region TTL, finite resource limits, separate mesh and public listeners, and an intact member-local store; the same rules apply to `NSGW_KEYNET_RELAY__` overrides. |
| ns-remote | No wire change. C3a implements the node registration policy above in `keynet-runtime::relay_client` (the attempt state must hold several candidates with cancellation, not a loop over sends; the start, retry, re-registration and reflect paths use the selected source, not the first resolved target) and verifies it against an unchanged single relay and isolated independent relays. C3b extends the namespace E2E to two relay members on separate networks. |
| documentation repository | The v0.9 revision on a `feat/keynet-cascaded-relays` branch cut from `main` (`a8a3022`), reviewed independently under the delegated design-decision rule before implementation starts. |

## Workstreams and DAG

| ID | Repo | Task | Depends on |
| --- | --- | --- | --- |
| C0 | docs | Done 2026-09-20: keynet v0.9 on documentation `main` `abb1dad` (SHA-256 `a763e6db…`), written by a design lane, independently reviewed (seven findings applied) and merged | none |
| C1 | ns-shared | `keynet-proto::region` codecs, pure join, presence and staging decisions, fixtures with negative and state vectors, inventory and consumer pins | C0 |
| C2 | nsgw | Relay region implementation, configuration validation, readiness and status, three-member in-process tests, runbook | C0, C1 |
| C3a | ns-remote | Node registration policy (D5) with cancellation, exact-source controls and WSS fallback interaction, verified against a single unchanged relay | C0 |
| C3b | ns-remote | Real-binary region integration and the two-member namespace E2E covering the acceptance list | C2, C3a |
| C4 | deploy | DEV: a second relay member for the existing keynet authority; acceptance matrix additions | C3b; separate deployment authorization |

Each change is reviewed independently before it is integrated, and changes
integrate into `feat/keynet-cascaded-relays` only. Pushing, merging to `main`
and deployment each require separate authorization.

## Acceptance (E2E, real binaries in namespaces)

The tests use real relay and node binaries, controlled resolution and link
delay, durable member-local stores, and a small protocol probe for the
observations ordinary node traffic cannot expose (tentative replies, mesh
frames, queue admission). Namespace privileges need their own authorization;
these tests are separate from the C4 deployment.

1. Node A registered at member 1 and node B at member 2 pair through INTRO and
   INTRO_ACK forwarded over the mesh; DATA flows both ways; after B leaves,
   A's next DATA is answered with STATUS 1 by member 1 (advisory, on a
   subsequent send, never unsolicited).
2. A captured REGISTER of A replayed at member 2 while A is active at member 1
   causes zero activation and zero mark mutation at member 2, both before and
   after the marks arrive, and never moves A's session at member 1;
   convergence has no deadline while the members are partitioned.
3. Member 1 stops: A re-registers at member 2 with a greater incarnation, B's
   relayed path recovers, and all marks survive. Separately, member 1
   restarts with an intact store and comes back with its floors and no
   sessions.
4. Mesh partition and reconnect: STATUS 1 during the partition, SNAPSHOT
   resynchronization afterwards, exactly one mesh enqueue per original
   ingress and no replay of reconnect queues. With only the data connection
   failed, forwards fail with STATUS 1 once the failure is detected and
   recover after it reconnects, while presence and marks stay current.
5. Mixed carriers: A over WSS at member 1, B over UDP at member 2.
6. Budgets: a destination-budget MISS surfaces as STATUS at the entry only
   under the reply budgets; a short DATA trigger whose STATUS would exceed it
   is suppressed; a delayed MISS after the sender migrated produces nothing;
   no reply to an unregistered source exceeds the datagram that triggered it.
7. Region identity: a token naming the region authority works; a member
   advertising a different identifier rejects the registration; a peer with
   an unlisted member id or an expired certificate is rejected at the mesh
   handshake, and an existing connection closes when its member is removed.
8. Cross-site region: two members on separate networks joined by a private
   mesh link, with direct reachability suppressed; each node confirms at the
   first usable sampled response with exactly one confirmation target per
   round, forwarding crosses the mesh, and only one member ever holds the
   confirmed session for each incarnation.
9. Backpressure versus failure: with the data consumer of a pair stalled and
   its control connection live, the entry member's queue fills, further
   datagrams for that pair are dropped with STATUS 2, presence and marks keep
   flowing, and forwarding resumes when the stall clears; once the stall
   exceeds the detection window the pair is declared non-forwardable and the
   answer becomes STATUS 1. A datagram of the full 2048-byte relay maximum
   crosses the mesh intact (protocol probe at the codec boundary).
10. Snapshot interruption: a multi-chunk SNAPSHOT interrupted before its last
    chunk discards the partial presence, keeps the marks already joined, and
    a new snapshot completes the synchronization.
11. Ordering: a higher generation with a lower incarnation wins; a delayed
    PRESENT never restores a session removed by GONE; a changed boot epoch
    invalidates the old origin's routes.
12. Marks: equal-generation confirmations with different keys latch
    `conflicted`; a `revoked_through` floor survives a generation change and
    a restart; the joined state is persisted before routes change.
13. Bootstrap: a new member with no store stays registration-closed until it
    has received a complete mark snapshot from a selected intact peer.

## Security notes

- Members trust each other's sender admission, presence and mark assertions.
  A compromised authorized member can fabricate these, synthesize
  relay-session controls for sessions whose relay secret it holds, and
  propagate false high-water, revocation or conflict state through the
  region; that is persistent denial of service, not only transient routing
  loss, and the mesh carries no independently verifiable possession evidence
  against it. It still cannot derive node identity or end-to-end private
  keys, forge endpoint-authenticated pairing or in-band records, authorize a
  peer at an endpoint, or decrypt WireGuard payloads. All v1 installations
  share `DEFAULT_NETWORK_ID`; context equality is neither peer authorization
  nor a tenant boundary. Operator-only membership and the region CA are the
  trust boundary.
- The per-member v1 invariant is preserved: an unconfirmed or replayed
  REGISTER changes no retained mark and no active session. Region-wide
  convergence is bounded only by mesh propagation while connected and is
  unbounded during a partition (section 13.8 rule 2).
- Amplification rules are unchanged: FORWARD produces no reply to
  unregistered sources, STATUS keeps its existing budgets, and MISS is
  correlated to one live sender session (rule 3).
- Both connections authenticate members by certificates issued by the region
  CA and the configured member list; removal takes effect at reload or
  restart (rule 9), and there is no per-certificate revocation.

## Risks

- The relay core is already large and was reviewed in three parts (R1A to
  R1C); region logic must stay a separate module with a pure state machine.
- Replicated state, not connection count, bounds the region: every member
  holds the full retained-owner union, a full mark snapshot at the owner
  limit is on the order of 32000 frames per peer, and the current whole-store
  commit path would make bootstrap quadratic; rule 8 and its benchmark are
  required before any capacity claim.
- Presence churn and snapshot size grow with online slots; size-bounded
  chunking and per-member slot limits bound them, and region sizing remains
  an operator matter.
- Node failover depends on the runtime's registration policy (C3a); a cached
  single address would delay recovery until re-resolution.
- Parallel tentative registration multiplies REGISTER work by up to 3 at the
  members; tentative records are bounded (global 4096, per source IP 16, per
  owner 2) and expire in 10 s, and a REGISTERED reply never exceeds its
  request.
- A cross-site direct path may be worse than the relayed private-line path;
  v0.8 path selection still prefers a usable direct path (deferred knob).
- A two-member DEV topology on one host tests protocol integration and
  process failure, not host loss or real cross-site latency.
- Head-of-line blocking on the data connection turns mesh loss into jitter
  and, past the stall window, into a reconnection for that pair; fixing a
  lossy mesh link is an operator matter.
- Certificate issuance and rotation by the region CA is an operator
  procedure; expiry must be monitored through the status surface.

## Decisions required

| ID | Question | Default |
| --- | --- | --- |
| D1 | Start C1 and C2 only after `feat/keynet` reaches ns-shared and nsgw `main` | Closed 2026-09-18: keynet v1 was merged to `main` in both repositories and the branch was re-cut from it |
| D2 | Backbone transport and authentication | Decided 2026-09-18, revised the same day: TCP only, two mutual-TLS connections per member pair (control and data) authenticated by a region CA with the member list as the allowlist; head-of-line blocking on the data connection is accepted as on the node-side WSS fallback; the earlier WireGuard data tunnel and per-member certificate pins were withdrawn for configuration complexity (superseded) |
| D3 | Region size cap and topology | Adopted at the default 2026-09-20 after the independent review: 16 members, full mesh (120 pairs, 240 connections region-wide, 30 per member); the capacity bounds of section 13.8 rule 8 are the effective limit, and 16 is a topology cap, not a validated maximum load |
| D4 | Mark publication | Decided 2026-09-18: no synchronous member agreement; marks and presence are published after the local commit and joined monotonically; the guarantees and their limits are stated in section 13.8 rule 2 (a captured REGISTER never activates anywhere; convergence is unbounded during a partition; stale-state effects are not always transient) |
| D5 | Node attempt policy for a multi-address authority | Decided 2026-09-18: the same REGISTER to up to 3 addresses in parallel, exactly one confirmation target; the runtime rule set is the node registration policy section above |
| D6 | DEV topology for C4 | Adopted at the default 2026-09-20: a second address on the existing DEV relay host running a second independent process with its own certificate, store, listeners and operations endpoint; a second host only if host-loss survival becomes an explicit C4 acceptance goal; deployment authorization is separate |
| D7 | FORWARD fallback over the control channel | Withdrawn 2026-09-18: with TCP only there is no UDP data channel to fall back from |
| D8 | Mesh link MTU | Withdrawn 2026-09-18: TCP streams impose no mesh MTU; the node-side relayed ceiling stays 1376 |

## Annotations

- 2026-09-18: D2 decided by the user: two-channel backbone (control over mutual TLS, FORWARD over a member-to-member WireGuard tunnel). Superseded the same day, see below.
- 2026-09-18: D1 closed after keynet v1 merged to `main`; the branch was re-cut from the merged `main`.
- 2026-09-18: D4 decided by the user: members never wait for each other; marks and presence sync is asynchronous.
- 2026-09-18: cross-site regions (for example mainland China and Hong Kong members over a private line) are in scope; D5 changed to parallel tentative registration with a single confirmation so nodes pick the nearer member without DNS steering; D7 and D8 added.
- 2026-09-18: after a configuration review, D2 revised to TCP only with a region CA (two mutual-TLS connections per pair); D7 and D8 withdrawn.
- 2026-09-20: C0 delivered: design v0.9 written, reviewed independently (seven findings, five of them the mesh contract details this plan had left open, all applied) and merged into documentation `main` `abb1dad`; the design text is now the normative contract for C1 to C3.
- 2026-09-20: first independent review returned REVISE with 20 findings (9 blocking), all applied: MISS correlation and exit budgets; the mark join with an independent revocation floor and a null encoding; corrected D4 guarantees; the D5 runtime rule set; origin-owned presence with boot epochs and revisions; size-bounded SNAPSHOT with completion semantics; channel identification and data stall detection; queue and capacity bounds; the certificate lifecycle; an explicit revision of the section 13.5.1 atomic-namespace sentence; discovery rules per authority form; C3 split into C3a and C3b; tightened acceptance. D3 and D6 adopted at their defaults; the design pin moved to v0.8 and this plan now targets v0.9.

## Next steps

1. C0 is done (v0.9 on documentation `main` `abb1dad`); move the plan to
   approved when the campaign starts.
2. C1 and C3a after C0, C2 after C1, C3b after C2 and C3a; C4 after separate
   authorization.
