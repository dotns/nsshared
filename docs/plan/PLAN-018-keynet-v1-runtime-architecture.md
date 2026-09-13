# PLAN-018 Keynet v1 Cross-Repository Runtime Architecture

- **status**: approved
- **createdAt**: 2026-09-13 08:01 UTC
- **approvedAt**: 2026-09-13 11:08 UTC
- **designRevision**: `docs/ns/keynet.md` in the documentation repository at commit `4ae04faa06ca1f5d64e40aca58aa8e55a50c1e6e` (v0.7), SHA-256 `ceeca74ab6dad33f34df36ef789c1d32014679c9592655439210c169b0bebce6`

## Context

This proposal covers the cross-repository placement and verification strategy
for the Linux keynet v1 runtime. The design sections in scope are sections
2-7, the Linux rows of section 7.8, sections 13.5-13.7, and section 14 except
section 14.7 and the recovery commands. Sections 1, 8, and 9 constrain scope,
state ownership, and acceptance tests. Section 13 is authoritative for every
byte-level contract.

The active design revision was verified both as the working file and as the
object at docs commit `4ae04faa06ca1f5d64e40aca58aa8e55a50c1e6e`;
both have the recorded SHA-256 digest above.

## Approved resolution

The alternatives below are retained as architectural analysis. The approved
implementation boundary is:

- `ns-remote` owns an independent pure `keynet-wire` crate and consumes only
  data copies of the shared interoperability fixtures. It has no source or
  package dependency on `ns-shared`.
- Node behavior lives in `keynet-runtime`, with thin daemon, IPC, TUN, DNS and
  secure-storage adapters in the existing owning crates.
- Policy-neutral BoringTun, TUN and packet-pump primitives may be reused or
  factored from `tunnel-wg`; its policy semantics are not imported.
- The gateway relay is a separate `nsgw-keynet-relay` binary and service.
  `nsgw-server` is not modified. Policy-neutral TLS, listener, WebSocket and
  drain primitives may be reused or factored from `nsgw-wss`; its bearer,
  ACL, role, rendezvous, stream and allocation policy is not imported.
- End-to-end acceptance uses real binaries in isolated Linux namespaces,
  preferring rootless user and network namespaces. Host-privileged work needs
  separate authorization.
- The design gaps catalogued later in this document were resolved by v0.7.
  Section 13 of that revision is authoritative for the resulting bytes.

### Current repository boundaries

| Repository | Relevant current paths | Finding |
| --- | --- | --- |
| `ns-shared` | `crates/keynet-proto/`, `Cargo.toml`, `docs/plan/PLAN-017.md` | `keynet-proto` is a pure workspace crate. It has no async, socket, persistence, or production filesystem responsibility. Its package inherits workspace version `0.1.0` and `publish = false`. |
| `ns-remote` at `feat/keynet` (`769be2ac024ba2ff2d600c3d9315f6ad6a3f4158`) | `Cargo.toml`, `crates/ns/`, `crates/secure-storage/`, `crates/tunnel-wg/`, `crates/netstack/`, `.gitea/workflows/{qa,release}.yml`, `deploy/docker/Dockerfile` | All workspace dependencies are internal paths or registry crates. QA and release check out only `ns-remote`. The release builds `ns` before image assembly; the Dockerfile receives `dist/bin/ns-linux-*` and does not compile Rust. |
| `nsgw` at `feat/keynet` (`a81fe207673290cfe8233121ead41b5824cbb5d6`) | `Cargo.toml`, `crates/nsgw-server/`, `crates/nsgw-wss/`, `.github/workflows/ci.yml`, `Dockerfile` | The workspace already consumes five `ns-shared` crates through `../ns-shared/...`; CI checks out both repositories. `nsgw-server` owns typed config, listener startup, readiness, drain, and shutdown. `nsgw-wss` owns the existing JWT/ACL-aware WSS protocols, not a generic datagram carrier. |

The `ns-remote` daemon already publishes a private runtime descriptor, binds a
per-runtime Unix socket in `crates/ns/src/engine/daemon.rs`, restricts its
filesystem permissions, validates the live owner in `crates/ns/src/local_runtime/`,
and tests peer-credential isolation in
`crates/ns/src/tests/local_ipc_docker.rs`. `crates/secure-storage/` supplies the
platform credential boundary and a private-file fallback. Existing Linux TUN
creation and lifecycle live under `crates/ns/src/tun_device/` and
`crates/ns/src/engine/startup_tun.rs`.

`crates/tunnel-wg/src/lib.rs` is not a neutral WireGuard library. Its public
manager directly imports existing control messages, ACLs, NAT, telemetry,
gateway selection, subnet policy, and relay semantics. Its lower-level
`userspace_io.rs` and `tun_io.rs` contain useful BoringTun and packet-pump
patterns, but importing the crate wholesale would import unrelated product
policy into keynet.

## Architecture proposal

### 1. Sharing `keynet-proto` across repositories

#### Option A: sibling source checkout with a path dependency

Add `keynet-proto = { path = "../ns-shared/crates/keynet-proto" }` to the
consumer workspace dependency tables, matching the existing `nsgw` convention.
Change `ns-remote` QA and release jobs to check out an explicitly resolved,
immutable `ns-shared` commit beside `ns-remote` before Cargo metadata is read.
Record that shared commit in release provenance and require the lock/build
contract to reject a missing or unapproved revision.

For `ns-remote`, this does not require `ns-shared` in the Docker build context.
The release workflow compiles and statically links `keynet-proto` into
`dist/bin/ns-linux-*` first. `scripts/package-ns-docker.sh` then creates the
minimal image context containing the binary and runtime packaging inputs, and
`deploy/docker/Dockerfile` only copies that binary. The source dependency must
therefore be supplied to Cargo during QA/release compilation, not to image
assembly. Local builds require sibling checkouts at the documented layout.

For `nsgw`, add the dependency beside its existing sibling shared dependencies.
CI already supplies the checkout and validated shared revision. The canonical
multi-stage `nsgw/Dockerfile`, however, cannot resolve any current sibling path
dependency from `context: .`; its build contract must either stage both
repositories under one BuildKit context or consume a prebuilt binary. The
recommended production path is to standardize on a prebuilt, provenance-checked
musl binary image assembly, matching `ns-remote`; until that is done, a
repository-parent BuildKit context must copy `nsgw/` and the pinned
`ns-shared/` tree into the relative layout expected by Cargo.

Ownership remains in `ns-shared`. Consumer repositories pin a shared commit,
update that pin deliberately, and run interoperability fixtures at that pin.
The crate's workspace version is informative; the immutable commit is the
actual source version.

#### Option B: publish `keynet-proto` to a Cargo registry

Make only this package publishable, publish immutable semantic versions, and
consume it by exact version plus lockfile checksum. This removes sibling-layout
requirements and lets either Dockerfile compile from a single-repository
context. It introduces registry availability, credentials for a private
registry or a public-release commitment, a release process, and an additional
mapping from repository commits to crate versions. `ns-shared` still owns the
crate and compatibility policy.

#### Option C: vendor a source snapshot into each consumer

Copy or subtree a reviewed `keynet-proto` snapshot into each repository and
record its source commit and digest. Builds become self-contained and offline,
but three copies can drift, security fixes require multiple synchronized
updates, and byte-level conformance can no longer be inferred from crate
identity alone. This is viable only as a generated release artifact with an
automated digest/fixture equality gate.

#### Recommendation

Use Option A for v1. It matches the existing cross-repository model, preserves
one source owner, requires no new package distribution service, and explicitly
solves the `ns-remote` build gap by changing the compilation workflow rather
than incorrectly expanding its binary-only image context. Make the shared
commit a required release input in both consumers. Reconsider Option B when
independent consumer release cadence or third-party consumption justifies a
registry contract. Do not use Option C for ordinary development.

### 2. `ns-remote` runtime placement

#### Option A: implement everything as modules in `crates/ns`

Place state, admission, pairing, translation, transport, DNS, and CLI/IPC
handlers under `crates/ns/src/keynet/`. This minimizes initial workspace work
and gives direct access to daemon, TUN, DNS, and storage internals. It also
couples pure state machines and packet logic to a large binary crate, makes
privileged integration tests the default seam, and makes accidental reuse of
existing mesh/subnet policy more likely.

#### Option B: a dedicated runtime crate with thin `ns` adapters

Create `crates/keynet-runtime` for keynet-specific state machines, persistent
model, translator, WireGuard peer engine, transport adapter, pairing, resolver
record logic, and port bridges. Keep OS and process integration in `crates/ns`:

- `crates/ns/src/engine/daemon.rs` owns one keynet runtime instance and its
  cancellation/readiness lifecycle, as required by section 14.1.
- `crates/ns/src/keynet_ipc/` maps the section 14 commands and stable JSON v1
  results onto the existing authenticated private Unix socket. Authorization
  continues to require the runtime owner and peer credentials; no second local
  listener or unauthenticated loopback API is introduced.
- `crates/secure-storage/` stores identity private keys, WireGuard private keys,
  network-owner private keys, token secrets, and pair PSKs. Non-secret durable
  state uses a versioned, owner-private state file under the existing state
  root. Status, logs, token lists, and errors receive redacted projections.
- `crates/ns/src/tun_device/` owns Linux device creation, routes, link teardown,
  and privilege errors. It hands packet I/O to `keynet-runtime`, whose order is
  `TUN -> section 4 classifier/section 6 translator -> WireGuard -> transport`.
- `crates/ns/src/dns/` owns systemd-resolved and `/etc/resolv.conf` integration;
  the runtime supplies isolated per-user/per-network records and invalidation.

`keynet-runtime` depends on `keynet-proto`, BoringTun, and narrow injected
traits for clock, random source, secret persistence, route/TUN operations, DNS
publication, and sockets. It does not depend on the existing control-plane,
ACL, NAT, subnet, gateway, or account model.

#### Option C: extend `tunnel-wg` behind a keynet mode

Add another manager mode and branch around its current control, ACL, NAT,
subnet, gateway, and telemetry assumptions. This reuses a mature pump but
creates a broad conditional state machine whose policy types do not match
sections 2-7. It raises the risk that existing mesh semantics silently weaken
the section 4 destination/no-forwarding invariants.

#### Recommendation

Use Option B. The daemon, authenticated IPC, platform TUN, Linux DNS, and
secure-storage boundaries remain with their current owners, while keynet
protocol state remains independently testable. Do not depend on `tunnel-wg` as
a crate. During implementation, extract only demonstrably policy-neutral
BoringTun/TUN pump primitives into a small leaf crate if both runtimes need
identical code; otherwise copy the small mechanical pattern and keep keynet's
checks explicit. Reuse must exclude `WgConfig`, `AclEngine`, NAT conntrack,
subnet routes, gateway status, existing relay registration, and link-policy
selection.

The runtime persists the section 8 entities in two domains: secret material in
`secure-storage`, and versioned non-secret records in the owner-private state
root. A single serialized mutation coordinator publishes peer binding,
allowlist, aliases, reject routes, translation, and DNS in the order mandated
by sections 4, 6.3, 6.4, and 7.5. Packet processing uses immutable snapshots;
the mutation coordinator never blocks the packet loop on CLI input.

### 3. `nsgw` relay placement

#### Option A: new `nsgw-keynet-relay` crate, composed by `nsgw-server`

The new crate owns section 13.5 datagram parsing through `keynet-proto`,
tentative registrations, active slots, persistent relay marks, exact-source
binding, budgets, UDP receive/send queues, and a carrier-neutral binary-message
session. It exposes bind/run/readiness/drain interfaces and metrics without
depending on NSD control-plane messages or endpoint admission policy.

`nsgw-server` adds a `keynet-relay` feature and typed config for enablement,
the advertised relay name, UDP/TCP listen address, TLS identity/trust inputs,
persistent marks path, and every configured capacity. Runtime composition
binds both UDP and TCP on the token's same numeric host/port, starts accepting
only after marks are loaded, reports not-ready on bind/load failure, stops new
registrations during drain, bounds drain time, retires connections/slots on
shutdown, and preserves marks.

The TCP side accepts only `wss://host:port/keynet/v1` with subprotocol
`keynet-relay-v1`, disables compression, bounds aggregate fragmented messages
before allocation, and passes exactly one assembled binary datagram at a time
to the same relay core used by UDP.

#### Option B: feature-gated modules inside `nsgw-server`

Place the slot table, codecs, UDP task, WSS handler, and persistence directly
under `crates/nsgw-server/src/keynet_relay/`. This is faster to wire into config
and drain, but ties protocol logic to a binary crate, expands already large
runtime modules, and prevents focused relay tests without constructing server
state.

#### Option C: add keynet sessions to `nsgw-wss`

Reuse its listener and registry as another WSS role and put UDP beside it. The
existing crate assumes JWT/ACL authorization, NSC/NSN roles, rendezvous keys,
and its own frame/session semantics. Keynet registration instead authenticates
with section 13.5 REGISTER/PRESENCE and forwards one opaque datagram. Sharing
those state machines would blur the design's rule that the relay does not
authorize peers.

#### Recommendation

Use Option A, with a server feature gate for packaging rather than a feature
gate around the core's correctness. Reuse from `nsgw-wss` is limited to
policy-neutral TLS certificate loading, rustls acceptor construction, listener
multiplexing, WebSocket handshake helpers, and drain primitives after they are
factored behind neutral interfaces. Do not reuse its bearer verification,
ACL snapshots, NSC/NSN role parsing, rendezvous registry, stream codec,
allocation tables, or close-reason policy. UDP and WSS must share the new
crate's slot/marks table so a greater incarnation can migrate between carriers
atomically as section 13.5 requires.

### 4. Linux multi-node end-to-end strategy

The acceptance suite runs built `ns` and `nsgw-server` binaries, not an
in-process transport simulator. Unit/property tests remain responsible for
byte-exact section 13 vectors, malformed input, fragment/checksum coverage,
and deterministic state machines; the privileged suite proves composition.

#### Prerequisites and isolation

- Linux with user and network namespace support; root or passwordless access
  to `ip netns`, `ip`, `nft`, and `/dev/net/tun`; `CAP_NET_ADMIN` in the node
  namespaces and `CAP_NET_BIND_SERVICE` when DNS binds port 53.
- `iproute2`, `nftables`, `curl`, `jq`, `dig`, `socat`, `openssl`, and either
  `systemd-resolved` plus a private D-Bus daemon or an explicit skip of only
  that integration row. The fallback resolver case is always required.
- Prebuilt debug binaries and a temporary root outside the repositories.
  Every run uses a random, recorded suffix for namespace, veth, bridge, and
  state names. No host route, resolver, firewall table, or fixed process name
  is shared with concurrent runs.

Use documentation-reserved transport ranges. A direct fixture places node
namespaces `kn-a`, `kn-b`, and `kn-c` plus relay namespace `kn-r` on bridge
`kn-wan` at `198.18.0.11/24`, `.12`, `.13`, and `.20`. A relayed fixture puts
the nodes behind router namespaces on `10.201.0.0/24`, `10.202.0.0/24`, and
`10.203.0.0/24`; router WAN interfaces attach to `198.18.0.0/24`, use isolated
NAT tables, and permit node-to-relay traffic while dropping node-to-node
transport traffic. This makes a relay path necessary without altering overlay
packets.

Each namespace can reuse these ports because its socket table is isolated:

| Purpose | Address/port |
| --- | --- |
| Keynet relay UDP and TLS WebSocket | `198.18.0.20:51822` on UDP and TCP |
| Node direct/adapter UDP | `0.0.0.0:51830` |
| In-band control | overlay `N6(self):47900/udp` |
| Local resolver fallback | `127.0.0.53:53` |
| IPv6 and IPv4 TCP echo services | `:2201` |
| IPv6 and IPv4 UDP echo services | `:2202` |

The fixture creates a private CA and relay certificate whose SAN matches the
token relay host, deterministic identity/network/WireGuard seeds through
test-only key injection, per-node owner-only state directories, and
namespace-specific `/etc/netns/<name>/resolv.conf`. It starts the relay, waits
for listener readiness, starts daemonized nodes, and drives all mutations via
the real `ns keynet` CLI and authenticated local IPC. Readiness is a bounded
probe of JSON status and expected socket ownership; log text is diagnostic,
not an assertion API.

#### Deterministic path control

- **Direct UDP:** allow node-to-node adapter UDP and supply reachable endpoint
  hints. Wait until both peers report `path.kind = direct` with exact observed
  endpoints. Assert relay DATA counters do not increase during the payload
  window.
- **Relayed UDP:** drop node-to-node transport in both directions while
  allowing UDP to `198.18.0.20:51822`. Wait for positive REGISTERED/PRESENCE
  state and `path.kind = relay_udp`; assert the relay DATA counter and both
  endpoint payload counters increase by exact test payload sizes.
- **Relayed WSS:** additionally drop UDP to the relay before startup. Trust the
  fixture CA, wait through the specified 0/1/2-second attempts and 3-second
  fallback threshold, and require `path.kind = relay_wss`. Assert the negotiated
  path and subprotocol, then restore UDP and prove migration occurs only after
  a confirmed greater incarnation.
- **Failover:** begin direct, install the scoped node-to-node drop rules, and
  require the same established peer to select its already available relay
  path without address, alias, or allowlist changes.

#### Pairing-policy matrix

| Policy | Token | Required observations |
| --- | --- | --- |
| `auto` | reusable | Import yields a pairing ID; issuer admits without a pending item; both peers become ready. |
| `confirm` | reusable | Issuer creates exactly one pending item keyed by network, token ID, and full requester identity; retries do not change `first_received` or expiry; explicit approval admits; denial remains issuer-local and the joiner stays unconfirmed. |
| `recipient-only` | reusable | No admission and no pending item; the joiner remains waiting until expiry/cancellation. |
| Each policy | matching recipient-bound | All three admit immediately after the same validity/removal checks; a mismatched recipient fails import with exit code 3 and installs nothing. |

Run every policy over relayed UDP. Run `auto` and `confirm` over direct UDP,
and run at least one admitted and one non-admitted case over WSS. Repeat INTRO
and INTRO_ACK delivery to prove idempotency, and test the 1000-entry bounds in
focused non-privileged runtime tests rather than allocating that many TUN peers.

#### Packet-walk matrix

For every row, derive expected `N6`, `N4`, `alias6`, and `alias4` from the
fixture identities, query the real local resolver, send a nonce-bearing TCP
and UDP payload, and capture on both TUN sides. Assertions compare parsed packet
tuples and payload digests, never timing or log wording.

| Section 9 walk | Application request | Expected wire tuple | Translation assertion |
| --- | --- | --- | --- |
| IPv6 to IPv6 | `b.<ZONE>` AAAA to IPv6-only service | `N6(a) -> N6(b)` | No translated address appears. |
| IPv4 to IPv6 | `b.<ZONE>` A from `self4` | `N4(a) -> N6(b)` | Only node a maps `self4/alias6(b)`. |
| IPv6 to IPv4 | `b.v4.<ZONE>` AAAA to IPv4-only service | `N6(a) -> N4(b)` | Only node b maps `N4(b)/N6(a)`. |
| IPv4 to IPv4 | `b.v4.<ZONE>` A from `self4` | `N4(a) -> N4(b)` | Both endpoints use their independent `alias4` mappings. |

Run all four walks on direct UDP and relayed UDP, and one walk on WSS to prove
carrier transparency. Additional cases bind IPv4 and `IPV6_V6ONLY` services to
the same port, exercise the explicit TCP and UDP bridge, prove self-alias
traffic never reaches a carrier, verify removed peers retain reject routes and
DNS tombstones, and send oversized traffic to assert PMTU/PTB behavior without
using the 2048-byte codec bound as a path MTU.

#### DNS, rotation, and lifecycle assertions

- Query plain, `.v4`, identity, and PTR names. Assert A/AAAA service-family
  consistency, NODATA versus NXDOMAIN, TTL 60, immediate invalidation after a
  peer/alias change, refusal on overlay addresses, and no public fallback for
  the private zone.
- For the Linux fallback row, launch the forwarder after capturing the
  namespace's original resolver, assert unrelated names reach only that
  upstream, restart after a forced daemon exit, and verify exact restoration.
  For the systemd-resolved row, run a private bus/resolved instance, assert
  `SetLinkDNS` and routing-only `~<ZONE>` on the keynet-owned link, verify an
  unrelated split-DNS domain remains installed, then assert removal on exit.
- Schedule `K` generation `g+1` at a fixture-controlled future Unix time.
  Observe BINDING delivery/ACK, atomically advance both peer entries at cutover,
  keep derived addresses and aliases unchanged, establish a new WireGuard
  handshake under `K_{g+1}`, reject stale `g`, send REVOKE/REGISTER at the
  relay with a greater incarnation, and verify an intentionally offline peer's
  outcome against the resolved design decision listed below.
- Kill one daemon and the relay at each lifecycle phase. Restart from the same
  state directory and assert no secret appears in stdout, stderr, JSON status,
  logs, or descriptor files; pending timers use remaining monotonic/absolute
  budgets rather than restarting credentials.

Cleanup is registered before the first mutation and is idempotent: terminate
only recorded PIDs, delete only the run's network namespaces (which removes
their veths and nft state), remove the run-specific bridge if still present,
remove the temporary CA/state root, and finally assert that no recorded
namespace, interface, mount, process, or host route remains. A failed cleanup
fails the suite while preserving captured diagnostics in the temporary test
output selected by the ordinary test framework.

## Design gaps and contradictions

The following items are not decided here. Byte-level gaps must be resolved in
the authoritative design before dependent implementation proceeds.

### Required design-owner decisions

| Sections | Gap or contradiction | Work blocked |
| --- | --- | --- |
| 2.3, 7.5, 13.7 | BINDING is delivered only inside an established tunnel, yet an offline peer that missed cutover may know only the revoked old `K`. Section 2.3 says it receives the binding when it next connects, but does not define how that authenticated session is established after old-key rejection. Define the resynchronization path without inventing a wire record. | Offline rotation recovery and its E2E assertion. |
| 2.3, 13.7 | Cutover uses Unix time, but permitted clock skew, cutover lead time, late-BINDING behavior, the required relationship between `cutover` and `binding.not_after`, and the default old-key grace interval are unspecified. These affect whether peers switch atomically and whether a received binding is actionable. | Rotation scheduling and deterministic acceptance. |
| 13.7 | ENDPOINTS says a newer record replaces the old list, but the record has no generation, sequence, timestamp, or nonce. UDP can reorder the original and retransmissions, so a receiver cannot determine which valid record is newer. | Endpoint withdrawal, relay-list updates, and deterministic hole punching. |
| 13.7 | Hole punching says to send the peer's “next WireGuard datagrams” to candidates and also describes probes, but it does not define how a quiet session generates an authenticated probe or how one probe is correlated without exposing it to the host. | Direct-path promotion and failover acceptance. |
| 6.5, 14.2 | Alias export/import is a “signed file”, but its schema, signature context, signer, version, secret-handling rule, and rollback/conflict behavior are not specified in section 13. | Alias portability commands and cross-device fixtures. |
| 2.6, 7.1, 7.4, 13.4 | Tokens bind `net_name`, but no normalization maps a network display name to a valid DNS label. Local duplicate display names are suffixed and `product-domain` is installation configuration absent from the token. The canonical shared zone and behavior on differing local suffix/domain values are unspecified. | Stable DNS names across paired nodes. |
| 7.3 | PTR answers use “its name”, but the choice and precedence among a naming-layer label, local nickname, and immutable identity name are not defined. | Deterministic reverse-DNS responses. |
| 7.3, 7.8, 14.1 | The resolver is loopback-only and the daemon is per user, while port 53, a systemd-resolved link, and `/etc/resolv.conf` are host-global resources. The design requires per-user caches on shared hosts but does not define arbitration, a privileged system broker, or how multiple user daemons coexist. It also does not explain how systemd-resolved reaches a loopback-only server attributed to the keynet-owned link without creating a resolver loop. | Linux DNS ownership and multi-user acceptance. |
| 7.4, 13.5, 13.6 | The token's `relay` and optional `endpoint` are bounded text but have no complete grammar or canonical IPv4, bracketed IPv6, hostname, port, or short-ID parsing rules. `relay_name` comparison is byte-exact, so independent parsers can sign different bytes for the same endpoint. | Cross-implementation token and relay interoperability. |
| 2.4, 10 | Section 2.4 says recovery statements are not carried by pairing tokens; the section 10 identity-loss row says they travel “in new tokens”. Recovery is deferred, but the contradiction must be removed before recovery work. | Deferred recovery only. |
| 5.2, 8, 13.5 | Relay work/slot/mark/queue/packet/byte budgets are mandatory, but most numeric defaults, persistence capacity, exhaustion recovery, and operator reclamation of retained marks are unspecified. Section 13.5 requires refusing new identities rather than dropping security marks, which can become permanent exhaustion. | Production relay resource/security contract; functional relay tests can use explicit test values. |
| 5.1, 13.5, 13.7 | Exact `relay_name` is signed and tokens may use a short identifier, but the authoritative advertised name, TLS hostname mapping, configuration distribution, and behavior when UDP and WSS public endpoints differ are not specified. | Interoperable relay configuration outside explicit local fixtures. |
| 14.2, 14.5 | JSON is declared schema version 1 with stable fields and error codes, but per-command result schemas and the complete stable error-code vocabulary are absent. `--scan` is required but its Linux input/device contract and headless failure behavior are also unspecified. | CLI compatibility fixtures and QR scanning. |

### Implementation choices constrained by the design

These do not require new wire behavior and may be selected in implementation
plans, but the choice and tests must be recorded:

- Sections 5.1 and 11 make path hysteresis and the relay-session limit
  configuration. The implementation must expose bounded values and use the
  section 13.6 default of eight relay sessions; it cannot change path meaning.
- Sections 6.2-6.4 require inspecting all relevant Linux routes, rules,
  addresses, and firewall coverage and watching changes. The concrete netlink
  snapshot/watch strategy and conservative firewall adapter are platform
  choices; uncertainty must suspend an alias rather than silently admit it.
- Section 7.8 fixes resolver behavior. Choice of D-Bus client, forwarding DNS
  library, crash journal, and loopback address is implementation detail so long
  as existing split DNS is preserved and restoration is transactional.
- Sections 14.1-14.6 fix command behavior, output fields, confirmation, exit
  codes, and secrecy. The local request envelope and internal Rust types may
  follow the existing private IPC conventions; they must not create remote
  identifiers or new wire fields.
- Sections 5.2 and 13.5 fix source authentication and migration semantics.
  Hash-map layout, timer wheel, persistence engine, metrics names, and queue
  implementation are local choices, provided all stated bounds and retained
  high-water marks survive restart.

## Scope and sequencing

After approval, implementation should proceed in dependency order:

1. Finish and seal `keynet-proto`, then establish immutable shared-source pins
   and consumer build provenance.
2. Build independent node state/address and translator components while the
   relay core is built independently.
3. Compose the Linux TUN/WireGuard path and UDP relay carrier, then in-band
   control and pairing.
4. Add the WSS carrier, resolver/OS integration, CLI/IPC, rotation, and bridges.
5. Run the real-binary namespace suite only after the required components and
   design decisions exist.

This proposal deliberately preserves all deferred scope: recovery formats and
recovery commands (section 2.4), the optional naming layer and directory
(section 7.7), kernel WireGuard, the no-TUN SDK/proxy mode (section 6.8),
non-Linux OS integration, section 14.7 libns/mobile work, service/subnet/exit
extensions, and every deployment or managed-service change.

No production behavior, design text, source file, build configuration, image,
or deployment is changed by this proposal.

## Risks

- A path dependency without an immutable CI/release checkout would make local
  sibling state part of the build. The shared revision and digest/provenance
  gates are mandatory, not optional follow-up work.
- Extracting generic code from `tunnel-wg` or `nsgw-wss` can regress existing
  products. Extraction must preserve their public behavior and pass their full
  repository gates before keynet consumes the new seam.
- TUN, route, resolver, and firewall mutations can affect the host. Privileged
  tests remain inside uniquely named network namespaces and use idempotent
  cleanup plus post-run leak assertions.
- Relay state is attacker-controlled input at planetary scale. Parsing and
  budgets precede cryptography/allocation; persistence corruption and capacity
  exhaustion fail closed and affect readiness.
- Fixed-cutover rotation and ENDPOINTS ordering have unresolved design gaps.
  Implementing guessed behavior would create incompatible peers, so dependent
  work stops at those boundaries.

## Alternatives summary

The concrete alternatives and their ownership consequences are described in
the three placement sections above. A monorepo consolidation was also
considered and rejected for v1: it would solve path layout by changing all
repository release ownership, review boundaries, and deployment pipelines,
which is disproportionate to one shared pure crate.

## Decision table

| Decision | Options | Principal trade-off | Recommendation | Downstream work unblocked |
| --- | --- | --- | --- | --- |
| Shared protocol consumption | Sibling pinned path; Cargo registry; vendored snapshot | Operational checkout coupling versus publication machinery versus source drift | Sibling path with immutable shared commit and release provenance; keep image assembly binary-only | Node/relay dependencies, reproducible QA and releases |
| Node runtime placement | All in `ns`; dedicated runtime plus adapters; extend `tunnel-wg` | Initial wiring versus isolation/testability versus policy coupling | Dedicated `keynet-runtime`; thin daemon/IPC/TUN/DNS/storage adapters in `ns` | Identity/store, translation, data plane, transport, pairing, DNS, CLI, rotation, bridges |
| WireGuard reuse | Import `tunnel-wg`; extract neutral leaf primitives; independent adapter | Maximum reuse versus refactor risk versus duplication | Extract only neutral BoringTun/TUN pump seams when justified; never import existing policy semantics | Section 4 enforcement and stable virtual endpoint |
| Relay placement | New crate; server modules; extend `nsgw-wss` | Independent protocol core versus simpler wiring versus semantic coupling | New `nsgw-keynet-relay`, composed by a server feature | UDP relay core, WSS fallback, focused state/codec tests |
| Relay listener lifecycle | Separate service binary; `nsgw-server` composition | Isolation versus duplicate config/health/drain/deployment surface | `nsgw-server` owns config, bind, readiness, drain, shutdown; core owns sessions | One operational lifecycle without a new deployment |
| WSS reuse | Reuse full `nsgw-wss`; factor TLS/handshake helpers; independent stack | Code reuse versus incorrect JWT/ACL/stream semantics | Reuse only neutral TLS, handshake, mux, and drain helpers | Correct `/keynet/v1` datagram carrier |
| End-to-end harness | In-process simulation; containers; Linux network namespaces with real binaries | Speed versus realism and deterministic kernel isolation | Namespaces, scoped nft path control, deterministic keys, real IPC/TUN/DNS | Pairing policies, three carrier/path modes, four packet walks, DNS, translation, rotation |
| Unresolved protocol behavior | Implement local conventions; revise authoritative design | Short-term progress versus interoperability | Obtain design-owner decisions for the gaps above before dependent work | Offline rotation, ENDPOINTS ordering, alias files, canonical zones, production relay limits |

## Verification plan

For this documentation-only change:

1. Verify the working tree contains only this proposal.
2. Run `typos` on this file, because the repository's full `just qa` includes
   it and it directly applies to prose.
3. Run `cargo fmt --all -- --check` as the repository's non-mutating formatting
   gate. Rust compilation, Clippy, tests, dependency audit, and cargo-shear do
   not exercise Markdown and are not proportionate to a one-file proposal;
   their non-application is recorded in the delivery report.
4. Inspect the committed diff and commit with an English documentation-only
   message.

## Annotations

Approved architecture choices are recorded in the v0.7 design and its decision
record. The design gaps catalogued above are retained as historical rationale;
the active v0.7 text supplies the authoritative behavior and wire assignments.
