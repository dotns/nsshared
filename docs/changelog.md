## 2026-10-29 [docs]

Map candidate whole-floor reports and independent roster counters to current
APIs, fixtures and migration examples. Preserve legacy compatibility boundaries
and keep external adoption, review, retention and release prerequisites open.

## 2026-10-28 [feat]

Separate signed roster publication versions from attribution epochs with a new
canonical schema. Preserve legacy signed bytes, enforce both persisted floors,
and retain original usage attribution across publication refreshes.

## 2026-10-28 [feat]

Carry declaration metadata and explicit-CIDR Exit profiles in versioned M6
whole-floor reports. Preserve legacy report APIs and bytes, validate canonical
references and bounds, and correlate acknowledgements with the complete digest.

## 2026-10-28 [build]

Use union merging for the changelog and plan/task indexes so parallel appended
entries are retained. Preserve the existing fixture line-ending attribute.

## 2026-10-28 [feat]

Bind shared gateway reports and drain intent to accepted membership and runtime
custody, with correlated receipts and trusted endpoint validation. Preserve
existing observation encodings and add independent canonical and refusal vectors.
Runtime freshness and accepted-profile checks remain consumer-owned.

## 2026-10-28 [feat]

Carry positive participant custody generations in versioned enrollment and
authentication answers, bound to the issuer, participant and pending exchange.
Refuse legacy or incomplete answers and document durable custody provenance.
Other session frames, signed rosters and retention seal bytes remain unchanged.

## 2026-10-28 [feat]

Add a distinct Node posture operation behind `unstable-account` with bounded
complete snapshots, trusted membership validation and correlated receipts.
Include independent vectors and typed refusal coverage while preserving existing
heartbeat and disconnect payloads and independent posture reporting cadence.

## 2026-10-28 [docs]

Record verified identity lifecycle and bounded enrollment review answers at
explicit shared, producer and consumer revisions. Distinguish the planned shared
bootstrap adoption from historical JSON behavior, and retain remaining producer
vectors and live confirmation as open obligations.

## 2026-10-28 [feat]

Extend ordinary Node heartbeats with optional UDP reachability, full unhealthy-pair
snapshots and identity-keyed gateway RTT observations. Preserve omitted-field
semantics and original payload bytes, with bounded canonical validation, endpoint
feature negotiation and exact receipt correlation.

## 2026-10-28 [feat]

Export the discovery CBOR media type alongside its endpoint and document exact
Accept selection, response Content-Type, Vary handling and strict client decoding.
Discovery tuples, signed envelopes and vectors remain unchanged.

## 2026-10-28 [feat]

Require schema 3 for controlled admission snapshots and return each identity
with its class and admission-start version. Refuse legacy schemas and missing
or invalid history. Preserve signed roster bytes and participant transport,
with independent vectors and strict validation coverage.

## 2026-10-28 [feat]

Add ordinary Node heartbeat and disconnect contracts behind `unstable-account`,
with trusted membership and endpoint validation, bounded canonical codecs, exact
receipts and independent vectors. Existing gateway heartbeat forms remain intact;
runtime freshness and durable effects remain consumer-owned.

## 2026-10-28 [chore]

Merge the upstream CI cache configuration and documentation while retaining
the retention seal contract and both histories. The merged tree passes local
validation without source or test changes.

## 2026-10-27 [feat]

Add bounded canonical retention seals and correlated acknowledgements behind
`unstable-account`, carried by the existing participant REPORT/ANSWER frames.
Include independent vectors, typed identity and replay refusals, and protocol
documentation. Durable closure, settlement and cleanup remain consumer-owned.

## 2026-10-27 23:07 [ci]

Record shared-cache validation and complete the CI cache task. Sequential SSD
QA runs 4198 and 4202 passed on `b5f2fc3` in 12m35s and 14m07s, versus baseline
run 4182 at 28m28s. Both reported 99.62% overall cache hits, 99.25% Rust hits,
and zero cache errors. Verify the writable host bind mount in both jobs and
record old-disk comparisons, concurrent-load limitations and test timings in
`docs/task/20261027-1938-ci-sccache.md`. This record does not change the workflow.

## 2026-10-27 19:38 [ci]

Use checksum-verified sccache 0.19.0 with the runner's shared `/sccache` cache
for Workspace QA. Disable incremental compilation and always print cache
statistics. Retain registry/git source caching in a new namespace, with target
and binary caching disabled. Document the fixed checkout path and cache setup;
`just qa` and workflow triggers are unchanged.

## 2026-10-27 [docs]

Reconcile account adoption records with immutable producer and consumer revisions.
Record six matching corpora and the enrollment mismatch separately, preserving
open owner answers, live qualification and the unstable-account restriction.

## 2026-10-27 [chore]

Merge the released v0.7.0 history while preserving both parent histories.
Add the completed plan and validation records; source and tests are unchanged.

## 2026-10-27 [release]

Release `v0.7.0` at `95f1688` (the 2026-10-25 entries below): the restructured
workspace with the new defining crates, the deprecated `nsshared-proto` and
`nsshared-service-control` facades, and the `nsshared_control::account`
candidate behind the default-off `unstable-account` feature. The account
contract stays outside semver until the gate is removed in a later release. ns
`main` and nsd `refactor/unified-engine` already pin this revision.

## 2026-10-25 [feat]

Version 0.7.0 (unreleased; no tag). The workspace version moves from 0.6.0 to
0.7.0: the facades are deprecated and the defining crates are new.

- New crates: `nsshared-codec`, `nsshared-identity`, `nsshared-relay`,
  `nsshared-rendezvous`, `nsshared-control` and the development-only
  `nsshared-testkit`. `nsshared-proto` and `nsshared-service-control` are
  deprecated facades that keep their 0.6 paths.
- `nsshared_control::account` is a candidate contract behind the new
  `unstable-account` feature of `nsshared-control` (default off). It is not
  covered by semver and may change incompatibly before the gate is removed and a
  release is made. `service`, `node_control` and both facades build and behave
  the same without it; the dependencies only `account` needs (`base64`,
  `ed25519-dalek`, `hmac`, `idna`, `serde`, `serde_json`) are optional.
- `just qa` runs clippy, tests, doctests and documentation with and without the
  feature, and the scoped self-check does too when `nsshared-control` is
  affected. The account test binary requires the feature. `just semver` checks
  default features only.
- The account migration map, rewrite script and guide name the feature; the
  rewrite script's dependency advice adds it.

## 2026-10-25 [refactor]

Split the shared crates and reorganize the account contracts without changing
wire bytes.

- New crates: `nsshared-codec` (one canonical CBOR implementation with the NS
  array profile and the M6 value profile, strict base64), `nsshared-identity`,
  `nsshared-relay`, `nsshared-rendezvous`, `nsshared-control` (M6 `service`,
  `node_control`, `account`) and the development-only `nsshared-testkit`.
- `nsshared-proto` and `nsshared-service-control` are deprecated facades that keep
  their existing public paths; `nsshared-proto` no longer exports the unreleased
  `account` module, now `nsshared_control::account`. The M6 `CborError` and
  `ContractError` are non-exhaustive.
- Account contracts are organized by layer (node, control, publication) and family
  (realm, grants, subnet, edge, relay, usage) with one public path per item, shared
  private codec, limits and signing helpers, all signature domains in
  `account::domains` (bytes unchanged), consistent non-exhaustive error types and
  renamed generic items (`validate_admission_snapshot`, `ServiceDirection`,
  `USAGE_PART_DIGEST_DOMAIN`,
  `FrameKind`, `RouteError`, `L3AuthorityError`).
- Tests are one binary per crate area on the testkit; vectors live in
  `crates/<crate>/tests/vectors/` named after their test modules and producers;
  every base case is byte-identical (checked case by case against the base).
- Account migration kit for consumers: `docs/review/account-migration.json` maps
  every public `nsshared_proto::account` item and error variant of `1bc1d39e` to
  its successor (generated from rustdoc, `just account-migration-check`),
  `scripts/migrate-account-imports.py` rewrites a consumer's Rust imports and
  paths from it, and `docs/review/account-migration.md` lists the manual steps.
- Specifications are folded into `docs/spec/`; review, handoff, adoption and
  inventory state moved to `docs/review/`.
- `just semver` covers every library crate present at the release tag, checking
  the facades with `scripts/api_surface.py`.

The only behaviour change is the stricter scope text rule recorded below.

## 2026-10-25 [fix]

Apply one scope text rule to every opaque authority scope: 1 to 256 UTF-8 bytes
without whitespace or control characters. Behaviour change: publication content
now refuses control characters and whitespace in its scope (it checked only
emptiness and length), and subscription, snapshot request, source binding and
authentication source selection now refuse whitespace. Public-edge, material and
confidential configuration scopes keep their existing rule. Refusal vectors were
added to the publication, subscription, snapshot request, source selection and
control exchange fixtures; no existing case changed.

Bound M6 decoder reservations by the remaining input. Arrays and maps reserved
their declared member count before reading any member; a short nested input
could reserve megabytes. A regression vector covers nested unsatisfiable lengths.

## 2026-10-25 [docs]

Record review request delivery and the verified immutable package/consumer pair.
Clarify registration-only zero incarnation placeholders, preserve independent
grant and reporter custody, and add five canonical transition vectors without
changing crate sources or codecs.

Validation: immutable comparison matched 259 package inputs and four consumer
manifest/lock pairs; self-check passed with 542 tests and zero skips. Review
replies, producer adoption and live interoperability remain outstanding.

## 2026-10-24 [feat]

Add a separate provider-mappings Snapshot inventory with bounded canonical ids
and Subnet prefixes, exact nodes-source and membership checks, and isolated
replacement/withdrawal behavior. Validate typed inventory before exposing actions
through single-event or whole-snapshot APIs; preserve existing report and route bytes.

Validation: independent replacement and atomic mixed-snapshot vectors, unchanged
regression assertions and self-check passed with 541 tests and zero skips.
External producer and activation adoption remain outstanding.

## 2026-10-24 [docs]

Document the immutable shared candidate, delivered contracts and corrections,
verified gateway package pins, external adoption gaps and drafting ownership.
Add a read-only manifest/lock/source/vector comparison with temporary Git tests
that reject drift. Preserve historical delivery separately from approval.

Validation: all four selected consumer input pairs agree, 251 candidate inputs
match, and self-check passed with 537 tests and zero skips. External producer
review, interoperability, main publication and release remain outstanding.

## 2026-10-23 [feat]

Require canonical hostnames for HTTP routes and null names with empty aliases
and domains for raw TCP/UDP routes. Preserve HTTP bytes, realm-qualified route
identity, gateway-wide listener conflicts and backend endpoint uniqueness.
Regenerate existing raw-route fixtures without a compatibility fallback.

Validation: independent protocol/name and conflict vectors and self-check passed
with 537 tests and zero skips. NSD producer adoption remains outstanding.

## 2026-10-23 [fix]

Update tokio from 1.53.2 to 1.54.1 to resolve RUSTSEC-2026-0386. Preserve
existing manifests and advisory policy; only the package version and checksum
change in the lockfile. No affected AsyncFd constructor calls were found.

Validation: advisory checks and self-check passed with 536 tests and zero skips,
including compatibility checks, doctests and documentation.

## 2026-10-23 [fix]

Correct anonymous public-edge matching fixtures so group labels deny under every
selector, even when presented with a verified classification. Preserve matching
for verified explicit group members and all serialized policy and subject bytes.

Validation: all six group-label cases deny, the 42-case matching matrix passes,
and self-check passed with 536 tests and zero skips. No codec or wire change.

## 2026-10-23 [feat]

Add an explicit Anonymous subject-rule selector while preserving verified-only
null and qualified identity encodings. Document anonymous HTTP/TCP/UDP policy
matching, default deny and continued enforcement of required Auth dependencies.
Identity subjects and confidential authentication configuration remain unchanged.

Validation: independent policy, matching and public-edge vectors and self-check
passed with 535 tests and zero skips. External producer adoption and runtime
matching remain consumer obligations.

## 2026-10-23 [feat]

Define publication stream event/query names and inclusive decoded, encoded and
framed bounds. Require source-bound snapshot responses with exact pending
scope/source and delivery context validation, rejecting plain or mixed entries
atomically. Enforce the pending request's complete 8192-byte encoding ceiling.

Validation: independent stream and snapshot vectors, unchanged request-boundary
regressions and self-check passed with 532 tests and zero skips. NSD producer
and Node adapter adoption remain outstanding.

## 2026-10-23 [fix]

Update ctutils from 0.4.2 to 0.4.4 to resolve RUSTSEC-2026-0385 without
changing dependency requirements or advisory policy. Only the package version
and checksum change in the lockfile.

Validation: advisory checks passed; self-check passed with 527 tests and zero
skips, including compatibility checks and documentation.

## 2026-10-23 [feat]

Add exact Node L3 application-status requests and receipts, signed-inner-event
digests and retained source/context comparisons. Clarify that mapped Subnet
routes use exact resource selection without provider-wide Node host permission.
Existing policy, grant, Subnet and service-control bytes remain unchanged.

Validation: independent route and status vectors and self-check passed with
527 tests and zero skips. NSD issuance retention and Node runtime application
and reporting adoption remain outstanding.

## 2026-10-23 [docs]

Clarify that the current gateway emits no EchoReplySend usage rows because the
frozen packet runtime provides no per-packet successful-send receipt. Synthetic
replies remain unbilled; queue admission is never completed sending. Preserve
EchoProbeSend and all existing contracts, vectors and wire bytes.

Validation: documentation assertions and self-check passed with 521 tests and
zero skips. Runtime completion receipts and later billing qualification remain
outstanding.

## 2026-10-23 [feat]

Declare `node_local_names.v1` through the existing enrollment capability set.
Document identity-derived Node naming, retirement of four legacy registration
values and consumer-owned atomic cutover without changing exchange tuples.

Validation: independent registration and authenticated acceptance vectors,
canonical capability refusals and self-check passed with 522 tests and zero skips.
Producer adoption, consumer cutover and interoperability remain outstanding.

## 2026-10-22 [feat]

Add authenticated M6 unary and stream carrier contracts with exact pending
request correlation, singleton lease results, reverse proposal comparisons and
eight-field publication subscriptions. Bound sessions reject zero runtime and
session request identifiers while preserving existing M6 message bytes.

Validation: independent carrier and subscription vectors and original identifier
regressions passed; self-check passed with 523 tests and zero skips. NSD adoption,
durable session custody and runtime interoperability remain external obligations.

## 2026-10-22 [feat]

Add confidential certificate and client-CA acquisition contracts with exact
pending-request echoes, typed kind/realm/generation refusals and redacted secret
values. Preserve auth-only acquisition and installation-status ACK bytes.

Validation: independent payload and signed-carrier vectors passed; self-check
passed with 517 tests and zero skips. Producer adoption, current dependency
checks and runtime installation remain external obligations.

## 2026-10-22 [feat]

Allow mock relay startup with a caller-owned UDP socket and assigned-port DNS
identity. Preserve the original receive queue without rebinding or retries;
reject conflicting settings and release the socket on failure and shutdown.
Existing startup and command-line behavior remain unchanged.

Validation: four real UDP ownership tests passed; the runtime suite passed all
15 tests and self-check passed 515 tests with zero skips.

## 2026-10-22 [feat]

Separate provider Exit grants from client Subnet route snapshots by exact kind.
Validate independent recipient and membership context and enforce nodes authority
for Exit views while retaining egress contribution authority for Egress grants.
Replacement and withdrawal remain isolated per complete publication key.

Validation: independent multi-provider view and refusal vectors passed; self-check
passed with 511 tests and zero skips. Existing grant and route bytes remain
unchanged. NSD projection and client route adoption remain outstanding.

## 2026-10-22 [feat]

Add source-qualified ordinary provider Subnet route reports and correlated
allocation responses. Validate committed mapping authority, complete generations
and stable retained M6 references through withdrawal and reoffer. Refuse stale
reports and delayed responses without restoring withdrawn offers.

Validation: independent lifecycle and carrier vectors passed; self-check passed
with 510 tests and zero skips. NSD ingestion/allocation/persistence and provider
adoption remain outstanding; shared contracts add no runtime or I/O.

## 2026-10-22 [feat]

Add validated canonical content encoding, domain-separated signing input and
inner publication event encoding with supplied signatures. Preserve wire bytes
and consumer decisions; reject unknown ownership, invalid structural fields and
full-event overflow while retaining partial content and opaque family payloads.

Validation: independent byte/signature round trips and exact-size boundary checks
passed; self-check passed with 504 tests and zero skips. NSD producer adoption
and producer-owned interoperability vectors remain outstanding.

## 2026-10-21 [feat]

Add typed usage and Node-control catalogue publications with strict canonical
payloads and independent reporter/membership comparisons. Refuse malformed
replacement before advancing versions; preserve exact-key withdrawal and replay
tombstones without changing existing usage or control message bytes.

Validation: independent payload and source-bound replacement vectors passed;
self-check passed with 503 tests and zero skips. Producer review, adoption and
gateway persistence verification remain outstanding.

## 2026-10-21 [feat]

Require an explicit canonical realm and publication scope in authentication
requests. Constrain registration source authority to nodes in the accepted
Network, including Equal, and retain independent authority for each scope.
Old request shapes and mismatched response scopes refuse.

Validation: independent source-selection vectors and signature, correlation and
UTF-8 boundary checks passed. Candidate self-check passed with 500 tests and zero
skips; additional conformance checks passed with 502 tests and zero skips.
NSD producer adoption and interoperability vectors remain outstanding.

## 2026-10-21 [feat]

Require signed source authority alongside successful registration results and
authentication tokens. Verify nested authority against independent enrollment
facts and exact pending request correlation; refuse old response shapes.

Validation: independent response and source-selection vectors passed; candidate
self-check passed with 500 tests and zero skips. Additional conformance checks
passed with 501 tests and zero skips. NSD producer adoption and interoperability
vectors remain outstanding.

## 2026-10-21 [feat]

Add shared participant enrollment and renewal frames with fresh connection proofs,
exact request correlation and retained authorization deadlines. Add signed relay
owner and realm bindings with withdrawal and durable version-floor replay refusal.
Keep global directory and existing roster/report formats unchanged.

Validation: independent credential/binding sequences and refusal checks passed;
self-check passed with 496 tests and zero skips. Producer review and runtime
adoption remain outstanding.

## 2026-10-21 [feat]

Qualify grant, payer and active-authority identities by TCP, UDP or Exit protocol.
Permit equal or later expiry renewal only when all other owned content remains
identical. Preserve token ownership, retirement history and exact payer joins.

Validation: independent contract vectors and additional boundary checks passed;
self-check passed with 498 tests and zero skips. Family 5/6 tuples change;
producer adoption and independently owned interoperability vectors remain outstanding.

## 2026-10-21 [feat]

Add signed source bindings and exact delivery fences before publication decisions.
Define Node route select/clear commands with immutable source-owned receipts and
exact selection generations. Reject complete source snapshots on wrong-channel
entries while preserving authenticated unknown snapshot extensions.

Validation: 129 independent cases and retained regression assertions passed;
self-check passed with 492 tests, zero skips and static/API/docs checks. Producer
review, transaction persistence and consumer adoption remain outstanding.

## 2026-10-21 [feat]

Unify candidate membership realm identities as a 16-byte RealmId with strict
uppercase ULID text. Migrate affected publication, membership, policy, payer and
material fields while preserving existing binary wire bytes and separate discovery
and external identity namespaces. Arbitrary realm labels now refuse.

Validation: canonical and malformed identities, authenticated two-realm membership
removal and affected family checks passed. Self-check passed with 487 tests and
zero skips. NSD/ns producer confirmation and consumer adaptation remain outstanding.

## 2026-10-20 [feat]

Add canonical signed snapshot poll requests with exact authority scopes and
pending response correlation. Reuse existing publication snapshots and per-key
versions, retaining authenticated unknown extensions beside known updates while
refusing known stream-owned events and invalid authentication or scope.

Validation: 44 independent cases and unchanged mixed-snapshot regressions passed.
Self-check passed with 482 tests, zero skips and static/API/docs checks. Exact
producer confirmation and independently owned vectors remain outstanding.

## 2026-10-20 [fix]

Update rustls-webpki to 0.103.16 and remove unused bundled root packages from
the mock-rendezvous development dependency. Retain the existing explicit
aws-lc-rs Rustls connector and generated certificate trust configuration.
This clears RUSTSEC-2026-0382 and RUSTSEC-2026-0381 without audit exemptions.

Validation: dependency audit and API compatibility passed, no active ring
dependency was found across targets, and all 479 tests passed with zero skips.
The TLS smoke test also passed independently with unchanged assertions.

## 2026-10-20 [feat]

Add confidential authentication configuration values and exact pending/current
material correlation using existing signed control envelopes. Carry actual private
catalog values with redacted debug output, enforce credential identities across
methods and preserve query parameters in fixed HTTPS key acquisition endpoints.

Validation: 126 independent vectors and focused regressions passed. Self-check
passed with 473 tests, zero skips and static/API/docs checks. Producer confirmation
and independently owned vectors remain outstanding.

## 2026-10-20 [feat]

Add signed heartbeat, gateway observation, services, usage and material status
operations on the existing confidential carrier. Complete service and Exit floor
metadata and per-reference outcomes, preserve exact data text, and correlate
material installation status with its full pending context.

Validation: independent report and floor-text vectors and unchanged regression
assertions passed. Self-check passed with 475 tests, zero skips and all static,
API and documentation checks. Producer confirmation remains outstanding.

## 2026-10-20 [feat]

Add canonical authenticated publication subscription requests with exact
issuer/recipient/realm/scope entries, capability declarations, public ingress
indices and bounded logical attempt identity. Reuse existing signed carriers
and retain per-publication versions and channel ownership.

Validation: 35 independent vectors cover payload and signed-carrier acceptance
and refusals. Self-check passed with 469 workspace tests, zero skips and all
static/API/docs checks. Matching producer confirmation remains outstanding.

## 2026-10-20 [feat]

Add pure public-edge routing, generation-qualified material acknowledgements and
correlated declarations using existing service-control objects. Validate listener
and backend endpoint ownership across complete realm replacements while keeping
discovery names and material references realm-qualified.

Validation: 151 independent fixture cases and 12 focused tests passed; self-check
passed with 461 workspace tests, zero skips and static/API/docs checks. Standalone
service labels, open OIDC carriers and producer confirmation remain outstanding.

## 2026-10-20 [feat]

Add pure registration, authentication and information exchange contracts with
exact signed acceptance comparisons. Preserve machine claim, key qualification,
pin ownership and rotation predicates, including separate gateway and server
audience boundaries. Reuse existing bootstrap signing bytes and enrollment types.

Validation: 66 independent vectors and six consumer tests passed; self-check
passed with 455 workspace tests, zero skips, 41 selection tests and static/API/docs
checks. Producer confirmation and independently owned vectors remain outstanding.

## 2026-10-20 [feat]

Add pure qualified policy subjects, bindings, ordered admin claims and signed
request inputs using existing account signature domains. Preserve exact JWT
claim names and values, including whitespace and empty strings, within UTF-8
byte bounds. Retain reference and token syntax checks and existing carrier owners.

Validation: 122 independent cases cover canonical bytes, claim data, scope and
request-domain refusals. Candidate self-check passed with 449 Rust tests, zero
skips, 41 selection tests and static/API/docs checks. Open aggregate carriers
and independent producer confirmation remain documented.

## 2026-10-20 [fix]

Scope member manifest and lockfile changes by resolved dependency closures at
the merge base and working tree. Include versions, sources, checksums and enabled
features, select changed members and reverse consumers, and explain differences.
Global configuration and failed or incomparable metadata retain complete QA.

Validation: 41 selection tests cover added/removed dependencies, shared versions,
checksums, features, global inputs, failures and temporary export cleanup.
Self-check passed with 434 Rust tests, zero skips and all static/API/docs checks.

## 2026-10-20 [feat]

Add complete realm membership payloads with existing Node bindings and signed
records, plus observation-only policy counters. Keep authentication and scope in
the existing signed publication carrier. Validate exact bindings, ordering,
uniqueness and bounds before complete replacement without granting L3 permission.

Validation: 47 independent fixtures cover replacement, malformed non-renewal,
omission, empty withdrawal and replay refusal. Candidate self-check passed with
438 Rust tests, zero skips, 28 selection tests and static/API/docs checks.
Producer confirmation and independently owned producer vectors remain outstanding.

## 2026-10-20 [feat]

Replace the service usage subject with exact 16-byte realm-local UserId bytes.
Add separate completed-I/O and accepted relay DATA profiles, immutable report
parts and correlated acknowledgement, conflict, rejection and mapping-repair
contracts. Preserve historical payer and roster attribution without runtime I/O.

Validation: 77 independent fixture cases cover canonical bytes, historical
ownership, duplicate delivery and exact answer correlation. Candidate self-check
passed with 439 Rust tests, zero skips, 28 selection tests and static/API/docs
checks. Producer confirmation and live consumer instrumentation remain outstanding.

## 2026-10-20 [feat]

Add pure Egress/Exit grant publications, explicit binary realm/UserId payer
bindings, resource retirement snapshots and complete Node identity-to-key
authority. Validate payer ambiguity, exact resource context, retained retirement
history and fresh incarnations while preserving existing policy and Subnet bytes.
Runtime installation, expiry enforcement and persistence remain consumer-owned.

Validation: 72 independent fixture cases and five new consumer tests cover
accepted contracts, typed refusals and selective withdrawal. Self-check passed
with 434 Rust tests, zero skips, 28 selection tests and static/API/vector/docs
checks. Independent conformance checks found no departures. Producer confirmation
and independently owned producer vectors remain outstanding.

## 2026-10-20 [feat]

Share the pure Node-control v2 codec with unchanged message bytes, constants,
ACK hashes, endpoint selection and validation. Document ACK as at least accepted;
transport, persistence, retransmission and sessions remain consumer-owned.
Independent Python vectors reproduce all nine pinned gateway fixtures.

Validation: all ten predecessor tests, independent vectors and selection-budget
checks passed. Repository self-check passed with 429 Rust tests, zero skips,
28 selection tests, one documentation test and static checks.

## 2026-10-20 [fix]

Scope self-check package tests by tracked build and test inputs. Unreferenced
records and documents retain static checks without package tests; included files,
directory reads, unresolved computed inputs, configuration and vectors retain
complete QA. Input diagnostics identify referencing sources or uncertainty.

Validation: failing-first regressions cover documentation-only selection and
unresolved shell and Rust inclusion paths. All 28 selection tests, 416 Rust tests
with zero skips, one documentation test and static checks passed.

## 2026-10-19 [fix]

Remove the external WSS test's assumption that an allocated UDP port is free on
TCP. Hold an occupied configured WSS address through relay shutdown while UDP
allocates independently, preserving listener, certificate, registration and
capability assertions. Runtime behavior is unchanged.

Validation: the original TCP conflict was reproduced deliberately. All four
external integration tests passed twice; complete QA passed with 416 Rust tests,
0 skipped, 10 selection tests and 1 documentation test.

## 2026-10-19 [feat]

Add signed publication events with explicit scope, kind, owning channel, version
and validity. Distinguish complete replacement, empty withdrawal, absence and
authenticated ACL failure while retaining versions for withdrawn or denied state.
Borrow bounded encoded input, terminate streams on events over 1 MiB and reject
invalid snapshots before exposing any action. Existing M6 payloads stay opaque.

Validation: 95 independent signed fixtures and additional allocation, mutation,
version and snapshot-boundary checks passed. Complete QA passed with 416 Rust
tests, 0 skipped, 10 selection tests and 1 documentation test. All 330 previous
account fixtures retain their bytes; NSD producer confirmation remains requested.

## 2026-10-19 [feat]

Add confidential bootstrap discovery and signed opaque call carriers with ordered
endpoint selection, explicit pin intersection and supplied clock/replay checks.
Validate canonical origins with IDNA ToASCII and exact ASCII equality. Preserve
existing service-control bytes and leave transport authentication and replay
persistence with callers. Producer confirmation remains requested in the review.

Validation: 172 independent bootstrap vectors and the original invalid-IDNA
regression pass. Complete QA passed with 415 Rust tests, 0 skipped, 10 selection
tests and 1 documentation test; all existing fixture records remain unchanged.

## 2026-10-19 [feat]

Add complete Subnet route publications with M6 resource references, exact real
and mapped prefixes, full provider/client identities and tagged route selection.
Return minimal destination CIDR covers after exclusions, retain distinct bypasses
and advertise TCP, UDP and echo coverage only for selected real IPv4 destinations.
The contract uses the existing service-control crate through a one-way dependency.

Validation: 52 independent vectors cover 15 accepted and 37 refused publications,
including default/host prefixes, both address families and input bounds. Complete
QA passed with 408 Rust tests, 0 skipped, 10 selection tests and 1 documentation test.

## 2026-10-19 [feat]

Add typed verification of complete signed participant roster generations within
the existing issuer/recipient scope. Return membership, classes, epoch and signed
times together. Supplied-clock lifecycle status degrades diagnostically after
24 hours since authenticated renewal and expires at the exclusive signed deadline.
Complete empty, omission and class-only replacement update the whole generation.

Validation: 27 independent signed lifecycle vectors and complete QA passed with
406 Rust tests, 0 skipped, 10 selection tests and 1 documentation test. Existing
signed bytes and all 79 earlier account vectors are preserved.

## 2026-10-19 [feat]

Add the pure enrollment contract with bounded canonical capabilities and explicit
membership binding acceptance. Reuse the existing lifecycle for identity
replacement and authorized stable-identity key rotation; refuse rollback and
unlinked staged-version restarts. Preserve registry bytes and existing vectors.
Keep producer-profile questions explicit in the review request.

Validation: 29 independent enrollment vectors verify canonical bytes, binding
decisions and derived NodeId, N6 and N4 values. Complete QA passed with 405 Rust
tests, 0 skipped, 10 selection tests and 1 documentation test.

## 2026-10-19 [docs]

Prepare the L8 candidate review request for the NSD and node owners, pinned
to `41149fe1febf2ecee07f077d68a500e18822442c`. Include eleven family states,
the gateway inventory summary, 23 questions and two M6 API/vector requests.
All 25 dispositions are prepared; delivery and answers remain to be recorded.
Link the request and published candidate revision from the specification.
Complete QA passed, including spelling and documentation checks.

## 2026-10-19 [feat]

Add the pure `nsshared-proto::account` candidate and its specification: eleven
versioned families, distinct lifecycle counters and incarnations, normalized
Node L3 rules, explicit service byte units, and atomic identity/class rosters.
Local admission JSON requires named object fields; signed participant rosters
bind issuer, recipient, version and validity. Existing M6 types and bytes remain
in `nsshared-service-control`.

Validation: 50 independent candidate vectors, named-field regression tests,
and complete QA passed with 402 Rust tests, 0 skipped, 10 selection tests and
1 documentation test. Both vector drift checks and API compatibility passed.

## 2026-10-18 [feat]

Add `just self-check base`, defaulting to `main`. Crate-only changes retain
all workspace static, vector and API checks, then restrict tests and
documentation to the changed packages and their reverse dependencies.
Global inputs and empty diffs select the complete `just qa` recipe.
Selection tests run as part of complete QA.

Validation: 10 selection tests, 393 Rust tests with 0 skipped, and
1 documentation test passed. A temporary crate-only change verified scoped
selection and was restored before the final complete check.

## 2026-10-18 [chore]

Import the existing M6 service-control contract at
`aba1c5d5350550f85631034cf613e780bc4dbbe0` so the L8 account payload profile
extends its shared declarations and messages. Preserve the original commits,
canonical bytes, service-label rules, vectors, and rustls update.

Validation: `just qa` passed with 393 tests, 0 skipped, and 1 documentation
test; both vector drift checks and API compatibility checks passed.

## 2026-10-11 [docs]

Re-pin both spec coverage tables from docs `957de97a79f7` to `27a794d`: every
row's section and line range now points at the current text (220 rows, each
range checked to exist and to lie in the cited section). Rows whose text was
rewritten (§3.3 summary rule, §7.2 tiers, §7.6, §10.2 pairing via the app
channel, §11.2 tiers, rendezvous §9) were mapped by hand.

## 2026-10-10 [docs]

nsshared is in maintenance after `v0.6.0`: fixes, dependency updates and
milestone contracts (L11, L8, L9) only; see
`docs/plan/20261010-1200-nsshared-maintenance.md`. The README consumption
example uses the public mirror `https://github.com/dotns/nsshared`. Spec
coverage now cites the published docs commits (`2c5b8d3`, `91b2594`). nsplane
0.11 needs no change here.

## 2026-10-07 [feat]

Release `v0.6.0`: registry state persistence and member merge, requested by
the nsgw next-architecture draft as L10 (quick-v2 §3.3, §7.2, §7.6 in the docs
change after `05ea324`). Breaking:

- `record::RecordMarks` is the deterministic summary of a generation's
  records: `R` is the largest by `(issued_at, canonical bytes)` and the
  conflict keeps the record that caused it (`conflict_evidence`); new
  `merge`, `encode` / `decode` (`RecordState`) and `MarksDecodeError`.
  `RecordDecision::Refreshed` now also covers an equal `issued_at` with larger
  bytes.
- `rendezvous::registry::RegistryEntry` tracks publication tiers per record
  revision: a tier changes only with a larger revision, a smaller one never
  changes it, and two tiers at one revision latch a publication conflict that
  suppresses DNS (`dns`, `is_publish_conflicted`, `publish_revision`); new
  `merge(other, now)`, `encode` / `decode` (`RegistryState`) and
  `RegistryStateError`.
- New `registry_state` vectors from the independent generator: summaries in
  any order, merges both ways, restore refutations.

Consumers: nsgw (`nsgw-relay`, `nsgw-relay-region`) persists and replicates
registry entries with these; ns persists peer `RecordMarks` the same way.
Nodes must re-sign a record with a larger `issued_at` to change their tier.

## 2026-10-04 [feat]

Release `v0.5.0`: public DNS publication has three levels (quick-v2 §7.2,
§11.2, §11.3 in the docs change after `faca1ec`). Breaking:

- `rendezvous::message::PublishRequest::dns` is a `DnsPublication`
  (`none`, the default and the value when the JSON field is omitted;
  `address`, AAAA only; `record`, AAAA and TXT) instead of a `bool`; on the
  wire it is a string. `dns_u8` in the publish proof is 0, 1 or 2.
- `registry::publish_proof_message`, `create_publish_proof`,
  `publish_request`, `VerifiedPublish::dns` and `RegistryEntry::dns` take or
  return `DnsPublication`; `MessageError::Dns` rejects other values.
- The `registry` and `mailbox_json` vectors use the three levels.

Consumers: ns publishes with `none` unless configured; the registry operator
publishes AAAA for `address` and AAAA plus TXT for `record`.

## 2026-10-04 [feat]

Release `v0.4.0`: add `nsshared_proto::discovery`, public DNS discovery of
node records (quick-v2 §11.2): `node_dns_name`, `encode_dns_txt` (the
`v=ns2 r=` TXT value split into 255-byte character-strings) and
`verify_dns_answer` (string and total length, prefix, strict base64url,
record validity, expiry, queried node ID and AAAA = `N6`). The independent
generator adds the `dns_txt` vectors and reproduces the §11.2 example TXT.
Additive; consumers: ns (resolver side) and the planned authoritative DNS
(M8, publisher side). The equivalent ns overlay helper can move here.

## 2026-10-04 [refactor]

Release `v0.3.0`: prepare the public API for stability. Breaking:

- `nsshared-proto` exports modules instead of flat glob re-exports: `keys`,
  `identity`, `record`, `relay` (with `relay::budget`), `rendezvous`,
  `encoding` (now also `CborReader`, `CborWriter`, `CborError`) and
  `constants`. `IdentityKey`, `IdentitySecret`, `WgSessionKey`,
  `WgSessionSecret`, `NodeId`, `NodeRecord` and `RelayId` stay at the root.
  `RelayId` and `RelayIdError` moved under `relay`.
- Every public error and rejection enum and `rendezvous::error::ErrorCode`
  is `#[non_exhaustive]`; matches need a wildcard arm.
- Removed the application constants `DEFAULT_PAIRING_MAILBOX_TTL_SECONDS`,
  `MAX_PAIRING_MAILBOX_TTL_SECONDS`, `PREPARE_DEADLINE_SECONDS` and
  `MAX_RELAYED_INNER_MTU` (ns owns them).

QA: `just semver` (cargo-semver-checks 0.51.0) checks `nsshared-proto` and
`nsshared-telemetry` against the previous release tag and runs in `just qa`;
`just doc` denies rustdoc warnings. Version policy: while in 0.x, a minor
bump may break the API and a patch bump must not; from 1.0, semver applies.

## 2026-10-03 [refactor]

Release `v0.2.0`: nsshared keeps only generic protocols and tools (docs
`ns-shared/index.md`, commit `8ec71f3`). Breaking for every consumer:

- Merge `nsshared-wire` and `nsshared-rendezvous` into `nsshared-proto`; the
  rendezvous messages are `nsshared_proto::rendezvous`, the wire items stay at
  the crate root.
- Rename the rendezvous service: path `/rendezvous/v1`, subprotocol
  `ns-rendezvous-v1`, actor context `ns-rendezvous-actor-v1\0` (was the
  undeployed `/quick/v2`, `ns-quick-v2`, `ns-quick-actor-v2\0`).
- Move to ns: pairing payloads and PSK (now the ns app channel, docs
  `ns/app-channel.md`), the in-tunnel control channel, IPv4 alias candidates
  and `lan6`, and the `path` / `transport` / `peer_source` labels of
  `nsshared-telemetry`. Their vectors (`pairing`, `control_messages`,
  `alias4`, `lan6`) are dropped here; the last version is tag `v0.1.0`.
- Add `nsshared_proto::encoding`: strict base64url and padded standard base64.

Consumers: ns switches to `nsshared-proto` at `v0.2.0` and takes over the
moved code; nsgw adopts it with the relay v2 server.

## 2026-10-03 [refactor]

Keep only protocols shared by several components. Remove the relay region
member protocol from `nsshared-wire` (region frames, channel rules, snapshot
chunking, the mark join and `MAX_REGION_RENDEZVOUS_FRAME_BYTES`) and the region
forwarding bodies 10-12 (`nsshared_rendezvous::region`): only relay instances
encode them, so they belong to the relay; the last version is in tag `v0.1.0`.
Remove the file-transfer mailbox mapping (`KIND_TRANSFER`,
`transfer_open_request`): file transfer is an ns application. Clients keep the
`region` capability token, the `unavailable` retry rule and the authority
checks. The `region_frames` and `region_bodies` vectors are dropped. Breaking
for code that used the removed items.

## 2026-10-03 [chore]

Close the open v1 tasks and plans as superseded by the v2 protocol and
migration milestone M6, which redesigns the account contract instead of
porting it: CTRL-015, CTRL-016, CTRL-017, NODE-001, NODE-002, NODE-003,
SH-MESH-001, SH-MESH-002, keynet cascaded relays, PLAN-011, PLAN-015,
PLAN-016. Mark P3a complete; first release `v0.1.0`.

## 2026-10-03 [feat]

Add `nsshared-mock-server` (`examples/mock-server`, `publish = false`), a
combined mock for ns development: one `host:port` and one TLS certificate
serve relay v2 UDP, `wss://host:port/ns/v2` (relay mock) and
`wss://host:port/quick/v2` (rendezvous mock), routed per WebSocket upgrade
(404 for other paths, 400 without the subprotocol). The served directory is
the server itself announcing `udp`, `wss`, `mailbox` and `registry`, or a
configured directory that lists it. `nsshared-mock-rendezvous` exports
`accept_quick_request`, its `/quick/v2` upgrade check, for such routers. An
integration test registers a node on `/ns/v2` and over UDP, publishes and
looks up its record on `/quick/v2` and reads the directory, all on one port.
The relay's tentative REGISTERED announces the same tokens, through the new
`MockRelayConfig::extra_capabilities`.

## 2026-10-03 [feat]

Add `examples/mock-relay`, the `nsshared-mock-relay` example: a single-instance,
in-memory relay v2 mock (docs `ns/quick-v2.md` §8) for tests, as a library
(`MockRelay`, a sans-IO `Relay` core over `nsshared-wire`, `testing` node
helpers) and a binary. It serves the UDP carrier and the WSS carrier
(`wss://host:port/ns/v2`, subprotocol `ns-relay-v2`, self-signed or PEM
certificate) on one port, admits REGISTER, confirms sessions by PRESENCE and
forwards DATA between them. It is not a production relay: no region or mesh
replication, no owner fencing, no persistence and only simple per-node limits.
Integration tests cover two-node DATA over UDP, WSS and mixed carriers, and the
ns `RelayClient` byte layout. Not published.

## 2026-10-03 [feat]

Add `nsshared-mock-rendezvous` (`examples/mock-rendezvous`, `publish = false`),
a single-instance mock of the NS rendezvous v2 relay for ns development and
tests: `wss://{host:port}/quick/v2` with subprotocol `ns-quick-v2`, the
connection challenge and actor `hello`, the mailbox broker with the `recv`
long poll and sweeps, `directory` (its own entry or a configured directory)
and the node registry (`publish`, `lookup_node`, §3.3 ordering and the
conflict latch), with every rendezvous §6 and quick-v2 §7.4 limit
configurable. One instance, no region: frames 10-12 are not served and the
registry shard is the mock itself. All protocol rules come from
`nsshared-rendezvous`. It interoperates with the ns overlay registry client
and Quick pairing; integration tests drive pairing, transfer admission,
the registry and the limits over TLS WebSocket. Embeddable as a library
(`RendezvousServer`) or run as the `nsshared-mock-rendezvous` binary with a
self-signed or PEM certificate. See `examples/mock-rendezvous/README.md`.

## 2026-10-03 [feat]

Add typed keys to `nsshared-wire` (quick-v2 §2.1, §2.3): `IdentityKey` (Ed25519 `I`,
unpadded base64url text, node ID, address group, `N6`, `N4`, `lan6` and alias
derivations by delegation), `IdentitySecret` (seed, OS-random generation, signing-key
adapter), `WgSessionKey` and `WgSessionSecret` (X25519 `K`, `wg`-compatible padded base64),
with strict text parsing, typed `KeyParseError`, redacted `Debug` and zeroize on drop for
secrets. The module docs map each ns `NodeIdentity` helper to its replacement. Existing
raw-byte APIs are unchanged.

## 2026-10-03 [feat]

Add `nsshared-telemetry`, the telemetry conventions shared with NS:
`tracing` subscriber setup as composable pieces (`LogFormat` text or JSON, an
env filter read from a configurable variable with a default directive, the
boxed fmt layer, and `init`, which fails on an invalid filter or a second
call), the `Redacted` wrapper with `SENSITIVE_FIELDS` (the NS forbidden
labels), and the `path`, `transport` and `peer_source` label keys with their
`Path`, `Transport` and `PeerSource` values. No OpenTelemetry dependency and
no exporter; NS `metrics.rs` names no metric carrying these labels, so no
metric name is shared yet.

## 2026-10-03 [docs]

Add the [v1 crate analysis](design/v1-crate-analysis.md), which classifies
every part of the archived v1 `control`, `common`, `acl` and `tunnel-ws`
crates into: returns in P3b as the `nsshared-control` v2 contract, moves to
`nsplane-acl`, stays in ns, or is superseded by `nsshared-wire` /
`nsshared-rendezvous` or dropped. The P3a plan is now implementing, with an
owner amendment: the path is nsshared -> ns -> nsgw with nsgw deferred,
nsshared ships libraries only (mocks for ns live under `examples/` as
unpublished workspace members), and only a single relay instance is in scope.

## 2026-10-03 [refactor]

Drop the `ns-` prefix from the crate names: the wire and rendezvous crates are
now `nsshared-wire` and `nsshared-rendezvous` (libraries `nsshared_wire`,
`nsshared_rendezvous`), and the repository is now nsshared
(`https://git.pvv.cc/nsiod/nsshared.git`); no behaviour change.
Consumers update their dependency keys and git URLs.

## 2026-10-03 [feat]

Replace the v1 rendezvous crate with `nsshared-rendezvous`, the NS rendezvous v2
messages (docs `ns/rendezvous.md`, `ns/quick-v2.md` §7, §10.2): the
`/quick/v2` JSON transport, capability tokens, the connection challenge and
actor `hello`, the relay directory v2 and its update rules, error codes and
broker limits, the mailbox model with its phase rules as pure checks, the node
registry (publish proof, HRW sharding, §3.3 acceptance, `lookup_node`),
pairing Invite / Join / ACCEPT / COMPLETE payloads and the PSK, and the region
frame bodies of types 10 RENDEZVOUS_REQUEST, 11 RENDEZVOUS_RESPONSE and
12 REGISTRY_RECORD. In `nsshared-wire`, types 10-12 are control-connection only,
types 10 and 11 may reach 20480 bytes on the control connection, a NodeRecord
with a service period above 604800 s is invalid, and the canonical CBOR reader
and writer are public. See
[nsshared-rendezvous spec coverage](spec-coverage/nsshared-rendezvous.md).

## 2026-10-03 [feat]

Add `tools/vectors`, an independent conformance vector generator: Python
standard library only, implementing the specification text directly and
self-tested against RFC 8032, 7748, 5869 and 8949 vectors. It writes `.vec`
fixtures for both crates (identities, `lan6`, alias candidates, node records,
relay packets, control messages, region frames; hello signatures, registry
proofs and shard order, pairing payloads, `/quick/v2` JSON messages, region
frames 10-12), which the `vectors_*` tests consume byte for byte.
`just vectors` regenerates them and `just vectors-check`, part of `just qa`,
verifies them. See [nsshared-rendezvous spec coverage](spec-coverage/nsshared-rendezvous.md)
(Vectors) and [Quick conformance vectors](task/20261002-1516-quick-vectors.md).

## 2026-10-02 [feat]

Replace `quick-wire` with `nsshared-wire`, the NS protocol v2 wire layer (docs
`ns/quick-v2.md`): identity derivations (node ID, address group, `lan6`, alias
candidates), node records and the §3.3 ordering state, relay packets v2 with
REGISTER admission, session key and MACs, the region member protocol v2 and the
in-tunnel control messages. There is no v1 compatibility: KeyBinding,
INTRO / INTRO_ACK, `revoked_through` and the region QUICK frames are gone. The
consumers, the nsgw quick relay and ns, switch to `nsshared-wire` in migration
milestone M5 (plan P2). See [nsshared-wire spec coverage](spec-coverage/nsshared-wire.md)
and [nsshared-wire protocol crate](task/20261002-1516-quick-wire.md).

## 2026-10-02 [refactor]

Rebuild ns-shared on `next` around the Quick protocol. The workspace starts
with `quick-wire` (from `keynet-proto`) and the v1 rendezvous crate (from
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
