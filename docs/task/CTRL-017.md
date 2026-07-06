# CTRL-017 Policy-convergence observability: emit/echo completion, staleness budget, multi-NSD merge authority

- **status**: proposed
- **priority**: P1
- **owner**: unassigned (investigation delivered by campaign drrem-wsc-20260703)
- **createdAt**: 2026-07-03

## Description

Design-review finding DR-H4 (2026-07-03, high): the ACL plane has no
"has this policy landed everywhere?" signal, and several paths let a node
keep a stale ALLOW after a revocation. Three sub-claims: (a) mainline NSD
never emits `policy_version` and NSN/NSC heartbeats report `None` (only
NSGW echoes a real value); (b) the `last_good_max_age` stale-downgrade is
default-off and has no NSGW analogue; (c) the multi-NSD merge is a union
of allows, so revocation must land on every NSD.

This file is the INVESTIGATE-phase record only: symptom verification with
code evidence, the PLAN-095 gap, per-repo candidate change sets, the
design decision space, and the open questions the proposal phase must
answer. No option is selected here.

Evidence baselines: ns-shared worktree `bkd/wylncln4` @ `7799f85`
(== main merge-base); sibling live checkouts read-only at
`/workspace/nsiod/{nsd,ns,nsgw,nsiod-docs}` (all on `main`,
ns @ `a1f0fe9`).

## Symptom confirmation

### (a) Emit/echo loop is open everywhere except NSGW — CONFIRMED

NSD emit side (mainline `nsd`):

- `nsd/crates/nsd-api/src/sse/filter.rs:138` —
  `ControlMessage::PolicyVersion { .. } | ControlMessage::Unknown => Self::Unknown`
  in `VariantKind::from_message` (:108). No dedicated `VariantKind` row
  exists, so the event is never eligible in the connector/gateway variant
  sets (:216-254) and nothing is ever fanned out.
- Mainline NSD does maintain the per-realm counter — but only in the DB:
  `nsd/crates/nsd-api/src/handlers/admin/acl/mod.rs:115`
  (`bump_policy_version`, `acl_policies.version`, monotonic
  `saturating_add(1)`); every successful admin ACL write calls it and then
  `recompile_and_publish` (:138), which emits `acl_config` invalidations
  (`sse/outbox.rs:498` `commit_acl_invalidation`, `:1062`
  `fan_out_acl_invalidation`) but never a `policy_version` event.
- NSD ingest side: the envelope heartbeat handler
  `nsd/crates/nsd-api/src/envelope/handlers/machine_heartbeat.rs:21-24`
  decodes `control::api::HeartbeatRequest` (which carries
  `policy_version` since PLAN-095) and passes only `local_ips` to
  `handlers/heartbeat/core.rs` `record_heartbeat`, which persists only
  `machines.last_heartbeat` + `local_ips`. A reported version is decoded
  and discarded; there is no `reported_policy_version` column anywhere in
  mainline nsd (grep: zero hits).

NSN/NSC echo side (ns-shared + ns):

- The shared heartbeat sender hard-codes `None`:
  `crates/control/src/auth.rs:1189-1196` (`heartbeat_envelope`,
  `policy_version: None` with a PLAN-095 "deferred follow-up" comment).
  The legacy JSON path (`auth.rs:1111` `post_heartbeat_legacy`) has no
  such field at all. Send chain: `crates/control/src/lib.rs:652-655`
  (SSE loop tick) and `:902` (WS loop) → `send_heartbeat` (`lib.rs:1015`)
  → `HeartbeatClient::heartbeat` (`auth.rs:1048`).
- The shared consumer arm is a decode-and-ignore no-op:
  `crates/control/src/lib.rs:1338-1349` ("consumer not wired on this
  control plane"). The arm is currently unreachable in practice because a
  gated NSD emits only to machines that advertise `policy_version.v1`,
  and neither NSN nor NSC does: `ns/crates/nsn/src/main.rs:63-66`
  (`nsn_capabilities` = `[CAPABILITY_NSN_VIRTUAL_LISTENER_V1]`, applied
  at :716/:768/:1058) and `ns/crates/nsc/src/main.rs:2056-2061`
  (`client_capabilities` = `[CAPABILITY_NSC_APPLICATION_UDP_V1]`
  + capture-routes, applied at :1330-1331/:1494). The constant itself
  exists in the shared crate: `crates/common/src/state.rs:50`
  (`CAPABILITY_POLICY_VERSION_V1 = "policy_version.v1"`).

NSGW contrast (loop fully wired, consumer half):

- Capture: `nsgw/crates/nsgw-control/src/config_stream.rs:702-708`
  (`ControlMessage::PolicyVersion` → `record_policy_version`), with
  `:589` suppressing spurious activity refreshes.
- Store: `nsgw/crates/nsgw-control/src/client.rs:351` (field), `:497`
  (init 0), `:504` (`record_policy_version`), `:511`
  (`last_policy_version`, 0 ⇒ `None` ⇒ omitted from the wire).
- Echo: `nsgw/crates/nsgw-control/src/heartbeat.rs:260`
  (`policy_version: self.last_policy_version()`).
- Advertise: `nsgw/crates/nsgw-server/src/runtime/shared.rs:331`
  (`CAPABILITY_POLICY_VERSION_V1`).
- Matches `nsiod-docs/control-plane/06-config-event-model.md:314-331`
  §Divergences ("`policy_version` is consumer-only on mainline").

### (b) Staleness budget — PARTIALLY CONFIRMED; the "default-off" premise is stale for NSN

- Library default is off: `crates/control/src/multi.rs:198`
  (`last_good_max_age: None` in `new_with_recovery`; builder
  `with_last_good_max_age` at :250, doc "Default: unlimited").
  Enforcement lives in `crates/control/src/merge.rs:149-169`
  (`NsdAclSlot::effective` — a `FetchFailed` slot serves the last-good
  cache only while `elapsed <= max_age`, else `Degraded`) with the store
  field at `merge.rs:199`.
- BUT the only production consumer of `MultiControlPlane` (NSN) wires it
  unconditionally: `ns/crates/nsn/src/main.rs:1315-1317`
  `.with_last_good_max_age(Duration::from_secs(config.local_acl.last_good_max_age_secs))`,
  where `LocalAclConfig.last_good_max_age_secs` defaults to **86_400 s
  (24 h)** per PLAN-020 (`crates/common/src/lib.rs:349-350`, default fn
  :367-369). This landed 2026-05-24 (ns `5e0ba32`) and predates the
  review — in the shipped NSN binary the stale-downgrade is default-ON at
  24 h. CLI override: `--acl-last-good-max-age-secs`
  (ns main.rs:255-258, :451-452).
- Config edge: `last_good_max_age_secs = 0` maps to `Duration::ZERO`
  ⇒ instant degrade on the first `FetchFailed`; "unlimited" (`None`) is
  not expressible from NSN config at all.
- The budget clock does start on disconnect: `MultiControlPlane`
  synthesizes `AclPayload::FetchFailed` on transport drop
  (`crates/control/src/multi.rs:329-342`) and on terminal plane failure
  (`:536-544`), so a partitioned NSD's slot enters the cache/degrade
  path rather than pinning `Loaded` forever.
- NSC: the claim does not apply — NSC uses a single `ControlPlane`
  (no merge layer, no `NsdAclSlot`) and drops the ACL channel entirely
  (`ns/crates/nsc/src/main.rs:1486` `_acl_rx`, :1492); there is no NSC
  ACL consumer to bound.
- NSGW analogue: CONFIRMED absent — zero `last_good_max_age` (or any ACL
  age-bound) hits across nsgw crates. The gateway ACL/config consumers
  (`nsgw-control/src/config_stream.rs`,
  `nsgw-control/src/realm_config_snapshot.rs`) keep the last received
  policy with no age bound and no degraded marker: unbounded staleness on
  partition at the gateway pre-deny point.

### (c) Union-of-allows merge — CONFIRMED

- `crates/control/src/merge.rs:240-284` (`NsdConfigStore::merged_acl`):
  every NSD's effective policy contributes rules to a layered union
  (`acl::merge_layered`); module contract at `merge.rs:9-18`. WgConfig
  and ProxyConfig merges are unions too (`merge.rs:38-56`, `:61-93`).
  Documented in
  `nsiod-docs/control-plane/05-transport-selection-fallback.md:145-166`.
- Revocation consequence: deleting an allow on NSD-A while NSD-B still
  serves it keeps access alive until B also revokes. A partitioned B
  serves its last-good cache for up to the staleness budget (24 h on NSN
  by default; unbounded on NSGW); `ExplicitEmpty` contributes nothing but
  never narrows the union (`merge.rs:152`, `:268-270`).
- There is no quorum and no authority precedence: the only narrowing
  layers are the operator-local `deny_scope` (`merge.rs:277-283`) and
  the local ACL layer's front position (`multi.rs:237-246`), both
  node-local and operator-authored, not per-NSD authority.
- Credential-plane contrast (review context): client-CA distribution
  carries a `generation` ack loop (`GatewayClientCaBundle.generation`,
  `crates/control/src/messages.rs:2054-2057`); the ACL plane has no
  equivalent landed-signal.

## PLAN-095 status (emit-side plan)

`PLAN-095` lives in **nsgw** (`nsgw/docs/plan/PLAN-095.md`, status
completed 2026-06-27), not nsd. It delivered the **consumer half** only:

- Landed (verified in code): ns-shared wire types —
  `ControlMessage::PolicyVersion` (`crates/control/src/messages.rs:2065`,
  `event_type` :2113, decode test :2756-2770),
  `HeartbeatRequest.policy_version: Option<u64>` byte-additive
  (`crates/control/src/api.rs:156-161`, byte-parity test :511-547),
  `CAPABILITY_POLICY_VERSION_V1` (`crates/common/src/state.rs:50`);
  nsgw capture/store/echo/advertise (citations under (a) above); the two
  compile-forced no-op arms (ns-shared `lib.rs:1338`, nsd
  `filter.rs:138`).
- Explicitly deferred by PLAN-095 (its "Out of scope" list — this is
  exactly the DR-H4 gap): mainline nsd **emit** of `policy_version`; the
  real `machines.reported_policy_version` **ingest/surface** on mainline
  nsd; NSN/NSC consumer wiring (the lib.rs arm is only a compile stub);
  `nsio-proto` registration + `protocol_version` minor bump;
  per-served-realm gateway version visibility.
- Emit-side reference implementation exists in `nsd-remote@origin/main`
  (contract `docs/api/policy-version-sse-event.md`; capability-gated emit
  in `crates/nsd-distribute/src/notifier.rs`; heartbeat ingest into
  `machines.reported_policy_version`). nsd-remote is a migration repo:
  usable as a porting reference, but must never be cited in as-built
  docs.
- Mainline nsd already has usable emit-side substrate: the per-realm
  counter (`bump_policy_version`), the invalidation/outbox fan-out
  (`sse/outbox.rs:498`, `:1062`), persisted machine capabilities
  (`nsd-db/src/repo/machine.rs:244` `update_capabilities`), and a
  capability-gating precedent in `sse/gating.rs:46-81` (public-edge
  gates). Missing: a dedicated `VariantKind::PolicyVersion` + eligibility
  row, event construction on ACL writes + on subscribe snapshot burst,
  the heartbeat ingest column + persistence, and any convergence/lag
  surface.

## Candidate change set per repo

ns-shared is the live path-dep root for ns/nsd/nsgw: any ns-shared change
forces a same-window rebuild + QA of all three consumers; only
wire/semantic changes force synchronized behavior landings.

- **nsd (emit + ingest)** — all additive:
  - `crates/nsd-api/src/sse/filter.rs` `VariantKind::from_message`
    (:108-138) + the eligibility sets (:216-254): dedicated
    `PolicyVersion` variant kind, capability-gated
    (`machines.capabilities` ∋ `policy_version.v1`, gating in
    `sse/gating.rs`).
  - Event construction: after `bump_policy_version` in
    `handlers/admin/acl/mod.rs` `recompile_and_publish` (:138) /
    the outbox path (`sse/outbox.rs:498`, `:1062`), plus the initial
    snapshot burst on subscribe (`sse/publisher.rs` / `sse/handler.rs`).
  - Ingest: `envelope/handlers/machine_heartbeat.rs:21-24` pass
    `req.policy_version` into `handlers/heartbeat/core.rs`; new
    `machines.reported_policy_version` column via the migration tool
    (`nsd-db/src/repo/machine.rs`). DB migration required.
  - Optional (decision 2B): lagging-subscriber report — admin surface
    comparing `acl_policies.version` vs `machines.reported_policy_version`
    per realm.
- **ns-shared (echo + merge surface)**:
  - Echo (additive behavior; wire bytes change only once a version has
    been seen, `skip_serializing_if` keeps byte parity otherwise):
    replace the no-op arm `crates/control/src/lib.rs:1338-1349` with a
    per-plane last-seen cell (`Arc<AtomicU64>`, mirroring nsgw
    `client.rs:351`), thread the cell into `HeartbeatClient`
    (`auth.rs:170`, ctor :981, `heartbeat_client()` :1450) so
    `heartbeat_envelope` (`auth.rs:1189-1196`) reports
    `(v != 0).then_some(v)`. One cell per `ControlPlane` = naturally
    per-NSD under `MultiControlPlane`.
  - Staleness default (decision 2A): flip `multi.rs:198` `None` →
    `Some(default)` — behavior change for library embedders (NSN is the
    only current one, and it already overrides); alternatively leave the
    library default and treat NSN's 24 h config default as the product
    default. Config-level, not wire-affecting.
  - Merge semantics (decision 3B/3C/3D only): `merge.rs` `merged_acl`
    (+ possibly authority metadata on `AclConfig`/`AclPayload` in
    `messages.rs`). Serde-additive encoding, but a **semantic cascade**
    (all consumers must interpret the new layer in the same window) —
    the only candidate item that is effectively wire-affecting.
- **ns (NSN/NSC senders)** — all additive:
  - NSN: add `CAPABILITY_POLICY_VERSION_V1` to `nsn_capabilities()`
    (`crates/nsn/src/main.rs:63-66`).
  - NSC: add it to `client_capabilities()`
    (`crates/nsc/src/main.rs:2056-2061`) — see open question on whether
    NSC should echo at all (it has no ACL consumer, main.rs:1486).
  - No heartbeat-construction change in this repo: NSN/NSC heartbeats
    are built entirely inside ns-shared (`auth.rs`).
- **nsgw (staleness analogue, decision 2A)** — additive:
  - Age-bound / degraded-marker for kept-last config in
    `nsgw-control/src/config_stream.rs` and
    `nsgw-control/src/realm_config_snapshot.rs`; under 2B this repo has
    no code change (documentation instead).
- **nsiod-docs** (implement/docs phase): update
  `control-plane/06-config-event-model.md` §Divergences (:314-331) and
  the event tables (:181, :254), `control-plane/05` §merge (:145-166) if
  merge semantics change, `_zh` mirrors, and re-pin `_baseline.md`.

## Design decision space (enumerate only — proposal must choose)

1. **Emit + echo completion path**
   - 1A. Full loop: port the nsd-remote emit (capability-gated) to
     mainline nsd + ingest column + NSN/NSC capability advertisement +
     ns-shared echo cell. Pros: convergence becomes observable fleet-wide
     (NSN is the authoritative ACL decision point — the most valuable
     echo); enables any lag/convergence reporting. Cons: 4 repos touched;
     nsd needs a DB migration. Blast radius: additive everywhere; the
     path-dep window covers ns/nsd/nsgw rebuilds anyway.
   - 1B. NSD emit + ingest only (NSGW already echoes). Pros: smallest
     code delta; immediate value for gateways. Cons: NSN/NSC stay
     unobservable — the primary enforcement point still cannot be
     monitored; DR-H4 only partially addressed.
   - 1C. NSN/NSC echo without nsd emit — not viable alone: the gated NSD
     never emits to them, the cell stays 0, heartbeats keep omitting the
     field. Ordering constraint for any plan: emit (or at least the gate
     + event) must land before echo produces values; the additive wire
     types mean the two sides may land in either code order without
     breakage, but observability starts only when both exist.
2. **Staleness budget**
   - 2A. Default-on budget everywhere: keep/ratify the NSN 24 h default
     (`last_good_max_age_secs = 86_400`), optionally mirror it as the
     ns-shared library default, and add an NSGW analogue (age-bound or
     at minimum a `degraded` marker on stale snapshots). Pros: bounded
     revocation latency on partition at every enforcement point;
     symmetric story. Cons: a partition longer than the budget turns
     into fail-closed/degraded (availability loss) — needs an explicit
     product decision per point (gateway public edge degrading is
     user-visible); NSGW needs a new mechanism.
   - 2B. Documented acceptance + lag report: keep behavior as-is
     (NSN 24 h, NSGW unbounded, NSC n/a), document the per-point
     staleness budget table in control-plane/06, and add the NSD-side
     lagging-subscriber report (requires the decision-1 ingest).
     Pros: zero behavior risk; turns the gap into an operator-visible
     signal. Cons: NSGW staleness remains unbounded; report is only as
     good as heartbeat cadence (60 s, `lib.rs:387`).
   - Premise corrections the proposal must incorporate either way: the
     DR "default-off" claim is stale for NSN (on at 24 h since ns
     `5e0ba32`); `0` currently means "instant degrade", not "off";
     "unlimited" is not expressible from NSN config; the only budget
     observability today is the node-local `/api/status` `acl.sources`
     snapshot (`multi.rs:34-39`, `merge.rs:287-318`).
3. **Multi-NSD merge semantics**
   - 3A. Keep union-of-allows, document it as the contract, and lean on
     decisions 1+2 for visibility. Pros: no behavior change; matches the
     model that NSDs are independent authorities (multi-realm/tenant
     fan-in, disjoint-ish rule sets — union exists precisely so one NSD
     cannot silence another's realm); availability-friendly. Cons: the
     DR risk stands — revocation requires all-NSD landing; a compromised
     secondary keeps access alive.
   - 3B. Authority precedence: map each realm to an authoritative NSD
     (config or wire metadata); non-authoritative contributions for that
     realm are advisory/dropped. Pros: single revocation point per
     realm. Cons: needs a realm→NSD authority source of truth on every
     node; semantic cascade through `merged_acl`; risks dropping
     legitimate cross-realm grants; new failure mode when the authority
     is the partitioned one.
   - 3C. Quorum (k-of-n) on allows. Pros: tolerates one compromised
     NSD. Cons: NSDs are not replicas — they serve different realms and
     policies, so quorum over non-replicated sets is ill-defined;
     large availability loss on partition; almost certainly the wrong
     model for this topology.
   - 3D. Deny-wins revocation overlay: revocations distributed as
     explicit deny records that any NSD can carry and that override
     union allows (tombstones). Pros: revocation lands via ANY connected
     NSD, directly closing the stale-secondary hole. Cons: new wire +
     engine semantics (deny entries in `AclPayload`/policy), tombstone
     lifecycle/GC, and the authority question resurfaces for deny
     records themselves.

## Cross-repo worktree set for an implement phase

- WRITTEN (max scope, 1A + 2A): `nsd` (emit + gate + ingest + migration
  + optional lag surface), `ns-shared` (echo cell + tests; optional
  library default flip), `ns` (two capability-list lines), `nsgw`
  (staleness analogue), `nsiod-docs` (06/05 + `_zh` mirrors +
  `_baseline.md` re-pin).
- WRITTEN (min scope, 1B + 2B + 3A): `nsd` + `nsiod-docs` only;
  `ns-shared`/`ns`/`nsgw` untouched.
- REBUILD + QA ONLY: whenever ns-shared changes, `ns`, `nsd`, `nsgw`
  must rebuild against the new path-dep in the same landing window even
  if not written (live-tree landing rule).
- `nsd-remote` / `ns-remote`: read-only porting references; never cited
  in as-built docs, never part of the landing set.

## Open questions for the proposal phase

1. Which combination of the decision space (1A/1B × 2A/2B × 3A–3D)?
   The review's fix direction suggests 1A + (2A or 2B) + 3A-documented,
   but feasibility of each leg is independent.
2. Emit trigger set on mainline nsd: only ACL-write paths
   (`bump_policy_version` callers), or stamped on every projection like
   nsd-remote (idempotent, dedup by value), and does the subscribe-time
   snapshot burst include it?
3. Version scope vs topology: `HeartbeatRequest.policy_version` is a
   single u64. Per-NSD heartbeats make it per-NSD naturally on NSN; is a
   single home-realm value per NSD sufficient (NSGW deliberately scoped
   it home-realm; multi-realm gateways were declared out of scope in
   PLAN-095), and what does an NSN serving one realm from two NSDs
   report to each?
4. Staleness budget values and expressibility: ratify 86_400 s? make
   "unlimited" expressible (today `0` = instant degrade — footgun)? what
   does an NSGW degrade actually do at the public edge (fail-closed vs
   serve-stale-with-alert)?
5. Should NSC advertise/echo at all? It consumes no ACL
   (`_acl_rx` dropped) — an NSC-reported version could imply enforcement
   convergence that NSC does not perform. Report anyway for fleet
   inventory, or exclude NSC and document why?
6. Where does the convergence/lag surface live (admin API, metrics,
   both) and what threshold marks a subscriber "lagging" given the 60 s
   heartbeat cadence?
7. Is the deferred `nsio-proto` `policy_version` registration +
   `protocol_version` minor bump a prerequisite for the mainline emit
   side, or can it trail?
8. Does decision 2A's library-default flip (multi.rs:198) belong in
   ns-shared, or should the default live only in NSN config
   (`LocalAclConfig`) to keep the library policy-free?

## Proposal

Recommended combination: **1A + 2A + 3A**, plus the NSD-side
lagging-subscriber report described under 2B (decision-1's ingest makes
it nearly free, and it is the piece that answers "has revocation X
landed everywhere?" directly). This follows the review's fix direction
on every axis, with one explicit deviation: NSC is excluded from the
echo (question 5). The investigation's premise corrections are
incorporated throughout (NSN's budget is already ON at 24 h; `0` means
instant degrade; "unlimited" is not expressible today).

### Axis 1 — emit/echo scope: 1A (full loop, NSC excluded)

[recommend] Adopt 1A: port the capability-gated `policy_version` emit
from the nsd-remote reference to mainline nsd, ingest the heartbeat
echo into a new `machines.reported_policy_version` column, wire the
ns-shared echo cell, and advertise `policy_version.v1` from NSN — but
not from NSC.

Rationale: NSN is the authoritative ACL decision point; 1B leaves the
one node class that actually enforces policy unobservable, so DR-H4's
core question would stay unanswerable where it matters most. 1C is not
viable alone (a gated NSD never emits to non-advertisers, so the echo
cell would stay 0 forever). Every 1A piece is additive — the wire types
landed in PLAN-095 with byte-parity and decode tests — and the
ns-shared echo cell forces the ns/nsd/nsgw rebuild window anyway, so
1B's smaller footprint buys little. The NSC carve-out is justified
under question 5.

### Axis 2 — staleness budget: 2A (default-on budgets) + lag report

[recommend] Adopt 2A: ratify the shipped NSN default
(`last_good_max_age_secs = 86_400`), keep the ns-shared library
default at `None` (question 8), add an NSGW analogue as an age-bound
degraded marker (default 86_400 s) that serves stale with an alert
rather than failing closed, and document the per-point budget table in
control-plane/06.

Rationale: bounded revocation latency at every enforcement point is
the review's intent, and NSN already ships it (the review's
"default-off" premise is stale — ON at 24 h since ns `5e0ba32`), so 2A
on NSN is ratification, not a behavior change. The NSGW analogue is
new but marker-only: failing closed at the public edge would convert a
>24 h control partition into a data-plane outage for every served
realm — a larger blast radius than the staleness it mitigates, while
NSN's own budget still bounds authoritative enforcement. The residual
risk (flows where NSGW is the only enforcement point keep stale ALLOW
past the budget) is accepted explicitly and surfaced by the degraded
marker; revisit fail-closed once the alert has operational history.
On top of 2A, adopt 2B's lagging-subscriber report (question 6): the
review posed 2A and 2B as alternatives, but with 1A's ingest landed
the report is a small additive surface and the only artifact that
answers the headline question, so take both.

### Axis 3 — merge semantics: 3A (union-of-allows as documented contract)

[recommend] Adopt 3A: keep union-of-allows, document it as the
multi-NSD contract in control-plane/05, and lean on decisions 1+2 for
revocation visibility.

Rationale: the union exists because NSDs are independent authorities
over different realms — one NSD must not be able to silence another's
realm — and it is availability-friendly shipped behavior. 3C (quorum)
is rejected: NSDs are not replicas, so k-of-n over non-replicated rule
sets is ill-defined; the investigation already flags it as the wrong
model. 3B (authority precedence) and 3D (deny-wins overlay) are
out-of-scope alternatives needing their own design cycle: 3B requires
a realm→NSD authority source of truth on every node plus a semantic
cascade through `merged_acl` (the one effectively wire-affecting
candidate), and 3D introduces new wire + engine semantics (deny
records, tombstone lifecycle/GC) with the authority question
resurfacing for the deny records themselves. Neither is needed to
close DR-H4's observability gap; 3D is the most promising future
direction for the revocation-must-land-everywhere hole and should be
raised as a candidate finding for the next design cycle.

### Answers to the open questions

1. **Combination** — [recommend] 1A + 2A + 3A, plus the 2B
   lagging-subscriber report; per-axis justification above.
2. **Emit trigger set** — [recommend] Port the nsd-remote trigger
   model: stamp the current version on every ACL projection with
   dedup-by-value suppression, and include the current version in the
   subscribe-time snapshot burst, rather than hand-picking
   `bump_policy_version` call sites. Projection-stamping is idempotent
   and self-healing (a missed emit converges on the next projection or
   reconnect), it is exactly what the reference implementation ships
   (its rollback flow re-projects and re-emits), and the snapshot-burst
   inclusion is what makes reconnect convergence observable without
   waiting for the next ACL write.
3. **Version scope vs topology** — [recommend] Keep the single `u64`
   with per-NSD-connection scope: one echo cell per `ControlPlane`, so
   an NSN attached to two NSDs reports to each NSD the last version
   seen on that NSD's own connection. Version counters are per-NSD and
   not comparable across NSDs (independent authorities), so each NSD
   evaluates convergence against its own counter and the operator
   aggregates per-NSD reports (question 6). Home-realm scoping stays
   as PLAN-095 shipped it; per-served-realm gateway visibility remains
   deferred.
4. **Budget values / expressibility / NSGW degrade** — [recommend]
   Ratify `86_400` s as the NSN product default; turn
   `last_good_max_age_secs = 0` into a startup configuration error;
   do not make "unlimited" expressible; give NSGW a config max-age
   defaulting to `86_400` s whose expiry marks the snapshot degraded,
   fires a metric + alert/log, and keeps serving stale. Details:
   today `0` silently means "degrade on first `FetchFailed`" — a
   footgun; rejecting it at startup with an explicit error forces a
   deliberate positive value (an operator who truly wants
   instant-degrade sets `1`). "Unlimited" is deliberately not
   expressible because an unlimited knob reintroduces exactly the
   unbounded-staleness hole DR-H4 flags; a large explicit value (e.g.
   `2_592_000` = 30 d) is the escape hatch. NSN budget expiry keeps
   its shipped meaning (slot → `Degraded`, its last-good cache leaves
   the union: fail-closed for that NSD's grants, node-local). At the
   NSGW public edge, fail-closed is explicitly rejected as the default
   degrade behavior — it would turn a long control partition into a
   full outage of every served realm; serve-stale-with-alert bounds
   the risk operationally while NSN bounds it authoritatively.
5. **NSC echo** — [recommend] Exclude NSC: do not add
   `policy_version.v1` to `client_capabilities()`, and document the
   exclusion in control-plane/06. This deliberately narrows the
   review's "extend the echo to NSN/NSC": NSC consumes no ACL
   (`_acl_rx` is dropped, ns `main.rs:1486`), so an NSC-reported
   version would read as enforcement convergence that NSC does not
   perform — polluting the exact signal this design exists to create
   and letting the lag report falsely reassure (or cry wolf) on nodes
   with no enforcement role. Revisit only if NSC gains an ACL
   consumer.
6. **Lag surface + threshold** — [recommend] Build both surfaces on
   nsd: an admin API convergence report (per realm: current
   `acl_policies.version`, each subscriber's
   `reported_policy_version` + heartbeat age, and the lagging list;
   under the existing admin ACL surface) as the primary operator
   answer, plus metrics (per-realm lagging-subscriber count and max
   lag age) for standing alerts. "Lagging" = an advertising subscriber
   whose reported version is below current while the current version
   has been outstanding longer than a 180 s grace — 3× the 60 s
   heartbeat cadence, mirroring the 3×-keepalive convention from the
   companion idle-deadline design; the grace is configurable and its
   coupling to the cadence must be documented. Non-advertising
   subscribers are listed separately as "unobservable", never as
   converged; advertising subscribers that have never reported show as
   "never reported" rather than silently passing.
7. **nsio-proto registration + protocol_version bump** — [recommend]
   Not a code prerequisite; land the registration in the `nsio-proto`
   registry (an external coordination item, not one of this campaign's
   worktrees) in the same window as the nsd emit slice. Per the
   reference contract (Constitution §25), a new SSE event type must be
   registered in `nsio-proto` with a `protocol_version` MINOR bump;
   the change is purely additive so the envelope major and old clients
   are unaffected, and capability gating means nothing is emitted to
   non-advertisers regardless of registry state — hence code may merge
   first. The bump does gate (a) any NSD advertisement of the event in
   `/api/v1/info` (mirroring the reference precedent) and (b) the
   nsiod-docs as-built re-pin declaring `policy_version` a mainline
   protocol member (slice 5 waits for it).
8. **Library default flip** — [recommend] No flip: `multi.rs:198`
   stays `None`; the product default lives only in NSN's
   `LocalAclConfig` (already `86_400` via PLAN-020). This keeps the
   ns-shared library policy-free, avoids a silent behavior change for
   future embedders, keeps one source of truth for the shipped
   default, and shrinks the ns-shared diff to the echo cell alone.
   Document "embedders should set a budget" on
   `with_last_good_max_age` instead.

### Phased implementation plan

Worktree set (written): **nsd, ns-shared, ns, nsgw, nsiod-docs** —
five repos. `nsio-proto` is an external coordination item alongside
slice 1, not a campaign worktree. Because ns-shared is the live
path-dep root, the slice-2 write forces a same-window rebuild + QA of
ns, nsd, and nsgw even though their own slices are small; schedule
slices 1–4 into one landing window to pay that cost once.
`nsd-remote`/`ns-remote` stay read-only porting references and are
never cited in as-built docs.

- **Slice 1 — nsd: emit + gate + ingest + convergence surface**
  (additive; one tool-generated DB migration; no wire change — the
  event type already exists in ns-shared). Files:
  `crates/nsd-api/src/sse/filter.rs` — dedicated
  `VariantKind::PolicyVersion` (:108-138) + eligibility rows
  (:216-254), gated on `machines.capabilities` ∋ `policy_version.v1`
  per the `sse/gating.rs:46-81` precedent; event construction on the
  projection path (`handlers/admin/acl/mod.rs:138`
  `recompile_and_publish`, `sse/outbox.rs:498`/`:1062`) plus the
  subscribe snapshot burst (`sse/publisher.rs`/`sse/handler.rs`), with
  dedup by value; ingest via
  `envelope/handlers/machine_heartbeat.rs:21-24` →
  `handlers/heartbeat/core.rs` → new
  `machines.reported_policy_version` column
  (`nsd-db/src/repo/machine.rs`; migration emitted by the migration
  tool, additive nullable column); convergence report endpoint +
  metrics per question 6.
- **Slice 2 — ns-shared: echo cell** (additive; byte parity until a
  version is seen). Files: `crates/control/src/lib.rs:1338-1349`
  no-op arm → per-plane `Arc<AtomicU64>`; thread the cell through
  `HeartbeatClient` (`auth.rs:170`, ctor :981, `heartbeat_client()`
  :1450) so `heartbeat_envelope` (`auth.rs:1189-1196`) reports
  `(v != 0).then_some(v)`. One cell per `ControlPlane` is naturally
  per-NSD under `MultiControlPlane`. No `multi.rs:198` change
  (question 8).
- **Slice 3 — ns: NSN capability + config validation** (additive; no
  wire). Files: `crates/nsn/src/main.rs:63-66` — add
  `CAPABILITY_POLICY_VERSION_V1` to `nsn_capabilities()`; NSN startup
  validation rejecting `last_good_max_age_secs = 0` where the config
  is wired (`main.rs:1315-1317`; CLI `:255-258`/`:451-452`). NSC
  untouched (question 5).
- **Slice 4 — nsgw: staleness analogue** (additive; no wire). Files:
  `nsgw-control/src/config_stream.rs`,
  `nsgw-control/src/realm_config_snapshot.rs` — last-refresh
  timestamp, max-age (default 86_400 s), degraded marker + metric +
  alert/log on expiry; serving behavior unchanged.
- **Slice 5 — nsiod-docs: contract + budgets + runbook** (docs only;
  after the nsio-proto bump lands). Files:
  `control-plane/06-config-event-model.md` §Divergences (:314-331) +
  event tables (:181, :254) — `policy_version` becomes a mainline
  emitted+echoed event, NSC exclusion documented;
  `control-plane/05-transport-selection-fallback.md` §merge
  (:145-166) — union-of-allows documented as the 3A contract, the
  per-point staleness budget table (NSN 24 h fail-closed-per-slot;
  NSGW 24 h serve-stale-with-alert; NSC n/a), and the "has revocation
  X landed?" runbook; `_zh` mirrors; `_baseline.md` re-pin.

Ordering constraints:

1. Slice 1 lands first: the heartbeat ingest (consumer of the echo)
   must exist before echoes carry values, and the emit side
   immediately lights up convergence for NSGW, which already
   advertises and echoes.
2. Slice 2 strictly before slice 3 — hard constraint: if NSN
   advertises before the echo cell exists, a gated NSD emits to NSN
   while NSN's heartbeat still omits the field, and the lag report
   flags NSN as permanently lagging (false alarm).
3. Slice 4 is independent and may land any time in the window.
4. Slice 5 lands last, after the nsio-proto registration (question 7).
5. The slice-2 ns-shared write triggers the same-window rebuild + QA
   of ns/nsd/nsgw (live-tree landing rule) regardless of their own
   slice content.

All slices are additive; none is wire-affecting in the
byte-compatibility sense (PLAN-095 landed the wire types with byte
parity and decode tests). The only wire-visible delta is behavioral:
heartbeats start carrying `policy_version` once a version has been
seen, which pre-change readers already tolerate.

### Acceptance criteria

- **Slice 1, emit/gate:** an admin ACL write on realm R produces
  exactly one `policy_version` event with the bumped value on a
  subscriber advertising `policy_version.v1` and none on a
  non-advertising subscriber; a reconnecting advertiser receives the
  current version in the snapshot burst with no intervening write;
  re-projection with an unchanged version emits nothing (dedup).
- **Slice 1, ingest/surface:** an envelope heartbeat carrying
  `policy_version: N` persists `machines.reported_policy_version = N`;
  an absent field leaves it NULL; the convergence report lists a
  subscriber as lagging only when it advertises, reports < current,
  and the current version has been outstanding past the grace;
  non-advertisers appear as "unobservable"; metrics agree with the
  report.
- **Slice 2, echo:** after the consumer arm records version N, the
  next heartbeat envelope carries N; before any event is seen the
  field is omitted and the encoding is byte-identical to pre-change
  (extends the existing byte-parity test); under `MultiControlPlane`,
  two planes echo their own versions independently.
- **Slice 3:** NSN's registration advertises `policy_version.v1`
  (visible in `machines.capabilities` on nsd);
  `last_good_max_age_secs = 0` fails startup with an explicit error;
  the 86_400 s default behavior is unchanged.
- **Slice 4:** with the config stream cut and the snapshot age past
  the budget, the degraded marker is set, the metric flips, and the
  alert/log fires while data-plane traffic keeps serving from the
  stale snapshot; reconnect with a fresh snapshot clears the marker.
- **Slice 5:** the divergence table no longer lists `policy_version`
  as consumer-only; the budget table and runbook exist; `_zh` mirrors
  updated; `_baseline.md` re-pinned to the landed commits.
- **End-to-end:** after revoking access to realm R on every NSD
  serving R, the operator opens each such NSD's convergence report
  and reads: realm R at version V, all advertising subscribers
  reported ≥ V within grace ⇒ "landed everywhere observable", with
  non-advertising nodes explicitly enumerated as unobservable
  (upgrade-pending) rather than silently counted as converged. NSGW
  landings are visible the same way (it already echoes); NSC is
  documented as not applicable.

### Risks and mitigations

- **False "all clear" from non-advertising nodes** (capability-gating
  pitfall): old nodes never look lagging because they never advertise.
  Mitigation: the report classifies them "unobservable", never
  "converged", and the end-to-end answer enumerates them.
- **False "lagging" from advertise-before-echo:** prevented by the
  slice-2 → slice-3 ordering; the report additionally distinguishes
  "never reported" from "reported stale" so an out-of-order rollout is
  diagnosable at a glance.
- **Heartbeat-cadence vs grace coupling:** the 180 s grace is 3× the
  60 s cadence; a cadence change silently invalidates the threshold.
  Mitigation: grace configurable, coupling documented next to the
  cadence constant (same pattern as the idle-deadline/keepalive
  coupling note in PLAN-011).
- **Config footgun `0`:** anyone deliberately running `0` (instant
  degrade) fails startup after slice 3. Mitigation: explicit error
  message naming the replacement (`1` for instant-degrade semantics),
  plus a changelog migration note; no silent remapping.
- **NSGW serve-stale residual risk:** where the gateway is the sole
  enforcement point for a flow, stale ALLOW persists past the budget
  (alert-only). Accepted explicitly (question 4) because NSN's budget
  bounds authoritative enforcement and edge fail-closed is the bigger
  hazard; revisit fail-closed once the degraded alert has operational
  history.
- **nsd DB migration:** additive nullable column generated by the
  migration tool; NULL-safe reads keep mixed fleets safe (old nodes
  simply never populate it).
- **A slice ships alone:** every slice degrades to the status quo,
  not to breakage — slice 1 alone lights up NSGW convergence only;
  slice 2 alone is dormant (NSN does not yet advertise); slice 4
  alone is an independent observability win; the only forbidden
  partial state is slice 3 without slice 2 (ordering rule above).
- **ns-shared blast radius:** the echo cell is the only ns-shared
  code change (merge/multi semantics untouched), but the write still
  forces the full ns/nsd/nsgw rebuild + QA window — bundle the
  slices into one landing window and run the consumer QA baseline
  once.

## ActiveForm

Investigating policy-convergence observability (emit/echo/merge)

## Dependencies

- **blocked by**: proposal-phase decision on the option space above.
- **blocks**: the nsd emit/ingest slice, the ns capability slice, the
  nsgw staleness-analogue slice, and the nsiod-docs divergence rewrite
  that an approved proposal would cut.
- **related**: nsgw PLAN-095 (consumer half, completed); ns-shared
  PLAN-020 (layered union merge + last-good cache); nsd-remote TASK-049
  (emit-side reference, migration repo).

## Notes

- 2026-07-03: investigation completed under campaign
  drrem-wsc-20260703 (design-review finding DR-H4). Evidence-only; no
  proposal decisions taken, no source edits anywhere.
- Key premise correction vs the review text: the stale-downgrade is
  default-ON (24 h) in the shipped NSN binary via
  `LocalAclConfig.last_good_max_age_secs` (since ns `5e0ba32`,
  2026-05-24); "default-off" is true only of the raw ns-shared library
  default and of NSGW (no analogue at all).
- 2026-07-03: proposal recorded (1A + 2A + 3A plus the NSD lag report;
  NSC excluded from the echo; all 8 open questions answered); awaiting
  human approval before any implement phase.
