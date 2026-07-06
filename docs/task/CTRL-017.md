# CTRL-017 Policy-convergence observability (Tier-1 re-scope): heartbeat-age lag report + staleness budget + union documentation

- **status**: review — DESIGN complete, gated on USER approval before implement
- **priority**: P1
- **owner**: unassigned (design revised by campaign drrem-wsc-20260703)
- **createdAt**: 2026-07-03
- **revisedAt**: 2026-07-04
- **revises**: original `proposed` CTRL-017 at `bkd/inqgedgs:docs/task/CTRL-017.md`
  (investigation + proposal recommending **1A + 2A + 3A**). This file replaces
  the **proposal**; the original's INVESTIGATE-phase evidence still stands and
  is cited, not repeated.

## Executive summary

DR-H4 (design-review finding, 2026-07-03, high): the ACL plane has no
"has this policy landed everywhere?" signal, and a revoked ALLOW can survive
on a node that went dark before the revocation propagated.

The original proposal answered this with **1A** — port the mainline-nsd
`policy_version` **emit**, ingest the heartbeat echo into a new
`machines.reported_policy_version` column, wire an ns-shared echo cell, and
advertise `policy_version.v1` from NSN — plus **2A** (staleness budget) and
**3A** (union-of-allows as documented contract).

**USER decision: Tier 1 only.** Drop **1A / `policy_version` emit+echo**
entirely. Rationale: `policy_version` is precise-but-expensive observability
whose main payoff is multi-NSD "connected-but-lagging" detection; a cheaper
**heartbeat-age** lag signal catches the dominant failure — *a node gone or
partitioned since the policy changed* — with **no wire, DB, or nsio-proto
change**; and neither 1A nor Tier-1 actually **closes** the union revocation
hole (that is a separate Tier-3 deny-wins decision, deferred).

Revised target = **Tier-1 lag report + 2A + 3A**:

1. **Tier-1 convergence lag report** (nsd, read-only, EXISTING signals):
   compare each realm's current `acl_policies.version` / `updated_at` against
   each subscriber's `machines.last_heartbeat`. A node that has **not**
   heartbeat since the ACL last changed is flagged *unobserved /
   potentially-unconverged* (never silently "converged"). Explicitly **coarser**
   than `policy_version`: it proves a node was *connected+alive after the
   change*, not that it *applied* the new policy. That coarseness is the
   accepted trade.
2. **2A staleness budget** (kept): ratify the shipped NSN 24 h
   (`86_400 s`) default; add an NSGW analogue — an age-bound **degraded**
   marker + metric/alert that **serves stale rather than failing closed**
   (proposed default); make `last_good_max_age_secs = 0` a startup error.
3. **3A union-of-allows** (kept): document it as the multi-NSD contract; the
   revocation hole becomes **partially observable** via the Tier-1 report but
   is **not fixed** — the deny-wins tombstone fix (3D) is deferred to Tier-3.

Blast radius collapses from **five written repos + a DB migration + a wire/
proto bump** to **nsd (read-only report) + nsgw (degraded marker)**, plus a
~3-line NSN startup guard in `ns`. **ns-shared is untouched** — the item that
forced the whole live-tree path-dep rebuild cascade (the echo cell) is gone,
and the PLAN-095 wire types stay dormant.

This is **DESIGN, gated on USER approval**. One sign-off remains (§6): the
NSGW degrade behavior (serve-stale-with-alert vs fail-closed, with a
recommended per-listener fail-closed opt-in for high-sensitivity public-edge
listeners).

---

## 1. Delta from original (bkd/inqgedgs CTRL-017)

### 1.1 DROPPED — all of axis-1 (1A `policy_version` emit/echo)

Every 1A leg is removed. None of the following is built:

| Dropped item | Original slice | Evidence of what would have changed |
|---|---|---|
| mainline-nsd `policy_version` **emit** (dedicated `VariantKind::PolicyVersion`, eligibility rows, event construction on the projection path, dedup-by-value, subscribe snapshot burst) | Slice 1 | `nsd/crates/nsd-api/src/sse/filter.rs:108-138`, `:216-254`; no-op arm stays at `filter.rs:138` |
| heartbeat **ingest** of `policy_version` + new `machines.reported_policy_version` **column + DB migration** | Slice 1 | `nsd/.../envelope/handlers/machine_heartbeat.rs:21-24`; column never created (grep: zero hits — stays zero) |
| ns-shared **echo cell** (`lib.rs:1338-1349` no-op arm → `Arc<AtomicU64>`, threaded through `HeartbeatClient`) | Slice 2 | `crates/control/src/lib.rs:1338-1349`, `crates/control/src/auth.rs:1189-1196` — the decode-and-ignore / `policy_version: None` stay as-is |
| NSN **`CAPABILITY_POLICY_VERSION_V1` advertisement** | Slice 3 | `ns/crates/nsn/src/main.rs:63-66` unchanged |
| **nsio-proto registration + `protocol_version` minor bump** | Q7 | not performed |

**Consequences of the drop (the point of Tier-1):**

- **ns-shared is untouched.** The echo cell was the only ns-shared write in
  the original; removing it removes the live-tree path-dep landing rule that
  forced a same-window rebuild + QA of ns, nsd, and nsgw. See §4.
- **No DB migration** on nsd (the `reported_policy_version` column is gone).
- **No wire change and no nsio-proto bump.** The PLAN-095 wire types remain
  **defined but dormant**: `ControlMessage::PolicyVersion`
  (`crates/control/src/messages.rs:2065`),
  `HeartbeatRequest.policy_version: Option<u64>` (`crates/control/src/api.rs:156-161`,
  serialized-away by `skip_serializing_if`), and
  `CAPABILITY_POLICY_VERSION_V1` (`crates/common/src/state.rs:50`). Nothing
  reads or emits them on the mainline path after this change; they are left in
  place for a future Tier-2 without re-litigating PLAN-095.
- **NSGW's existing `policy_version` consumer is left in place, not removed,
  and simply never fed.** NSGW already captures/stores/echoes `policy_version`
  (`nsgw/crates/nsgw-control/src/config_stream.rs:708`,
  `client.rs:351/504/511`, `heartbeat.rs:260`) from PLAN-095. Because mainline
  nsd never emits, that path stays dormant (`last_policy_version()` → `0` →
  omitted). We do **not** touch it; ripping it out would be churn outside this
  tier's scope.

### 1.2 CHANGED — the lag report is re-based on heartbeat age (the core substitution)

The original **also** proposed a lagging-subscriber report, but as a cheap
add-on **riding on 1A's ingest**: per realm, compare `acl_policies.version`
against each subscriber's `machines.reported_policy_version` (Q6, Slice 1).

Tier-1 keeps the report as the **primary and only** convergence surface and
**re-bases it on an existing signal**: compare `acl_policies.updated_at`
(when the version last changed) against `machines.last_heartbeat` (when the
node was last demonstrably connected). This substitutes an *applied-version*
comparison with a *node-liveness-since-change* comparison — strictly coarser,
detailed in §2. This is the central design change of the re-scope.

### 1.3 KEPT — 2A and 3A (unchanged in intent)

- **2A** (§3): NSN 24 h ratification, NSGW serve-stale degraded marker,
  `= 0` startup error — unchanged from the original recommendation, **except**
  that per-listener fail-closed is elevated from an answered sub-point to the
  one remaining **open USER sign-off** (§6).
- **3A** (§5): union-of-allows documented as the contract; 3B/3C/3D remain
  out of scope; 3D (deny-wins tombstones) is named as the Tier-3 successor
  that actually closes the hole. The "observable" qualifier is tightened to be
  honest about what heartbeat-age can and cannot see (§5).

---

## 2. Tier-1 convergence lag report (nsd, read-only)

### 2.1 Existing signals — no schema, wire, or proto change

Verified present in mainline nsd (`/workspace/nsiod/nsd` @ `main`):

- **Current version + when it last changed, per realm.** `acl_policies`
  carries `version BIGINT` and `updated_at TIMESTAMPTZ`
  (`crates/nsd-db/migrations/0004_acl.sql`). Every ACL CRUD write calls
  `bump_policy_version` (`crates/nsd-api/src/handlers/admin/acl/mod.rs:115`)
  → `AclPolicyRepo::upsert`, which stamps `updated_at = CURRENT_TIMESTAMP` /
  `now()` (`crates/nsd-db/src/repo/acl/policy.rs:74`, `:100`).
  `AclPolicyRepo::get_current(realm)` (`policy.rs:128`) returns the row with
  both `version` and `updated_at` populated (`:201-202`, `:214-215`). So
  **`updated_at` is the "policy last changed at" timestamp `T_R` — already
  persisted, no new column.**
- **Per-subscriber last connectivity.** `record_heartbeat` sets
  `machines.last_heartbeat = Utc::now()` on every heartbeat
  (`crates/nsd-api/src/handlers/heartbeat/core.rs`). The `machines` row also
  carries `realm`, `lifecycle`, `staled_at`, `capabilities`
  (`crates/nsd-db/src/repo/machine.rs:125-126`).
- **Per-realm subscriber enumeration.**
  `MachineRepo::list_by_realm_including_inactive(realm)`
  (`crates/nsd-db/src/repo/machine.rs:609`) returns every non-deleted machine
  in the realm with `last_heartbeat` + `lifecycle`.

The report is therefore a **pure read** over columns that already exist.

### 2.2 Semantics — the coarse convergence model

Evaluate at query time `now`. For realm `R`: `V_R = acl_policies.version`,
`T_R = acl_policies.updated_at`, `policy_age(R) = now − T_R`. For machine `M`
in `R`: `H_M = machines.last_heartbeat`, `hb_age(M) = now − H_M`.

Why heartbeat-age is a valid (coarse) convergence proxy: an ACL write fans an
`acl_config` invalidation to every **currently-connected** subscriber
(`recompile_and_publish` → `commit_acl_invalidation` / `fan_out_acl_invalidation`),
and a **reconnect** delivers a fresh snapshot that already contains the new
policy. So a heartbeat **after** `T_R` proves `M` was connected+alive after
the change and therefore received the new policy — by push if it stayed
connected, by snapshot if it reconnected.

Per-machine classification w.r.t. `R`'s current policy:

| State | Condition | Meaning |
|---|---|---|
| **observed** (coarse-converged) | `H_M ≥ T_R` | Connected+alive after the change ⇒ received the new policy. **Caveat:** does *not* prove it *fetched+compiled+applied* it — the exact gap `policy_version` would have closed. |
| **settling** (benign) | `H_M < T_R` **and** `policy_age(R) ≤ grace` | Change is fresh; `M` simply has not hit its next heartbeat tick yet. Not alarming. |
| **unobserved** (potentially-unconverged) | `H_M < T_R` **and** `policy_age(R) > grace` | Has **not** heartbeat since the change, past the point a healthy node would have ticked. **May still serve a revoked ALLOW from last-good cache.** Never reported as converged. |

`unobserved` sub-labels (from `lifecycle` / `hb_age`): `never-reported`
(`H_M` null), `dark` (`hb_age` large / `lifecycle = stale`), `flapping`
(recent-ish but still `< T_R` — only transient or clock-skew).

**Honest properties (state these in the docs, §5.1 runbook):**

- A healthy connected node keeps heartbeating, so it advances to `observed`
  within one cadence of any change; past `grace`, only genuinely-dark nodes
  remain `unobserved`. There is **no false "unobserved"** for a node that is
  actually up.
- The only **false "observed"** window is a node that reconnected (advancing
  `H_M` past `T_R`) then died before applying — bounded by the fact that
  fetch+apply is near-synchronous with the reconnect snapshot. This is the
  residual Tier-1↔1A gap and is accepted.
- Any ACL change resets `T_R`, so a revocation immediately re-arms the bar:
  every not-yet-ticked node is `settling`, then after `grace` the still-dark
  ones become `unobserved` — exactly the set that might still serve the
  revoked grant.

### 2.3 Which machines count as subscribers

Tier-1 cannot cleanly tell ACL consumers from non-consumers — that
distinction needed the `policy_version.v1` capability echo we dropped.
`list_by_realm_including_inactive` returns **all** non-deleted realm machines.
Recommended handling:

- Report all realm machines; optionally exclude `machines.type` values known
  to consume no ACL (the `type` column is already selected;
  e.g. NSC drops its ACL channel — `ns/crates/nsc/src/main.rs:1486`).
- Document that the observed/unobserved split is **heartbeat-based, not
  apply-based**, and is conservative: it is a *superset* of "ACL consumers
  that might be stale," so it never under-reports risk.

### 2.4 Report shape — `GET /admin/v1/acl/convergence?realm=X` (ReadOnly)

Hangs off the existing admin ACL surface (`crates/nsd-api/src/handlers/admin/acl/mod.rs`;
siblings under `/admin/v1/acl/*`). Illustrative body:

```json
{
  "realm": "acme",
  "policy_version": 42,
  "policy_changed_at": "2026-07-04T12:00:00Z",
  "policy_age_secs": 3600,
  "grace_secs": 180,
  "heartbeat_cadence_secs": 60,
  "subscribers": { "total": 10, "observed": 8, "settling": 0, "unobserved": 2 },
  "unobserved": [
    { "machine_id": "m-7f…", "lifecycle": "stale", "last_heartbeat": "2026-07-04T09:30:00Z",
      "heartbeat_age_secs": 9000, "label": "dark",
      "note": "no heartbeat since policy change; may serve revoked ALLOW from last-good cache" }
  ],
  "caveat": "convergence is heartbeat-based (connected-since-change), not policy-apply-based"
}
```

### 2.5 Metric shape — nsd `/metrics` (existing `prometheus_client`)

nsd already exposes `Metrics` (`crates/nsd-api/src/metrics.rs`,
`state.rs:182`) at `/metrics` (`lib.rs:91`, encoder at
`handlers/metrics.rs:19`). Add per-realm gauges:

- `nsd_acl_policy_version{realm}` — current `V_R`.
- `nsd_acl_policy_age_seconds{realm}` — `policy_age(R)`.
- `nsd_acl_convergence_unobserved_subscribers{realm}` — count in `unobserved`.
- `nsd_acl_convergence_max_unobserved_age_seconds{realm}` — max `hb_age` over
  `unobserved` (0 when none), for standing alerts.
- *(optional)* `nsd_acl_convergence_subscribers{realm,state}` — full
  observed/settling/unobserved breakdown.

### 2.6 Threshold

- Heartbeat cadence = **60 s** (`crates/control/src/lib.rs:387`).
- **`grace = 3 × cadence = 180 s`** (default, configurable). Absorbs the
  post-change settling window (one missed tick is normal) with margin for
  jitter/retry; mirrors the 3×-keepalive convention. The coupling to the
  60 s cadence must be documented — if the cadence is retuned, `grace`
  follows.
- Alerting fires on `nsd_acl_convergence_unobserved_subscribers > 0` held for
  longer than an operator SLO, and/or
  `nsd_acl_convergence_max_unobserved_age_seconds` beyond a chosen bound.

---

## 3. Staleness budget (2A — kept)

### 3.1 NSN — ratify, do not change behavior

The DR "default-off" premise is **stale**. NSN wires the budget
unconditionally: `ns/crates/nsn/src/main.rs:1315-1316`
`.with_last_good_max_age(Duration::from_secs(config.local_acl.last_good_max_age_secs))`,
and `LocalAclConfig.last_good_max_age_secs` defaults to **86_400 s (24 h)**
(`crates/common/src/lib.rs:336`, `:349-350`, `:367`, PLAN-020). Enforcement:
a `FetchFailed` slot serves last-good only while `elapsed ≤ max_age`, else
`Degraded` (`crates/control/src/merge.rs:149-169`); the budget clock starts on
transport drop / terminal failure (`crates/control/src/multi.rs:329-342`,
`:536-544`). So NSN already bounds revocation latency at 24 h — **2A on NSN is
ratification, not a behavior change.** Keep the value; do not flip the
library default (`multi.rs:198` stays `None`) so ns-shared stays policy-free
and untouched.

### 3.2 NSN — reject `last_good_max_age_secs = 0` at startup

Today `0` maps to `Duration::ZERO` ⇒ instant degrade on the first
`FetchFailed` — a silent footgun; "unlimited" is deliberately **not**
expressible (an unlimited knob reintroduces the exact unbounded-staleness hole
DR-H4 flags; the escape hatch is a large explicit value). Add a ~3-line
startup guard in NSN, immediately before the wiring at
`ns/crates/nsn/src/main.rs:1315`, rejecting `0` with a clear error (NSN
already uses `.context(...)` / bail-style errors, e.g. `main.rs:3852`). This
lives in **NSN startup (`ns`)**, not in `LocalAclConfig` (ns-shared), so
ns-shared stays untouched and no cascade is triggered.

### 3.3 NSGW — new age-bound degraded marker (serves stale)

CONFIRMED absent: zero `last_good_max_age` (or any ACL age-bound) across nsgw
crates. The gateway keeps last-good realm config with no age bound
(`RealmConfigBucket` — `nsgw/crates/nsgw-control/src/realm_config_snapshot.rs:381`;
no timestamp field today), i.e. unbounded staleness on partition at the
pre-deny point. Add, in `realm_config_snapshot.rs` + the refresh driver
`config_stream.rs` (refresh site: `realm_config_snapshot.rs:729`
"refreshed gateway realm config snapshot"):

- a per-realm **last-refreshed-at** timestamp on the bucket/state;
- a **`last_good_max_age`** (default **86_400 s**) checked at serve/refresh;
- on expiry: mark the served snapshot **degraded**, increment a metric, fire
  an alert/log — **and keep serving** (data plane not failed closed by
  default). Use the existing nsgw `prometheus` pattern
  (`IntGaugeVec`/`IntCounterVec`, e.g. `nsgw-wg/src/relay.rs:1579-1596`):
  e.g. `nsgw_realm_config_degraded{realm}` gauge +
  `nsgw_realm_config_age_seconds{realm}`.

Serving behavior below the budget is unchanged. **The default degrade action
is the open sign-off in §6.**

---

## 4. Blast radius

| Repo | Original (1A + 2A + 3A) | Revised (Tier-1 + 2A + 3A) |
|---|---|---|
| **nsd** | emit + gate + **ingest** + **DB migration** + report + metrics | **read-only lag report + metrics** — no emit, no ingest, no migration, no wire |
| **ns-shared** | **echo cell** + `HeartbeatClient` threading → **forces live-tree rebuild cascade** | **UNTOUCHED** — no cascade; PLAN-095 wire types stay dormant |
| **ns** (NSN/NSC) | NSN capability advertisement + `= 0` guard | **`= 0` startup guard only** (~3 lines; no ns-shared, no wire, no NSC change) |
| **nsgw** | staleness degraded marker | staleness degraded marker (**unchanged**) |
| **nsio-proto** | registration + `protocol_version` minor bump | **none** |
| **nsiod-docs** | contract + budgets + runbook (+ re-pin `policy_version` as a protocol member) | contract + budgets + runbook (**reduced** — no protocol-member re-pin) |

**Substantive landings: nsd + nsgw.** The `ns` touch is a ~3-line NSN startup
guard that does not touch ns-shared and forces no rebuild of nsd/nsgw. The
coordinator's "nsd + nsgw only" framing holds for the substantive work and for
the defining reduction — **ns-shared is untouched, so the live-tree path-dep
cascade is avoided**. There is no DB migration, no wire change, and no
nsio-proto bump anywhere in this tier.

---

## 5. Multi-NSD merge (3A — kept, documented)

Union-of-allows is the shipped contract: every NSD's effective policy
contributes rules to a layered union (`crates/control/src/merge.rs:240-284`;
`ExplicitEmpty` contributes nothing but never narrows — `merge.rs:152`,
`:268-270`). It exists because NSDs are independent authorities over different
realms — one NSD must not be able to silence another's realm — and it is
availability-friendly. Document it as the 3A contract in
`nsiod-docs/control-plane/05-transport-selection-fallback.md:145-166`.

**Revocation hole — now partially observable, still not fixed.** Deleting an
allow on NSD-A while NSD-B still serves it keeps access alive until B also
revokes. Be precise about what Tier-1 sees:

- **Node-liveness-since-change (per NSD): observable.** Each NSD's report
  flags its own subscribers that have gone dark since its last ACL change —
  the nodes that may still serve a stale grant from last-good cache. This is
  the dominant, common failure and Tier-1 surfaces it directly.
- **Cross-NSD version skew: observable only by correlation.** A secondary NSD
  that never received the revoke shows a stale-but-internally-consistent
  version; an operator must compare per-NSD reports to notice `V_A ≠ V_B` for
  what should be the same revocation. Tier-1 does not do this correlation for
  you.
- **The union hole itself is not closed.** Revocation still requires landing
  on every NSD. The true fix — **deny-wins revocation tombstones (3D)** that
  any connected NSD can carry to override union allows — needs new wire +
  engine semantics (deny entries in `AclPayload`, tombstone lifecycle/GC) and
  is **deferred to a separate Tier-3 decision**. 3B (authority precedence) and
  3C (quorum) remain rejected/out-of-scope for the reasons in the original
  investigation.

### 5.1 Docs deliverables (nsiod-docs, docs phase)

- `control-plane/06-config-event-model.md`: `policy_version` stays documented
  as **consumer-only / dormant on mainline** (unchanged §Divergences,
  `:314-331`) — the emit is explicitly **not** landing in this tier.
- `control-plane/05-transport-selection-fallback.md`: union-of-allows as the
  3A contract; the per-point **staleness budget table** (NSN 24 h fail-closed
  per-slot; NSGW 24 h serve-stale-with-alert [pending §6]; NSC n/a); the
  **coarse-convergence semantics** (heartbeat-since-change ≠ policy-applied,
  the Tier-1↔`policy_version` gap); and the **"has revocation X landed?"**
  runbook keyed on the §2.4 report.
- `_zh` mirrors; re-pin `_baseline.md`. No `nsio-proto` protocol-member re-pin
  (nothing was registered).

---

## 6. Open decision — the one remaining USER sign-off

**NSGW degrade behavior when the staleness budget (§3.3) expires.**

- **Option A — serve-stale-with-alert (RECOMMENDED default).** On budget
  expiry, mark degraded + metric + alert, **keep serving** the last-good
  config. Rationale: failing closed at the public edge would convert a long
  control-plane partition into a full data-plane outage of *every* served
  realm — a larger blast radius than the staleness it mitigates — while NSN's
  own 24 h budget still bounds authoritative enforcement. The residual risk
  (flows where NSGW is the only enforcement point keep a stale ALLOW past the
  budget) is accepted and made visible by the degraded marker.
- **Option B — fail-closed.** Stop serving on expiry. Rejected as a global
  default (turns partition into outage), but valid for specific
  high-sensitivity listeners.
- **RECOMMENDED middle: per-listener fail-closed opt-in.** Default
  serve-stale-with-alert globally (Option A); add a per-listener
  `fail_closed_on_stale` flag so high-sensitivity **public-edge** listeners
  can opt into Option B. The per-listener config surface already exists
  (`nsgw/crates/nsgw-server/src/config.rs` — distinct listeners incl. public
  ingress, `:519-522`), so this is an additive config field, not a new
  mechanism.

**Requested sign-off:** approve **serve-stale-with-alert default +
per-listener fail-closed opt-in**, or choose global fail-closed / global
serve-stale.

Minor decisions (recommended defaults, not blocking): `grace = 180 s`
(3×60 s), configurable; report enumerates
`list_by_realm_including_inactive` with an optional `type` filter; keep the
NSN `= 0` startup guard in this tier.

---

## 7. Phased implementation plan (on approval)

Written repos: **nsd, nsgw** (substantive) + **ns** (3-line guard) +
**nsiod-docs** (docs). ns-shared untouched → **no live-tree rebuild
cascade**; the three code repos can land independently. `nsd-remote` /
`ns-remote` stay read-only references, never cited in as-built docs.

- **Slice 1 — nsd: convergence lag report + metrics** (read-only; no
  migration, no wire). New `GET /admin/v1/acl/convergence?realm=X` (ReadOnly)
  on `crates/nsd-api/src/handlers/admin/acl/mod.rs`, reading
  `AclPolicyRepo::get_current` (`updated_at` + `version`) and
  `MachineRepo::list_by_realm_including_inactive` (`last_heartbeat`,
  `lifecycle`, `type`); classification per §2.2; `grace` configurable
  (default 180 s). Metrics per §2.5 on the existing `Metrics`/`/metrics`.
- **Slice 2 — nsgw: staleness degraded marker** (additive; no wire). Per-realm
  last-refreshed timestamp + `last_good_max_age` (default 86_400 s) on
  `realm_config_snapshot.rs`; degraded marker + metric + alert/log on expiry;
  serving unchanged. Public-edge per-listener `fail_closed_on_stale` field
  **iff** §6 approves the opt-in.
- **Slice 3 — ns: NSN `= 0` startup guard** (~3 lines; no ns-shared, no wire).
  Reject `last_good_max_age_secs = 0` before `main.rs:1315`.
- **Slice 4 — nsiod-docs** (docs; §5.1). Contract + budget table + coarse-
  convergence semantics + revocation runbook; `_zh` mirrors; `_baseline.md`
  re-pin.

Ordering: slices 1–3 are independent (no shared wire/schema). Slice 4 lands
last. No cross-repo landing-window constraint (ns-shared untouched).

---

## 8. Acceptance criteria

1. **Lag report.** `GET /admin/v1/acl/convergence?realm=X` returns `version`,
   `policy_changed_at`, `policy_age_secs`, `grace_secs`, per-state counts, and
   an `unobserved` list. Given a just-bumped version: a machine with
   `last_heartbeat < updated_at` older than `grace` appears in `unobserved`
   (never `observed`); a machine with `last_heartbeat ≥ updated_at` appears in
   `observed`; within `grace`, a not-yet-ticked machine is `settling`.
2. **Metrics.** `/metrics` exposes the §2.5 gauges with correct per-realm
   values; after every machine heartbeats past a change,
   `nsd_acl_convergence_unobserved_subscribers{realm} = 0`.
3. **No schema/wire/proto change (negative acceptance).** `git diff` touches
   no `migrations*/`, no `crates/control/src/{messages,api}.rs`, no
   `crates/common/src/state.rs`, no nsio-proto, and adds no
   `reported_policy_version` column.
4. **NSGW degraded marker.** With `last_good_max_age` configured, a control
   partition exceeding the budget marks the served realm snapshot degraded,
   increments the metric, fires an alert/log, and **continues serving**
   (unless a listener opted into fail-closed per §6); below the budget, no
   degraded marker.
5. **NSN `= 0` guard.** NSN startup with `last_good_max_age_secs = 0` exits
   with a clear config error; any `≥ 1` starts normally; the 86_400 default is
   unchanged.
6. **Docs.** control-plane/05 + 06 carry the union-of-allows contract, the
   per-point staleness budget table, the coarse-convergence semantics
   (incl. the Tier-1↔`policy_version` gap), and the "has revocation X landed?"
   runbook; `_zh` mirrors updated.

---

## 9. Gate

This is **DESIGN**, gated on **USER approval** before any implement phase.
Approve the §6 sign-off (NSGW degrade behavior) and the Tier-1 re-scope, then
the plan in §7 may proceed. Status: **review**.
