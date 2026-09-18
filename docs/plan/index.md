# ns-shared - Plan Index

> Historical Mesh plan entries are retained as implementation records. Standalone Mesh removal is tracked in [PLAN-019](PLAN-019.md).

> Updated: 2026-09-18

## Usage

Each plan is a single line linking to its detail file. All detailed information lives in `docs/plan/PLAN-NNN.md`.

### Format

- [ ] [**PLAN-001 Short plan title**](PLAN-001.md) `YYYY-MM-DD`

### Status Markers

| Marker | Meaning |
|--------|---------|
| `[ ]`  | Draft / Pending review |
| `[-]`  | Approved / Implementing |
| `[x]`  | Completed |
| `[~]`  | Rejected / Abandoned |
| `[d]`  | Deleted detail file; index entry retained |

### Rules

- Only update the checkbox marker; never delete the line.
- New plans append to the end.
- See each `PLAN-NNN.md` for full details.

---

## Plans

- [x] [**PLAN-001 Proxy OTel path label**](PLAN-001.md) `2026-06-13`
- [x] [**PLAN-002 Public edge contract: gateway_http_config / gateway_l4_map (nsgw PLAN-066 S1)**](PLAN-002.md) `2026-06-13`
- [x] [**PLAN-003 Gateway certificate distribution contract (nsgw PLAN-071 S1)**](PLAN-003.md) `2026-06-14`
- [x] [**PLAN-004 Reconcile current docs with implementation**](PLAN-004.md) `2026-06-15`
- [x] [**PLAN-005 Shared route-capture contract**](PLAN-005.md) `2026-06-15`
- [x] [**PLAN-006 Config-stream capability transport**](PLAN-006.md) `2026-06-15`
- [x] [**PLAN-007 Canonical internal DNS helpers**](PLAN-007.md) `2026-06-17`
- [x] [**PLAN-008 WG GatewayEgress control contract**](PLAN-008.md) `2026-06-17`
- [x] [**PLAN-009 Multi-endpoint control-transport fallback**](PLAN-009.md) `implementing`
- [x] [**PLAN-010 Reproducible ns-shared QA lockfile**](PLAN-010.md) `2026-06-27`
- [ ] [**PLAN-011 Control-stream stale-policy detection**](PLAN-011.md) `2026-07-03`
- [x] [**PLAN-012 Public-edge upstream authority wire contract**](PLAN-012.md) `2026-07-10`
- [x] [**PLAN-013 Causal scoped WG relay wire contract**](PLAN-013.md) `2026-07-13`
- [x] [**PLAN-014 Structured framed-WSS tunnel task lifecycle**](PLAN-014.md) `2026-07-25`
- [-] [**PLAN-015 Unified node capability and subnet-route contracts**](PLAN-015.md) `2026-08-16`
- [-] [**PLAN-016：Mesh v1 共享 wire 与确定性状态契约**](PLAN-016.md) `2026-09-07`

- [x] [**PLAN-019 Remove the standalone Mesh shared protocol**](PLAN-019.md) `2026-09-16`
- [x] [**PLAN-017 Keynet-proto wire and derivation primitives for keynet v0.6**](PLAN-017.md) `2026-09-13`
- [x] [**Keynet-proto phase 2 KeyBinding outcome**](../../crates/keynet-proto/docs/plan/phase-2-key-binding.md) `2026-09-13`
- [x] [**20260913-0641-consolidate-keynet-feature-branches Consolidate keynet feature branches**](20260913-0641-consolidate-keynet-feature-branches.md) `2026-09-13`
- [d] [**Keynet approved design archive**](../decisions/keynet/README.md) `2026-09-13`
- [x] [**20260913-0657-clean-keynet-campaign-worktrees Clean retired keynet worktrees**](20260913-0657-clean-keynet-campaign-worktrees.md) `2026-09-13`
- [-] [**20260918-0951-keynet-cascaded-relays Keynet cascaded relays: multi-member relay regions**](20260918-0951-keynet-cascaded-relays.md) `2026-09-18`
