# ns-shared - Plan Index

> Updated: 2026-07-10

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
