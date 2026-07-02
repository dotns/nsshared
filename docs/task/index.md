# ns-shared - Task List

> Updated: 2026-07-01

## Usage

Each task is a single line linking to its detail file. All detailed information lives in `docs/task/PREFIX-NNN.md`.

### Format

- [ ] [**PREFIX-001 Short imperative title**](PREFIX-001.md) `P1`

### Status Markers

| Marker | Meaning |
|--------|---------|
| `[ ]`  | Pending |
| `[-]`  | In progress |
| `[x]`  | Completed |
| `[~]`  | Closed / Won't do |

### Priority: P0 (blocking) > P1 (high) > P2 (medium) > P3 (low)

### Rules

- Only update the checkbox marker; never delete the line.
- New tasks append to the end.
- See each `PREFIX-NNN.md` for full details.

---

## Tasks

- [x] [**OBS-001 Add proxy path labels**](OBS-001.md) `P1`
- [x] [**EDGE-001 Define public edge shared contract**](EDGE-001.md) `P0`
- [x] [**EDGE-002 Define gateway certificate distribution contract**](EDGE-002.md) `P0`
- [x] [**DOC-001 Reconcile current docs with implementation**](DOC-001.md) `P1`
- [x] [**EDGE-003 Define gateway-owned backend contract**](EDGE-003.md) `P0`
- [x] [**CAPTURE-001 Define shared route-capture contract**](CAPTURE-001.md) `P0`
- [x] [**CAPTURE-002 Carry config-stream capabilities on stream open**](CAPTURE-002.md) `P0`
- [x] [**CAPTURE-003 Define GatewayExit gateway nft input contract**](CAPTURE-003.md) `P0`
- [x] [**CAPTURE-004 Define exit-node selection and pairing contracts**](CAPTURE-004.md) `P0`
- [x] [**DNS-001 Define canonical internal DNS helpers**](DNS-001.md) `P0`
- [x] [**EGRESS-001 Define WG GatewayEgress control contract**](EGRESS-001.md) `P0`
- [x] [**CTRL-011 Add ordered multi-endpoint control-transport fallback**](CTRL-011.md) `P2`
- [x] [**CTRL-012 Add nsd_default_mode primary-by-transport selector**](CTRL-012.md) `P2`
- [x] [**CTRL-013 Distinct-host control-transport fallback (return winning endpoint)**](CTRL-013.md) `P3`
- [x] [**CTRL-014 nsc pre-control discovery + registration over the fallback list**](CTRL-014.md) `P1`
- [x] [**HYG-001 Commit lockfile for reproducible QA**](HYG-001.md) `P1`
- [x] [**EGRESS-002 Carry GatewayEgress selected owner hint**](EGRESS-002.md) `P0`
- [x] [**EDGE-004 Add public edge upstream TLS policy contract**](EDGE-004.md) `P0`
- [-] [**CTRL-015 Add RouteEntry.aliases wire field for custom service-domain aliases**](CTRL-015.md) `P1`
