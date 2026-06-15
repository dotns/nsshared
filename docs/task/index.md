# ns-shared - Task List

> Updated: 2026-06-15

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
