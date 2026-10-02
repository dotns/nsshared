# ns-shared - Task List

- [x] [**20260924-1228-quick-explicit-relay-pin Remove URI invitations**](20260924-1228-quick-explicit-relay-pin.md)

> Historical Mesh task entries are retained as implementation records. Standalone Mesh removal is tracked in [SH-MESH-003](SH-MESH-003.md).

> Updated: 2026-09-18

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
- [ ] [**CTRL-016 Add config-stream idle read deadline and control-socket TCP keepalive**](CTRL-016.md) `P1`
- [ ] [**CTRL-017 Decide cross-repo stale-policy bound for control-plane loss**](CTRL-017.md) `P1`
- [x] [**USAGE-001 Define gateway.usage_report wire contract**](USAGE-001.md) `P1`
- [x] [**EDGE-005 Add route-level upstream authority wire contract**](EDGE-005.md) `P0`
- [x] [**CTRL-018 Surface typed candidate-report rate limits**](CTRL-018.md) `P1`
- [x] [**CTRL-019 Define causal scoped WG relay roster and lease contract**](CTRL-019.md) `P0`

### V1 WgRelay activation compatibility (ns PLAN-121)

- [x] [**LNK-001 Activate non-future V1 WgRelay leases immediately**](LNK-001.md) `P0`
- [x] [**WSS-001 Own and join framed tunnel child tasks**](WSS-001.md) `P1`

### Gateway build identity reporting

- [~] [**CTRL-020 Add the gateway build identity report contract**](CTRL-020.md) `P1`

### Unified node capability and subnet-route contracts (PLAN-015)

- [-] [**NODE-001 Define unified node capability and subnet-route contracts**](NODE-001.md) `P0`
- [-] [**NODE-002 Give the approved-subnet-route projection a consumer channel**](NODE-002.md) `P0`
- [-] [**NODE-003 Carry the control plane's overlay address assignment to the node**](NODE-003.md) `P0`

### WireGuard plaintext MTU default (ns PLAN-129)

- [x] [**MTU-001 Define the shared WireGuard plaintext MTU default**](MTU-001.md) `P1`

### Control-message address wire form

- [x] [**SHARED-002 Decode address-shaped ControlMessage fields from CBOR**](SHARED-002.md) `P0`

- [x] [**COMPAT-001 Restore relay interoperability with current NS nodes**](COMPAT-001.md) `P0`

- [-] [**SH-MESH-001：定义 Mesh wire 类型与兼容向量**](SH-MESH-001.md) `P1`
- [-] [**SH-MESH-002：实现确定性成员归约与恢复摘要**](SH-MESH-002.md) `P1`

- [x] [**SH-MESH-003 Remove the standalone Mesh shared protocol**](SH-MESH-003.md) `P1`
- [x] [**20260913-0641-consolidate-keynet-feature-branches Consolidate keynet feature branches**](20260913-0641-consolidate-keynet-feature-branches.md) `P0`
- [x] [**20260913-0657-clean-keynet-campaign-worktrees Clean retired keynet worktrees**](20260913-0657-clean-keynet-campaign-worktrees.md) `P1`
- [x] [**20260916 Define the Keynet default context**](20260916-keynet-default-context.md) `P1`
- [ ] [**20260918-0951-keynet-cascaded-relays Keynet cascaded relays: multi-member relay regions**](20260918-0951-keynet-cascaded-relays.md) `P1`
- [x] [**20260921-0309-region-frame-codec Region frame codec**](20260921-0309-region-frame-codec.md) `P1`
- [x] [**20260921-0541-region-marks-join Add region marks join**](20260921-0541-region-marks-join.md) `P1`
- [x] [**20260921-0634-region-presence-decision Add region presence decision**](20260921-0634-region-presence-decision.md) `P1`
- [x] [**20260921-0821-region-snapshot-staging Region snapshot staging and durable-cut evidence**](20260921-0821-region-snapshot-staging.md) `P1`
- [x] [**20260923-2208-quick-pairing Implement relay-addressed quick pairing**](20260923-2208-quick-pairing.md) `P1`
- [x] [**20260925-1655-region-settled-frame Region SETTLED frame**](20260925-1655-region-settled-frame.md) `P1`
- [x] [**20260926-0649-region-snapshot-local-supersession Snapshot completion retires superseded local presence first**](20260926-0649-region-snapshot-local-supersession.md) `P1`
- [x] [**20260927-2148-region-quick-frames Region quick frames and extended region HELLO**](20260927-2148-region-quick-frames.md) `P1`
- [x] [**20260927-2212-region-quick-owner-decision Region quick owner agreement decision**](20260927-2212-region-quick-owner-decision.md) `P1`
- [x] [**20260929-2150-relay-placement-probe-set Add the gateway probe-set projection type**](20260929-2150-relay-placement-probe-set.md) `P2`
- [x] [**20261002-1516-next-workspace-baseline Build the next workspace on the Rust baseline**](20261002-1516-next-workspace-baseline.md) `P1`
- [ ] [**20261002-1516-quick-wire Complete the quick-wire protocol crate**](20261002-1516-quick-wire.md) `P1`
- [ ] [**20261002-1516-quick-vectors Generate the Quick conformance vectors independently**](20261002-1516-quick-vectors.md) `P1`
- [ ] [**20261002-1516-quick-rendezvous Define the quick-rendezvous message types**](20261002-1516-quick-rendezvous.md) `P1`
- [ ] [**20261002-1516-quick-consumers Move nsgw and ns onto the shared Quick crates**](20261002-1516-quick-consumers.md) `P2`
