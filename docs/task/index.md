# ns-shared - Task List

- [x] [**Dedicated sccache directory in CI**](20261108-0024-dedicated-sccache-directory.md)

- [x] [**Release-ready contract inventory**](20261106-2358-release-ready-contract-inventory.md)

- [x] [**Service authority and scope refusals**](20261105-1804-service-error-refusals.md)

- [x] [**Shared contract upstream synchronization**](20261105-1519-shared-contract-upstream-sync.md)

- [x] [**Captured authentication conditions**](20261105-1444-captured-authentication-condition.md)

- [x] [**Default Exit floor encoding**](20261105-1250-default-exit-floor.md)

- [x] [**Ordinary Node L3 Echo authorization**](20261105-1239-ordinary-node-l3-echo.md)

- [x] [**Public pool roster Network coverage**](20261030-1816-public-pool-roster-coverage.md)

- [x] [**Candidate vector coverage**](20261030-0004-candidate-vector-coverage.md)

- [x] [**Independent service-label input boundaries**](20261030-0006-service-label-boundaries.md)

- [x] [**Exact registration recovery**](20261029-1238-registration-recovery.md)

- [x] [**Candidate release and migration inventory**](20261029-1215-candidate-release-inventory.md)

- [x] [**Separate roster attribution epochs**](20261028-2141-roster-attribution-epoch.md)

- [x] [**M6 floor content**](20261028-2010-m6-floor-content.md)

- [x] [**Preserve appended documentation entries**](20261028-merge-documentation-entries.md)

- [x] [**Fenced gateway reports**](20261028-1442-fenced-gateway-report.md)

- [x] [**Participant custody generation**](20261028-1156-participant-custody-generation.md)

- [x] [**Shared Node posture contract**](20261028-0826-node-posture.md)

- [x] [**Enrollment review answers**](20261028-0421-enrollment-review-answers.md)

- [x] [**Node heartbeat observations**](20261028-0309-node-heartbeat-observations.md)

- [x] [**Discovery representation selector**](20261028-0318-discovery-media-type.md)

- [x] [**Snapshot admission history**](20261028-0131-snapshot-admission-history.md)

- [x] [**Ordinary Node liveness**](20261028-0104-node-liveness.md)

- [x] [**Merge CI cache history**](20261028-0013-merge-ci-cache-history.md)

- [x] [**Retention seal and acknowledgement**](20261027-2313-retention-seal.md)

- [x] [**Account adoption evidence**](20261027-2017-account-adoption-evidence.md)

- [x] [**Merge release history**](20261027-1909-merge-release-history.md)

- [x] [**20260924-1228-quick-explicit-relay-pin Remove URI invitations**](20260924-1228-quick-explicit-relay-pin.md)

> Historical Mesh task entries are retained as implementation records. Standalone Mesh removal is tracked in [SH-MESH-003](SH-MESH-003.md).

> Updated: 2026-10-27

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
- [~] [**CTRL-015 Add RouteEntry.aliases wire field for custom service-domain aliases**](CTRL-015.md) `P1`
- [~] [**CTRL-016 Add config-stream idle read deadline and control-socket TCP keepalive**](CTRL-016.md) `P1`
- [~] [**CTRL-017 Decide cross-repo stale-policy bound for control-plane loss**](CTRL-017.md) `P1`
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

- [~] [**NODE-001 Define unified node capability and subnet-route contracts**](NODE-001.md) `P0`
- [~] [**NODE-002 Give the approved-subnet-route projection a consumer channel**](NODE-002.md) `P0`
- [~] [**NODE-003 Carry the control plane's overlay address assignment to the node**](NODE-003.md) `P0`

### WireGuard plaintext MTU default (ns PLAN-129)

- [x] [**MTU-001 Define the shared WireGuard plaintext MTU default**](MTU-001.md) `P1`

### Control-message address wire form

- [x] [**SHARED-002 Decode address-shaped ControlMessage fields from CBOR**](SHARED-002.md) `P0`

- [x] [**COMPAT-001 Restore relay interoperability with current NS nodes**](COMPAT-001.md) `P0`

- [~] [**SH-MESH-001：定义 Mesh wire 类型与兼容向量**](SH-MESH-001.md) `P1`
- [~] [**SH-MESH-002：实现确定性成员归约与恢复摘要**](SH-MESH-002.md) `P1`

- [x] [**SH-MESH-003 Remove the standalone Mesh shared protocol**](SH-MESH-003.md) `P1`
- [x] [**20260913-0641-consolidate-keynet-feature-branches Consolidate keynet feature branches**](20260913-0641-consolidate-keynet-feature-branches.md) `P0`
- [x] [**20260913-0657-clean-keynet-campaign-worktrees Clean retired keynet worktrees**](20260913-0657-clean-keynet-campaign-worktrees.md) `P1`
- [x] [**20260916 Define the Keynet default context**](20260916-keynet-default-context.md) `P1`
- [~] [**20260918-0951-keynet-cascaded-relays Keynet cascaded relays: multi-member relay regions**](20260918-0951-keynet-cascaded-relays.md) `P1`
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
- [x] [**20261002-1516-quick-wire Build the ns-wire protocol crate**](20261002-1516-quick-wire.md) `P1`
- [x] [**20261002-1516-quick-vectors Generate the Quick conformance vectors independently**](20261002-1516-quick-vectors.md) `P1`
- [x] [**20261002-1516-quick-rendezvous Define the quick-rendezvous message types**](20261002-1516-quick-rendezvous.md) `P1`
- [ ] [**20261002-1516-quick-consumers Move nsgw and ns onto the shared Quick crates**](20261002-1516-quick-consumers.md) `P2`
- [x] [**20261003-2200-shared-scope-trim Remove relay-internal region protocol and the transfer mapping**](20261003-2200-shared-scope-trim.md) `P1`
- [x] [**Import the existing M6 service-control contract**](20261018-1204-m6-service-control-import.md) `P1`
- [x] [**Add scoped workspace self-checks**](20261018-2214-scoped-self-check.md) `P1`
- [x] [**Define the L8 account payload profile**](20261019-0029-l8-account-payload-profile.md) `P1`
- [x] [**Prepare the L8 candidate review request**](20261019-0203-l8-candidate-review-request.md) `P1`
- [x] [**Define enrollment and membership identity**](20261019-1120-enrollment-identity.md) `P1`
- [x] [**Define the signed participant roster lifecycle**](20261019-1200-participant-roster-lifecycle.md) `P1`
- [x] [**Define Subnet route selection**](20261019-1214-subnet-selection.md) `P1`
- [x] [**Define bootstrap discovery and envelope trust**](20261019-1241-bootstrap-envelope-trust.md) `P1`
- [x] [**Define signed publication events**](20261019-1413-signed-publication-events.md) `P1`
- [x] [**Fix external WSS listener ownership checks**](20261019-1447-external-wss-listener-ownership.md) `P1`
- [x] [**20261020-1118-build-input-self-check Scope self-check by build and test inputs**](20261020-1118-build-input-self-check.md)
- [x] [**Share the Node-control codec**](20261020-1230-node-control-codec.md) `P1`
- [x] [**Define service grants and Node authority**](20261020-1509-grant-authority.md) `P1`
- [x] [**Define service and relay usage contracts**](20261020-1607-usage-contracts.md) `P1`
- [x] [**Define complete realm publication payloads**](20261020-1620-realm-publication-payloads.md) `P1`
- [x] [**Scope self-check by resolved dependency changes**](20261020-1640-resolved-dependency-self-check.md) `P1`
- [x] [**Define policy and claim canonical values**](20261020-1625-policy-claims.md) `P1`
- [x] [**Define control exchange contracts**](20261020-1744-control-exchange.md) `P1`
- [x] [**Define public-edge material and declaration contracts**](20261020-1727-public-edge-contract.md) `P1`
- [x] [**Define publication subscription requests**](20261020-1839-publication-subscription.md) `P1`
- [x] [**Complete control report exchanges**](20261020-1848-control-report-exchanges.md) `P1`
- [x] [**Define confidential authentication configuration**](20261020-1902-confidential-auth.md) `P1`
- [x] [**Update certificate dependencies**](20261020-2033-update-certificate-dependencies.md) `P1`
- [x] [**Define publication snapshot poll requests**](20261020-2213-publication-snapshot-request.md) `P1`
- [x] [**Define canonical realm identity**](20261021-0335-canonical-realm-identity.md) `P1`
- [x] [**Define source binding and route selection**](20261021-0357-source-selection.md) `P1`
- [x] [**Protocol-qualified grant identity and expiry renewal**](20261021-0451-protocol-grant-renewal.md) `P1`
- [x] [**Define participant credentials and directory bindings**](20261021-0447-participant-credentials-directory-bindings.md) `P1`
- [x] [**Carry signed source authority in control responses**](20261021-1109-source-response-binding.md) `P1`
- [x] [**Select authentication source scope explicitly**](20261021-1355-authentication-source-scope.md) `P1`
- [x] [**Define usage and Node-control profile publications**](20261021-2159-profile-publications.md) `P1`
- [x] [**Encode inner signed publication events**](20261022-0839-publication-event-producer.md) `P1`
- [x] [**Define ordinary provider Subnet route reports**](20261022-1014-provider-subnet-report.md) `P1`
- [x] [**Separate Exit grants and client Subnet route views**](20261022-1615-subnet-publication-views.md) `P1`
- [x] [**Start the mock relay with an owned UDP socket**](20261022-1938-owned-udp-socket.md) `P1`
- [x] [**Define confidential certificate and client-CA acquisition**](20261022-2227-confidential-material.md) `P1`
- [x] [**Define the authenticated M6 control carrier**](20261022-2237-service-control-carrier.md) `P1`
- [x] [**Declare local Node naming**](20261023-0317-node-local-naming.md) `P1`
- [x] [**Document current echo reply non-emission**](20261023-0324-echo-reply-non-emission.md) `P1`
- [x] [**Define Node L3 route admission and applied status**](20261023-0450-node-l3-status.md) `P1`
- [x] [**Update the constant-time utility dependency**](20261023-0918-fix-constant-time-dependency.md) `P1`
- [x] [**Define publication stream and snapshot delivery**](20261023-0905-publication-delivery.md) `P1`
- [x] [**Define explicit anonymous public-edge selectors**](20261023-1118-anonymous-public-edge.md) `P1`
- [x] [**Refuse group labels as policy principals**](20261023-1153-group-label-principals.md) `P1`
- [x] [**Update the asynchronous I/O dependency**](20261023-1548-fix-async-io-dependency.md) `P1`
- [x] [**Define protocol-specific public-edge route names**](20261023-1548-public-edge-protocol-names.md) `P1`
- [x] [**Prepare the immutable candidate handoff**](20261024-1115-candidate-handoff.md) `P1`
- [x] [**Define provider mapping eligibility snapshots**](20261024-1655-provider-mapping-eligibility.md) `P1`
- [x] [**Record review delivery and registration lifecycle placeholders**](20261025-0157-review-request-delivery.md) `P1`
- [x] [**20261025-0802-nsshared-restructure Restructure the shared crates and apply the review revisions**](20261025-0802-nsshared-restructure.md) `P1`

- [x] [**20261027-1938-ci-sccache Use the runner shared compiler cache**](20261027-1938-ci-sccache.md) `P1`

- [-] [**20261106-1356-gateway-public-address-contract Report public ingress host independently of WG transport**](20261106-1356-gateway-public-address-contract.md) `P1`

- [x] [**20261107-0206-release-next Prepare the next release**](20261107-0206-release-next.md) `P1`

- [x] [**20261107-0213-stable-account-release Release the unconditional account API**](20261107-0213-stable-account-release.md) `P1`

- [x] [**20261107-1726-exit-readiness-contract Define provider-confirmed Exit observations**](20261107-1726-exit-readiness-contract.md) `P1`

- [x] [**20261107-1808-exit-publication-validation Validate Exit observations at publication acceptance**](20261107-1808-exit-publication-validation.md) `P1`

- [x] [**20261108-1300-mailbox-reply-capacity Refuse mailbox writes that make complete replies unreadable**](20261108-1300-mailbox-reply-capacity.md) `P1`
