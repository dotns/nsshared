# ns-shared - Plan Index

- [x] [**Ordinary Node L3 Echo authorization**](20261105-1239-ordinary-node-l3-echo.md)

- [x] [**Public pool roster Network coverage**](20261030-1816-public-pool-roster-coverage.md)

- [x] [**Candidate vector coverage**](20261030-0004-candidate-vector-coverage.md)

- [x] [**Independent service-label input boundaries**](20261030-0006-service-label-boundaries.md)

- [x] [**Exact registration recovery**](20261029-1238-registration-recovery.md)

- [x] [**Candidate release and migration inventory**](20261029-1215-candidate-release-inventory.md)

- [x] [**Separate roster attribution epochs**](20261028-2141-roster-attribution-epoch.md)

- [x] [**M6 floor content**](20261028-2010-m6-floor-content.md)

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
- [~] [**PLAN-011 Control-stream stale-policy detection**](PLAN-011.md) `2026-07-03`
- [x] [**PLAN-012 Public-edge upstream authority wire contract**](PLAN-012.md) `2026-07-10`
- [x] [**PLAN-013 Causal scoped WG relay wire contract**](PLAN-013.md) `2026-07-13`
- [x] [**PLAN-014 Structured framed-WSS tunnel task lifecycle**](PLAN-014.md) `2026-07-25`
- [~] [**PLAN-015 Unified node capability and subnet-route contracts**](PLAN-015.md) `2026-08-16`
- [~] [**PLAN-016：Mesh v1 共享 wire 与确定性状态契约**](PLAN-016.md) `2026-09-07`

- [x] [**PLAN-019 Remove the standalone Mesh shared protocol**](PLAN-019.md) `2026-09-16`
- [x] [**PLAN-017 Keynet-proto wire and derivation primitives for keynet v0.6**](PLAN-017.md) `2026-09-13`
- [x] [**Keynet-proto phase 2 KeyBinding outcome**](../../crates/keynet-proto/docs/plan/phase-2-key-binding.md) `2026-09-13`
- [x] [**20260913-0641-consolidate-keynet-feature-branches Consolidate keynet feature branches**](20260913-0641-consolidate-keynet-feature-branches.md) `2026-09-13`
- [d] [**Keynet approved design archive**](../decisions/keynet/README.md) `2026-09-13`
- [x] [**20260913-0657-clean-keynet-campaign-worktrees Clean retired keynet worktrees**](20260913-0657-clean-keynet-campaign-worktrees.md) `2026-09-13`
- [~] [**20260918-0951-keynet-cascaded-relays Keynet cascaded relays: multi-member relay regions**](20260918-0951-keynet-cascaded-relays.md) `2026-09-18`
- [x] [**20260921-0309-region-frame-codec Region frame codec**](20260921-0309-region-frame-codec.md) `2026-09-21`
- [x] [**20260921-0541-region-marks-join Add region marks join**](20260921-0541-region-marks-join.md) `2026-09-21`
- [x] [**20260921-0634-region-presence-decision Region presence decision**](20260921-0634-region-presence-decision.md) `2026-09-21`
- [x] [**20260921-0821-region-snapshot-staging Region snapshot staging and durable-cut evidence**](20260921-0821-region-snapshot-staging.md) `2026-09-21`
- [x] [**20260923-2208-quick-pairing Relay-addressed quick pairing**](20260923-2208-quick-pairing.md) `2026-09-23`
- [x] [**20260925-1655-region-settled-frame Region SETTLED frame**](20260925-1655-region-settled-frame.md) `2026-09-25`
- [x] [**20260926-0649-region-snapshot-local-supersession Snapshot completion retires superseded local presence first**](20260926-0649-region-snapshot-local-supersession.md) `2026-09-26`
- [x] [**20260927-2148-region-quick-frames Region quick frames and extended region HELLO**](20260927-2148-region-quick-frames.md) `2026-09-27`
- [x] [**20260927-2212-region-quick-owner-decision Region quick owner agreement decision**](20260927-2212-region-quick-owner-decision.md) `2026-09-27`
- [-] [**20261002-1516-ns-shared-rebuild Rebuild ns-shared around a complete Quick protocol**](20261002-1516-ns-shared-rebuild.md) `2026-10-02`
- [x] [**20261003-1400-nsshared-p3-release Complete nsshared for its first release (P3a) and publish**](20261003-1400-nsshared-p3-release.md) `2026-10-03`
- [x] [**20261003-2300-nsshared-v0-2-scope Narrow nsshared to generic protocols and release v0.2.0**](20261003-2300-nsshared-v0-2-scope.md) `2026-10-03`
- [x] [**20261004-0900-nsshared-api-stability Prepare the nsshared API for stability (v0.3.0)**](20261004-0900-nsshared-api-stability.md) `2026-10-04`
- [x] [**20261010-1200-nsshared-maintenance Put nsshared in maintenance after v0.6.0**](20261010-1200-nsshared-maintenance.md) `2026-10-10`
- [x] [**Import the existing M6 service-control contract**](20261018-1204-m6-service-control-import.md) `2026-10-18`
- [x] [**Add scoped workspace self-checks**](20261018-2214-scoped-self-check.md) `2026-10-18`
- [x] [**Define the L8 account payload profile**](20261019-0029-l8-account-payload-profile.md) `2026-10-19`
- [x] [**Prepare the L8 candidate review request**](20261019-0203-l8-candidate-review-request.md) `2026-10-19`
- [x] [**Define enrollment and membership identity**](20261019-1120-enrollment-identity.md) `2026-10-19`
- [x] [**Define the signed participant roster lifecycle**](20261019-1200-participant-roster-lifecycle.md) `2026-10-19`
- [x] [**Define Subnet route selection**](20261019-1214-subnet-selection.md) `2026-10-19`
- [x] [**Define bootstrap discovery and envelope trust**](20261019-1241-bootstrap-envelope-trust.md) `2026-10-19`
- [x] [**Define signed publication events**](20261019-1413-signed-publication-events.md) `2026-10-19`
- [x] [**Fix external WSS listener ownership checks**](20261019-1447-external-wss-listener-ownership.md) `2026-10-19`
- [x] [**20261020-1118-build-input-self-check Scope self-check by build and test inputs**](20261020-1118-build-input-self-check.md)
- [x] [**Share the Node-control codec**](20261020-1230-node-control-codec.md) `2026-10-20`
- [x] [**Define service grants and Node authority**](20261020-1509-grant-authority.md) `2026-10-20`
- [x] [**Define service and relay usage contracts**](20261020-1607-usage-contracts.md) `2026-10-20`
- [x] [**Define complete realm publication payloads**](20261020-1620-realm-publication-payloads.md) `2026-10-20`
- [x] [**Scope self-check by resolved dependency changes**](20261020-1640-resolved-dependency-self-check.md) `2026-10-20`
- [x] [**Define policy and claim canonical values**](20261020-1625-policy-claims.md) `2026-10-20`
- [x] [**Define control exchange contracts**](20261020-1744-control-exchange.md) `2026-10-20`
- [x] [**Define public-edge material and declaration contracts**](20261020-1727-public-edge-contract.md) `2026-10-20`
- [x] [**Define publication subscription requests**](20261020-1839-publication-subscription.md) `2026-10-20`
- [x] [**Complete control report exchanges**](20261020-1848-control-report-exchanges.md) `2026-10-20`
- [x] [**Define confidential authentication configuration**](20261020-1902-confidential-auth.md) `2026-10-20`
- [x] [**Update certificate dependencies**](20261020-2033-update-certificate-dependencies.md) `2026-10-20`
- [x] [**Define publication snapshot poll requests**](20261020-2213-publication-snapshot-request.md) `2026-10-20`
- [x] [**Define canonical realm identity**](20261021-0335-canonical-realm-identity.md) `2026-10-21`
- [x] [**Define source binding and route selection**](20261021-0357-source-selection.md) `2026-10-21`
- [x] [**Protocol-qualified grant identity and expiry renewal**](20261021-0451-protocol-grant-renewal.md) `2026-10-21`
- [x] [**Define participant credentials and directory bindings**](20261021-0447-participant-credentials-directory-bindings.md) `2026-10-21`
- [x] [**Carry signed source authority in control responses**](20261021-1109-source-response-binding.md) `2026-10-21`
- [x] [**Select authentication source scope explicitly**](20261021-1355-authentication-source-scope.md) `2026-10-21`
- [x] [**Define usage and Node-control profile publications**](20261021-2159-profile-publications.md) `2026-10-21`
- [x] [**Encode inner signed publication events**](20261022-0839-publication-event-producer.md) `2026-10-22`
- [x] [**Define ordinary provider Subnet route reports**](20261022-1014-provider-subnet-report.md) `2026-10-22`
- [x] [**Separate Exit grants and client Subnet route views**](20261022-1615-subnet-publication-views.md) `2026-10-22`
- [x] [**Start the mock relay with an owned UDP socket**](20261022-1938-owned-udp-socket.md) `2026-10-22`
- [x] [**Define confidential certificate and client-CA acquisition**](20261022-2227-confidential-material.md) `2026-10-22`
- [x] [**Define the authenticated M6 control carrier**](20261022-2237-service-control-carrier.md) `2026-10-22`
- [x] [**Declare local Node naming**](20261023-0317-node-local-naming.md) `2026-10-23`
- [x] [**Document current echo reply non-emission**](20261023-0324-echo-reply-non-emission.md) `2026-10-23`
- [x] [**Define Node L3 route admission and applied status**](20261023-0450-node-l3-status.md) `2026-10-23`
- [x] [**Update the constant-time utility dependency**](20261023-0918-fix-constant-time-dependency.md) `2026-10-23`
- [x] [**Define publication stream and snapshot delivery**](20261023-0905-publication-delivery.md) `2026-10-23`
- [x] [**Define explicit anonymous public-edge selectors**](20261023-1118-anonymous-public-edge.md) `2026-10-23`
- [x] [**Refuse group labels as policy principals**](20261023-1153-group-label-principals.md) `2026-10-23`
- [x] [**Update the asynchronous I/O dependency**](20261023-1548-fix-async-io-dependency.md) `2026-10-23`
- [x] [**Define protocol-specific public-edge route names**](20261023-1548-public-edge-protocol-names.md) `2026-10-23`
- [x] [**Prepare the immutable candidate handoff**](20261024-1115-candidate-handoff.md) `2026-10-24`
- [x] [**Define provider mapping eligibility snapshots**](20261024-1655-provider-mapping-eligibility.md) `2026-10-24`
- [x] [**Record review delivery and registration lifecycle placeholders**](20261025-0157-review-request-delivery.md) `2026-10-25`
- [x] [**20261025-0802-nsshared-restructure Restructure the shared crates and apply the review revisions**](20261025-0802-nsshared-restructure.md) `2026-10-25`
