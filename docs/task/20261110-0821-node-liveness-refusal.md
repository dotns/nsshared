# 20261110-0821-node-liveness-refusal Define typed Node liveness refusal receipts

- **status**: completed
- **priority**: P1
- **owner**: runtime-fence/0naltmjx
- **createdAt**: 2026-11-10 08:21 UTC

## Description

Implement the approved signed and correlated heartbeat/posture refusal contract on main f76374fd. Keep existing success, envelope, M6 and fixture bytes unchanged. Add exact independent vectors, strict codec/correlation tests, specification and 0.11.0 release metadata. Deliver a pull request without merging or tagging.

## ActiveForm

Implementing and verifying Node liveness refusal receipts.

## Dependencies

- **blocked by**: (none; owner approved on 2026-11-10 08:30 UTC)
- **blocks**: consumer adoption in NSD and Node

## Notes

- Full tier. Adopted plan: [Node liveness refusal contract](../plan/20261110-0803-node-liveness-refusal-contract.md).
- Repository has no tracked AGENTS.md or CLAUDE.md; workspace instructions and existing unconditional account API apply. No source checkout changes.

- RED: the focused refusal integration test failed to compile against main because the new public types and context validator did not exist (exit 101).
- GREEN: the same focused target passed all 3 tests, covering 10 legal payloads and 10 independent signed responses plus malformed and correlation refusals.
- All 53 pre-existing tracked fixtures are byte-identical to main after independent regeneration. Account is unconditional; no feature flag is available or added.

- Baseline alignment after merge is recorded as tk nsdoc #1164. No feature-branch baseline pin is published.

- IMPROVE: added full-width u64 fence/ID and zero-pending-ID coverage; clarified shared NodeReportError docs for request and response endpoint checks. Existing runtime validation and bytes are unchanged.
- Read-only consumer audit at ns bb2d61483: transport/raw.rs maps report 401/403 to Unauthorized and other non-2xx statuses including 409 to ServerError. service_control.rs retains shared UnaryReply/ServiceControlError and exact M6 pending correlation; auth/client/service_control.rs keeps outcome-unknown RecoveryRequired distinct. No M6 enum/code or adapter behavior changes are needed in this shared delivery. NSD/Node runtime adoption remains in their approved plans.

- Final verification: `CARGO_NET_OFFLINE=true just qa` passed all recipes, using the existing registry cache without disabling gates. The final run compares against v0.10.0: 630 nextest tests passed, 71 script tests passed, doctests passed (3 passed, 1 existing ignored), rustdoc, fmt, Clippy, deny, shear, typos, vectors and all workspace semver/facade checks passed.
- Focused acceptance: `cargo test -p nsshared-control --test account control:: --locked` passed 52 tests (including all 4 refusal tests). The independent producer supplies 54 records: 10 valid payloads, 10 signed responses and 34 invalid payloads. All 53 existing fixture files remain identical to f76374fd.
- Additional compatibility diagnostic: `cargo semver-checks --package nsshared-control --baseline-rev v0.10.0 --default-features --release-type patch` passed 229 checks (31 inapplicable skips). The API is additive; the prepared 0.11.0 follows the delivery's requested minor version. No release tag is created.
- Full diff and security review passed with no findings. Consumer runtime/lab checks are outside this shared contract delivery. Durable verification evidence: `/workspace/warehouse/runtime-fence-nsshared/`.

- complete: Signed refusal codecs, vectors and specification delivered; full just qa and focused/API checks passed.
