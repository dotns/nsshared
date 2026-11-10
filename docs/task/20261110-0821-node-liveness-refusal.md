# 20261110-0821-node-liveness-refusal Define typed Node liveness refusal receipts

- **status**: in_progress
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
