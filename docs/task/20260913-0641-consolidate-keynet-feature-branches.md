# 20260913-0641-consolidate-keynet-feature-branches Consolidate keynet feature branches

- **status**: completed
- **priority**: P0
- **owner**: operator/fcpkehpe-migration
- **createdAt**: 2026-09-13 06:41

## Description

Preserve the paused keynet protocol work on the canonical feature branches,
restore the dedicated ns-shared integration main with additive revert history,
and retain the approved design records, diagrams, and original proposals in
their appropriate repositories. Phase 2 remains unreviewed rework.

## ActiveForm

Consolidating paused keynet feature branches and restoring the integration main.

## Dependencies

- **blocked by**: (none)
- **blocks**: future keynet campaign resumption

## Notes

The migration uses the verified preservation map from campaign cmp-202609130355.
No remote fetch, push, or history rewrite is permitted.

- complete: Canonical feature preservation, additive main restoration, and migration QA completed; Phase 2 remains paused rework.
- 2026-09-13: Corrected the maintained diagram location to
  `/workspace/nsiod/mermaid/keynet/`. The fourteen duplicate copies were removed
  from docs/feat/keynet in commit `7da63a0`; its README now points to that source.
