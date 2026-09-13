# 20260913-0657-clean-keynet-campaign-worktrees Clean keynet campaign worktrees

- **status**: completed
- **priority**: P1
- **owner**: keynet-cleanup/20260913
- **createdAt**: 2026-09-13 06:57

## Description

Remove the retired keynet campaign worktrees and temporary branches after preserving their history. Keep feat/keynet, every main ref, unrelated branches and worktrees, and the canonical diagrams unchanged. Verify the exact cleanup inventory and record the result.

## ActiveForm

Cleaning retired keynet campaign branches and worktrees.

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Notes

The user explicitly requested this cleanup after feature consolidation. No campaign execution is active except this cleanup. Recovery inventory and a verified standalone Git bundle are stored in `/workspace/nsiod/ns-shared/tmp/20260913-0657-clean-keynet-campaign-worktrees`. Source files and protocol artifacts are outside this task.

Removed eleven campaign worktrees and fifteen temporary branch refs. Preserved all main refs, every unrelated branch and worktree, the seven feature refs, and all fourteen canonical diagram hashes. The two non-ancestor refuter tips were tree-equivalent to preserved manager commits and remain recoverable from the bundle. All dedicated primary checkouts now use feat/keynet. No protocol or source changes were made.

- complete: Verified branch inventory, worktree removal, retained refs, baseline main tree, diagram hashes and recovery bundle.
