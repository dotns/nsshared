# 20260913-0657-clean-keynet-campaign-worktrees Clean keynet campaign worktrees

- **status**: completed
- **createdAt**: 2026-09-13 06:57
- **approvedAt**: 2026-09-13 06:57
- **relatedTask**: 20260913-0657-clean-keynet-campaign-worktrees

## Context

Feature consolidation is complete in the canonical repositories. The dedicated ns-shared integration clone retains eleven campaign worktrees and thirteen temporary branches. The canonical ns-shared repository retains two redundant recovery branches. All worktrees are clean except ignored Cargo build output. The two refuter branch tips have identical trees to preserved manager commits; their distinct histories are included in the recovery bundle.

## Proposal

Verify a standalone history bundle and preservation inventory. Remove the eleven linked campaign worktrees and fifteen temporary branch refs across the two ns-shared repositories. Switch the three dedicated primary checkouts to feat/keynet while retaining main refs. Verify retained refs, unrelated worktrees and diagram hashes, then complete tracking on the canonical feature branch.

## Risks

Deleting an unpreserved ref or a worktree with uncommitted data would lose work. Check cleanliness, exact branch tips and tree equivalence before removal, and retain the verified bundle. Remove the cleanup session worktree last, running commands from the canonical repository.

## Scope

Campaign cmp-202609130355 Git worktree and branch metadata, disposable Cargo build output, and this task's tracking records. Preserve all main refs and unrelated worktrees. Do not change source, fixtures, approved designs or `/workspace/nsiod/mermaid/keynet`.

## Alternatives

Keeping the retired worktrees would retain unnecessary disk usage and duplicate working copies. The verified history bundle preserves recovery without retaining temporary branches.

## Annotations

Full tracking applies because cleanup spans repositories and removes local Git metadata. The user's explicit cleanup instruction supplies approval. No new campaign dispatch or phase acceptance is implied.

Completed: eleven worktrees and fifteen branch refs removed; all preservation checks passed. No source or build inputs changed, so the previously accepted QA evidence remains applicable.
