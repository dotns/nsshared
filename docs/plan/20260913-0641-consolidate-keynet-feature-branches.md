# 20260913-0641-consolidate-keynet-feature-branches Consolidate keynet feature branches

- **status**: implementing
- **createdAt**: 2026-09-13 06:41
- **approvedAt**: 2026-09-13 06:41
- **relatedTask**: 20260913-0641-consolidate-keynet-feature-branches

## Context

The dedicated ns-shared integration clone accumulated phase 1, paused phase 2
rework, and project decision records on local campaign branches while canonical
repositories use feat/keynet as the intended preservation branch. Canonical
nsgw and ns-remote have no keynet implementation delta. The documentation
repository already has its independent keynet design history on feat/keynet.

## Proposal

Transfer the exact paused ns-shared manager tree and final project decision
archive to canonical ns-shared/feat/keynet through local object preservation.
Add PMA tracking on that branch. Preserve design diagrams and original proposals
on docs/feat/keynet without changing the authority digest or applying pending
relay text. Create matching local feature refs in dedicated clones, then restore
only the dedicated ns-shared main with reverse-order additive revert commits.

## Risks

Phase 2 has not passed review and must remain marked as paused rework. The
documentation archive and phase tracking both append to the plan index, so their
merge needs an explicit all-records resolution. Main restoration must preserve
unrelated history and must not use reset or branch deletion.

## Scope

Canonical ns-shared, nsgw, ns-remote, and docs feature branches; dedicated
keynet clone refs; local preservation bundle; additive reverts on the dedicated
ns-shared main only.

## Alternatives

Keeping the work only in campaign branches leaves the intended feature branches
without the paused work and keeps main as an implicit integration branch.
