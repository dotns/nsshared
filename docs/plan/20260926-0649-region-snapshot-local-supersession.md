# 20260926-0649-region-snapshot-local-supersession Snapshot completion retires superseded local presence first

- **status**: completed
- **createdAt**: 2026-09-26 06:49
- **approvedAt**: 2026-09-26 06:49
- **relatedTask**: 20260926-0649-region-snapshot-local-supersession

## Context

`decide_region_presence` keeps one selected record per owner. When a remote record wins over a local-origin record it emits the local retirement (stop acknowledgments, stop forwarding, drop queued output, mesh-only GONE reason 2) with a caller-supplied local revision, and refuses with `MissingLocalRetirementRevision` without one. `complete_region_snapshot` runs the same selection for staged records (`select_presence`) but overwrites a losing local record silently.

## Proposal

- `RegionSnapshotCompletionInput` gains `local_member_id`.
- `RegionSnapshotEffect` gains `RetireLocalPresence(RegionPresenceSession)`; `RegionSnapshotDisposition` gains `LocalRetirementRequired`.
- During completion, a staged record that the shared selection prefers over an existing record of the local member is collected instead of applied. If any are collected the decision returns the input table and staging unchanged, the collected sessions as `RetireLocalPresence` effects and `LocalRetirementRequired`. The stage stays complete, so the caller retires the sessions through its ordered local publications (which allocate the GONE revisions) and repeats the completion, which then finds no local record to supersede.
- The revision is not supplied to the pure function because the caller allocates local revisions in publication order; a completion-time revision would overtake local events already queued.

## Risks

Additive API change for every constructor of the completion input; the only consumer is the nsgw regional relay, updated in the same change set.

## Scope

- `crates/keynet-proto/src/region.rs`
- `crates/keynet-proto/tests/region_presence.rs` and the tests that construct `RegionSnapshotCompletionInput`
- `docs/changelog.md`, this plan and its task

## Alternatives

Supplying a revision base to completion and emitting GONE effects inline (as the event decision does) was rejected: the local revision must follow already queued local publications. Letting the caller diff tables after completion would move the selection rule out of the shared decision.

## Annotations

(none)
