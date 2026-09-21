# 20260921-0634-region-presence-decision Region presence decision

- **status**: completed
- **priority**: P1
- **owner**: implementation-session
- **createdAt**: 2026-09-21 06:34

## Description

Add a pure region-presence state transition that evaluates authenticated origin events against explicit durable marks, channel state, and capacity. Seal the corresponding fixture family and its inventories.

## ActiveForm

Implementing the deterministic region-presence state transition and sealed fixture coverage.

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Notes

- Investigation: the region frame module already provides presence, retirement, and retained-mark wire values. It has no state-transition decision for origin ownership, revision watermarks, or collision resolution.
- Investigation: fixture loading and release validation use independent manifest metadata, file digests, and per-family case inventories.
- Proposal: add an explicit table, authenticated-stream input, event, channel state, capacity, and effect model. The transition returns a replacement table and ordered effects without I/O or mutable global state.
- Proposal: accept only current-stream revisions above the per-origin scalar high water; retire only an exact GONE session; invalidate an origin on a boot-epoch replacement and require snapshot completion before its new routes become usable.
- Proposal: add a sealed region-presence fixture family and independent loader, release, and refutation inventories.
- Failing test evidence: `generation_precedes_incarnation_in_presence_selection` initially failed because `decide_region_presence` and its explicit state model were absent.
- Acceptance: ordering applies generation, then incarnation, then compatible durable marks, and finally member id. Exact GONE retirement, scalar revision high water, stale stream rejection, epoch invalidation, snapshot requirement, grace-channel eligibility, local supersession effects, and retained durable floors are covered by sealed cases.
- Verification: focused presence, release inventory, and refutation inventory tests passed. Formatting, workspace linting with warnings denied, and the keynet-proto nextest suite passed.
