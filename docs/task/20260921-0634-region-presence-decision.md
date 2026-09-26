# 20260921-0634-region-presence-decision Region presence decision

- **status**: completed
- **priority**: P1
- **owner**: (none)
- **createdAt**: 2026-09-21 06:34

## Description

Add a pure region-presence state transition that evaluates authenticated origin events against explicit durable marks, channel state, and capacity. Seal the corresponding fixture family and its inventories.

## ActiveForm

Completed deterministic region-presence selection and sealed fixture coverage.

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Notes

- Investigation: the region frame module already provides presence, retirement, and retained-mark wire values. It has no state-transition decision for origin ownership, revision watermarks, or collision resolution.
- Investigation: fixture loading and release validation use independent manifest metadata, file digests, and per-family case inventories.
- Proposal: add an explicit table, authenticated-stream input, event, channel state, capacity, and effect model. The transition returns a replacement table and ordered effects without I/O or mutable global state.
- Proposal: accept only current-stream revisions above the per-origin scalar high water; retire only an exact GONE session; invalidate an origin on a boot-epoch replacement and require snapshot completion before its new routes become usable.
- Proposal: add a sealed region-presence fixture family and independent loader, release, and refutation inventories.
- Failing test evidence: `higher_generation_stays_selected_when_its_required_channel_is_down` first reported `channel eligibility overrode higher-generation selection`; `same_origin_lower_generation_cannot_replace_the_selected_session` first reported `same-origin lower generation replaced the selected session`; `presence_cannot_route_before_its_generation_mark_is_durable` first reported `presence became eligible before its generation-specific mark was durable`; `presence_capacity_overflow_invalidates_origin_synchronization` first reported `capacity overflow left the origin synchronized after dropping presence`; `stale_callback_cannot_leave_grace_presence_eligible_after_channel_loss` first reported `stale callback left grace-cached presence eligible with data down`; `missing_retirement_revision_cannot_restore_mark_incompatible_eligibility` first reported `retirement error restored eligibility below the durable generation`; `missing_retirement_revision_keeps_refreshed_eligibility_when_local_candidate_loses` first reported `local losing candidate restored stale selected eligibility`.
- Acceptance: selection applies generation, then incarnation, before channel eligibility. Eligibility requires durable MARKS for the selected generation and a live channel pair; member id resolves only equal compatible state. A rejected capacity insertion marks its origin snapshot-required and re-evaluates retained routes. Explicit channel state re-evaluates retained presence before stale-stream rejection. Both local-retirement error paths preserve the eligibility-refreshed pre-event table and its revision high water. Exact GONE retirement, epoch invalidation, successful local supersession effects, and retained durable floors are covered by sealed cases.
- Verification: formatting and warning-denied workspace linting completed without diagnostics. The keynet-proto nextest suite executed 129 tests: 129 passed, 0 skipped, and 0 ignored.
