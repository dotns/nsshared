# 20260926-0649-region-snapshot-local-supersession Snapshot completion retires superseded local presence first

- **status**: completed
- **priority**: P1
- **owner**: implementer/presence-supersession
- **createdAt**: 2026-09-26 06:49

## Description

`complete_region_snapshot` replaces a local-origin presence record with a winning staged record from the snapshot origin without the local retirement the event decision requires: no stop effects, no mesh-only GONE reason 2. The member then keeps serving and advertising a session the region has superseded. Completion must instead report the superseded local sessions and leave the tables and staging unchanged, so the caller retires them in its local publication order and completes the snapshot afterwards.

Acceptance: a staged record that wins over a local record (higher incarnation, or the equal-state tie-break for a lower remote member id) yields `LocalRetirementRequired` with one `RetireLocalPresence` effect per superseded session and unchanged tables; once the local record is gone the same completion succeeds; a staged record that loses to a local record completes without retirement. The event decision contract (`refutation_presence_retirement_error.rs`) is unchanged.

## ActiveForm

Making snapshot completion retire superseded local presence first.

## Dependencies

- **blocked by**: (none)
- **blocks**: nsgw regional presence supersession

## Notes

- Plan record: `docs/plan/20260926-0649-region-snapshot-local-supersession.md`.
- Change: `complete_region_snapshot` collects each existing record of `input.local_member_id` that `select_presence` loses to a staged record; if any, it returns the input table and staging unchanged, `RegionSnapshotEffect::RetireLocalPresence(session)` for each, and `RegionSnapshotDisposition::LocalRetirementRequired`. The collection is bounded by the stage and fails as `CapacityExhausted` if it cannot reserve. Nothing else in completion changed.
- Failing-test evidence: the three new `tests/region_presence.rs` cases first failed to build (`no field local_member_id`, `no variant LocalRetirementRequired`, `no variant RetireLocalPresence`). With the rule disabled, `completion_retires_a_superseded_local_session_before_replacing_it` failed with "completion replaced a local session without retiring it: Completed []" and `completion_retires_a_local_session_that_loses_the_equal_state_tie_break` with "a lower remote member id did not retire the equal local session: Completed"; `completion_keeps_a_local_session_that_wins_the_equal_state_tie_break` guards the opposite case.
- Existing completion inputs in the tests name member 16, which owns no record there, so their outcomes are unchanged. `refutation_presence_retirement_error.rs` is unchanged and passes.
- Verification: `just qa` passed (formatting, Clippy, 878 tests with 878 passed and 0 skipped, cargo-deny, cargo-shear, typos).
- Done: snapshot completion retires superseded local presence first.
