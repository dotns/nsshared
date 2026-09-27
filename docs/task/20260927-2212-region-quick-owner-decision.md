# 20260927-2212-region-quick-owner-decision Region quick owner agreement decision

- **status**: completed
- **priority**: P1
- **owner**: implementer/region-quick-owner-decision
- **createdAt**: 2026-09-27 22:12

## Description

Add the pure owner agreement and fencing decision for region quick pairing to `keynet-proto`: given the local owner and epoch, the peer's owner and epoch from its HELLO (or the legacy HELLO), and the member's in-memory state, return the link state (agreed, inactive, mismatched) and whether the local member may serve a broker. The decision cases are vectors in the sealed `keynet-region-quick-v1` set.

## ActiveForm

Completed the region quick owner agreement decision.

## Dependencies

- **blocked by**: 20260927-2148-region-quick-frames
- **blocks**: region quick owner forwarding in the relay

## Acceptance

- For every combination of local and peer owner and epoch in the decision vectors (equal; peer higher; peer lower; equal epoch with different owner; either side without owner; legacy peer) the decision returns the stated link state and serving permission.
- A fence raised by a higher epoch persists across later agreed links and is lifted only by a local epoch at least as high as the highest observed; a same-epoch owner conflict fences both sides.
- Altering, adding, removing or linking a decision vector fails the release inventory test.
- No dependency was added and the module performs no I/O.

## Notes

- Plan record: `docs/plan/20260927-2212-region-quick-owner-decision.md`.
- Fixture: `region_quick_owner.vec` with 25 cases; `manifest.txt` of the set gains the file, its case inventory, `data_file_count=2` and the `region_quick_owner` coverage entry. `region_quick_frames.vec` and the `keynet-v1` set are unchanged.
- Failing-test evidence: before the module existed, `tests/region_quick_owner.rs` failed to build with `unresolved imports keynet_proto::RegionQuickLink, keynet_proto::RegionQuickOwner, ...`. After the manifest listed the new file and before the inventory constants were updated, `region_quick_release_matches_the_sealed_inventory` failed with `release manifest does not match the sealed inventory`.
- Mutation checks: with the same-epoch conflict record removed, the vector test failed at `conflict_after_agreed_link step2`; with a local epoch equal to the highest treated as above it, the vector, sweep and two-member tests failed.
- Verification: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings` and `cargo nextest run -p keynet-proto -p keynet-quick --locked` (186 tests, 186 passed, 0 skipped) passed.
- Done: the region quick owner agreement decision is complete.
