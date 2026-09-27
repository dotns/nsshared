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
- A peer HELLO extension is never read as the legacy HELLO: an out-of-range extension makes the link mismatched and fences the member at least as much as a valid claim with the same epoch.
- No dependency was added and the module performs no I/O.

## Notes

- Plan record: `docs/plan/20260927-2212-region-quick-owner-decision.md`.
- Fixture: `region_quick_owner.vec` with 32 cases, seven of them with out-of-range extensions; `manifest.txt` of the set gains the file, its case inventory, `data_file_count=2` and the `region_quick_owner` coverage entry. `region_quick_frames.vec` and the `keynet-v1` set are unchanged.
- Failing-test evidence: before the module existed, `tests/region_quick_owner.rs` failed to build with `unresolved imports keynet_proto::RegionQuickLink, keynet_proto::RegionQuickOwner, ...`. After the manifest listed the new file and before the inventory constants were updated, `region_quick_release_matches_the_sealed_inventory` failed with `release manifest does not match the sealed inventory`.
- Out-of-range extension: the earlier API converted an out-of-range extension to `None` before the decision, which read it as the legacy HELLO. A test giving a member at epoch 5 a peer extension with owner 0 and epoch 9 failed with `an extension presenting epoch 9 was read as a legacy HELLO: RegionQuickOwnerDecision { link: Mismatched, may_serve: true }, highest observed epoch 0`. The decision now takes the peer's `Option<RegionHelloExtension>` directly and records an out-of-range claim as its epoch with no acceptable owner; that test is `an_out_of_range_extension_is_never_read_as_a_legacy_hello`. With the old legacy reading restored inside the new API, three tests failed: that test, the sweep (`local None peer ... quick_owner: 0, quick_owner_epoch: 0 ... may_serve: true`) and the vectors (`extension_epoch_zero_local_without_owner step1`).
- Mutation checks: with the same-epoch conflict record removed, the vector test failed at `conflict_after_agreed_link step2`; with a local epoch equal to the highest treated as above it, the vector, sweep and two-member tests failed.
- Verification: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings` and `cargo nextest run -p keynet-proto -p keynet-quick --locked` (187 tests, 187 passed, 0 skipped) passed.
- Done: the region quick owner agreement decision is complete.
