# 20260921-0541-region-marks-join Add region marks join

- **status**: completed
- **priority**: P1
- **owner**: (assigned)
- **createdAt**: 2026-09-21 05:41

## Description

Add a pure, deterministic join for retained region marks. Cover the join laws,
durability-facing changed result, and sealed fixture inventory.

## ActiveForm

Completed a deterministic retained-mark join and sealed vector family.

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Notes

Investigation: `RegionMarks` already carries the generation, key, conflict,
revocation, and incarnation floors used by region frames. The frame codec is
pure and provides no persistence behavior. The fixture loader and release
inventory independently pin metadata, file names, case inventories, and
digests.

Proposal: add a same-owner pure join that returns its resulting marks and a
changed flag. Keep revocation independent of generation, reset
generation-specific fields at a higher generation, and deterministically
represent equal-generation key conflicts. Add fixed-order law tests and a
sealed marks vector family without changing existing vectors.

Acceptance: fixed inputs cover idempotence, pairwise commutativity,
associativity, and every ordering. The tests also cover independent revocation
floors, higher-generation resets, equal-generation conflicts, deterministic
representatives, and exact changed reporting.

Verification: the initial `cargo test -p keynet-proto --test region_marks`
failed with `unresolved import keynet_proto::join_region_marks`. The focused
marks and inventory tests passed after implementation. `cargo fmt --all --
--check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`,
and `cargo nextest run -p keynet-proto --locked` completed without failures,
skips, or ignored cases.
