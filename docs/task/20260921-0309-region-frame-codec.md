# 20260921-0309-region-frame-codec Region frame codec

- **status**: completed
- **priority**: P1
- **owner**: (unassigned)
- **createdAt**: 2026-09-21 03:09

## Description

Add the region frame codec and its sealed fixture while preserving the existing fixture release checks.

## ActiveForm

Completing the region frame codec and sealed fixture.

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Notes

The required fixture changes the manifest metadata to the v0.9 release and adds `region_frames.vec`. `tests/vectors.rs` independently fixes the v0.7 metadata, the twelve-file count, and the complete allowed file set. Its loader therefore rejects the required fixture and manifest before the requested release inventory can pass. The file is outside the allowed edit set.

The loader and release inventory now independently pin the v0.9 metadata, file list, digest, and region-frame case inventory. The loader remains an explicit allowlist and validates the case family directly.

Failing test evidence: `region_frame_contract_is_available` initially failed because `RegionChannel`, `RegionFrame`, and `RegionPing` were unresolved imports.

Acceptance: all frame types, nested schemas, enum ranges, canonical CBOR rejections, channel typing, allocation-safe prefix validation, limits, carried-datagram separation, and sealed-fixture refutations are covered.

Checks: `cargo fmt --all -- --check && cargo clippy --workspace --all-targets --locked -- -D warnings && cargo nextest run -p keynet-proto --locked` passed.
