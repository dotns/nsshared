# 20260921-0309-region-frame-codec Region frame codec

- **status**: in_progress
- **priority**: P1
- **owner**: (unassigned)
- **createdAt**: 2026-09-21 03:09

## Description

Add the region frame codec and its sealed fixture while preserving the existing fixture release checks.

## ActiveForm

Resolving the fixture inventory scope conflict.

## Dependencies

- **blocked by**: permission to update `crates/keynet-proto/tests/vectors.rs`
- **blocks**: (none)

## Notes

The required fixture changes the manifest metadata to the v0.9 release and adds `region_frames.vec`. `tests/vectors.rs` independently fixes the v0.7 metadata, the twelve-file count, and the complete allowed file set. Its loader therefore rejects the required fixture and manifest before the requested release inventory can pass. The file is outside the allowed edit set.
