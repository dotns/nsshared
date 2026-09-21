# 20260921-0309-region-frame-codec Region frame codec

- **status**: draft
- **createdAt**: 2026-09-21 03:09
- **approvedAt**: 2026-09-21 03:09
- **relatedTask**: 20260921-0309-region-frame-codec

## Context

The requested fixture must add `region_frames.vec`, increase `data_file_count`, and pin the v0.9 design metadata. The existing fixture loader in `tests/vectors.rs` requires the v0.7 metadata, twelve files, and an exact file set. It rejects a new fixture file even if the manifest digest is regenerated.

## Proposal

Extend the existing fixture loader with the same v0.9 metadata, the new file digest, and the region case inventory. Then add the codec, tests, fixture, release seal, and refutation coverage.

## Risks

Without updating the existing loader, the required fixture turns an otherwise passing test suite into a deterministic failure. Updating only the release inventory leaves the independent loader inconsistent.

## Scope

The required loader update is outside the allowed file list.

## Alternatives

No alternative can add the physical fixture and preserve the existing loader's exact-file check without modifying `tests/vectors.rs`.

## Annotations

Implementation is blocked pending expansion of the allowed edit set.
