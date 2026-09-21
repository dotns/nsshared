# 20260921-0309-region-frame-codec Region frame codec

- **status**: completed
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

The codec, focused tests, sealed fixture, manifest, and the two independent inventory witnesses were updated.

## Alternatives

Fixture sealing requires an explicit declared file set and case inventory; directory discovery cannot prove the release contents.

## Annotations

The fixture loader and release inventory independently declare matching v0.9 metadata, file digest, and region-frame case inventory. The loader validates the declared file and case sets directly; neither witness derives its allowlist from directory contents or from the other witness.
