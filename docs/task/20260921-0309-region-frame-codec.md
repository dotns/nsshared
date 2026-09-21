# 20260921-0309-region-frame-codec Region frame codec

- **status**: completed
- **priority**: P1
- **owner**: (unassigned)
- **createdAt**: 2026-09-21 03:09

## Description

Add the region frame codec and its sealed fixture while preserving the existing fixture release checks.

## ActiveForm

Completing the region frame codec and sealed fixture.

## Notes

The v0.9 fixture release declares `region_frames.vec` alongside the existing fixture files, with its digest and exact case inventory. The sealed loader validates the declared files, metadata, and case family directly.

The loader and release inventory independently declare matching v0.9 metadata, file digests, and region-frame case inventory. This duplication prevents either witness from inheriting an unverified allowlist from directory contents or from the other witness.

Failing test evidence: `region_frame_contract_is_available` initially failed because `RegionChannel`, `RegionFrame`, and `RegionPing` were unresolved imports.

Acceptance: all frame types, nested schemas, enum ranges, canonical CBOR rejections, channel typing, allocation-safe prefix validation, limits, carried-datagram separation, and sealed-fixture refutations are covered.

Checks: `cargo fmt --all -- --check && cargo clippy --workspace --all-targets --locked -- -D warnings && cargo nextest run -p keynet-proto --locked` passed.
