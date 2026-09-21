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

The HELLO encoder and decoder reject `conn_gen` zero through their shared validation path; zero remains reserved.

After the initial HELLO, control permits every control frame except HELLO and FORWARD, while data permits only FORWARD. The exported post-handshake policy therefore prohibits a second HELLO on both channels.

Failing test evidence: `region_frame_contract_is_available` initially failed because `RegionChannel`, `RegionFrame`, and `RegionPing` were unresolved imports.

Regression evidence: `hello_encoder_rejects_zero_connection_generation` and `hello_decoder_rejects_zero_connection_generation` initially failed because zero connection generation was accepted. `control_hello_is_not_legal_after_handshake` initially failed because control HELLO remained legal after the handshake.

The region-frame test module keeps the encoder, decoder, and post-handshake control HELLO regressions with the frame contract coverage.

Acceptance: all frame types, nested schemas, enum ranges, canonical CBOR rejections, first-frame-only HELLO channel typing, nonzero HELLO connection generation, allocation-safe prefix validation, limits, carried-datagram separation, and sealed-fixture refutations are covered.

Checks: `cargo fmt --all -- --check && cargo clippy --workspace --all-targets --locked -- -D warnings && cargo nextest run -p keynet-proto --locked` passed with the HELLO regression tests and the complete package suite.
