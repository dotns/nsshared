# 20260925-1655-region-settled-frame Region SETTLED frame

- **status**: completed
- **priority**: P1
- **owner**: implementer/region-settled
- **createdAt**: 2026-09-25 16:55

## Description

Add a control-only region frame, SETTLED (type 10), that carries a data connection generation and a cumulative settled forward id. An exit member sends it to tell the entry member that every forward on that data generation with an id up to and including the value has been finally decided (delivered, answered with MISS, or dropped), so no MISS for those ids will follow. The frame uses the same strict fixed-arity canonical CBOR rules as MISS, is legal only on control after HELLO, and rejects a zero data generation or a zero settled forward id. The frame version stays 1.

## ActiveForm

Completed the region SETTLED frame.

## Dependencies

- **blocked by**: (none)
- **blocks**: nsgw regional SETTLED watermark

## Notes

- Plan record: `docs/plan/20260925-1655-region-settled-frame.md`.
- Wire form: `[1, 10, [data_conn_gen, settled_forward_id]]`; the accepted vector for generation 1 and forward id 2 is `0000000683010a820102`. Encoding and decoding share `validate_frame`, so a zero generation or zero forward id is `InvalidFrame` on encode and `InvalidEncoding` on decode. MISS keeps accepting zero fields at the codec, as before.
- Sealed fixture: `region_frames.vec` adds `settled`, `settled_zero_generation`, `settled_zero_forward_id` and `settled_wrong_channel`; the manifest case list and file digest, the loader in `tests/vectors.rs`, and the release inventory (case list, file digest, manifest digest) declare them together. The fixture release name and design metadata are unchanged.
- Failing-test evidence: before the codec change, `tests/region_frames.rs` failed to build with `unresolved import keynet_proto::RegionSettled` and `no variant ... named Settled found for enum RegionFrameType`.
- Verification: `just fmt-check`, `just lint`, `just test` (871 tests, 871 passed, 0 skipped), `just deny`, `just shear` and `just typos` passed.
- Done: the region SETTLED frame is complete.
