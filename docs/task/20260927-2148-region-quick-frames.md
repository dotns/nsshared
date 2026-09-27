# 20260927-2148-region-quick-frames Region quick frames and extended region HELLO

- **status**: completed
- **priority**: P1
- **owner**: implementer/region-quick-frames
- **createdAt**: 2026-09-27 21:48

## Description

Add the optional region HELLO extension `[capabilities, quick_owner, quick_owner_epoch]`, the control-only QUICK_REQUEST (type 11) and QUICK_RESPONSE (type 12) frames, the quick frame body limit with its own prefix decoder, and a separate sealed fixture set for them. A HELLO without extension, the 4096-byte limit, the existing prefix decoder, `REGION_FRAME_VERSION` and the existing fixture set are unchanged. The crate stays a pure codec with no new dependency.

## ActiveForm

Completed the region quick frames and extended region HELLO.

## Dependencies

- **blocked by**: (none)
- **blocks**: region quick owner forwarding in the relay

## Acceptance

- A HELLO without extension encodes to the sealed `hello_control` and `hello_data` bytes; the existing sealed-vector and release inventory tests pass with their expectations for the `keynet-v1` set unmodified.
- An extended HELLO round-trips on control, is rejected on data, keeps unknown capability bits, and is rejected with owner 0, owner 17 or epoch 0.
- QUICK_REQUEST and QUICK_RESPONSE round-trip; they are rejected on the data channel, before HELLO, with a zero request id, an address of 0, 3, 5, 15 or 17 bytes, an actor, request or response one byte over 16384, and a non-empty actor or response with status 2 or 3.
- The malformed-encoding sweep covers the five- and six-element HELLO and both quick frames.
- The base prefix decoder rejects 4097; the quick prefix decoder accepts the largest valid QUICK_REQUEST and rejects one byte more; `MAX_REGION_QUICK_FRAME_BYTES` equals its measured size, 32838.
- Adding, removing, altering or linking a file in the new set fails the release inventory test.

## Notes

- Plan record: `docs/plan/20260927-2148-region-quick-frames.md` (wire text of the extension and both frames).
- Fixture set: `crates/keynet-proto/tests/fixtures/keynet-region-quick-v1/` with `manifest.txt` naming the plan record as its design source and `region_quick_frames.vec` with 36 cases.
- `tests/region_frames.rs` changes only where the new variants and field require it: `extension: None` in two HELLO literals, two names in the frame type table, and the declared control list length of eleven.
- `tests/release_inventory.rs` verifies both sets through one parameterised seal; the `keynet-v1` constants are unchanged. Each drift case now first verifies the unaltered copy, so a rejection is caused by the alteration.
- Failing-test evidence: before the codec change, `tests/region_quick_frames.rs` failed to build with `unresolved imports keynet_proto::MAX_REGION_QUICK_FRAME_BYTES, ...` and `struct RegionHello has no field named extension`.
- Verification: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings` and `cargo nextest run -p keynet-proto -p keynet-quick --locked` (180 tests, 180 passed, 0 skipped) passed.
- Done: the region quick frames and extended HELLO are complete.
