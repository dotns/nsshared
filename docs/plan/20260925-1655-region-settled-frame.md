# 20260925-1655-region-settled-frame Region SETTLED frame

- **status**: completed
- **createdAt**: 2026-09-25 16:55
- **approvedAt**: 2026-09-25 16:55
- **relatedTask**: 20260925-1655-region-settled-frame

## Context

An entry member keeps one MISS correlation for every forward it writes to an exit member. A correlation ends only on a MISS, on its reply-window deadline, or when the pair or data generation retires. A delivered forward never ends it, so the per-pair correlation limit caps cross-member forwarding at that limit per reply window. The exit needs a frame that tells the entry which forwards will never produce a MISS.

## Proposal

Add `RegionFrameType::Settled = 10` and `RegionSettled { data_conn_gen: u32, settled_forward_id: u64 }`. The body is a two-element CBOR array `[data_conn_gen, settled_forward_id]` with the shortest-form unsigned integer rules shared by every region frame. It is a control frame: legal on control after HELLO and illegal on data. Encoding and decoding reject a zero data generation (reserved, as for HELLO) and a zero settled forward id (settles nothing). `REGION_FRAME_VERSION` stays 1; members of one region upgrade together.

The sealed `region_frames.vec` fixture gains an accepted `settled` vector and rejected `settled_zero_generation`, `settled_zero_forward_id` and `settled_wrong_channel` vectors. The fixture manifest, its digest, the release inventory and the fixture loader declare the new cases together.

## Tests

- `tests/region_frames.rs`: round trip and integer widths, the malformed-form sweep, zero-field rejection on encode and decode, channel typing, and the sealed vector cases.
- `tests/vectors.rs` and `tests/release_inventory.rs`: the updated manifest, digest and case inventory.

## Risks

A member that does not know type 10 rejects the frame as an unsupported type and closes its control connection, so region members must run the same release.

## Scope

- `crates/keynet-proto/src/region.rs`
- `crates/keynet-proto/tests/region_frames.rs`, `tests/vectors.rs`, `tests/release_inventory.rs`
- `crates/keynet-proto/tests/fixtures/keynet-v1/region_frames.vec`, `manifest.txt`
- this plan and its task record

## Alternatives

Echoing a per-forward acknowledgement would double control traffic; a cumulative watermark covers any number of forwards with one frame. Negotiating the frame in HELLO would add a version path that a single-release region does not need.
