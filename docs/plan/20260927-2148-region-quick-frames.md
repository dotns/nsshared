# 20260927-2148-region-quick-frames Region quick frames and extended region HELLO

- **status**: completed
- **createdAt**: 2026-09-27 21:48
- **approvedAt**: 2026-09-27 21:48
- **relatedTask**: 20260927-2148-region-quick-frames

## Context

A relay region will designate one member as the quick pairing owner and let every other member forward quick pairing messages to it over the region control connection. The region HELLO body is a fixed five-element array with no capability field, a base decoder rejects any other length and any unknown frame type, and a control frame body is limited to 4096 bytes while a quick pairing message may be 16 KiB. The codec therefore needs an optional HELLO extension that only configured members send, two control frames for the forwarded exchange, and a separate size limit that applies to those frames alone.

## Proposal

### Extended HELLO

`RegionHello` gains `extension: Option<RegionHelloExtension>`. Without it the body is unchanged:

```text
[region_name, member_id, boot_epoch, channel, conn_gen]
```

With it the body has six elements; the sixth is a three-element array:

```text
[region_name, member_id, boot_epoch, channel, conn_gen,
  [capabilities, quick_owner, quick_owner_epoch]]
```

- `capabilities` is an unsigned 64-bit bit set. Bit 0 (`REGION_CAPABILITY_QUICK_FORWARDING`) means the sender decodes QUICK_REQUEST and QUICK_RESPONSE. The decoder keeps every bit, known or not.
- `quick_owner` is a member id in 1..=16; `quick_owner_epoch` is at least 1.
- The extension is legal only on the control channel. A data-channel HELLO with six elements is rejected. `REGION_FRAME_VERSION` stays 1.

Accepted control vector (member 1, epoch 2, generation 3, capabilities 1, owner 2, owner epoch 5): `00000014830101866772656c61792d610102000383010205`.

### QUICK_REQUEST (type 11) and QUICK_RESPONSE (type 12)

```text
[1, 11, [request_id, client_ip, challenge, actor, request]]
[1, 12, [request_id, status, actor, response]]
```

- `request_id`: unsigned integer, nonzero.
- `client_ip`: byte string of exactly 4 (IPv4) or 16 (IPv6) bytes.
- `challenge`: byte string of exactly 32 bytes.
- `actor`: opaque byte string of at most `MAX_REGION_QUICK_ACTOR_BYTES` (1024) in both frames, empty when the connection has none.
- `request`, `response`: opaque byte strings of at most `MAX_REGION_QUICK_MESSAGE_BYTES` (16384, the value of `keynet_quick::MAX_MESSAGE_BYTES`).
- `status`: 1 completed, 2 not serving as owner, 3 busy. With a status other than 1, `actor` and `response` are empty.

The bytes of a non-empty `actor` are the actor's `keynet_quick::Hello` in the compact JSON form in which `keynet-quick` serialises its messages. The largest valid `Hello` in that form is 687 bytes: two 32-byte arrays and one 16-byte array written as decimal numbers, an authority of 253 bytes, and a 20-digit expiry. The bound of 1024 is that size rounded up to the next power of two. It is a constant of `keynet-proto`, separate from the message bound. The codec checks only the length of `actor` and never parses it; the forwarding member and the owner apply and check the encoding. `keynet-proto` has no dependency on `keynet-quick`, as a build or a development dependency.

Both frames are control-only and legal only after HELLO. Both use the canonical CBOR rules of every region frame: definite lengths, shortest-form integers, fixed arity, no trailing bytes. Encoding rejects a violating frame with `InvalidFrame`; decoding rejects it with `InvalidEncoding`, or `WrongChannel` on the data channel.

Accepted vectors: an IPv4 request with an empty actor and a three-byte request, `0000003183010b850144c0000201582055555555555555555555555555555555555555555555555555555555555555554043010203`; a not-owner response, `0000000883010c8401024040`.

### Frame limits

`MAX_REGION_QUICK_FRAME_BYTES` is 17478, the encoded body of the largest valid QUICK_REQUEST: a nine-byte request id, a 16-byte address, the 32-byte challenge, a 1024-byte actor and a 16384-byte request. The largest QUICK_RESPONSE is smaller. `MAX_REGION_FRAME_BYTES` (4096) and `decode_region_frame_prefix` are unchanged. `decode_region_quick_frame_prefix` accepts up to the quick limit and `RegionFrame::decode_quick_control` decodes with it; both are meant only for a control connection whose HELLO exchange agreed on quick forwarding. Both decoders hold every frame type to its own limit, so HELLO, SNAPSHOT and the other types keep 4096 bytes on every connection. The encoder applies the same per-type limit.

### Channel typing

`CONTROL_REGION_FRAME_TYPES` lists eleven types. `RegionFrameType::is_legal_before_hello_on` (and `RegionChannel::permits_before_hello`) states that HELLO is the only legal first frame on either channel.

## Tests

- `tests/region_quick_frames.rs`: sealed vectors, extended HELLO round trip and rejection, quick frame round trip and field rejection, channel and stage typing, the malformed-encoding sweep over both HELLO lengths and both quick frames, and the measured limits.
- `tests/region_frames.rs`: the existing sealed-vector test, unchanged in its expectations for the existing set; the declared control list now has eleven entries.
- `tests/release_inventory.rs`: the existing set keeps its digests; the new set is sealed the same way.

## Risks

- A base-branch decoder rejects a six-element HELLO and closes the connection. The change is additive only because a member sends the extension exactly when its configuration names an owner.
- Using the quick prefix decoder on a connection that did not agree on quick forwarding admits bodies up to 17478 bytes for quick frames. Non-quick types stay at 4096 bytes on both decoders.
- The codec checks only the bounds of the opaque payloads; their meaning belongs to the quick pairing layer.
- The actor bound depends on the `keynet_quick::Hello` layout staying as it is; a test where both crates meet checks that the largest valid `Hello` fits.

## Scope

- `crates/keynet-proto/src/region.rs`
- `crates/keynet-proto/tests/region_quick_frames.rs`, `tests/region_frames.rs`, `tests/release_inventory.rs`
- `crates/keynet-proto/tests/fixtures/keynet-region-quick-v1/manifest.txt`, `region_quick_frames.vec`
- this plan and its task record

## Alternatives

- Raising `MAX_REGION_FRAME_BYTES` would let every frame type grow on every connection, including links that never agreed on quick forwarding.
- Bumping `REGION_FRAME_VERSION` would break mixed-version regions that have no owner configured; a capability-gated extension keeps them byte for byte on the base wire.
- Bounding the actor by the 16384-byte message limit was rejected. No sender can legitimately produce an actor that large, since the actor is always a `Hello` of at most 687 bytes. That bound would raise the quick frame limit to 32838 bytes and widen what a member may push at the owner on the control connection. The codec bound follows what the field is.

## Annotations

The new fixture set lives in its own directory with its own manifest, so the existing `keynet-v1` directory and manifest stay byte for byte. The vectors were produced by a CBOR writer independent of the codec; its legacy HELLO output equals the sealed `hello_control` and `hello_data` bytes.
