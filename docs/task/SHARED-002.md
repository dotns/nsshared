# SHARED-002 Decode address-shaped ControlMessage fields from CBOR

- **status**: completed
- **priority**: P0
- **owner**: fix/control-message-address-wire-form
- **createdAt**: 2026-08-29 04:20 UTC
- **completedAt**: 2026-08-29 06:05 UTC
- **relatedTask**: reported in the sibling `ns` repository as
  `ns/docs/task/SHARED-002.md`; the fix belongs here.

## Description

`ControlMessage` is `#[serde(tag = "type")]`. Serde buffers an
internally-tagged variant into `Content` and re-deserializes it through a
`ContentDeserializer` that always reports `is_human_readable() == true`, while
`ciborium` reports `false` and therefore *wrote* the binary form. `SocketAddr`,
`IpAddr`, `Ipv4Addr` and `IpNet` all switch shape on that flag, so every one of
those fields was written as a Rust-native enum map or octet sequence and then
rejected with `invalid type: map, expected socket address`. The failure is
fatal rather than skipped: a known variant that fails to decode returns
`LiveStreamExit::Disconnected`, and `backoff_secs` resets on a successful
connect, so a consumer reconnects roughly once a second for as long as the
message keeps being projected.

Measured, not assumed: **10 of the 24 `ControlMessage` variants were
undecodable** from a natively-encoded CBOR payload — `wg_config`,
`proxy_config` (both `RewriteTarget` arms), `routing_config`, `gateway_config`,
`gateway_wg_relay`, `gateway_egress_wg_config.v1`, `gateway_exit_config.v1`,
`gateway_http_config.v1`, `gateway_l4_map.v1`, `peer_candidates`. The sibling
report named two.

Also measured: **no realm is in a reconnect loop today.** NSD's only
config-stream producer serializes through `serde_json::Value` before encoding
CBOR (`nsd/crates/nsd-api/src/sse/publisher.rs`, `config_stream_payload_cbor`),
so those bytes were already strings. The defect is real at this crate's API
surface — `from_cbor(to_cbor(&msg))` fails — and detonates the moment anyone
removes that laundering hop.

Acceptance criteria:

- Every address-shaped field reachable from a `ControlMessage` variant carries
  one wire encoding in both JSON and CBOR.
- Bytes an un-upgraded producer already wrote keep decoding.
- JSON is unchanged, and the config-stream producer's bytes are unchanged.
- Cross-repository CBOR shapes are pinned, not only the JSON ones.
- Focused tests and repository quality gates pass; `ns`, `nsd` and `nsgw`
  build and test against the change.

## ActiveForm

Giving address-shaped control-message fields one wire encoding.

## Resolution

`mod serde_wire_addr` in `crates/control/src/messages.rs`, applied to all 27
previously bare address-shaped fields; the three fields already on
`serde_ipnet_vec` were folded into the same family. It **writes one form and
accepts two**: always the human-readable string, and on read the string form or
the legacy non-human-readable form.

Scope note: `subnet_route.rs` was left alone — its `serde_ipv4net` has written
the string form since it was introduced, so no legacy binary bytes exist for
it, and `ControlMessage::SubnetRouteConfig` already round-tripped. The raw
envelope payloads in `api.rs` were also left alone: they are `ciborium` on both
ends and symmetric, so converting them would open a second ordered cutover for
no gain.

## Cutover order

**Deploy NSD before the node.**

`P2pCandidate` is the one annotated type that also rides a raw-`ciborium`
envelope, `peer_candidates.report`, where the binary form is the *working*
shape today. A new producer's string form is rejected by a consumer that
predates this change (`unknown variant "10.200.0.11:51820", expected "V4" or
"V6"`), and no reader change here can fix an already-deployed binary. The
tolerant reader covers the opposite cell, an un-upgraded node reporting to an
upgraded NSD.

Blast radius of the one ordered cell is bounded: NSD answers `BadPayload`, the
node retries on its existing backoff (250 ms rising to 5 s) and logs a warning,
direct-P2P promotion does not happen, and it self-heals once NSD is upgraded.
Every other cell of the old/new × producer/consumer × CBOR/JSON matrix passes,
and the config-stream and JSON producer bytes are byte-identical before and
after.

## Dependencies

- **blocked by**: (none)
- **blocks**: direct-P2P promotion against a real NSD; any realm projecting
  `wg_relay_roster` over a natively encoded CBOR config stream

## Notes

The `nsd-mock` compensation in `ns`
(`tests/docker/nsd-mock/src/registry.ts`, `socketAddrForControlMessage`) needs
no code change: it already renders both wire forms to the string form, so it
keeps working, and it stops dropping IPv6 candidates once the node emits them
as strings. Its comments describe the string form as a compensation and are
stale after this lands; correcting them belongs to `ns`.
