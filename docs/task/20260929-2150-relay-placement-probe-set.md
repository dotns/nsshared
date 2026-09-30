# 20260929-2150-relay-placement-probe-set Add the gateway probe-set projection type

- **status**: completed
- **priority**: P2
- **owner**: bkd:z4ujbfcj
- **createdAt**: 2026-09-29 21:50

## Description

Add the gateway-bound probe-set projection type that nsgw consumes to authorize roster probes.

Plan: nsd-remote `docs/plan/20260929-2147-relay-placement-measurement.md` (approved 2026-09-29 21:50); the
wire contract is its "Wire contract" section.

## ActiveForm

Add the gateway probe-set projection type.

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Notes

- 2026-09-29: `GatewayWgRelayConfig.probe_set: Vec<GatewayWgRelayProbeEntry>`
  (`crates/control/src/messages.rs`), `#[serde(default, skip_serializing_if = "Vec::is_empty")]`.
  Entry fields `machine_id` (string), `machine_key_pub` and `wg_pubkey` (base64 via
  `serialize_wg_public_key`, hex or base64 accepted on decode), all required inside an entry.
- Tests: `gateway_wg_relay_probe_set_round_trips_with_pair_identity_encodings`,
  `gateway_wg_relay_probe_set_is_absent_when_empty_and_defaults_when_missing`,
  `gateway_wg_relay_probe_entry_requires_every_identity_field`; the wire compat matrix now
  carries a non-empty probe set that the legacy decoder ignores.

- unclaim: handed to bkd lane
- 2026-09-29: Handed to the bkd lane. Reviewed the earlier work against the wire contract: entry
  encodings reuse the `GatewayWgRelayPair` serde helpers, the field is skipped when empty and
  defaults when missing, and a config without probe entries keeps its exact CBOR and JSON bytes.
  Kept as is; focused tests and `just qa` pass.

- complete: merged into integration/relay-placement
