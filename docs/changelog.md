## 2026-07-17 [feat]

Activated non-future V1 WgRelay leases immediately at receipt.

- `translate_wg_relay_lease_deadlines` now maps a not-before barrier at or
  before the authenticated signed timestamp to activation exactly at the
  monotonic receipt anchor, with no added guard.
- A future barrier keeps the existing guarded calculation and bound for old
  producer compatibility, and hard expiry stays receipt-anchored behind the
  conservative guard (a 300-second lease still expires at receipt plus 235
  seconds).
- All typed failures remain, including `NoUsableWindow` for legacy
  future-barrier leases and degenerate short leases; wire types, constants,
  and function signatures are unchanged.
- Consumer-local widening: a non-future lease now has a usable window once
  its signed interval exceeds the 65-second guard, where the always-guarded
  translation required more than twice the guard. Production leases keep the
  fixed 300-second interval, so only the activation instant changes there.

## 2026-07-13 [feat]

Added the causal scoped WgRelay roster and forwarding-lease contract.

- Added restart-unique checked control-stream sessions to config-stream and
  realm-snapshot requests, with one session shared across endpoint fallbacks.
- Added optional per-scope rosters, optional per-realm forwarding leases, and a
  default-false durable fleet-cutover attestation.
- Exposed authenticated envelope timestamps from config-event and unary
  verification together with receipt-time monotonic anchors, preserving both
  through scoped gateway delivery.
- Exported the fixed causal lease timing constants and one checked monotonic
  deadline translator that rejects invalid bounds, ordering, and overflow.
- Added scope/session-specific transport status and endpoint-confined
  `MultiControlPlane` children without synthetic config-arrival success.
- Added JSON/CBOR round-trip, omission-default, old/new compatibility, session,
  signed-timestamp, timing-bound, queued-anchor, three-transport fallback, and
  real A/B endpoint-confinement coverage.

## 2026-07-11 [feat]

Added shared control support for reliable direct-P2P candidate reporting.

- HTTP 429 responses now map to a typed `RateLimited` error with optional
  `current_epoch` and `retry_after_ms` data. The shared unary status mapper
  covers SSE, Noise, and QUIC, while older or malformed response bodies remain
  compatible with absent optional fields.
- Verification passed with `just qa` and `cargo test --doc --workspace
  --locked`.

## 2026-07-10 [feat]

Added the public-edge upstream authority wire contract.

- Added an optional `GatewayHttpRoute.upstream_authority` field that affects
  only the upstream HTTP virtual host.
- Kept public listener, certificate, authentication, OIDC, and ACL identity on
  `GatewayHttpRoute.host`; upstream TLS SNI is derived from the explicit
  authority when present.
- Added JSON/CBOR round-trip and legacy-decode compatibility coverage.

## 2026-07-01 15:29 [feat]

Added the public-edge upstream TLS re-encryption wire contract.

- Add an optional `GatewayHttpRoute.upstream_tls` policy for HTTPS NSN-backed
  backends.
- Added the gateway capability scope used to gate b-lite support during rollout.
- Added serde compatibility coverage proving old payloads without
  `upstream_tls` default to plaintext behavior.
- Verification passed with `just qa`.

## 2026-06-30 19:10 [feat]

Added the GatewayEgress selected-owner route hint.

- `ServiceBackendKind::GatewayEgress` now carries an optional
  `selected_gateway_id` field so NSD can project the gateway owner selected for
  a gateway-owned service VIP.
- The field is byte-additive: legacy payloads without the field deserialize to
  `None`, and routes without an owner omit the field when serialized.
- Verification passed with `just qa`.
