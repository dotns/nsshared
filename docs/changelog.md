## 2026-07-11 [feat]

Added shared control and telemetry support for reliable direct-P2P candidate
reporting.

- HTTP 429 responses now map to a typed `RateLimited` error with optional
  `current_epoch` and `retry_after_ms` data. The shared unary status mapper
  covers SSE, Noise, and QUIC, while older or malformed response bodies remain
  compatible with absent optional fields.
- Added bounded-cardinality, no-label instruments for active candidates,
  confirmed misses, age expirations, inconclusive gather cycles, and
  acknowledged empty reports.
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
