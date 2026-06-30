## 2026-06-30 19:10 [feat]

Added the GatewayEgress selected-owner route hint.

- `ServiceBackendKind::GatewayEgress` now carries an optional
  `selected_gateway_id` field so NSD can project the gateway owner selected for
  a gateway-owned service VIP.
- The field is byte-additive: legacy payloads without the field deserialize to
  `None`, and routes without an owner omit the field when serialized.
- Verification passed with `just qa`.
