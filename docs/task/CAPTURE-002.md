# CAPTURE-002 Carry config-stream capabilities on stream open

- **status**: completed
- **priority**: P0
- **owner**: g-fix2
- **createdAt**: 2026-06-15

## Description

Carry the local `ConfigStreamRequest` capability tokens across the deployed
`GET /api/v1/config/stream` open path.

Acceptance criteria:

- SSE, Noise, and QUIC `connect_stream` preserve the signed config-stream
  envelope instead of dropping it after bearer-token setup.
- Non-empty config-stream requests add an encoded `request` query parameter to
  the stream path; empty/default requests keep the legacy path unchanged.
- Focused transport tests prove the encoded request contains
  `capture_routes.v1` and the GET request still has no body.

## ActiveForm

Carrying config-stream request capabilities on stream open.

## Dependencies

- **blocked by**: CAPTURE-001
- **blocks**: GatewayExit real-binary end-to-end validation

## Notes

- 2026-06-15: Investigation found `ControlPlane` and NSC already populate
  `ConfigStreamRequest.capabilities`, but transport implementations ignored the
  signed envelope and opened `/api/v1/config/stream` with only the bearer token.
- 2026-06-15: SSE, Noise, and QUIC now derive the config-stream GET path from
  the signed envelope. Empty/default requests keep the legacy path; non-empty
  requests send the signed envelope as a base64url `request` query parameter.
