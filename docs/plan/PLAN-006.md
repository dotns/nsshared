# PLAN-006 Config-stream capability transport

- **status**: completed
- **createdAt**: 2026-06-15
- **approvedAt**: 2026-06-15
- **completedAt**: 2026-06-15
- **relatedTask**: CAPTURE-002

## Context

GatewayExit E2E found that NSC advertises `capture_routes.v1`, but the token
does not reach NSD during config-stream subscription. The shared control client
already builds a signed `config.stream` envelope from `ConfigStreamRequest`;
however, SSE/Noise/QUIC transport stream opens ignore that envelope and use a
bare `GET /api/v1/config/stream` with only the bearer token.

## Proposal

1. Add a shared `config_stream_path` helper that validates the envelope payload
   as `ConfigStreamRequest`.
2. Keep the legacy stream path for empty/default requests.
3. For non-empty requests, encode the signed envelope as a base64url `request`
   query parameter and use that path from SSE, Noise, and QUIC.
4. Add focused tests for default omission and non-empty capability transport.

## Scope

In scope: `crates/control/src/transport/{sse,noise,quic}.rs` and focused tests.

Out of scope: data-plane changes, NSC route-manager behavior, NSGW nft/SNAT, or
new capability tokens.

## Risks

- Query length grows when the signed envelope is present, but the payload is a
  small capability list and remains well below typical request-line limits.
- Legacy NSD builds ignore the new query parameter; the same-window NSD change
  decodes and verifies it.

## Verification

- `cargo test -p control config_stream_path --all-targets`
- `cargo test -p control connect_stream_gets_config_stream_over_http --all-targets`
- `just qa` (`/tmp/gfix2-ns-shared.log`, `DONE_0`)
