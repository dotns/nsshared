# CTRL-019 Define causal scoped WG relay roster and lease contract

- **status**: completed
- **priority**: P0
- **owner**: local session
- **createdAt**: 2026-07-13 04:11

## Description

Implement the shared-contract slice of ns PLAN-114 only after approval. Define
the following additive, serde-defaulted wire contract:

- a restart-unique `ControlStreamSession` composed of a random boot nonce and
  checked per-attempt counter, carried as optional `stream_session` metadata on
  `ConfigStreamRequest`;
- the same optional exact session on the currently empty
  `GatewayRealmConfigSnapshotRequest`, because that independently polled and
  signed snapshot is the authoritative source of NSGW WgRelay tables;
- an optional atomic `WgRelayIdentityRoster` on `GatewayConfig`, carrying the
  exact session, durable config generation, exact endpoints, readiness lease,
  confirmation barrier, and a default-false durable fleet-cutover attestation;
- an optional per-realm session- and generation-bound forwarding lease on the
  `GatewayWgRelayConfig` events returned inside the signed realm snapshot; and
- scope/session metadata on both edges of internal control status so a delayed
  prior-attempt close cannot affect the current attempt.

Retain the verified signed-envelope timestamp instead of returning only the
decoded payload. Define shared, non-tunable lease constants and checked helpers:
`MAX_WG_RELAY_LEASE_SECS = 300`, the existing
`MAX_CLOCK_SKEW_SECS = 60`, and `WG_RELAY_CLOCK_MARGIN_SECS = 5`. At receipt,
callers must translate accepted wall-clock deadlines to monotonic instants with
the PLAN-114 formula; wire objects never carry a process-local `Instant`.

Endpoint-confine each fixed-scope `MultiControlPlane` child by clearing the
inherited center list and copying the selected entry's URL-derived mode, realm,
bootstrap trust, and envelope pins. Config forwarding must not synthesize
connection success.

`stream_session` presence must force the signed `?request=` SSE path even when
all legacy request fields are empty. The same logical session must be carried
over SSE, Noise, and QUIC endpoint attempts.

## ActiveForm

Completed the independent gate corrections. Authenticated signed time and its
receipt-time monotonic anchor now reach scoped gateway consumers without being
re-anchored after queueing. The shared checked deadline helper is the single
PLAN-114 wall-clock to monotonic translation, and the transport-fallback and
scope-confinement tests exercise the actual request/delivery seams.

## Dependencies

- **blocked by**: ns PLAN-114 approval
- **blocks**: nsd LNK-009; nsgw LNK-012; ns LNK-020

## Acceptance Criteria

- Old producers decode as roster/lease/cutover absence, not authoritative
  empty or fleet-ready state; all additions are unknown-field wire-compatible.
- The snapshot request defaults to no session. Only a request carrying the
  exact active config-stream session can receive a WgRelay forwarding lease;
  the signed event echoes that session exactly.
- The verified config-event and unary-response APIs expose the authenticated
  envelope timestamp together with the payload; no caller reconstructs it from
  local wall time.
- Every lease deadline is rejected unless it is ordered and no more than the
  shared 300-second maximum from its signed timestamp. Checked conversion uses
  a 65-second skew-plus-margin guard and fails closed on overflow.
- A restart changes the boot nonce, reconnect increments the checked attempt,
  endpoint fallbacks retain one logical session, and counter exhaustion fails
  closed.
- A recorded still-fresh response from a prior boot or attempt cannot match a
  new session even when the replay cache is empty.
- Session-only requests round-trip through plaintext/TLS SSE and Noise/QUIC;
  only a fully default legacy request uses the bare SSE URL.
- Fixed scope A cannot connect/fail over to B or publish B state under A, and
  vice versa, in real two-endpoint tests.
- Roster/status/lease generation stays per scope/session and is never
  substituted, merged, or evicted across scopes.
- JSON/CBOR fixtures prove omission defaults the fleet gate to false and cover
  all eight old/new NSD x ns x NSGW combinations defined by PLAN-114.
- Explicit `ConfigStreamRequest`, `GatewayRealmConfigSnapshotRequest`,
  `GatewayConfig`, and `GatewayWgRelayConfig` literals are updated, and every
  dependent workspace compiles against one exact shared revision.

## Notes

- 2026-07-13 04:11 - Created as the shared schema task for PLAN-114.
- 2026-07-13 05:09 - Revised for restart replay, generation-only SSE carriage,
  fixed-scope endpoint confinement, and the selected NSGW causal lease.
- 2026-07-13 07:02 - Re-grounded the forwarding contract on the independent
  signed realm-config snapshot, added verified timestamps, monotonic lease
  constants, and the default-false fleet cutover. Design tracking only; no
  production change is authorized.
- 2026-07-13 - Claimed after PLAN-114 implementation approval for cascade
  slice 1 of 4.
- 2026-07-13 - Completed the additive JSON/CBOR contract, authenticated
  timestamp exposure, checked reconnect sessions, scoped status propagation,
  endpoint confinement, and focused control-crate quality gates.
- 2026-07-13 - Reopened after the independent gate found that the config-stream
  delivery path discarded authenticated timing metadata and that the shared
  checked monotonic lease translation helper was missing.
- 2026-07-13 - Completed receipt-anchor propagation, the shared fail-closed
  deadline translator, three-transport fallback request coverage, and the real
  A/B fixed-scope connect/publish test; all control and workspace gates passed.
