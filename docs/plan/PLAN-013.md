# PLAN-013 Causal scoped WG relay wire contract

- **status**: completed
- **createdAt**: 2026-07-13
- **approvedAt**: 2026-07-13
- **relatedTask**: CTRL-019

## Context

The control crate currently has no restart-unique stream session on either the
config stream or the independently polled realm snapshot. `GatewayConfig` and
`GatewayWgRelayConfig` carry no causal roster or lease metadata. Signed config
event and unary response verification authenticates an envelope timestamp but
returns only the decoded payload or unit, preventing consumers from performing
the required one-time monotonic deadline translation.

The approved PLAN-114 cascade requires an additive shared contract before NSD,
NSGW, and the ns consumer can compile their behavior slices against one exact
revision. It also requires the shared control runtime to bind that session to
each logical reconnect, preserve it across endpoint fallbacks, publish
scope/session-specific status, and endpoint-confine fixed-scope children.

## Proposal

Add a checked `ControlStreamSession` with a random non-zero 128-bit boot nonce
and `NonZeroU32` attempt counter. Carry it optionally on both signed request
types and preserve signed request carriage for session-only config streams.

Attach an optional per-scope `WgRelayIdentityRoster` to `GatewayConfig` and an
optional per-realm `WgRelayForwardingLease` to `GatewayWgRelayConfig`. Missing
fields remain unproven, and the fleet gate defaults false. Return a shared
verified-payload wrapper containing the authenticated envelope Unix timestamp
from config-event and unary verification. Export the fixed lease, skew,
margin, guard, and healthy-renewal constants with their required inequality.

Add JSON/CBOR round-trip, omission-default, old/new unknown-field compatibility,
session invariant, timestamp exposure, and constant relationship tests.

Retain a receipt-time `Instant` alongside the authenticated signed timestamp in
the non-wire verified-payload wrapper. Preserve both values through SSE framing,
the control stream, gateway dispatch, and `ScopedGatewayConfig`; no `Instant`
is serialized. Add one public fallible lease-deadline translator implementing
the exact PLAN-114 guard, checked arithmetic, strict ordering, and fail-closed
overflow behavior for every downstream consumer.

Exercise one logical session across multiple SSE, Noise, and QUIC fallback
attempts by inspecting the signed request each transport receives. Exercise a
fixed-scope B child against real A/B listeners and verify that only B receives
the stream request and that the signed gateway event is published with scope B.

Generate one session nonce per `ControlPlane`, advance its checked attempt once
per outer reconnect, and carry the exact session on every transport fallback.
Replace boolean-only status with scope/session-specific status on both internal
edges. Build every `MultiControlPlane` child from exactly its selected endpoint
and remove config-arrival-based synthetic connection success.

## Risks

- Public verification return types and explicit struct literals are expected
  source breaks for same-window path dependents.
- A zero nonce or exhausted attempt counter must fail closed rather than wrap.
- Omitting a roster, lease, session, or fleet gate must never become an
  authoritative empty or ready state.
- A child that retains inherited endpoint selectors could publish one NSD's
  state under another scope; fixed-scope configs must contain one endpoint.

## Scope

The control-crate wire types, verification result API, shared constants,
session lifecycle and signed request carriage, scoped status, fixed-scope
endpoint confinement, focused compatibility tests, tracking records, and
changelog entry only. NSD publication, NSGW monotonic enforcement, and ns
readiness behavior remain in the downstream cascade slices.

## Alternatives

Returning only a timestamp from unary verification was rejected because the
config-event path would still need a separate payload-plus-time shape. One
generic verified-payload wrapper keeps both authenticated paths consistent.

## Annotations

- Approved by the explicit PLAN-114 implementation dispatch on 2026-07-13.

## Outcome

Added the additive roster, forwarding-lease, and exact-session wire shapes.
Both signed verification paths now retain the authenticated signed timestamp
and a receipt-time monotonic anchor. Config-stream metadata remains intact
through SSE framing, dispatch, queueing, and `ScopedGatewayConfig`. The one
shared checked translator implements the fixed PLAN-114 guard and fails closed
on invalid bounds, ordering, or monotonic overflow. The control runtime carries
one session through the actual SSE, Noise, and QUIC fallback loop, and a real
A/B SSE scenario proves fixed-scope B connects only to B before publishing B
state. Focused control tests and the full repository quality gate pass.
