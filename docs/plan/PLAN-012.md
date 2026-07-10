# PLAN-012 Public-edge upstream authority wire contract

- **status**: completed
- **createdAt**: 2026-07-10 11:01
- **approvedAt**: 2026-07-10 11:01
- **relatedTask**: EDGE-005

## Context

`GatewayHttpRoute` already carries optional `upstream_tls`, whose `sni` is produced from the public route host. It has no field for the authority sent to the HTTP backend, so NSGW currently preserves the inbound public Host. The shared contract is consumed through sibling path dependencies by NSD and NSGW.

## Proposal

Add `upstream_authority: Option<String>` to `GatewayHttpRoute` with `serde(default, skip_serializing_if = "Option::is_none")`. Keep `PublicEdgeUpstreamTlsPolicy.sni` as the only wire-level TLS SNI source; NSD derives that value from the explicit upstream authority when present, otherwise from `host`. Add JSON/CBOR round-trip and legacy-decode tests.

## Risks

- Struct literals in consumers must initialize the additive field.
- A consumer must reject malformed authorities instead of forwarding them.

## Scope

Shared control message shape, compatibility tests, PMA records, and changelog only.

## Alternatives

A second route-level `upstream_sni` field was rejected because it would create two independently configurable sources alongside `upstream_tls.sni`.

## Annotations

- Approved by the user's option 1 decision: generic route-level product fix with no development-only sidecar.

## Outcome

Added the optional serde-compatible authority field and contract documentation.
The existing TLS policy remains the sole SNI wire value, derived by producers
from the override when present. Focused compatibility tests and `just qa`
passed.
