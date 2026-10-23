# Protocol-specific public-edge names

- **status**: implementing
- **createdAt**: 2026-10-23 15:48
- **approvedAt**: 2026-10-23 15:48

## Context

PublicEdge currently validates every route name as a hostname. Listener ownership already distinguishes HTTP hosts from raw protocol/port listeners.

## Proposal

Preserve the thirteen-position version 1 tuple and HTTP bytes. Represent the name as Option<String>; require HTTP text and raw null with empty aliases/domains. Restrict hostname ownership to HTTP. Update specifications and independent Python vectors before the codec.

## Risks

Raw-route bytes intentionally change. Updated consumers reject named raw routes and older consumers reject null raw names. HTTP host rules, backend uniqueness and material joins must remain intact.

## Scope

Pure public-edge API/codec, independent vectors and consumer tests, and the public-edge specification, profile and review request.

## Alternatives

Empty names and inferred hostnames violate the protocol contract.

## Validation

Establish a failing independent-vector test, then run formatting, lint and the repository self-check.
