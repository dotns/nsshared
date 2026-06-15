# CAPTURE-001 Define shared route-capture contract

- **status**: completed
- **priority**: P0
- **owner**: gx-e0-t0
- **createdAt**: 2026-06-15

## Description

Define the inert shared `capture_routes` projection for NSC route capture as a
separate additive field from service `routes`.

Acceptance criteria:

- `RoutingConfig` exposes a distinct `capture_routes` list that is omitted when
  empty and ignored by older consumers.
- Capture-route entries carry route id, generation, gateway/profile/realm
  binding, destination CIDRs, NSC source address/prefix, route table/priority
  policy, and kill-switch policy.
- The type shape does not carry service-domain, service-port, or backend VIP
  fields, and rustdoc states that capture routes never allocate service VIPs.
- CBOR round-trip coverage exists for the new route-capture shape.
- Existing empty `RoutingConfig`, `RouteEntry`, `WgConfig`, and public-edge wire
  shapes remain byte-identical when no capture routes are present.

## ActiveForm

Completed the shared route-capture contract.

## Dependencies

- **blocked by**: none
- **blocks**: nsd capture-route emission gate, NSC TUN route manager, gateway
  exit runtime

## Notes

- 2026-06-15: Investigation found the current service `RouteEntry` and
  public-edge backend enums are the wrong surface for captured exit CIDRs.
  Proposal recorded in `docs/plan/PLAN-005.md`; implementation waits for
  explicit PMA approval.
- 2026-06-15: Implemented the additive `RoutingConfig.capture_routes` contract,
  capability token, route-capture policy types, and CBOR round-trip /
  byte-stability coverage.
