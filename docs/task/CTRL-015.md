# CTRL-015 Add RouteEntry.aliases wire field for custom service-domain aliases

- **status**: in progress
- **priority**: P1
- **owner**: main session (ns PLAN-098, plan R)
- **createdAt**: 2026-07-02 07:46

## Description

Add an additive `aliases: Vec<String>` field to `control::messages::RouteEntry`,
carrying user-declared custom domains that resolve to the same service as the
canonical `domain` (FQID). Serde `#[serde(default, skip_serializing_if =
"Vec::is_empty")]` so an empty list serializes away and the wire stays
byte-identical for services without a declared domain (protects RoutingConfig
fixtures and envelope-pin flows). No other shared change. Producer/consumer
slices: nsd ROUTE-005, ns SVIP-005.

Acceptance:
- `RouteEntry` with empty `aliases` serializes without an `"aliases"` key
  (byte-identical to the pre-change wire).
- `RouteEntry` with populated `aliases` round-trips.
- Existing RouteEntry / RoutingConfig round-trip and legacy-decode tests stay
  green.

## ActiveForm

Adding RouteEntry.aliases additive wire field

## Dependencies

- **blocks**: nsd ROUTE-005, ns SVIP-005 (same-window path-dep cascade)

## Notes

- 2026-07-02: design anchored in ns PLAN-098 (plan R — aliases ride the
  consumer-side routing_config channel, not the producer-side dns_config).
