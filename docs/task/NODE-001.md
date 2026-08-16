# NODE-001 Define unified node capability and subnet-route contracts

- **status**: pending
- **priority**: P0
- **owner**: unassigned
- **createdAt**: 2026-08-16 06:06 UTC
- **relatedPlan**: PLAN-015

## Description

Implement the additive capability vocabulary, bounded route-advertisement
report, and authoritative approved-subnet-route projection selected by
PLAN-015 without changing existing service or capture-route semantics.

## Acceptance criteria

- Capability constants and route types have one shared implementation owner.
- IPv4 prefix, route-count, encoded-size, identity, and generation validation
  is deterministic and bounded.
- Overlay-reserved range rejection takes NSD's effective `vip_pool` /
  `tunnel_ip_pool` as an input. A validator pinned to the default CIDRs is a
  defect: both pools are operator-configurable, so a deployment that overrides
  either would accept a prefix swallowing the overlay's own address space.
- Full-snapshot withdrawal and stale-generation behavior is explicit.
- Old/new round trips and cross-repository fixtures prove compatibility.
- Unknown capabilities and advertisements never grant route authority.
- ns-shared locked QA plus focused ns/nsd/nsgw compatibility gates pass.

## Dependencies

- **blocked by**: PLAN-015 approval
- **blocks**: ns PLAN-124 S2-S4, nsd PLAN-129, nsgw PLAN-123

## Notes

- 2026-08-16 06:06 UTC: Proposal task created pending approval; unclaimed.
- 2026-08-16 06:27 UTC: Plan review applied — overlay-reserved range rejection
  now takes NSD's effective pool configuration as an input instead of pinning
  the default CIDRs.
