# 20260921-0634-region-presence-decision Region presence decision

- **status**: completed
- **createdAt**: 2026-09-21 06:34
- **approvedAt**: 2026-09-21 06:34
- **relatedTask**: 20260921-0634-region-presence-decision

## Context

The region codec models frames and retained marks but does not yet model the pure decision that selects usable origin presence. The fixture seal currently declares frame and mark families only.

## Proposal

Introduce a side-effect-free transition with an explicit presence table, authenticated stream, event, retained marks, channel states, capacity, and local retirement revision. It will retain scalar high-water revisions per origin, reject stale streams and revisions, require compatible marks and a live channel pair for eligibility, apply generation then incarnation ordering, and use member id only for equal eligible state. Local supersession produces exactly four mesh-local actions.

Add fixture cases for origin ownership, full-owner collisions, ordering, mark filtering, retirement precision, revision watermarks, stale streams, epoch replacement, local supersession, grace eligibility, and retained floors. Declare the family independently in the fixture loader and release inventory.

## Risks

The state table must preserve retained marks outside the transition and must not let an ineligible higher-generation record displace an eligible record. Boot epochs must be treated as opaque identities rather than numeric versions.

## Scope

Region presence decision types and tests; one new sealed fixture file; manifest and independent fixture inventories.

## Alternatives

Keeping opaque mutable state would hide origin, channel, and capacity inputs and would make deterministic validation difficult, so the transition returns its complete next table instead.

## Annotations

The requested change authorizes implementation after this investigation and proposal.

Implementation completed with a sealed region-presence family, independent loader and release inventory declarations, and pure state-transition coverage for the documented ordering and retirement rules.
