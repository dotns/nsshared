# 20260921-0634-region-presence-decision Region presence decision

- **status**: completed
- **createdAt**: 2026-09-21 06:34
- **approvedAt**: 2026-09-21 06:34
- **relatedTask**: 20260921-0634-region-presence-decision

## Context

The region codec models frames and retained marks but does not yet model the pure decision that selects usable origin presence. The fixture seal currently declares frame and mark families only.

## Proposal

Introduce a side-effect-free transition with an explicit presence table, authenticated stream, event, retained marks, channel states, capacity, and local retirement revision. It retains scalar high-water revisions per origin, rejects stale streams and revisions, selects generation before incarnation regardless of channel eligibility, and uses compatible durable marks and a live channel pair only to determine whether the selected record is eligible. Member id resolves only an equal generation and incarnation with compatible marks. Local supersession produces exactly four mesh-local actions.

Add fixture cases for origin ownership, full-owner collisions, ordering, mark filtering, retirement precision, revision watermarks, stale streams, epoch replacement, local supersession, grace eligibility, and retained floors. Declare the family independently in the fixture loader and release inventory.

## Risks

The state table must preserve retained marks outside the transition and must keep a higher-generation record selected even when a required channel makes it ineligible. Boot epochs must be treated as opaque identities rather than numeric versions.

## Scope

Region presence decision types and tests; one new sealed fixture file; manifest and independent fixture inventories.

## Alternatives

Keeping opaque mutable state would hide origin, channel, and capacity inputs and would make deterministic validation difficult, so the transition returns its complete next table instead.

## Annotations

Separating deterministic session selection from route eligibility prevents temporary channel loss from changing ownership while retaining durable-mark floors as the eligibility boundary.

The completed table has a sealed region-presence family, independent loader and release inventory declarations, and pure state-transition coverage for ordering and retirement rules.
