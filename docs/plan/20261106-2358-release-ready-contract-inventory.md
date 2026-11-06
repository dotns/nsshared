# Release-ready contract inventory

- **status**: completed
- **createdAt**: 2026-11-06 23:58
- **approvedAt**: 2026-11-06 23:58
- **relatedTask**: 20261106-2358-release-ready-contract-inventory

## Context

Shared release preparation needs a current inventory of each candidate
contract: its producer and consumers, the shared candidate vectors, the NSD
producer corpus that exercises it, the consumer copy and its review state.
The existing tables are bounded to older NSD and ns revisions, and NSD now
proposes a producer corpus for bootstrap discovery and `info.get` information.

## Proposal

Add one release-ready table to the candidate inventory, refreshed by source
inspection and file comparison at the current NSD, ns and nsgw revisions, and
point the family 1 producer gap at the proposed NSD corpus. Keep the gate,
release and review holds.

## Risks

A listed corpus must not read as a complete family suite, owner approval,
a matched downstream reader or live qualification. The bootstrap corpus is
not merged in NSD at the inspected revision.

## Scope

`docs/review/account-inventory.md` and these PMA records; no code, vectors,
dependencies or release changes.

## Alternatives

Rewriting the handoff and adoption records at the new revisions would mix a
release inventory with review evidence; they keep their named revisions.

## Validation

Documentation-only: check every named file, slice and vector against the
inspected revisions, compare the ns copies byte for byte, then run `just qa`.
