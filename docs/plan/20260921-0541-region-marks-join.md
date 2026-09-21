# 20260921-0541-region-marks-join Add region marks join

- **status**: completed
- **createdAt**: 2026-09-21 05:41
- **approvedAt**: 2026-09-21 05:41
- **relatedTask**: 20260921-0541-region-marks-join

## Context

`RegionMarks` is the region-frame representation of a retained owner floor.
The normative marks rule defines a monotonic join and requires callers to
persist changed joins before route changes or publication. Existing fixture
verification uses separate loader and release-inventory witnesses.

## Proposal

Add a side-effect-free join for marks from one owner scope. It returns the
joined state and whether that state differs from the caller's current state.
The join takes the maximum present revocation, selects all generation-specific
fields from a higher generation, and merges equal-generation values with a
maximum incarnation, latched conflict, and lexicographically smallest key.
Add law-oriented tests and a sealed vector family with matching independent
inventory declarations.

## Risks

Changed reporting is directional because it compares the joined state with the
caller-owned current state. The joined state itself must remain associative,
commutative, and idempotent. A new fixture must update every independent seal
without altering existing vector bytes.

## Scope

The region marks API, join tests, one new fixture, and the two independent
fixture inventories.

## Alternatives

Embedding persistence or route application in the join would hide durable
completion and violate the pure state boundary, so the join returns data only.

## Annotations

Owner scope is validated before marks are combined so retained floors cannot
cross network or identity boundaries.

## Results

The completed join returns only state and a changed indicator; persistence,
route changes, acknowledgments, and publication remain caller effects. The
new sealed vector family is pinned by independent loader and release
inventories, including its digest and exact case list. Formatting, linting,
and the keynet-proto test suite completed without failures, skips, or ignored
cases.
