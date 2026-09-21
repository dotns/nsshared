# Region snapshot staging

## Status

Completed.

## Description

Provide a pure bounded decision model for incoming region snapshots. A valid
snapshot is staged by authenticated origin and becomes published presence only
after all chunks, durable mark joins, and floor validation succeed. Each
accepted chunk requests its changed durable mark joins immediately, while
presence remains staged until final durable completion. Invalid or interrupted
transfers retain caller-owned durable marks while withholding staged routes.

## Investigation

The existing presence table tracks selected records and origin revision state.
Its event decision already keeps durable marks as read-only inputs and makes
route eligibility depend on both completed synchronization and live channels.
The new staging state can therefore remain separate from the published table
until a successful completion decision.

## Proposal

Use explicit inputs for snapshot capacity, authenticated stream identity, slot
derivation, durable marks, channel state, and published presence capacity.
Return a replacement staging table, replacement presence table, ordered
durable-mark join requests, and a disposition for every input. A mark-bearing
chunk is refused without changing staging until caller input proves the prior
batch durable. Seal every new fixture case in the manifest and independent
inventories.

## Acceptance

- Empty final snapshots complete without publishing a route.
- Partial or malformed chunks never publish a route or acknowledgment.
- Durable marks survive every invalidation path.
- Each accepted mark-bearing chunk requests changed joins before final receipt.
- A later mark batch waits for durable caller input from the prior batch.
- Snapshot staging, fixture inventory, and release digest checks pass.

## Notes

The first behavior test covered an empty final snapshot and verified that
publication remained deferred until durable completion.

The focused regression
`nonfinal_mark_joins_stream_before_invalidation_and_backpressure` ran before
the ordering change and failed with `a non-final mark chunk did not request
durable persistence while routes remained closed`. It verifies immediate join
requests, bounded batch draining, invalidation of staged presence, and
preservation of the explicit durable-mark input.

The first focused test failed before implementation because the staging
decision API was absent. The final focused fixture suites and the locked
package test run passed; 136 tests executed with zero skipped.
