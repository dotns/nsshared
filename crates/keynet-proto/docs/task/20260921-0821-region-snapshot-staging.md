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

## Corrected invariants

An accepted mark batch retains complete mark records only until caller input
proves that batch durable. Drained batches retain a separately bounded set of
full owners for whole-snapshot uniqueness, not their complete mark records or
the presence-stage allocation. Completion accepts a final stage only after its
undrained batch is durable and every earlier batch has already been proved
durable at the same snapshot cut.

Snapshot presence slots use the protocol `derive_slot_id` function directly.
Durable completion names the current authenticated stream and snapshot id, so
an older callback leaves a replacement stage unchanged. The per-origin cursor
records every accepted snapshot id and remains through interruption and
reconnect for the same boot epoch.

## Acceptance

- Empty final snapshots complete without publishing a route.
- Partial or malformed chunks never publish a route or acknowledgment.
- Durable marks survive every invalidation path.
- Each accepted mark-bearing chunk requests changed joins before final receipt.
- A later mark batch waits for durable caller input from the prior batch.
- Drained mark batches do not consume the presence-stage bound, while a
  separately bounded owner index still rejects duplicates across the snapshot.
- Completion callbacks match both the current stream and snapshot id.
- An accepted snapshot id cannot be reused within its boot epoch.
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

The focused refutations were run before these invariant repairs:
`persisted_mark_batches_do_not_accumulate_in_snapshot_staging` failed with
`snapshot staging retained 257 mark records after the first batch was durable`;
`snapshot_slot_validation_uses_the_protocol_derivation` failed with
`noncanonical slot was accepted with disposition AwaitingDurableMarks`;
`delayed_completion_cannot_invalidate_a_reconnected_snapshot` failed with
`an old persistence completion discarded the reconnected snapshot`; and
`an_abandoned_snapshot_id_cannot_be_reused_after_reconnect` failed with
`an abandoned snapshot id was accepted after reconnect`.

The first focused test failed before implementation because the staging
decision API was absent. The final focused fixture suites and the locked
package test run passed; 136 tests executed with zero skipped.

The corrected refutation targets, region presence suite, release inventories,
format check, warning-denied workspace lint, and locked package test run
passed. The package test run executed 141 tests with zero skipped or ignored.
