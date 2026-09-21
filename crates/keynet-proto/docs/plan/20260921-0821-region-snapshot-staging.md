# Region snapshot staging

- **status**: completed
- **createdAt**: 2026-09-21 08:21
- **approvedAt**: 2026-09-21 08:21

## Context

The region module already models authenticated presence events, durable mark
joins, origin revision watermarks, channel eligibility, and bounded published
presence. SNAPSHOT frames carry their cuts and nested records, but no pure
state captures an incoming multi-chunk snapshot before it is published.

The fixture release already seals region frame, mark, and presence families.
The presence family needs explicit cases for staged receipt, durable mark
joining, final publication, and every invalidation boundary.

## Proposal

Add a pure snapshot-staging table keyed by authenticated origin. It retains a
single bounded partial snapshot per origin and separately retains the last
completed identifier for stale-id rejection. Chunk decisions validate the
initial index, contiguous progression without wrap, stable identifier and
cuts, record ownership, sender epoch, revision range, derived slots, and
bounded staged entry count. Each accepted mark-bearing chunk returns its
changed durable-mark joins immediately. A later mark-bearing chunk is refused
until caller-owned durable marks prove the prior batch durable; neither path
publishes routes.

Retain full mark records only for the one batch awaiting durable proof. Once a
later valid input proves that batch durable, discard those records and retain
only a separately bounded full-owner index for duplicate detection across the
snapshot. Keep staged presence under its own bound. Completion rechecks that
the current durable state contains every owner from the drained prefix as well
as the complete floors in the remaining batch, rather than relying on an
unbounded in-memory mark union or an earlier observation.

Use the protocol slot derivation directly for every staged presence. Require a
completion callback to name the current authenticated stream and exact
snapshot id, returning unchanged state for a stale callback. Record the
greatest syntactically valid initial snapshot id before later capacity checks,
then preserve it across interruption and reconnect until the origin boot epoch
changes.

Apply an explicit per-origin mark-staging byte ceiling, capped by the protocol
64 KiB maximum. Charge the pending durable batch, the retained whole-snapshot
owner index, and their retained vector allocation overhead against that
ceiling. A count limit remains an additional bound, never a substitute for
byte accounting.

Add a completion decision that accepts only marks which already include every
requested durable join, validates staged presence against those resulting
floors, and then replaces the completed origin's presence while preserving
unrelated origins. Interruption and every invalid input discard only partial
staging, mark the origin unsynchronized, and leave caller-owned durable marks
unchanged. A new control connection resets partial staging for its origin.

Extend the sealed presence fixture inventory and its two independent release
inventory witnesses with the complete staging case family. Keep the v0.9
design pin unchanged and recalculate only the changed fixture and manifest
digests.

## Risks

Completion must not make staged entries eligible before the caller has
persisted every returned mark join and the current durable input still contains
the drained owners. A mark-bearing continuation must not grow staging before
the prior batch drains. Byte capacity checks must include retained allocation
capacity before staged-vector growth. A snapshot origin must not erase another
origin's published presence. A stale completion must never invalidate a
replacement stage, and an overflowed snapshot identifier must not become
reusable.

## Scope

- `src/region.rs` snapshot staging decisions and validation helpers.
- Region presence tests and sealed presence vectors.
- Fixture manifest, release inventory, vector inventory, and refutation
  inventory updates.

## Alternatives

Applying each chunk directly to published presence was rejected because an
interrupted or malformed transfer could expose a partial route set. Keeping
staging in hidden mutable state was rejected because callers need explicit,
testable state transitions and durable-mark ordering.

## Verification

The first focused test, `empty_snapshot_completes_only_after_durable_finalization`,
failed before implementation because the snapshot staging decision symbols did
not exist. The focused region presence, release inventory, refutation
inventory, and vector suites passed after implementation.

The focused regression
`nonfinal_mark_joins_stream_before_invalidation_and_backpressure` was run
before the per-chunk ordering change and failed with `a non-final mark chunk
did not request durable persistence while routes remained closed`. It passes
with immediate mark join effects, unchanged staging under batch backpressure,
and caller-owned durable floors retained after invalidation.

The focused refutations were run before the corrected model:
`persisted_mark_batches_do_not_accumulate_in_snapshot_staging` reported
`snapshot staging retained 257 mark records after the first batch was durable`;
`snapshot_slot_validation_uses_the_protocol_derivation` reported
`noncanonical slot was accepted with disposition AwaitingDurableMarks`;
`delayed_completion_cannot_invalidate_a_reconnected_snapshot` reported
`an old persistence completion discarded the reconnected snapshot`; and
`an_abandoned_snapshot_id_cannot_be_reused_after_reconnect` reported
`an abandoned snapshot id was accepted after reconnect`.

Formatting, warning-denied workspace linting, and the locked package test run
passed. The package test run executed 136 tests with zero skipped.

The corrected refutation targets, region presence suite, release inventories,
format check, warning-denied workspace lint, and locked package test run
passed. The package test run executed 141 tests with zero skipped or ignored.

The next focused refutations ran before the new invariant repairs:
`completion_rechecks_marks_from_every_durable_batch` failed with `snapshot
completed after an earlier durable floor disappeared`;
`mark_owner_index_obeys_the_snapshot_staging_byte_cap` failed with `snapshot
retained 65600 bytes of mark-owner index`; and
`an_overflowed_snapshot_id_cannot_restart_the_same_epoch` failed with
`capacity-invalidated snapshot id was accepted again`.

The final format check, warning-denied workspace lint, and locked package test
run passed. The package test run executed 144 tests with zero skipped, and no
package test is marked ignored.
