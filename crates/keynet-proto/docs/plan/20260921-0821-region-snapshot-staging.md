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
persisted every returned mark join. A mark-bearing continuation must not grow
staging before the prior batch drains. Capacity checks must precede
staged-vector growth. A snapshot origin must not erase another origin's
published presence.

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

Formatting, warning-denied workspace linting, and the locked package test run
passed. The package test run executed 136 tests with zero skipped.
