# Region snapshot staging and durable-cut evidence

- **status**: completed
- **priority**: P1
- **owner**: (none)
- **createdAt**: 2026-09-21 08:21

## Description

Provide a pure bounded decision for incoming region snapshots. Presence stays
staged until contiguous final receipt, exact owner validation, durable mark
batches, and a complete local durable-cut receipt succeed. Invalid transfers
retain caller-owned durable floors and suppress routes and acknowledgments.

## Investigation

Published presence and durable marks are already explicit caller-owned state.
The staging decision can therefore keep partial presence separate and request
local persistence or owner-index work as effects. A retained full mark batch
can be checked with the existing full join-domination predicate, but drained
values cannot safely be reconstructed at completion. A complete-cut receipt is
needed to cover those drained values.

Keeping every mark owner in the stage would make a streamed cut grow with the
whole retained union. Exact scoped requests to a bounded local owner index
retain only scalar progress in the stage while still rejecting a duplicate from
an earlier drained batch. Replay high-water must likewise be separate from
active staging occupancy so capacity rejection consumes an identifier without
admitting another origin past the stage bound.

## Implemented contract

- A typed local durable-batch acknowledgment binds stream, pair epochs,
  identifier, cuts, progress, commitment, store lineage, and durable revision.
  Changed joins require a revision advance; identical floors request neither a
  write nor a revision advance.
- A typed final receipt binds the complete ordered cut, final progress, and
  local store state. Missing or invalid evidence invalidates only the partial
  stage and leaves synchronization closed.
- Exact scoped owner validation uses a store-backed index request/result with
  bounded deterministic accounting. It retains no whole-cut owner vector in
  snapshot staging and rejects duplicate owners across drained batches.
- Identifier fences reserve valid new identifiers before fallible admission,
  survive same-epoch interruption and reconnect, reset only with an
  authenticated epoch replacement, and remain separate from active-stage
  capacity.
- Empty final cuts, unchanged joins, identical floors, and dominating floors
  are positive controls. No effect authorizes a route or acknowledgment before
  durable completion.

## Failing-first evidence

The original empty-final test failed before the staging decision symbols were
available. The per-chunk persistence regression then failed before the
streaming repair with `a non-final mark chunk did not request durable
persistence while routes remained closed`.

Earlier focused regressions recorded failures for accumulated drained batches,
noncanonical slots, delayed replacement callbacks, identifier reuse after
reconnect, missing earlier floors at completion, unbounded mark-owner bytes,
and identifier reuse after capacity failure.

The preserved durability diagnostic was executed before this rework. It ran
nine cases with two passing controls and seven failures: five non-dominating
drained floors completed instead of returning `DurableMarksNotPersisted`, and
two capacity refusals admitted a reused identifier instead of returning
`ChunkAfterCompletion`.

The unchanged-floor control was written before its final implementation and
failed with `an identical durable floor requested a no-op durable write`. It
now proves that an identical floor advances staging with no persistence effect
and no durable-revision change.

## Acceptance

- Non-final changed joins request local persistence before another mark batch
  or completion; interruption or malformed continuation discards staged
  presence but not caller-owned floors.
- Batch acknowledgments and final receipts reject mismatched commitments,
  stale control streams, rollback, incomplete progress, missing evidence, and
  incompatible durable state.
- Exact owner-index results reject duplicate owners across a drained boundary
  and reject non-exact allocation accounting; drained batches leave zero
  mark-staging bytes in the stage.
- A fenced origin cannot bypass an occupied staging slot, while a strictly
  newer identifier is admitted after the slot is released.
- Release metadata, fixture digests, and the two independent inventories agree
  on the revised sealed presence cases and unchanged v0.9 design pin.

## Verification

Focused staging and release inventory suites passed. The locked self-check
passed formatting, warning-denied workspace linting, and package tests: 159
executed, 159 passed, zero skipped, and zero ignored. The release inventory
also passed with the fixture manifest, per-file digests, independent witnesses,
and unchanged v0.9 design pin in agreement.
