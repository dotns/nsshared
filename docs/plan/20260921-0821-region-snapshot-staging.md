# Region snapshot staging and durable-cut evidence

- **status**: completed
- **createdAt**: 2026-09-21 08:21
- **approvedAt**: 2026-09-21 08:21

## Context

The region module already has authenticated presence decisions, durable mark
joins, revision watermarks, channel eligibility, and bounded published
presence. Incoming `SNAPSHOT` chunks need a pure, bounded staging decision so
partial data cannot publish a route and durable mark work can drain before the
final chunk completes.

The fixture release seals frame, mark, and presence families independently.
The presence family therefore needs explicit records for staged receipt,
durable batches, durable-cut evidence, owner-index validation, replay fences,
completion, and every invalidation boundary.

## Decision

Use an explicit stage per authenticated origin/local boot-epoch pair. Chunks
start at zero, stay contiguous without wrapping, retain one identifier and two
cuts, and leave presence unpublished until a final `more = false` chunk has a
valid local durable-cut receipt.

Every mark-bearing chunk first emits an exact, bounded owner-index validation
request. The trusted local index atomically tests and reserves the current
batch owners in a snapshot-scoped exact index. Its result records scalar owner
count and deterministic allocation accounting, not a whole-cut owner list.
This keeps one pending batch bounded while preserving exact duplicate rejection
across batches that have already drained.

After owner validation, each changed mark join emits a typed durable-batch
effect. The caller may release that batch only with matching trusted local
storage evidence: authenticated origin and both boot epochs, current control
stream identity, identifier, cuts, contiguous progress, batch commitment,
store lineage, and non-rolled-back durable revision. Unchanged joins request
neither a write nor a revision advance. A final receipt binds the complete
ordered cut commitment and final progress, so completion covers drained values
without reconstructing them in memory.

Acknowledgments, receipts, and exact owner-index results are local integration
inputs rather than peer claims or wire fields. The pure decision validates
their scope and monotonicity, but cannot detect a false assertion from a
storage integration that claims forgotten data remains durable.

Replay fences are retained independently of active stages. A schema-valid,
authenticated nonzero identifier is reserved before staging admission; a
refused or abandoned identifier remains unavailable through same-epoch
reconnects and only a strictly greater restart is admitted. Fences are bounded
by the configured member set, do not consume an active staging slot, and do
not bypass that slot's capacity.

The 256-record chunk bound, 64 KiB pending mark-staging bound, and retained
owner-union limit remain unchanged. Empty chunks retain zero mark-staging
bytes. The sealed release retains its v0.9 design pin and updates manifest and
independent inventory witnesses together.

## Risks

Receipt validation must fail closed for missing, mismatched, stale, incomplete,
or rolled-back local evidence without allowing an older callback to change a
replacement stream. The external owner index must be exact and bounded; a
probabilistic result or an unaccounted full-cut allocation would weaken the
contract. Invalid chunks and capacity failures must discard only staged
presence, preserving caller-owned durable floors and replay fences.

## Historical failing-first evidence

The initial empty-final behavior test failed before the staging API existed.
The per-chunk persistence regression failed before streaming was added with
`a non-final mark chunk did not request durable persistence while routes
remained closed`.

The earlier bounded-streaming regressions failed before their repairs: drained
mark storage retained 257 records, a noncanonical slot was accepted, a delayed
completion removed a replacement stage, an abandoned identifier was accepted
after reconnect, an earlier durable floor could disappear at completion,
mark-owner allocation reached 65600 bytes, and a capacity-invalidated
identifier could restart.

The imported durability diagnostic ran before this revision with nine focused
cases: two controls passed and seven cases failed. Five failures reported
`Completed` where `DurableMarksNotPersisted` was required after a drained
generation, incarnation, revocation, conflict, or key representative regressed.
Two capacity-fence failures reported `AwaitingDurableMarks` where
`ChunkAfterCompletion` was required for a reused identifier.

The unchanged-floor control was added before the final streaming refinement and
failed with `an identical durable floor requested a no-op durable write`. It
now proves that a fully dominating batch advances staging without a persistence
effect or durable-revision change.

## Verification

Focused durability, streaming, byte-budget, replay-fence, staging, and release
inventory suites passed. The locked self-check passed formatting, warning-denied
workspace linting, and the package test suite: 159 tests executed, 159 passed,
zero skipped, and zero ignored. Release inventory validation confirms the
fixture manifest, per-file digests, independent witnesses, and v0.9 design pin.
