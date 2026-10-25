# Source binding and route selection

- **status**: completed
- **priority**: P1
- **owner**: (exclusive)
- **createdAt**: 2026-10-21 03:57

## Description

Deliver typed signed source authority, exact publication delivery fences and
Node/route select-clear DTOs with immutable original receipt decisions.

## ActiveForm

Implementing source-bound publication and selection contracts.

## Dependencies

- **blocked by**: canonical realm identity (completed)
- **blocks**: source-aware consumer adoption

## Notes

Investigation and approved proposal: ../plan/20261021-0357-source-selection.md.
Specification and independent vectors precede implementation. Directory/participant
definitions retain their separate ownership; producer review remains open.

## Acceptance

- `source_selection_fence` accepts A, selects/clears A, replaces authority with B
  while I/K/N4/N6 stay fixed, selects B, refuses A's higher-version delayed event
  before and after canonical restoration, preserves A's original clear receipt
  and B's selection, and accepts B's current event.
- 129 independently generated cases cover source/profile, request/attempt,
  channel, complete-empty/failure, exact clear targets, malformed/retired fields,
  multi-scope snapshot atomicity and ambiguous-source refusal.
- The failing-first consumer test initially found missing APIs. An executable
  follow-up failed with `request-fresh-attempt: Err(Authority)` before the fix;
  fresh carrier nonces now preserve original request/receipt ownership without
  bypassing carrier replay checks.
- Four focused tests pass. `just self-check` against the integration baseline
  passed formatting, lint, supply-chain, unused dependency, spelling, independent
  vectors, public API, 41 check-selection tests, 492 workspace tests with zero
  skipped, doctests and documentation compilation.
- Local review covered all new source and producer code and changed documentation;
  no unresolved implementation findings remain. M6 and existing publication bytes
  are unchanged; the mandatory outer signed-byte delta is explicit.

## Documentation and external adoption

Q18 records the settled owner choice: shared participant credential plus separate
NSD-signed directory binding, with the global directory unchanged. P07 owns the
pending shared definitions; P08 owns pending gateway adoption. The source/selection
candidate only cross-references them and defines neither contract. NSD producer
review, producer vectors and NSD/ns adoption remain outstanding; fixture acceptance
establishes neither confirmation nor interoperability.

## Completion

Q18 now consistently distinguishes the settled owner choice from pending P07
shared definitions, P08 gateway adoption and external NSD/ns work. No participant
or directory-binding contract was added to the source/selection implementation.
The current `just self-check` at 68c6591 passed, including 491 workspace tests
with zero skipped. The candidate documentation and implementation are complete;
NSD producer review, producer vectors and runtime adoption remain outstanding.

## Snapshot channel validation

Inspection found that source snapshot aggregation retained ChannelMismatch beside
valid replacements. UnknownKind also requires an explicit signed snapshot-channel
check because the low-level event decision recognizes extensions before checking
known ownership. Both source snapshot APIs share the same aggregation path.

Reject a complete source snapshot on a known channel mismatch or an extension
that declares Stream. Preserve authenticated snapshot-channel unknown pairs and
exact source/context/scope, ordering and multi-scope atomicity. Keep the existing
low-level publication contracts unchanged. Verify the imported stream-entry
regression, independent mixed-event accepted/refused vectors and the current
self-check before recording completion.

## Snapshot validation results

The stream-entry regression first failed with an accepted batch containing
ChannelMismatch and Replace. Independently generated mixed-event cases also
failed before the fix. Both source snapshot APIs now reject channel mismatch
atomically, including a known stream-owned pair that declares Snapshot and an
unknown pair that declares Stream. Authenticated snapshot-channel UnknownKind
extensions retain their adjacent valid actions.

The corpus contains 129 independent cases, including 28 new mixed batches:
six accepted controls and 22 refused batches. Every new batch has independently
ordered full keys and checked per-event authentication/actions; all single-scope
batches exercise both entry points, and multi-scope batches preserve atomicity.
Bad inner/outer signatures, old source, wrong context and wrong scope remain
refused. The valid-only and authenticated mixed-extension controls are retained.

Nine focused tests passed. The current `just self-check` at 619eacf passed
formatting, lint, dependency checks, spelling, independent vectors, API checks,
41 check-selection tests, 492 workspace tests with zero skipped, doctests and
documentation compilation. Only these completion records changed afterward.

Inspection covered every ChannelMismatch/UnknownKind handling path. The source
snapshot aggregator was fixed, and the single-source wrapper inherits that fix.
The snapshot-request boundary already checks both declared channel and known
ownership. Low-level publication decisions and raw snapshot neutral-result
semantics remain unchanged, along with their existing independent controls;
strict source snapshot validation adds no new low-level contract requirement.
