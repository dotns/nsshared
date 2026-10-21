# Source binding and route selection

- **status**: in_progress
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
- 101 independently generated cases cover source/profile, request/attempt,
  channel, complete-empty/failure, exact clear targets, malformed/retired fields,
  multi-scope snapshot atomicity and ambiguous-source refusal.
- The failing-first consumer test initially found missing APIs. An executable
  follow-up failed with `request-fresh-attempt: Err(Authority)` before the fix;
  fresh carrier nonces now preserve original request/receipt ownership without
  bypassing carrier replay checks.
- Four focused tests pass. `just self-check` against the integration baseline
  passed formatting, lint, supply-chain, unused dependency, spelling, independent
  vectors, public API, 41 check-selection tests, 491 workspace tests with zero
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
