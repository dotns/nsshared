# 20261108-1300-mailbox-reply-capacity Refuse mailbox writes that make complete replies unreadable

- **status**: completed
- **priority**: P1
- **owner**: root/20261108-1300-mailbox-reply-capacity
- **createdAt**: 2026-11-08 13:00 UTC
- **relatedPlan**: 20261108-1300-mailbox-reply-capacity

## Description

Repair issue nsshared8 at the live broker admission boundary: accepted joins and
sends can create a complete mailbox reply larger than the unchanged16KiB frame.
All12 repositories/all branches were refreshed; no active mailbox capacity claim
or competing implementation exists. Existing backup, registration, release and
Gateway public-address owners retain their scopes.

## Scope

Own only live mailbox join/send prospective-response admission and focused tests
in nsshared, plus this task/plan and their index entries. No shared phase changes,
wire/schema/dependency/version changes, history replay policy, production state,
host network/power changes or unrelated mailbox lifetime refactor.

## Acceptance

Establish actual failing regressions on current source before changing runtime
code. Refuse a write atomically with existing Capacity/QueueFull when a complete
affected owner/peer reply exceeds hard or configured frame size. Keep accepted
messages readable in order; retry after acknowledgement must reuse the next
sequence. Preserve counters, participant indexes, notifications and durable
history on refusal. Replay existing large histories unchanged and explicitly
retain their old transactional receive failure; do not discard accepted data.
Verify normal small writes, exact byte boundaries and durable recovery; run
focused suites, repository gates and independent review before protected merge.

## Authorization

Full tier under the user's standing explicit repair/test/commit/push/merge
approval, renewed by the request to continue claiming and fixing bugs. This is a
bounded broker transport-capacity repair, not a shared protocol redesign.

## Admission probe boundary

Probe only the complete views named by the successful Join/Send outcome wake
list: owner for Join and recipient for Send. This prevents a pre-existing large
queue in the other direction from blocking a valid reverse-direction write.
Each probe uses a disposable clone and after0. Outer request rate/time accounting
retains its existing semantics; refusal has no new mailbox, durable-history or
notification effects.

## Initial verification

Actual unmodified-runtime regressions failed before the repair: NSGW4/4 and
canonical mock real-TLS2/2. Dependency transport setup failures are retained
separately and are not product RED. Focused regressions pass NSGW7/7 and
real-TLS2/2, including ACK/retry, exact configured limits, close and durable
refusal/replay controls. Full affected suites, quality gates and hosted QA are
still pending. No formal-environment or historical-data recovery pass is claimed.

## Final source qualification

Hosted QA on source2a95228 passes all616 tests with0 skipped, formatting,
workspace all-target Clippy, supply-chain/spelling/vector and repository gates.
This includes the new counter/watch and configured-boundary unit cases, plus
the2 authenticated real-TLS regressions. Independent source review passes.
Local focused TLS tests also pass; a standalone local self-check is not claimed
as completed. This component is ready for protected final-head checks and merge;
NSGW companion PR121 has its own independent acceptance. No formal production
acceptance or retroactive recovery of existing oversized data is claimed.

- complete: Exact-source hosted QA616/616, focused TLS2/2 and independent review pass; final-head protected merge remains gated.
