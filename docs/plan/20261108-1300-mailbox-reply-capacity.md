# 20261108-1300-mailbox-reply-capacity Refuse mailbox writes that make complete replies unreadable

- **status**: completed
- **createdAt**: 2026-11-08 13:00 UTC
- **approvedAt**: 2026-11-08 13:00 UTC (standing explicit user authorization)
- **relatedTask**: 20261108-1300-mailbox-reply-capacity

## Context

Mailbox phase transitions validate individual payload and queue limits but not
the serialized full reply. Four4096-byte intros or two8192-byte messages exceed
the16KiB transport envelope after their writes already succeeded. Broker receive
encoding failure then leaves state intact but inaccessible.

## Proposal

Keep the shared state machine and its historical replay unchanged. In each live
broker's existing speculative transition, encode prospective affected owner/peer full
views before join/send commit. Map oversize join to Capacity and oversize send
to QueueFull. Do not emit partial views, raise frame limits or introduce cursors.
The same broker boundary is repaired in NSGW and the canonical shared mock.

## Risks

A check must not acknowledge data, refresh activity, notify waiters, consume a
sequence or append durable history. Inspect an isolated clone. Existing oversized
histories must still replay without rejecting or deleting original accepted
records; their existing receive refusal remains explicit until normal expiry or
existing actor operations reduce state. This prevents newly unreadable states;
it does not retroactively claim old oversized records are newly readable.

## Verification

Actual RED then GREEN for max introductions and messages, configured cap and
boundary controls, both directions, refusal bookkeeping, ACK/retry sequences,
and durable reconstruction. Preserve the old oversized receive regression using
legacy history fixtures, rather than creating new oversized live writes. Run the
affected suites, repository quality gates, independent review and hosted QA.

## Alternatives

Changing the shared phase's join/send rules would also change durable historical
replay. Raising limits, truncating replies or discarding histories changes the
protocol or loses accepted data. Broker-level prospective admission avoids those
changes and requires no dependency-pin or schema migration.

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
