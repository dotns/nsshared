# 20261108-1351-mailbox-open-lookup-capacity Investigate configured Open and lookup reply capacity

- **status**: implementing
- **createdAt**: 2026-11-08 13:51 UTC
- **approvedAt**: 2026-11-08 13:51 UTC (explicit delegated test authorization)
- **relatedTask**: 20261108-1351-mailbox-open-lookup-capacity

## Context

Open carries owner intro into future Found. Configured capacity may differ from
hard transport capacity. Envelope arithmetic must establish reachability before
claiming a bug; actual initial authentication must pass the same selected cap.

## Proposal

Use unchanged canonical encoders to measure real valid messages. Add one separate
integration target using the existing authenticated TLS fixture for a reachable
candidate. After actual RED and Root's explicit scope extension, validate the full
Found before Open commits indexes, counts or notification state. Use existing
Capacity on response-cap exhaustion and preserve actual output and exit.

## Risks

False positives from comparing incomplete JSON, unreachable handshake limits or
invented timestamps are avoided by canonical encoding and actual TLS controls.

## Scope

Open-only broker guard, one atomic refusal/allocation-reuse unit control, new TLS
test target, own task/plan/index/changelog records and private receipts. Join/Send,
phase, replay, public schema, dependencies and new Opened validation remain unchanged.

## Alternatives

If no valid Open fits while its Found exceeds the cap, record a passing falsification
and leave product source unchanged. Root decides follow-up after the evidence.

## Reachability and authorized repair

On unchanged main98e3f002, canonical Open279 bytes was accepted with configured
cap279 after actual Challenge154 and signed Hello186. Actual Found284 violated
that cap; exact cap284 control passed. Actual TLS RED:2 passed/1 failed, exit101.
Root extended the same claim to the minimal Open precommit Found admission check
using existing Capacity; no Opened behavior change, phase, replay, pins or Join/Send
changes. Add atomic refusal/allocation-reuse control and run focused GREEN/gates.

## Observed behavior

The original mock actually sent and the authenticated TLS client received the
284-byte Found at configured cap279; lookup did not return InvalidMessage. This
is a configured reply-cap enforcement defect, not a default16KiB lookup outage.
The minimal guard refuses Open with Capacity before reserving its allocation.
The exact284-byte cap still accepts Open and returns Found, without truncation.

## Local verification

The new focused TLS/encoder tests pass3/3. The affected mock crate all-targets
suite passes60 tests with no failures or ignored tests. The initial nextest attempt
failed before executing tests because offline workspace metadata required absent
proptest1.11.0; it is retained as setup failure and not product RED or a green gate.
The completed cargo test suite used no retries. Root owns final hosted acceptance.

## Delivery checkpoint

Linked defect: [nsshared31](https://git.pvv.cc/nsiod/nsshared/issues/31), publicly
registered/coordinated by Root with the exact received-Found observation.
Affected-crate Clippy, doctests and workspace fmt check all completed with exit0.
Source and tests are ready for Root's independent review; no commit, push, merge,
deployment or production operation was performed by this worker. Task remains
in progress pending Root's final hosted acceptance and delivery.

## Root independent review

Independent review confirms that complete Found encoding and configured-size
admission precede all indexes, counters and watch/mailbox publication. Phase,
Join/Send and dependency pins are unchanged. Strengthened real-TLS controls
verify exact id, kind, intro bytes and expiry, preventing a truncation workaround;
all3 focused cases pass after that test-only addition. The original agent suite
passes60/60 mock tests, Clippy/doc/fmt/typos. Full hosted QA remains mandatory.
