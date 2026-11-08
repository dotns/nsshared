# 20261108-1351-mailbox-open-lookup-capacity Investigate configured Open and lookup reply capacity

- **status**: in_progress
- **priority**: P1
- **owner**: root/acl-contract-open-lookup-20261108-1351
- **createdAt**: 2026-11-08 13:51 UTC
- **relatedPlan**: 20261108-1351-mailbox-open-lookup-capacity

## Scope

Calculate canonical configured-cap reachability, add an authenticated TLS regression
and perform the authorized minimal Open precommit Found reply admission repair.
Base is origin/main98e3f002, which contains PR30. No shared phase, wire, dependencies,
Join/Send implementation or tracking, production, push or merge operation.

## Acceptance

Confirm Challenge, Hello, Open and Opened fit the selected cap while Found does not.
If impossible, record falsification rather than inventing a defect. If reachable,
establish a real authenticated loopback TLS RED and retain raw evidence for Root.
Root extended this claim to the minimal Shared repair after actual RED. Final
independent review, commit, hosted QA and merge remain Root's scope.

## Authorization

Full investigation/testing tier under the user's standing repair authorization and
Root's explicit delegated test-only request; proposal gate is already satisfied.

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
