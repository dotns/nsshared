# NODE-002 Give the approved-subnet-route projection a consumer channel

- **status**: in progress
- **priority**: P0
- **owner**: node-002-s4d
- **createdAt**: 2026-08-16 22:55 UTC
- **claimedAt**: 2026-08-16 22:55 UTC
- **relatedPlan**: PLAN-015

## Description

NODE-001 landed the `subnet_route_config.v1` wire contract and a
`ControlMessage::SubnetRouteConfig` dispatch arm that deliberately decodes and
drops: installing approved subnet routes is node data-plane work, so the arm
carries an explicit comment saying the consumer is not wired.

The node-side consumer now exists. ns PLAN-124 S4b shipped
`Agent::admit_subnet_routes` and `Agent::reconnect_control_session` with a real
implementation and no caller, because nothing in this repository could deliver a
projection to a running agent. This task closes exactly that: the dispatch arm
gains an optional consumer channel, so a node that wants approved subnet routes
can receive them.

Nothing about the wire contract changes. No message type, enum variant, field,
or bound is added, removed, or renamed.

## Acceptance criteria

- `ControlPlane` can hand an approved-subnet-route projection to a consumer that
  asks for one.
- A control plane with no consumer attached behaves exactly as it does today:
  decode, log, ignore. No route state, no channel send, no behaviour change for
  `nsc`, `nsn`, `nsd`, or `nsgw`.
- A dropped receiver is treated as shutdown, consistent with every other
  attached consumer in `dispatch_message`.
- The projection is proven to arrive through the real dispatch path, not by a
  direct call to the arm.
- Locked QA passes, and `ns`, `nsd`, and `nsgw` all build against this exact
  tree.

## Dependencies

- **blocked by**: NODE-001 (contracts)
- **blocks**: ns PLAN-124 S4d

## Proposal

### Shape

`ControlPlane` gains one field and one setter:

```rust
subnet_route_tx: Option<mpsc::Sender<SubnetRouteConfig>>,
pub fn set_subnet_route_tx(&mut self, tx: mpsc::Sender<SubnetRouteConfig>)
```

This copies `status_tx`, not `peer_candidates_tx`. Both are in the same
established channel set, and the optional form is chosen deliberately:

1. **A mandatory channel is a shutdown hazard for consumers that will never want
   it.** Every mandatory arm in `dispatch_message` treats a dropped receiver as
   `return Ok(true)` — shut the control plane down. `nsc` and `nsn` do not
   consume subnet routes, so a mandatory receiver would force each to spawn a
   drain task (as they already must for `peer_candidates_rx`) or silently
   acquire a control plane that exits on the first projection.
2. **The init tuples are already wide.** `ControlPlaneInit` is a 9-tuple and
   `MultiControlPlaneInit` a 10-tuple; widening both forces a destructuring edit
   at every call site in two repositories purely to say "not interested".
3. **Fail-closed either way.** No sender means no consumer means no route
   admitted — today's behaviour.

### Cascade surface

Adding a field to a struct that other repositories construct can break a
construction site even when no match arm changes, so `ns`, `nsd`, and `nsgw` are
all built against this exact tree and each result is reported with the commit it
was built at. `ns-shared` must not merge ahead of its consumers.

### Evidence

A scripted `ControlStream` yields a real `subnet_route_config.v1` message into
the real `run_loop`, and the test asserts the projection arrives on the attached
receiver. Proving it through dispatch is the point: a test that called the arm
directly would demonstrate nothing about the wiring. A companion test holds the
no-consumer case at today's behaviour.

The other half of the live path — the projection reaching
`Agent::admit_subnet_routes` — lives in `ns`, because `dispatch_message` is
private and `run_loop` is `#[cfg(test)]`, and neither should be widened to make
one cross-repository test possible. The two halves meet at the receiver the
`ns-agent` binary connects.

## Annotations

- 2026-08-16 22:55 UTC: Claimed on `bkd/3xgps08o` from main `4ee2f95`, paired
  with ns NODE-003 stage S4d on ns branch `bkd/3xgps08o`. One merge window
  across both repositories.
