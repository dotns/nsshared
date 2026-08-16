# NODE-002 Give the approved-subnet-route projection a consumer channel

- **status**: review — must merge with the ns arm, not ahead of it
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

## Implementation

Landed on `bkd/3xgps08o` as `d99cc24`, from main `4ee2f95`. Paired with ns
NODE-003 stage S4d on ns `bkd/3xgps08o`; **one merge window**, and this
repository must not merge ahead of `ns`.

### What shipped

One file, `crates/control/src/lib.rs`:

- `ControlPlane::subnet_route_tx: Option<mpsc::Sender<SubnetRouteConfig>>` and
  `pub fn set_subnet_route_tx`.
- The `ControlMessage::SubnetRouteConfig` arm forwards the decoded projection
  when a consumer is attached, treats a dropped receiver as shutdown like every
  other attached consumer, and keeps NODE-001's decode-and-ignore log when no
  consumer is attached.

`ControlPlaneInit`, `MultiControlPlaneInit`, `ControlMessage`,
`subnet_route.rs`, and every existing call site are untouched.

### Cascade result

| repository | commit built | command | result |
|---|---|---|---|
| `ns` | `5d650e1` | `cargo build --workspace --all-targets` | pass |
| `nsd` | `7719a5f` | `cargo build --workspace --all-targets` | pass |
| `nsgw` | `87fb4cf` | `cargo build --workspace --all-targets` | pass |

**Neither `nsd` nor `nsgw` needed an edit.** That is a consequence of the
optional-sender shape: it adds no field a caller must initialize and no tuple
element a caller must destructure.

### Evidence

| test | proves |
|---|---|
| `an_attached_consumer_receives_the_subnet_route_projection` | a real `subnet_route_config.v1` message driven through the real `run_loop` arrives on the attached receiver, unchanged |
| `no_consumer_leaves_the_projection_decoded_and_ignored` | **a guard, not a defect proof.** It passes on both trees by design and pins the unchanged behaviour of every consumer that attaches nothing. It observes the *next* message still dispatching, because a shutdown on the projection would stop the loop before it arrives |

RED: reverting the arm to decode-and-ignore while keeping the field and setter
— so the failure is an assertion, not a compile error — fails
`an_attached_consumer_receives_the_subnet_route_projection` with
`the projection must reach an attached consumer: Elapsed(())`. The guard test
passed under that mutation, as its label says it should. The mutation was
injected after the green tree was committed, then reverted, and both proofs
re-checked against the final tree.

The other half of the live path — the projection reaching
`Agent::admit_subnet_routes` — is in `ns`, recorded under NODE-003 S4d.

### Pre-existing tests and pins modified

**No others.** No existing test was changed, deleted, or weakened, and no
pinned invariant moved.

### Gate results

Each stage's exit code captured directly, never through a pipe.

| stage | command | exit |
|---|---|---|
| fmt | `cargo fmt --all` | **0** |
| lint | `cargo clippy --workspace --all-targets -- -D warnings` | **0** |
| test | `cargo test --workspace --no-fail-fast` | **0** — 683 passed, 0 failed, 0 ignored across 12 suites |

## Annotations

- 2026-08-16 22:55 UTC: Claimed on `bkd/3xgps08o` from main `4ee2f95`, paired
  with ns NODE-003 stage S4d on ns branch `bkd/3xgps08o`. One merge window
  across both repositories.
- 2026-08-16 23:30 UTC: Implemented. The cross-repository cascade an earlier ns
  slice anticipated was measured and is smaller than stated: the dispatch arm
  already existed, so no wire contract, enum variant, or exhaustive match
  changed, and both consumer repositories built unmodified.
