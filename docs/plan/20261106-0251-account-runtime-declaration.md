# 20261106-0251-account-runtime-declaration Account runtime declaration contract

- **status**: implementing
- **createdAt**: 2026-11-06 02:51
- **approvedAt**: 2026-11-06 02:45
- **relatedTask**: 20261106-0251-account-runtime-declaration

## Context

Authentication already supplies an unchanged signed source. RuntimeBind supplies
a separate runtime fence. Neither carries an ordinary Node runtime capability
snapshot. Existing registration, binding, source and fence codecs remain authoritative.

## Proposal

Add node.runtime.declare.v1 with strict nested request and receipt codecs, complete
request digest, request authentication against independently retained membership
and signer facts, and response correlation against the exact pending request.
Reuse capability syntax without normalization or policy interpretation. Validate
canonical bytes and nested consumption, positive counters and all declared limits.

## Risks

Decoding or a valid signature cannot establish current custody. Producer transaction
admission and consumer current-attachment checks remain separate responsibilities.
Receipt matching includes the entire signed source and complete capability set.

## Scope

Only the new control leaf, operation and export wiring, necessary internal codec
visibility, focused account/control tests and these owned records change.
No dependencies, M6 variants, authentication bytes or source allocation change.

## Alternatives

Co-locating support in authentication would change its established six-field bytes.
The accepted separate declaration preserves that contract and orders support after bind.

## Validation

Commit focused test inputs before execution, implement the smallest codec and
validators, then commit the complete implementation before qualifying checks.
Retain first failures, exact source and immediate exits. Combined behavior requires
both consumers to adopt the same actually delivered immutable shared revision.
