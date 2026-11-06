# 20261106-0251-account-runtime-declaration Account runtime declaration contract

- **status**: completed
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


## Outcome

The selected operation, strict eight-field request, three-field receipt and pure
validators are implemented. Existing binding/source encodings remain unchanged;
only the registration and runtime-fence codec helpers gained control-module
visibility. The complete canonical request digest includes the source signature
and full supported capability set. Independent membership and signer trust remain
separate from current storage authority.

All six focused tests and the prescribed self-check passed on committed input
`1fabaccf6ff5f3b81919ab3eb45ec493f933be26`; full QA selected by that self-check
passed 424 default and 597 Account tests, with all existing vector and static gates.
The initial missing-API/test-import compilation failure and the subsequent two
fixture-constant lint failures are retained in the execution evidence. No failure
was waived or converted into a passing run. Publication and matched producer/client
qualification remain separate delivery steps.
