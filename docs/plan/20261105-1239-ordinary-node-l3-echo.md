# 20261105-1239-ordinary-node-l3-echo Ordinary Node L3 Echo authorization

- **status**: completed
- **createdAt**: 2026-11-05 12:39
- **approvedAt**: 2026-11-05 12:39
- **relatedTask**: 20261105-1239-ordinary-node-l3-echo

## Context

The Node L3 codec currently uses the TCP/UDP-only TransportProtocol shared with Service grants and Realm rules. Both protocol decoding and nonzero port validation refuse Echo. The existing canonical six-field rule and exact namespace/identity authority wrapper must remain intact. A distinct L3Protocol can add fixed Echo selectors without widening unrelated authority. The public Node module needs only a re-export of that type.

## Proposal

Introduce Node-only L3Protocol values EchoV4=1, Tcp=6, Udp=17 and EchoV6=58. Echo requires both existing port slots to be zero; TCP/UDP retain nonzero inclusive ranges and unchanged canonical bytes. Export the type through the Node module. Extend actual codec and authority tests and define fixed request/reply types, code zero, authenticated runtime feature custody, mixed-version refusal and the released enforcement prerequisite in the normative specification.

## Risks

The new Rust field type requires consumers to migrate their Node protocol matches. Old decoders reject new wire values. Capability admission must therefore precede issuance, and consumer enablement remains unavailable without an immutable released code-zero-before-state enforcement path. Codec acceptance alone demonstrates no packet enforcement.

## Scope

Node L3 representation and its public export, account codec/authority/route tests, and account specifications. Existing non-Node TransportProtocol and decoders remain TCP/UDP-only. No dependency, runtime advertisement or deployment changes.

## Alternatives

Widening TransportProtocol would expand unrelated family authority and is rejected. New type/code fields are unnecessary because the two Echo selectors have fixed semantics.

## Validation

Record a decoder failure before implementation, run standalone formatting and lint checks before tests, verify focused account cases, and run the prescribed self-check. Retain exact TCP/UDP fixtures and verify malformed, unknown, scope, identity, direction and non-Node refusal.


## Outcome

Implemented the distinct Node protocol representation, minimal public export and zero-slot Echo validation. Existing TCP/UDP encodings and non-Node protocol types and decoders remain unchanged. Actual codec and authority tests cover both Echo selectors, malformed forms and exact scope boundaries; existing route and transport vectors continue to pass.

The decoder regression failed before implementation and passed afterward. The focused selection passed 32 tests. The final self-check passed all prescribed static checks, 70 script tests, 422 default-feature tests and 588 account-feature tests, with zero nextest skips. Documentation checks passed with the existing ignored doctest preserved. Local review found no unresolved defects.

This delivers a shared contract for immutable producer/consumer pinning. Consumer capability advertisement and Echo enablement still require compatible released enforcement of code zero before flow-state grant or reuse. Construction and codec validation alone do not qualify packet delivery.
