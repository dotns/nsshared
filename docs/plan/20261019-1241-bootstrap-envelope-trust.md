# Bootstrap discovery and envelope trust

- **status**: implementing
- **createdAt**: 2026-10-19 12:41
- **approvedAt**: 2026-10-19 12:41
- **relatedTask**: 20261019-1241-bootstrap-envelope-trust

## Context

Family 11 already covers discovery and envelope verification but has no detailed
contract. Enrollment binds membership keys; it does not establish transport trust.
The existing signed roster demonstrates canonical content inside a signed carrier.
The service-control Message remains the only service message codec and its raw
envelope stays private. Inventoried trust requires confidential ordered endpoints,
WebPKI discovery, SPKI and signing-key pins, and explicit local-pin intersection.

## Proposal

Specify canonical discovery and signed opaque carriers, then publish independent
Python decisions and signatures consumed directly by Rust tests. Implement only
pure validation with supplied clock and replay observations. Keep the registry and
existing fixture entries unchanged. Document producer questions in Q11 and Q21.

## Risks

Origin normalization, signature domain confusion, empty pin intersections and clock
boundaries must fail closed. Replay persistence and WebPKI authentication belong
to callers; pure validation must not imply either was performed locally.

## Scope

Account bootstrap/envelope modules, independent producer and consumer tests,
profile, review request and the associated plan and work records.

## Alternatives

Retaining JSON or historical wire shapes would introduce compatibility code.
Recreating service-control messages would duplicate their existing contract.

## Acceptance results

The candidate specification, independent producer, pure validators and consumer
tests are implemented. The consumer reads 100 new named vectors with explicit
bytes and decisions. All 106 pre-existing fixture entries and registry bytes are
unchanged. The focused suite passed ten tests, including the four bootstrap tests.

The first consumer build failed because the required bootstrap public APIs were
absent. After implementation, format and lint checks passed, and the generator
reported all nine fixture files current. The first complete scoped self-check
passed 410 tests with zero skipped, plus documentation and static checks.

A final scoped self-check after clarifying the review request failed in the
unchanged external relay test: external_mode_announces_wss_without_a_tcp_listener,
examples/mock-relay/tests/external.rs:269, returned AddrInUse during a bind.
It reported 35 passed, one failed and cancelled the remaining tests. This proves
a failed bind, not its ownership or underlying cause. Acceptance remains blocked
until that unrelated test is diagnosed and the final scoped self-check passes.
No retry or test weakening was introduced.
