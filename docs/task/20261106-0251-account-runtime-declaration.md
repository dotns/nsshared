# 20261106-0251-account-runtime-declaration Account runtime declaration contract

- **status**: completed
- **priority**: P1
- **owner**: account-runtime-contract
- **createdAt**: 2026-11-06 02:51

## Description

Continue the accepted ordinary Node Echo contract with a separate signed runtime
support declaration. Preserve authentication, RuntimeBind and existing vectors.

## ActiveForm

Implementing strict declaration bytes and authenticated pending-request validation.

## Dependencies

- **blocked by**: none
- **blocks**: immutable producer and consumer adoption, combined qualification

## Acceptance

- [x] Strict eight-element request and three-element receipt with bounded nested codecs.
- [x] Mandatory original registration, exact nodes source and complete capability syntax.
- [x] Complete-request domain digest and independently pinned envelope correlation.
- [x] Focused refusal vectors and prescribed relevant shared checks.

## Notes

Full-tier implementation approval was supplied before work. The existing accepted
contract owns this continuation; these detail records track only the bounded shared
change. Shared indexes and historical records remain under their existing ownership.
The isolated source starts at c523414f7d9e19e9e4bbdf4f785cd96d610d945e.
Tests will be committed before execution; current checks are not run.

The committed focused RED input failed compilation: the new contract exports were
absent, and the test hex helper import required its public module path. Both
observations are retained; the import is corrected with the implementation.


## Validation results

The immutable product/test input is
`1fabaccf6ff5f3b81919ab3eb45ec493f933be26`.
The first implementation static run failed on two single-string `concat!` fixture
constants; simplifying those constants was committed before subsequent checks.
Formatting and both workspace lint configurations then passed, followed by all
six focused declaration tests. The explicit focused filter left 166 unrelated
tests outside that run; it introduced no ignored test.

`just self-check feat/r3-campaign-2` selected full QA and passed on that immutable
input: 424 default-feature tests and 597 Account-feature tests, zero nextest skips,
71 script tests, all 48 existing generated fixture comparisons, dependency checks,
spelling and public API compatibility. Both doctest and documentation configurations
passed, retaining only the existing vectors macro example ignored once per mode.
No dependency, toolchain, old vector, authentication or RuntimeBind bytes changed.

The new request fixture is 503 canonical bytes and retains the complete source
signature. Tests cover exact request/receipt bytes and digest, nested arities and
consumption, nonminimal/truncated/trailing data, identifier/counter and capability
bounds, independent source trust, envelope direction/kind/recipient/nonce, signature,
clock/replay and pending sequence/digest correlation. Current custody, transaction
ordering and data-plane qualification remain producer/consumer responsibilities.
Final local review covered all changed source and tests and found no scope or
correctness defect. Only these owned detail records changed after qualification.

## Delivery

The branch is ready for guarded non-force source delivery by the existing delivery
owner. Consumers must use the same actual delivered immutable revision through
their existing transports. No source publication, consumer adoption, production
operation or combined Account ping success is claimed here.
