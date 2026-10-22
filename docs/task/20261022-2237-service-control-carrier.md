# 20261022-2237-service-control-carrier Service control carrier

- **status**: completed
- **priority**: P1
- **createdAt**: 2026-10-22 22:37

## Description

Deliver the pure candidate M6 carrier, exact unary and stream correlation, eight-field subscription, independent vectors and adoption documentation without changing M6 bytes.

## ActiveForm

Implementing authenticated service control contracts and vectors.

## Dependencies

Existing BootstrapEnvelope and Message contracts.

## Notes

Investigation and approved implementation approach are recorded in [the plan](../plan/20261022-2237-service-control-carrier.md). Specification and independent producer precede implementation.

## Acceptance results

- Independent Python fixtures cover 148 carrier cases across two Networks and
  46 subscription cases, including exact M6 round trips, legal unary pairs,
  bootstrap and Error shapes, signed empty receipts, singleton leases, three
  event kinds, reverse answers and context/encoding refusals.
- Failing first: publication_subscription_vectors and its signed-carrier test
  refused the new tuple with `ArrayLength { expected: 7, actual: 8 }` before the
  decoder change. The final subscription tests accept eight fields and refuse
  the old seven-field shape.
- Initial carrier fixture failures were corrected in the independent producer:
  ServiceRef is a three-element array, snapshot scope puts the subject first
  and has no schema member, and service.retry-port is not session-bearing.
  The shared Message decoder and M6 crate were unchanged.
- The dependent realm identity subscription fixtures were regenerated at the
  new arity so their malformed-realm refusals still exercise realm validation.
- Formatting, workspace lint, focused vector tests and generator verification
  passed. The final `just self-check feat/l8-account-profile` on implementation
  commit `52075779946dfe1327c341cd6d7a3830fa5b1ad2` passed: 516 tests, zero
  failures or skips, 28 generated fixture files current, semantic compatibility,
  doctests and documentation checks clean. Later changes only complete these
  plan and acceptance records.
- Local review covered the complete carrier, subscription delta, producers,
  tests and adoption documentation with no outstanding findings. The contract
  remains pure and the service-control crate has no diff.
- NSD carrier adoption and independent real producer review remain outstanding;
  fixture evidence does not establish live interoperability. The subscription
  format change is explicitly breaking for existing consumers.
