# 20261021-1355-authentication-source-scope Authentication source scope

- **status**: completed
- **createdAt**: 2026-10-21 13:55
- **priority**: P1

## Description

Require exact authentication source selection and nodes-only registration authority, including Equal. Independent bytes cover per-scope acceptance and swapped-source refusal without runtime or I/O.

## ActiveForm

Validating explicit source selection.

## Dependencies

- **blocked by**: none
- **blocks**: none

## Notes

Investigation and approved implementation are described in the matching plan. Verification completed.

## Acceptance results

- Registration comparison requires nodes in the accepted Network, including initial and Equal enrollment. Correctly signed egress and other-Network registration bindings are refused.
- Authentication requests require the exact five-field tuple with a canonical realm and bounded scope selector; old arity, invalid purpose, malformed selector and invalid scope bounds are refused.
- Independent Python fixtures cover separate nodes and egress authentication in one Network with independent pending nonces, retained bindings and swapped-scope/realm refusal. Existing nested signature, correlation, source replacement, delayed publication and immutable-clear checks remain.
- Failing-first evidence: `cargo test -p nsshared-proto --test source_selection_vectors source_selection_fence --locked` failed with `Cbor(ArrayLength { expected: 4, actual: 5 })` before the request codec changed.
- The focused source-selection and control-exchange suites passed all 11 tests. `just fmt-check lint` passed before testing.
- `just self-check feat/l8-account-profile` passed at `dececf6`: 41 check-selection tests, 500 tests passed with zero skipped, doctests and documentation checks passed. Only these acceptance records changed afterward.
- Specifications, profile and review request describe the incompatible request delta. AuthenticationResponse and SignedSourceBinding bytes remain unchanged. NSD N04 adoption, producer-owned vectors and real interoperability remain outstanding.
