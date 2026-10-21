# 20261021-1355-authentication-source-scope Authentication source scope

- **status**: completed
- **createdAt**: 2026-10-21 13:55
- **approvedAt**: 2026-10-21 13:55
- **relatedTask**: 20261021-1355-authentication-source-scope

## Context

Authentication requests omit source selection. Registration verifies independently supplied source facts but does not constrain them to nodes in its accepted Network. Existing nested signatures and response encodings can be reused.

## Proposal

Specify the mandatory realm/scope selector, extend independent vectors, then add pure request validation and registration scope comparison. Preserve response bytes and existing source replacement and immutable receipt checks.

## Risks

The request arity change is incompatible; external producers and consumers must adopt the same revision.

## Scope

Control exchange codec, independent producers and consumer vectors, specifications, profile and review request.

## Alternatives

An omitted-selector default would allow ambiguous authority and is refused.

## Acceptance results

- Registration comparison requires nodes in the accepted Network, including initial and Equal enrollment. Correctly signed egress and other-Network registration bindings are refused.
- Authentication requests require the exact five-field tuple with a canonical realm and bounded scope selector; old arity, invalid purpose, malformed selector and invalid scope bounds are refused.
- Independent Python fixtures cover separate nodes and egress authentication in one Network with independent pending nonces, retained bindings and swapped-scope/realm refusal. Existing nested signature, correlation, source replacement, delayed publication and immutable-clear checks remain.
- Failing-first evidence: `cargo test -p nsshared-proto --test source_selection_vectors source_selection_fence --locked` failed with `Cbor(ArrayLength { expected: 4, actual: 5 })` before the request codec changed.
- The focused source-selection and control-exchange suites passed all 11 tests. `just fmt-check lint` passed before testing.
- `just self-check feat/l8-account-profile` passed at `dececf6`: 41 check-selection tests, 500 tests passed with zero skipped, doctests and documentation checks passed. Only these acceptance records changed afterward.
- Specifications, profile and review request describe the incompatible request delta. AuthenticationResponse and SignedSourceBinding bytes remain unchanged. NSD N04 adoption, producer-owned vectors and real interoperability remain outstanding.
