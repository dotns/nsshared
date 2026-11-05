# Preserve captured authentication conditions

- **status**: completed
- **priority**: P1
- **owner**: (assigned)
- **createdAt**: 2026-11-05 14:44

## Description

Restore the established six-element authentication request alongside delivered
Default M6 and Node-only L3 contracts. Keep each captured registration identifier
independent of binding and source generations. Reject missing, malformed and
noncanonical conditions and document the five-element incompatibility.

## ActiveForm

Restoring and verifying captured authentication conditions.

## Dependencies

- **blocked by**: none
- **blocks**: compatible immutable consumer adoption

## Investigation

The exchange, public export, existing regression, two vector producers and their
fixtures have an exact established source. Source-selection test logic already
checks canonical request/response bytes. The authentication response and all
other delivered contract implementations can remain unchanged.

## Proposal

See [the implementation plan](../plan/20261105-1444-captured-authentication-condition.md).

## Acceptance

- Six-element round-trip preserves the independently captured condition.
- Independent vectors reject five-element requests and invalid conditions.
- Default, Node-only L3, explicit and TCP/UDP contracts retain their coverage.
- Documentation states exact compatibility and authority boundaries.

## Notes

Implementation approved with the bounded restoration request.

The initial focused run failed all three selected tests: the registration-incarnation
regression and source-selection consumer rejected six-element inputs with an
array-length mismatch, while the exchange vector consumer refused the valid
six-element authentication fixture. Formatting and both feature-mode lints had
passed first. The codec, public export, producers and fixtures now exactly match
the established six-element source. The restored regression additionally compares
both populated and explicit-null encodings with independent fixture bytes.

## Acceptance Results

- `authentication_retains_independent_registration_incarnations` passed with
  exact populated-condition and explicit-null fixture bytes. Changing each
  captured fact preserves the independently asserted binding and source selector.
- `control_exchange_vectors` passed with the established malformed-identifier,
  condition-shape, five-element, trailing-data and nonminimal-encoding refusals.
- `independent_source_selection_vectors` passed with the restored canonical
  request bytes and unchanged response/source-selection checks.
- Formatting and both feature-mode lints passed after restoration.
- `just self-check` passed: 424 default-feature tests and 591 account-feature
  tests, with zero skips in both runs; static checks, independently generated
  vectors, default API compatibility, documentation and doctests also passed.
- Existing complete Default floor, explicit profile, Node-only Echo, TCP/UDP and
  non-Node protocol restriction coverage passed with the delivered behavior.
- Local fixture observations establish codec behavior; authority comparison
  remains the consuming server's responsibility. The specification records the
  exact five-versus-six-element incompatibility and captured-receipt requirements.

No product change remains in this scope. Consumer adoption requires compatible
immutable publication after integration verification.

## Final validation

- [ ] Run the complete integration check on the composed source.
