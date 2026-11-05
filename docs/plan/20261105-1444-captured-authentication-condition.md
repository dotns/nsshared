# Preserve captured authentication conditions

- **status**: completed
- **createdAt**: 2026-11-05 14:44
- **approvedAt**: 2026-11-05 14:44
- **relatedTask**: 20261105-1444-captured-authentication-condition

## Context

The delivered authentication request has five elements and lacks the captured
registration condition. The established six-element contract at
`9969abd8507ea3de057b0b870492755908206e89`, introduced by
`3b5c4878e71b4b77d21cf86c442272a088e0ba65`, retains independent server Node,
credential-incarnation and Account-activation identifiers. These sources diverge;
the delivered source also includes required Default M6 and Node-only L3 behavior.

## Proposal

Restore the exact condition type, public export and six-element codec from the
established source. Restore its independent exchange and source-selection vector
producers and fixtures. Reuse the existing registration-incarnation regression
and malformed-input controls. Preserve response bytes, source refresh, Default
M6, explicit profiles, Node L3 and TCP/UDP encodings.

## Risks

Five-element clients are incompatible in both directions. Explicit null carries
no authority; Account clients retain and supply their original receipt facts.
The server must compare captured facts with current authority before issuance.
No current-row synthesis, alternate decoder or broader omission is permitted.

## Scope

Authentication exchange/export, existing exchange and source-selection tests and
vectors, their two independent producers, and the control specification.

## Alternatives

Accepting both arities or inferring a missing condition would lose the captured
registration fence. Reverting the complete dependency would lose Default and
Node-only L3 contracts. Restore only the established authentication owners.

## Validation

Run formatting and lints before the focused failing regression, then restore the
codec and require the focused controls and scoped self-check to pass.

## Results

The codec, public export, both independent producers and both fixtures exactly
match `9969abd8507ea3de057b0b870492755908206e89`. Only the authentication
specification and restored regression add clarifications and stronger byte
comparisons beyond that source. Existing response/source-refresh and delivered
Default/Node-only L3 implementations remain intact.

Formatting and both feature-mode lints passed before the failing focused run.
The three focused tests first failed against the five-element decoder, then all
passed after restoration. `just self-check` passed with 424 default-feature and
591 account-feature tests, neither run skipping any test, as well as static,
vector, compatibility, documentation and doctest checks. The existing Default
floor, ordinary Node Echo and non-Node TCP/UDP restriction controls all passed.
