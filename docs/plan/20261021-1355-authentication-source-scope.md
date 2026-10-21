# 20261021-1355-authentication-source-scope Authentication source scope

- **status**: implementing
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
