# Public pool roster Network coverage

- **status**: completed
- **createdAt**: 2026-10-30 18:16
- **approvedAt**: 2026-10-30 18:16
- **relatedTask**: 20261030-1816-public-pool-roster-coverage

## Context

The relay specification defines recipient-bound complete rosters and independently
verified directory bindings, but does not state public-pool Network membership coverage.

## Proposal

Document that public-pool rosters contain Nodes from every Network covered by the
directory binding, including later-created Networks without resaving the pool.
Distinguish membership coverage from signed issuer/recipient scope, and retain
separate global authority, tenant consent, service authorization and billing boundaries.

## Risks

Wording must not introduce a field, change validation, or imply runtime verification.

## Scope

Only the participant roster and directory binding documentation and these records.

## Alternatives

Leaving coverage implicit would leave the membership rule ambiguous.

## Acceptance

The participant roster and directory binding sections now explicitly cover all
bound Networks, including later-created Networks without a pool resave. Signed
issuer/recipient scope, tenant consent, billing and validation remain unchanged.

A documentation assertion first failed with `public-pool Network coverage is not
explicit`, then passed after the edit. `just fmt-check`, `just lint`, and
`just self-check feat/r3-campaign-2` passed. These checks establish documentation
consistency and repository checks only; no runtime repair is verified.
