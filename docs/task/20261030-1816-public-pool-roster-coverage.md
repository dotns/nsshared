# Public pool roster Network coverage

- **status**: completed
- **priority**: P2
- **createdAt**: 2026-10-30 18:16

## Description

Clarify public-pool roster membership for all covered Networks, including Networks
created after pool selection, without changing tenant consent or billing.

## ActiveForm

Documenting public-pool roster coverage.

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Notes

Investigation found separate signed roster scope and binding eligibility contracts.
The approved proposal preserves their existing validation and wire representation.
Documentation acceptance does not establish runtime behavior or verify a producer repair.

## Acceptance

The participant roster and directory binding sections now explicitly cover all
bound Networks, including later-created Networks without a pool resave. Signed
issuer/recipient scope, tenant consent, billing and validation remain unchanged.

A documentation assertion first failed with `public-pool Network coverage is not
explicit`, then passed after the edit. `just fmt-check`, `just lint`, and
`just self-check` passed. These checks establish documentation
consistency and repository checks only; no runtime repair is verified.
