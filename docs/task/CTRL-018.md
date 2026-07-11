# CTRL-018 Surface candidate-report rate limits and metrics

- **status**: completed
- **priority**: P1
- **owner**: local session
- **createdAt**: 2026-07-11

## Description

Implement the `ns-shared` portion of sibling `ns` PLAN-110: map HTTP 429
responses to a typed error carrying optional `current_epoch` and
`retry_after_ms` fields while remaining compatible with older response bodies,
and expose the bounded P2P gather/report metric facade.

## ActiveForm

Completed the additive typed error mapping across SSE, Noise, and QUIC unary
transports through their shared status mapper, plus the bounded P2P metrics
facade.

## Acceptance Criteria

- HTTP 429 never requires string matching by callers.
- Additive epoch and retry fields are decoded when present.
- Older or malformed 429 bodies still produce a typed rate-limit error with
  absent optional fields.
- Focused control-crate tests and repository quality gates pass.
- Active candidates, confirmed misses, age expiry, inconclusive cycles, and
  acknowledged empty reports have bounded-cardinality metrics.

## Notes

- 2026-07-11 - Claimed as the `ns-shared` slice of sibling PLAN-110.
- 2026-07-11 - Completed with typed legacy-compatible 429 coverage, bounded
  no-label metric instruments, and full `just qa` plus workspace doctests.
