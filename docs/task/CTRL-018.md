# CTRL-018 Surface typed candidate-report rate limits

- **status**: completed
- **priority**: P1
- **owner**: local session
- **createdAt**: 2026-07-11

## Description

Implement the `ns-shared` portion of sibling `ns` PLAN-110: map HTTP 429
responses to a typed error carrying optional `current_epoch` and
`retry_after_ms` fields while remaining compatible with older response bodies.

## ActiveForm

Completed the additive typed error mapping across SSE, Noise, and QUIC unary
transports through their shared status mapper. The out-of-scope telemetry
facade identified by the first pre-merge re-gate was removed from this slice.

## Acceptance Criteria

- HTTP 429 never requires string matching by callers.
- Additive epoch and retry fields are decoded when present.
- Older or malformed 429 bodies still produce a typed rate-limit error with
  absent optional fields.
- Focused control-crate tests and repository quality gates pass.

## Notes

- 2026-07-11 - Claimed as the `ns-shared` slice of sibling PLAN-110.
- 2026-07-11 - First pre-merge re-gate required the telemetry facade to move to
  a separate slice; typed legacy-compatible 429 coverage remains in scope.
- 2026-07-11 - Removed the telemetry facade and re-ran full `just qa` plus
  workspace doctests successfully.
