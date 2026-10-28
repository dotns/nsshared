# Fenced gateway reports

- **status**: completed
- **createdAt**: 2026-10-28 14:42
- **approvedAt**: 2026-10-28 14:42
- **relatedTask**: 20261028-1442-fenced-gateway-report

## Context

GatewayReport and its receipt lack membership and runtime context. NodePostureRequest and NodeReportContext provide the existing fenced pattern.

## Proposal

Add FencedGatewayReportRequest and FencedGatewayReportResponse with scope, runtime fence and nested unchanged report/receipt bytes. Use the existing gateway.report operation and persisted Node context; drain remains the report flag. Retain the legacy payload vectors as encoding tests, with shared operation validation requiring the fenced forms.

## Risks

Shared operation callers must supply the fenced form. Runtime freshness and accepted profile remain storage comparisons made by consumers.

## Scope

Report contracts, exports, account tests, independent vector producer and control specification.

## Alternatives

Changing GatewayReport would invalidate existing observation bytes. A new identity or operation is unnecessary.

## Validation

- The initial `fenced_gateway_operation_accepts_scoped_payload` regression failed with `Cbor(ArrayLength { expected: 12, actual: 4 })` before implementation.
- Formatting and both default-feature and account-feature Clippy checks passed before testing.
- The scoped self-check passed: 413 default-feature tests and 569 account-feature tests, with zero skips; all four fenced gateway tests passed.
- `just vectors-check` confirmed all 47 fixture files; `just semver` passed with no compatibility update required. Existing gateway, Node heartbeat and posture fixture bytes are unchanged.
- Local diff review covered all changed contract, test, generator and specification files with no blocking findings. The existing report fixture harness now tests legacy payload encoding directly and asserts rejection by shared dispatch.

Runtime freshness, source custody and persisted accepted profile comparisons remain consumer responsibilities, as documented in the control specification.
