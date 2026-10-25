# Provider Subnet route report

- **status**: completed
- **priority**: P1
- **createdAt**: 2026-10-22 10:14

## Description

Deliver pure source-qualified provider route reports with canonical bytes,
stable allocation comparisons, complete withdrawal and stale-source refusal.

## ActiveForm

Completed the provider report contract and independent consumer sequence.

## Dependencies

Existing source binding, SubnetSelection, BootstrapEnvelope and M6 ServiceRef.

## Notes

Investigation and proposal: [plan](../plan/20261022-1014-provider-subnet-report.md).
Acceptance requires independent bytes and pure decisions through withdrawal,
retained-state reconstruction and source replacement, with no runtime or I/O.

## Acceptance results

- The new API consumer first failed to compile because the report module did not
  exist. The behavioral regression
  `provider_subnet_report_delayed_response_after_withdrawal` subsequently failed
  with “a delayed response must not restore withdrawn offers”; supplying the last
  accepted report to response comparison corrected the missing generation fence.
- `provider_subnet_report` and its five companion tests pass against 74
  independently specified fixtures, covering explicit/default and empty offers,
  retries, updates, partial/complete withdrawal, reconstructed retained custody,
  reoffer stability, source retirement, carrier correlation and invalid authority.
- `just self-check` with the existing integration comparison base passed all static
  checks, independent vectors, API compatibility, 510 tests with zero skips,
  doctests and documentation generation. The checked implementation commit is
  `7e84ad5543f8265ed41f0c099f17dd2d37dc7157`; later edits update these records only.
- The Subnet publication and select/clear codecs remain unchanged. The only
  existing prefix-helper change exposes validation and containment to sibling
  contract modules. M6 is consumed through its existing codec without edits.
- NSD N30/N07/N08 and ns S11/S25 adoption and producer-owned interoperability
  evidence remain external obligations. Shared index and changelog updates are
  left for integration.
