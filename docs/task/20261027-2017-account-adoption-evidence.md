# Account adoption evidence

- **status**: completed
- **priority**: P1
- **createdAt**: 2026-10-27 20:17

## Description

Update each outstanding account adoption item with immutable upstream evidence or the precise missing confirmation. Preserve all contracts, vectors, code, tests and the unstable-account feature restriction.

## ActiveForm

Producer and consumer evidence reconciled.

## Notes

Investigation and approved implementation: [plan](../plan/20261027-2017-account-adoption-evidence.md). Documentation-only; no executable regression or vector modification is appropriate.

## Acceptance results

- Reconciled the three review records against NSD `ff278641` and ns `6ea11348`; pending follow-ups remain labelled pending.
- Verified six exact producer/consumer JSON pairs: publications, routes, delivery, service_control, status and directory. An initial equality check failed for enrollment; all nine request/response carriers differ, so current byte pairing remains open. The existing historical reader is recorded without promoting it to matching current evidence.
- Verified all 31 explicit upstream file locators, cross-document adoption anchors, unchanged heading structure and Q01–Q23 delivery dates with unanswered owner dispositions.
- Documentation-only change: no failing executable regression was introduced; no code, test or vector files changed.
- Formatting and both default/candidate lint configurations passed before the complete check.
- The configured self-check selected its complete validation path and passed with exit 0: 70 script tests, 413 default-feature tests and 545 candidate-feature tests passed. Both nextest runs had zero skipped tests. Documentation tests and documentation builds passed; the existing testkit example remained ignored in each documentation-test configuration.
- Dependency checks, 42 vector files and API compatibility checks passed. Only these progress records changed after the passing self-check.
- Owner answers, live interoperability, complete producer/consumer coverage and retention sealing remain explicit external obligations. The unstable-account restriction is unchanged.
