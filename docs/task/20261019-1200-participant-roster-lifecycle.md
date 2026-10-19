# Signed participant roster lifecycle

- **status**: in-progress
- **createdAt**: 2026-10-19 12:00
- **updatedAt**: 2026-10-19 12:00
- **plan**: ../plan/20261019-1200-participant-roster-lifecycle.md

## Goal

Return complete authenticated participant generations with typed refusals and
supplied-clock validity/degradation decisions, preserving existing signed bytes.

## Investigation

The roster's issuer and recipient already identify participant scope. Version is
the attribution epoch; entries are complete replacement. Existing verification
collapses authority and freshness causes. Enrollment demonstrates typed decisions
and independent expected values in the account fixture.

## Acceptance

- [ ] Independent vectors cover acceptance, complete replacement, class changes,
  authority/version/signature refusals and validity/degradation boundaries.
- [ ] Consumer reads canonical bytes, decisions and clock inputs from the fixture.
- [ ] Existing vectors retain their names and bytes.
- [ ] Formatting, lint and self-check pass.

## Validation

Pending.
