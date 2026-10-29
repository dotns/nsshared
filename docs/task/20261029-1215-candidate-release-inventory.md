# Candidate release and migration inventory

- **status**: completed
- **priority**: P1
- **createdAt**: 2026-10-29 12:15

## Description

Document current whole-floor M6 and independent roster counters using exported
names and existing independent fixtures. Preserve old-byte compatibility and
all outstanding producer, review, release and live prerequisites.

## Investigation

Read current specifications, historical adoption dispositions and shared delivery
reports. Whole-floor types are exported by both service surfaces. Roster schema 1
preserves bytes by coupling epoch to version; schema 2 separates counters.
The historical service-control fixture/test locators refer to an older layout;
current shared service fixtures live under nsshared-control.

## Acceptance

- Match exported types and existing fixture locations.
- Keep source adoption, corpus matching and release approval distinct.
- Preserve unstable-account and leave release revision/cohort unset.

## Notes

Documentation-only work; executable behavior and fixture bytes remain unchanged.

## Results

All acceptance items are documented in the four review documents. Public names,
legacy-byte boundaries and current fixture locations were checked against shared
specifications and public declarations. Candidate roster source compatibility
is explicitly distinguished from schema-1 wire compatibility. Remaining review,
producer, consumer, retention and release prerequisites stay open.

Failing-test-first is not applicable: only non-executable documentation changed;
no source, test or vector was modified. `just dev-check` and the specified
`just self-check` passed. Self-check selected full validation:
70 script tests, 421 default-feature tests and 579 account-feature tests passed,
zero nextest skips; 48 fixture files, semver/API, doctests and documentation passed.
Validation covers shared contracts only. Final release revision/cohort remain unset.
