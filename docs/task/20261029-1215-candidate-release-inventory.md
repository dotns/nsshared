# Candidate release and migration inventory

- **status**: in_progress
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
