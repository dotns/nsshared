# Fix constant-time dependency

- **status**: completed
- **priority**: P1
- **createdAt**: 2026-10-23 09:18

## Description

Remove the affected ctutils version from the shared lockfile without changing dependency requirements or advisory policy.

## Acceptance

The existing advisory check fails before the update and passes after it. Formatting, lint and the scoped quality check pass.

## Notes

The advisory check reports ctutils 0.4.2 through digest 0.11.3 and recommends upgrading to at least 0.4.4.

## Verification

`cargo deny check advisories` failed before the update with `advisories FAILED`, identifying ctutils 0.4.2 and recommending >=0.4.4. Cargo accepted 0.4.4 without changing requirements; only its version and checksum changed. `just fmt-check lint` and `just self-check` passed, including the advisory check, compatibility checks, workspace tests, doctests and documentation generation. No advisory exception was added.
