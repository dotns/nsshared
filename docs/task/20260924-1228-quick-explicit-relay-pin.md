# Remove URI invitations in favor of explicit relay PINs

- **status**: completed
- **priority**: P1
- **owner**: quick-cli
- **createdAt**: 2026-09-24 12:28

## Description

User explicitly requests removal of URI invitations, including compatibility.
Keep directory-prefixed default codes; custom relays use an eight-digit PIN
with an explicit relay selector, positional or private prompted input.

## ActiveForm

Canonical parser/formatter verified; NS integration and public examples are
tracked under the same task ID in their respective repositories.

## Dependencies

- **blocked by**: none
- **blocks**: delivery of the simplified invitation UX

## Notes

Coordinated across ns, ns-shared and product-docs. No protocol, identity,
authorization, expiry or broker cleanup changes; no deployment authorized.
The host has only 2.3 GiB free disk: reuse existing caches, serialize builds.

Verification: four canonical crate tests, crate all-target Clippy and workspace
format check pass. NS mirrors the four source files byte for byte and verifies
their hashes. No cryptographic or relay wire message changed. Not deployed.
