# 20261002-1516-quick-consumers Move nsgw and ns onto the shared Quick crates

- **status**: pending
- **priority**: P2
- **owner**: (unassigned)
- **createdAt**: 2026-10-02 15:16

## Description

Switch the nsgw quick relay and ns to the shared crates through Cargo git dependencies, remove the ns protocol copy, and update CI fetch credentials, cargo-deny sources and release checks in both repositories.

Acceptance: both repositories pass their QA with the shared crates and Quick end-to-end tests pass between ns and nsgw.

## ActiveForm

Moving consumers to the shared Quick crates

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Notes

Plan: [20261002-1516-ns-shared-rebuild](../plan/20261002-1516-ns-shared-rebuild.md)
