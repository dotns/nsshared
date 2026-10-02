# 20261002-1516-next-workspace-baseline Build the next workspace on the Rust baseline

- **status**: completed
- **priority**: P1
- **owner**: claude/session-20261001
- **createdAt**: 2026-10-02 15:16

## Description

Create the `next` workspace with only the Quick crates (`keynet-proto` and `keynet-quick` moved to `quick-wire` and `quick-rendezvous`, code unchanged), the pma-rust baseline (lints, toolchain, rustfmt 2024 style, cargo-deny, cargo-shear, typos, nextest, justfile), a Gitea QA workflow, and an ADR for consuming ns-shared through Cargo git dependencies.

Acceptance: `just qa` passes on `next`.

## ActiveForm

Building the next workspace baseline

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Notes

Plan: [20261002-1516-ns-shared-rebuild](../plan/20261002-1516-ns-shared-rebuild.md)

- complete: just qa passes on next (187 tests, doctests, vector checks)
