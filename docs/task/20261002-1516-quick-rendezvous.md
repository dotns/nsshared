# 20261002-1516-quick-rendezvous Define the quick-rendezvous message types

- **status**: completed
- **priority**: P1
- **owner**: R workstream
- **createdAt**: 2026-10-02 15:16

## Description

Replace the renamed `keynet-quick` with the rendezvous v2 mailbox messages, the relay capability vocabulary and the relay directory v2 types from docs `ns/rendezvous.md`.

Acceptance: every message type round-trips and rejects the documented invalid inputs.

## ActiveForm

Defining quick-rendezvous

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Notes

Plan: [20261002-1516-ns-shared-rebuild](../plan/20261002-1516-ns-shared-rebuild.md)

Completed 2026-10-03: delivered as crate `ns-rendezvous` (the v1 rendezvous
crate is deleted). Coverage: [ns-rendezvous spec coverage](../spec-coverage/ns-rendezvous.md).
