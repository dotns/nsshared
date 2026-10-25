# 20261022-1615-subnet-publication-views Subnet publication views

- **status**: completed
- **priority**: P1
- **createdAt**: 2026-10-22 16:15

## Description

Separate provider Exit grants and consumer route publications with independent
source-bound bytes and exact collection replacement/withdrawal validation.

## ActiveForm

Completed typed Subnet publication views.

## Dependencies

- **blocked by**: none
- **blocks**: none

## Notes

Investigation and approved implementation are recorded in the corresponding plan.

Acceptance passed: 23 independent source-bound events, typed payload separation,
recipient/membership/revision checks, nodes/egress ownership, and isolated provider
and client replacement/withdrawal. The registration test failed before implementation.
Existing channel fixtures now use valid grant payloads and independently retained
Egress source authority without weakening channel assertions.

`just self-check feat/l8-account-profile` passed on `83a8e60`; only these acceptance
records changed afterward. NSD N07/N08 and ns adoption remain outstanding.
