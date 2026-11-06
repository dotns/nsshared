# 20261106-1356-gateway-public-address-contract Report public ingress host independently of WG transport

- **status**: in_progress
- **priority**: P1
- **owner**: codex/public-ingress-20261106
- **createdAt**: 2026-11-06 13:56

## Description

Extend the Campaign gateway observation with a distinct optional public ingress host. Validate a DNS name or public IP and preserve absence separately from WG transport.

Acceptance: a configured domain wins over IP; IP is reported when no domain exists; the accepted value is visible in the public address UI; WG remains unavailable without a WG listener.

## ActiveForm

Implementing the Campaign public ingress address report.

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Notes

Coordinated with the matching 20261106-1356 tasks in nsshared, nsgw, and nsd.
