# 20261106-1356-gateway-public-address-contract Report public ingress host independently of WG transport

- **status**: implementing
- **createdAt**: 2026-11-06 13:56
- **approvedAt**: 2026-11-06 13:56
- **relatedTask**: 20261106-1356-gateway-public-address-contract

## Context

Campaign gateway reports have no public ingress address. The legacy WG endpoint is intentionally empty because this gateway has no WG listener. NSD public L4 display currently derives host from WG/WSS endpoints, so it cannot show the reachable public address.

## Proposal

Extend the Campaign gateway observation with a distinct optional public ingress host. Validate a DNS name or public IP and preserve absence separately from WG transport. Use a distinct optional public ingress host and test DNS preference, IP fallback, absence, and WG independence.

## Risks

The new shared contract and pinned dependencies require ordered PRs and coordinated production deployment. Reject malformed or private addresses before displaying a public URL.

## Scope

This repository only, plus coordinated tasks in the other two repositories. No old WG endpoint semantics change.

## Alternatives

Reusing the WG endpoint was rejected because it falsely marks WireGuard available.

## Annotations

The user pre-authorized automatic approval for choices requiring no product decision.
