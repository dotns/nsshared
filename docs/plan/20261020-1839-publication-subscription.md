# Publication subscription

- **status**: implementing
- **createdAt**: 2026-10-20 18:39
- **approvedAt**: 2026-10-20 18:39
- **relatedTask**: 20261020-1839-publication-subscription

## Context

The control exchange inventory maps stream subscriptions to publications but has no request codec. PublicationScope contains realm/scope; issuer and recipient belong to the enclosing authenticated key. The predecessor carries capability declarations, public ingress scope requests and a boot nonce with a checked attempt counter.

## Proposal

Specify a canonical bounded request with full issuer/recipient/realm/scope entries, capability declarations, public ingress indices into those entries and required logical attempt parts. Produce independent Python vectors and Rust consumer tests before implementing the pure codec. Reuse BootstrapEnvelope signing and verification without runtime state.

## Risks

Requests confer no authority. External provisioning must authorize each exact scope. Attempt identity must never reset publication versions or tombstones. NSD confirmation remains outstanding.

## Scope

Protocol account module, independent vectors, consumer tests and candidate documentation.

## Alternatives

A separate session protocol would duplicate publication acceptance state and is excluded. Public ingress indices retain exact realm and authority binding without ambiguous bare scope strings.
