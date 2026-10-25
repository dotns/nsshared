# Publication subscription

- **status**: completed
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

## Acceptance results

- `publication_subscription_vectors` and `publication_subscription_signed_carrier` passed, covering 35 independent Python-produced cases: four canonical payloads, 24 payload refusals, one valid signed carrier and six signed carrier refusals. Corrupt signatures and replay are also refused.
- The initial `cargo test -p nsshared-proto --test publication_subscription_vectors` failed with unresolved subscription API imports before implementation. The same focused test command passed after implementation.
- `just fmt-check` and `just lint` passed before the focused verification.
- `just self-check feat/l8-account-profile` passed on the implementation commit, including static checks, independent vector regeneration checks, API compatibility, workspace tests, doctests and documentation.
- Local review of the added Rust contract, Python producer, consumer tests and specification found no outstanding correctness defects. Runtime state, I/O and publication acceptance/version logic are unchanged.
- NSD producer confirmation and matching producer vectors remain external. Shared documentation indexes and changelog are updated separately.
