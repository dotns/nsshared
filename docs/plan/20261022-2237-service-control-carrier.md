# 20261022-2237-service-control-carrier Service control carrier

- **status**: implementing
- **createdAt**: 2026-10-22 22:37
- **approvedAt**: 2026-10-22 22:37
- **relatedTask**: 20261022-2237-service-control-carrier

## Context

PublicationSubscriptionRequest currently has seven fields. BootstrapEnvelope already authenticates opaque payloads; Message owns the exact M6 codec. No candidate correlation or reverse-operation validator exists.

## Proposal

Define the candidate wire mapping and independent Python vectors first. Add a pure carrier module with authenticated request decoding, retained pending request comparison, explicit empty receipts and failures, singleton leases, bound stream event decoding and reverse proposal comparison. Append a typed optional session tuple to subscriptions and reject the old arity.

## Risks

The subscription tuple is an incompatible candidate change. Empty receipts establish carrier acceptance only. Source contribution ownership, persistence, revision floors and deadlines remain consumer obligations.

## Scope

Proto contracts and tests, independent vector producers and canonical documentation. The service-control crate is unchanged.

## Alternatives

A parallel M6 schema or runtime client would duplicate existing contracts. Reuse the Message codec and caller-supplied authentication facts instead.

## Validation

Independent vectors cover two Networks, bootstrap/error shapes, receipts, singleton leases, reverse operations and strict encoding/context refusals. Run formatting and lint, focused vectors and repository self-check.
