# Signed participant roster lifecycle

- **status**: implementing
- **createdAt**: 2026-10-19 12:00
- **approvedAt**: 2026-10-19 12:00
- **relatedTask**: 20261019-1200-participant-roster-lifecycle

## Context

`SignedRoster` already authenticates complete membership/class publications but
returns only a generic authority error and no accepted generation. Its bytes,
signature domain and existing verification behavior must remain stable.

## Proposal

Define participant scope as the signed issuer/recipient pair. Add a pure typed
verification API returning that scope, epoch, complete mapping and signed times.
Decode refused class shapes explicitly. Add supplied-clock lifecycle decisions:
valid, diagnostically degraded after 24 hours since authenticated renewal, and
expired at the exclusive signed deadline. Generate independent signed Python
fixtures and sequences before implementing the Rust consumer contract.

## Risks

Typed parsing must preserve canonical CBOR validation and strict bounds. Diagnostic
degradation must never extend expiry or deny otherwise valid membership.

## Scope

The account roster contract, its independent producer and consumer fixtures,
atomic roster specification and the related review questions. No runtime state.

## Alternatives

Adding a scope field would change signed bytes and assume broader authorization.
Keep the existing participant credential scope instead.
