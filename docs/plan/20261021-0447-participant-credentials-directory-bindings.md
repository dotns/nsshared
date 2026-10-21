# Shared participant credentials and directory bindings

- **status**: implementing
- **createdAt**: 2026-10-21 04:47
- **approvedAt**: 2026-10-21 04:47

## Context

Existing participant roster verification already defines issuer/recipient scope,
strict increasing complete generations and hard expiry. Participant TLS framing
and proofs currently live in the gateway. RealmId already enforces canonical text.

## Proposal

Specify shared existing proof constants and bounded frames, then dedicated
provisioned enrollment and correlated renewal. Define a separate signed directory
binding with complete realm replacement and per-issuer/id persisted floors.
Produce independent Python bytes before pure Rust codecs and validators.

## Risks

Self-presented keys must never authorize enrollment. Refusal is not withdrawal;
idempotence cannot extend expiry, and restart must retain empty withdrawal floors.

## Scope

Protocol types, vectors, tests and candidate specifications only. No runtime,
transport I/O, storage, credential custody or global directory changes.

## Alternatives

A second authentication protocol or embedding eligibility into directory entries
would break existing semantics; preserve framing and use a separate signed record.

## Annotations

Implementation approved with the complete specification. Shared indexes and
changelog are maintained separately.
