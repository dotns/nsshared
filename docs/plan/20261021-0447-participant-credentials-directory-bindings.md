# Shared participant credentials and directory bindings

- **status**: completed
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

The implementation preserves existing authentication and roster/report wire
contracts and adds separately scoped enrollment, renewal and directory eligibility.

## Results

Specification and independently generated credential/binding vectors precede the
pure codec implementation in history. The supplied-state validators and all four
contract tests pass, including the complete participant transport sequence.
The final self-check passed all 496 tests with zero skips, plus static checks,
independent vectors, API compatibility, doctests and documentation. The existing
directory and roster/report/answer bytes are unchanged. Producer confirmation,
gateway runtime migration and ns/NSD interoperability remain outstanding.
