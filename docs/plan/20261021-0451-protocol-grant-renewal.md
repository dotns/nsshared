# Protocol-qualified grant identity and expiry renewal

- **status**: implementing
- **createdAt**: 20261021-0451
- **approvedAt**: 20261021-0451
- **relatedTask**: 20261021-0451-protocol-grant-renewal

## Context

Grant ordering currently uses resource/client only. Payer and active claim tuples omit protocol, and successor validation refuses all deadline changes. Source wrappers authenticate opaque family payloads separately.

## Proposal

Specify the full resource/client/discriminator key first, generate independent dual-protocol and Exit renewal bytes, then update pure codecs, exact joins and successor checks. Keep the seven-field grant and usage bytes unchanged. Retain resource/token retirement history.

## Risks

The payer and active claim tuples change incompatibly. Token ownership must remain unique across grant keys within each resource. Embedded Subnet content cannot change during renewal.

## Scope

Pure grant types, producers, consumer tests and grant/profile/review documentation.

## Alternatives

Unqualified joins and old tuple fallback cannot distinguish independent protocol lifetimes and are refused.
