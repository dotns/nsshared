# Protocol-qualified grant identity and expiry renewal

- **status**: completed
- **createdAt**: 2026-10-21 04:51
- **approvedAt**: 2026-10-21 04:51
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

## Acceptance results

- `protocol_grant_renewal` initially failed with `Ordering` when decoding the independent dual-protocol publication, before the implementation changed.
- Independent Python bytes and Rust consumers now cover protocol-qualified ordering, exact payer/active joins, unchanged tokens and payer attribution during renewal, earlier-deadline and changed-content refusal, selective TCP withdrawal with continuing UDP authority, retired TCP refusal, fresh regrant and Exit renewal.
- Separate boundary tests refuse shared resource tokens, duplicate keys, wrong protocol/token/payer joins, stale revisions and embedded Subnet changes. Old tuple arities and malformed discriminators refuse.
- Signed source fixtures carry the revised payer/active tuples. Existing malformed, expiry and payer coverage remains. Usage producer and fixture bytes are unchanged against the integration base.
- `just fmt-check` and `just lint` passed before final testing. `just self-check feat/l8-account-profile` passed at `237605185d5e21d8c33067c785341f7263534094`: 495 tests passed, zero skipped; doctest, documentation, vectors and compatibility checks passed. The earlier implementation also passed the same check before adding independent retired-protocol refusal bytes.
- Local review covered the changed pure codecs, joins, successor checks, producers, consumer tests and specifications; no unresolved findings remain.
- NSD producer adoption and producer-owned interoperability vectors remain outstanding. The observations above use fixture authority.
