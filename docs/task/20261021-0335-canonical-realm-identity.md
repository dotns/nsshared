# Canonical realm identity

- **status**: completed
- **priority**: P1
- **createdAt**: 20261021-0335

## Description

Introduce one pure RealmId for unsigned big-endian 128-bit values with strict uppercase 26-character Crockford text. Preserve text and binary wire positions, replace affected identity fields with the shared type, and reject old labels. Specify independent vectors before implementation, including membership versus valid public routes and removal.

## Investigation

Text membership realms currently accept arbitrary labels while policy and payer realms use 16 binary bytes. These cannot be compared without an invented mapping. Discovery hints, external provider namespaces and opaque scopes have separate meanings.

## Acceptance

Independent text/binary equality, strict owning-decoder refusal, two-realm membership removal sequence, and existing family checks.

## Notes

Implementation approved.

## Verification

The first regression failed because `lowercase-membership` was accepted by the
membership decoder. After implementation, `realm_identity_membership` and the
owning-decoder refusal tests pass. Independent fixed text/byte pairs, zero,
maximum, every bit position and arbitrary u128 values cover the codec and order.
The signed fixture sequence authenticates membership and public-edge carriers,
admits only the route realm in membership, and removes that eligibility while
the route publication remains valid.

Focused checks passed for publication, membership, public-edge, confidential
configuration, machine claims, subscription, snapshot, reports, policy, grant and
usage families. `just fmt-check` and `just lint` passed before testing.
`just self-check feat/l8-account-profile` passed, including static checks,
independent fixture regeneration, API compatibility, tests and documentation.
The unchanged usage and grant fixtures retain their exact signed bytes and
historical payer-pair assertions. Local diff review found no remaining defects.

The existing invalid-empty constructed membership test now checks duplicate
RealmIds because invalid text cannot inhabit the typed field; independent wire
vectors still refuse empty text. The oversized-members fixture now has a valid
canonical realm so it continues to reach the member-count bound.

NSD/ns producer confirmation and producer/consumer adoption remain outstanding.
No runtime admission or mapping implementation is included.
