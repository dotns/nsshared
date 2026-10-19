# Enrollment and membership identity

- **status**: completed
- **priority**: P1
- **owner**: (assigned)
- **createdAt**: 2026-10-19 11:20

## Description

Define the enrollment publication, canonical opaque capabilities and membership
binding acceptance. Distinguish replacement, authorized stable-identity rotation,
staged-version restart refusal and rollback. Verify each binding's derived
identifiers against independently generated expectations.

## ActiveForm

Completed enrollment contracts and independent consumer vectors.

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Notes

Investigation and proposal: [enrollment plan](../plan/20261019-1120-enrollment-identity.md).
Registry identifiers and bytes are preserved. Endpoint and producer-profile
questions remain explicit in the review request.

## Acceptance

- `enrollment_identity_vectors`: passed, covering 29 named vectors and direct
  comparisons with independent expected identifiers, addresses and canonical bytes.
- `enrollment_contract_refusals`: passed for staged-version restart, rollback,
  invalid capabilities, unauthorized rebind and nonminimal/trailing CBOR.
- `enrollment_validates_constructed_contracts`: passed for in-memory validation
  of capability bounds, ordering, invalid accepted bindings and invalid lifecycles.
- Failing-first evidence: `enrollment_identity_vectors` initially failed with
  `missing independent consumer vector: enrollment-accepted`.
- `cargo fmt --all -- --check` and workspace clippy passed.
- `python3 -B tools/vectors/generate.py --check`: nine fixtures up to date.
- The repository self-check passed at `a330e1327772cc9b6a68a71df1ca1b5f6df97fbd`:
  405 workspace tests passed, zero skipped, plus static, semantic compatibility,
  doctest and documentation checks.

No runtime, persistence, session or producer implementation was added. Endpoint
forms, same-key refresh, signed K generation, ordinary derivation version width
and capability meanings remain explicit prepared producer questions.
